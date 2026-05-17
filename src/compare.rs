use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cost::estimate_resource_cost;
use crate::db::{latest_terraform_state_id, open_cloudmapper_db};
use crate::model::{Resource, SCHEMA_VERSION};

#[derive(Debug, Serialize)]
pub struct CompareReport {
    pub schema_version: String,
    pub run_id: String,
    pub scan_id: String,
    pub terraform_state_id: String,
    pub generated_at: String,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub id: String,
    #[serde(rename = "type")]
    pub finding_type: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terraform_address: Option<String>,
    pub reason: String,
    pub recommended_action: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blast_radius: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub attributes: Value,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Medium,
    High,
    Critical,
}

#[derive(Clone)]
struct AwsResource {
    uid: String,
    provider: String,
    account_id: String,
    partition: String,
    region: String,
    service: String,
    resource_type: String,
    id: String,
    arn: Option<String>,
    name: Option<String>,
    tags: BTreeMap<String, String>,
    attributes: Value,
    evidence: Vec<Value>,
}

#[derive(Clone)]
struct TerraformResource {
    address: String,
    resource_type: String,
    aws_uid: Option<String>,
    attributes: Value,
}

pub fn compare_infra(
    db_path: &Path,
    scan_id: Option<&str>,
    terraform_state_id: Option<&str>,
) -> Result<CompareReport> {
    let connection = open_cloudmapper_db(db_path)?;
    let scan_id = match scan_id {
        Some(scan_id) => scan_id.to_string(),
        None => latest_scan_id(&connection)?.context("no AWS scan found in map database")?,
    };
    let terraform_state_id = match terraform_state_id {
        Some(state_id) => state_id.to_string(),
        None => latest_terraform_state_id(&connection)?
            .context("no imported Terraform state found in map database")?,
    };
    let mut report = compare_connection(&connection, &scan_id, &terraform_state_id)?;
    write_findings(&connection, &report)?;
    report.findings.sort_by_key(finding_sort_key);
    Ok(report)
}

fn compare_connection(
    connection: &Connection,
    scan_id: &str,
    terraform_state_id: &str,
) -> Result<CompareReport> {
    let generated_at = Utc::now().to_rfc3339();
    let run_id = format!("compare:{scan_id}:{terraform_state_id}");
    let aws_resources = load_aws_resources(connection, scan_id)?;
    let terraform_resources = load_terraform_resources(connection, terraform_state_id)?;
    let terraform_by_uid = terraform_resources
        .iter()
        .filter_map(|resource| {
            resource
                .aws_uid
                .as_ref()
                .map(|uid| (uid.clone(), resource.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let aws_uids = aws_resources.keys().cloned().collect::<BTreeSet<_>>();

    let mut findings = Vec::new();
    for resource in aws_resources.values() {
        if let Some(terraform_resource) = terraform_by_uid.get(&resource.uid) {
            if let Some(finding) = terraform_owned_public_ingress(resource, terraform_resource) {
                findings.push(finding);
            }
            if let Some(finding) = costed_instance_type_drift(resource, terraform_resource) {
                findings.push(finding);
            }
            continue;
        }

        if let Some(finding) = unmanaged_public_resource(resource, connection, scan_id)? {
            findings.push(finding);
        } else {
            findings.push(unmanaged_resource(resource));
        }
    }

    for resource in terraform_resources {
        let Some(aws_uid) = &resource.aws_uid else {
            continue;
        };
        if !aws_uids.contains(aws_uid) {
            findings.push(state_only_resource(&resource));
        }
    }

    Ok(CompareReport {
        schema_version: format!("{SCHEMA_VERSION}.compare.v1"),
        run_id,
        scan_id: scan_id.to_string(),
        terraform_state_id: terraform_state_id.to_string(),
        generated_at,
        findings,
    })
}

fn latest_scan_id(connection: &Connection) -> Result<Option<String>> {
    connection
        .query_row(
            "SELECT id FROM scans ORDER BY collected_at DESC, id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("loading latest AWS scan id")
}

fn load_aws_resources(
    connection: &Connection,
    scan_id: &str,
) -> Result<BTreeMap<String, AwsResource>> {
    let mut statement = connection.prepare(
        r#"
        SELECT uid, provider, account_id, partition, region, service, resource_type,
               resource_id, arn, name, tags_json, attributes_json, evidence_json
        FROM resources
        WHERE scan_id = ?1
        "#,
    )?;
    let rows = statement.query_map(params![scan_id], |row| {
        let tags_json: String = row.get(10)?;
        let attributes_json: String = row.get(11)?;
        let evidence_json: String = row.get(12)?;
        Ok(AwsResource {
            uid: row.get(0)?,
            provider: row.get(1)?,
            account_id: row.get(2)?,
            partition: row.get(3)?,
            region: row.get(4)?,
            service: row.get(5)?,
            resource_type: row.get(6)?,
            id: row.get(7)?,
            arn: row.get(8)?,
            name: row.get(9)?,
            tags: parse_json(tags_json)?,
            attributes: parse_json(attributes_json)?,
            evidence: parse_json(evidence_json)?,
        })
    })?;

    let mut resources = BTreeMap::new();
    for row in rows {
        let resource = row?;
        resources.insert(resource.uid.clone(), resource);
    }
    Ok(resources)
}

fn load_terraform_resources(
    connection: &Connection,
    state_id: &str,
) -> Result<Vec<TerraformResource>> {
    let mut statement = connection.prepare(
        r#"
        SELECT address, resource_type, aws_uid, attributes_json
        FROM terraform_resource_instances
        WHERE state_id = ?1
        "#,
    )?;
    let rows = statement.query_map(params![state_id], |row| {
        let attributes_json: String = row.get(3)?;
        Ok(TerraformResource {
            address: row.get(0)?,
            resource_type: row.get(1)?,
            aws_uid: row.get(2)?,
            attributes: parse_json(attributes_json)?,
        })
    })?;

    rows.collect::<Result<Vec<_>, _>>()
        .context("loading Terraform resources")
}

fn terraform_owned_public_ingress(
    resource: &AwsResource,
    terraform_resource: &TerraformResource,
) -> Option<Finding> {
    if !is_public_security_group(resource) {
        return None;
    }
    Some(Finding {
        id: finding_id("terraform_owned_public_ingress", &resource.uid),
        finding_type: "terraform_owned_public_ingress".to_string(),
        severity: Severity::High,
        aws_uid: Some(resource.uid.clone()),
        terraform_address: Some(terraform_resource.address.clone()),
        reason: format!(
            "{} is managed by Terraform but allows public ingress.",
            resource_label(resource)
        ),
        recommended_action:
            "Restrict public ingress in Terraform unless this exposure is intentional.".to_string(),
        blast_radius: Vec::new(),
        evidence: resource.evidence.clone(),
        attributes: public_ingress_attributes(resource),
    })
}

fn costed_instance_type_drift(
    resource: &AwsResource,
    terraform_resource: &TerraformResource,
) -> Option<Finding> {
    if resource.service != "ec2"
        || resource.resource_type != "instance"
        || terraform_resource.resource_type != "aws_instance"
    {
        return None;
    }
    let current_instance_type = string_attr(&resource.attributes, "instance_type")?;
    let terraform_instance_type = string_attr(&terraform_resource.attributes, "instance_type")?;
    if current_instance_type == terraform_instance_type {
        return None;
    }

    let current_cost = estimated_cost_for_attributes(resource, resource.attributes.clone())?;
    let terraform_cost =
        estimated_cost_for_attributes(resource, terraform_resource.attributes.clone())?;
    let monthly_delta = current_cost.monthly_usd - terraform_cost.monthly_usd;
    let hourly_delta = current_cost.hourly_usd - terraform_cost.hourly_usd;
    let severity = if monthly_delta.abs() >= 100.0 {
        Severity::High
    } else {
        Severity::Medium
    };

    Some(Finding {
        id: finding_id("terraform_instance_type_drift", &resource.uid),
        finding_type: "terraform_instance_type_drift".to_string(),
        severity,
        aws_uid: Some(resource.uid.clone()),
        terraform_address: Some(terraform_resource.address.clone()),
        reason: format!(
            "{} is managed by Terraform as {} but AWS is running {} (estimated {:+.2} USD/month).",
            resource_label(resource),
            terraform_instance_type,
            current_instance_type,
            monthly_delta
        ),
        recommended_action: format!(
            "Run Terraform plan/apply to return the instance to {terraform_instance_type}, or update Terraform to {current_instance_type} if the resize is intentional."
        ),
        blast_radius: Vec::new(),
        evidence: resource.evidence.clone(),
        attributes: json!({
            "service": resource.service,
            "type": resource.resource_type,
            "id": resource.id,
            "arn": resource.arn,
            "drift": {
                "attribute": "instance_type",
                "terraform_value": terraform_instance_type,
                "aws_value": current_instance_type
            },
            "cost": {
                "currency": current_cost.currency,
                "source": current_cost.source,
                "confidence": current_cost.confidence,
                "estimated_current_hourly_usd": round_money(current_cost.hourly_usd),
                "estimated_current_daily_usd": round_money(current_cost.daily_usd),
                "estimated_current_monthly_usd": round_money(current_cost.monthly_usd),
                "estimated_terraform_hourly_usd": round_money(terraform_cost.hourly_usd),
                "estimated_terraform_daily_usd": round_money(terraform_cost.daily_usd),
                "estimated_terraform_monthly_usd": round_money(terraform_cost.monthly_usd),
                "estimated_delta_hourly_usd": round_money(hourly_delta),
                "estimated_delta_daily_usd": round_money(hourly_delta * 24.0),
                "estimated_delta_monthly_usd": round_money(monthly_delta)
            }
        }),
    })
}

fn unmanaged_public_resource(
    resource: &AwsResource,
    connection: &Connection,
    scan_id: &str,
) -> Result<Option<Finding>> {
    if !is_public_security_group(resource) {
        return Ok(None);
    }
    let blast_radius = reverse_neighbors(connection, scan_id, &resource.uid)?;
    Ok(Some(Finding {
        id: finding_id("unmanaged_public_resource", &resource.uid),
        finding_type: "unmanaged_public_resource".to_string(),
        severity: Severity::Critical,
        aws_uid: Some(resource.uid.clone()),
        terraform_address: None,
        reason: format!(
            "{} exists in AWS, is absent from Terraform state, and allows public ingress.",
            resource_label(resource)
        ),
        recommended_action: "Import into Terraform or remove the public ingress rule.".to_string(),
        blast_radius,
        evidence: resource.evidence.clone(),
        attributes: public_ingress_attributes(resource),
    }))
}

fn unmanaged_resource(resource: &AwsResource) -> Finding {
    let mut attributes = json!({
        "service": resource.service,
        "type": resource.resource_type,
        "id": resource.id,
        "arn": resource.arn,
    });
    if let Some(cost) = current_cost_attributes(resource)
        && let Value::Object(map) = &mut attributes
    {
        map.insert("cost".to_string(), cost);
    }

    Finding {
        id: finding_id("unmanaged_resource", &resource.uid),
        finding_type: "unmanaged_resource".to_string(),
        severity: Severity::Medium,
        aws_uid: Some(resource.uid.clone()),
        terraform_address: None,
        reason: format!(
            "{} exists in AWS but is absent from Terraform state.",
            resource_label(resource)
        ),
        recommended_action:
            "Import into Terraform, add to the intended IaC stack, or delete if unused.".to_string(),
        blast_radius: Vec::new(),
        evidence: resource.evidence.clone(),
        attributes,
    }
}

fn state_only_resource(resource: &TerraformResource) -> Finding {
    Finding {
        id: finding_id("state_only_resource", &resource.address),
        finding_type: "state_only_resource".to_string(),
        severity: Severity::Medium,
        aws_uid: resource.aws_uid.clone(),
        terraform_address: Some(resource.address.clone()),
        reason: format!(
            "{} exists in Terraform state but was not found in the AWS scan.",
            resource.address
        ),
        recommended_action:
            "Run Terraform refresh/plan and verify whether the resource was deleted or scan coverage is missing."
                .to_string(),
        blast_radius: Vec::new(),
        evidence: Vec::new(),
        attributes: json!({
            "terraform_type": resource.resource_type,
        }),
    }
}

fn is_public_security_group(resource: &AwsResource) -> bool {
    resource.service == "ec2"
        && resource.resource_type == "security-group"
        && !public_ingress_rules(resource).is_empty()
}

fn public_ingress_attributes(resource: &AwsResource) -> Value {
    json!({
        "public_ingress": public_ingress_rules(resource),
        "service": resource.service,
        "type": resource.resource_type,
        "id": resource.id,
        "arn": resource.arn,
    })
}

fn public_ingress_rules(resource: &AwsResource) -> Vec<Value> {
    resource
        .attributes
        .get("ingress")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .filter(|rule| rule_has_public_cidr(rule))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn rule_has_public_cidr(rule: &Value) -> bool {
    array_contains(rule, "ipv4_ranges", "0.0.0.0/0") || array_contains(rule, "ipv6_ranges", "::/0")
}

fn array_contains(value: &Value, field: &str, needle: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|values| values.iter().any(|value| value.as_str() == Some(needle)))
        .unwrap_or(false)
}

fn estimated_cost_for_attributes(
    resource: &AwsResource,
    attributes: Value,
) -> Option<crate::model::ResourceCost> {
    let synthetic = Resource {
        uid: resource.uid.clone(),
        provider: resource.provider.clone(),
        account_id: resource.account_id.clone(),
        partition: resource.partition.clone(),
        region: resource.region.clone(),
        service: resource.service.clone(),
        resource_type: resource.resource_type.clone(),
        id: resource.id.clone(),
        arn: resource.arn.clone(),
        name: resource.name.clone(),
        tags: resource.tags.clone(),
        attributes,
        evidence: Vec::new(),
        raw: None,
    };
    estimate_resource_cost(&synthetic)
}

fn current_cost_attributes(resource: &AwsResource) -> Option<Value> {
    let cost = estimated_cost_for_attributes(resource, resource.attributes.clone())?;
    if cost.monthly_usd <= 0.0 {
        return None;
    }
    Some(json!({
        "currency": cost.currency,
        "source": cost.source,
        "confidence": cost.confidence,
        "estimated_current_hourly_usd": round_money(cost.hourly_usd),
        "estimated_current_daily_usd": round_money(cost.daily_usd),
        "estimated_current_monthly_usd": round_money(cost.monthly_usd),
        "estimated_delta_hourly_usd": round_money(cost.hourly_usd),
        "estimated_delta_daily_usd": round_money(cost.daily_usd),
        "estimated_delta_monthly_usd": round_money(cost.monthly_usd)
    }))
}

fn string_attr(attributes: &Value, key: &str) -> Option<String> {
    attributes
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn round_money(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

fn reverse_neighbors(connection: &Connection, scan_id: &str, uid: &str) -> Result<Vec<String>> {
    let mut statement = connection.prepare(
        r#"
        SELECT DISTINCT from_uid
        FROM relationships
        WHERE scan_id = ?1 AND to_uid = ?2
        ORDER BY from_uid
        "#,
    )?;
    let rows = statement.query_map(params![scan_id, uid], |row| row.get(0))?;
    rows.collect::<Result<Vec<_>, _>>()
        .context("loading blast-radius neighbors")
}

fn write_findings(connection: &Connection, report: &CompareReport) -> Result<()> {
    connection.execute(
        "DELETE FROM findings WHERE run_id = ?1",
        params![report.run_id],
    )?;
    let mut statement = connection.prepare(
        r#"
        INSERT INTO findings (
          run_id, id, finding_type, severity, aws_uid, terraform_address, reason,
          recommended_action, blast_radius_json, evidence_json, attributes_json, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
    )?;
    for finding in &report.findings {
        statement.execute(params![
            report.run_id,
            finding.id,
            finding.finding_type,
            severity_name(finding.severity),
            finding.aws_uid,
            finding.terraform_address,
            finding.reason,
            finding.recommended_action,
            serde_json::to_string(&finding.blast_radius)?,
            serde_json::to_string(&finding.evidence)?,
            serde_json::to_string(&finding.attributes)?,
            report.generated_at,
        ])?;
    }
    Ok(())
}

fn finding_sort_key(finding: &Finding) -> (std::cmp::Reverse<Severity>, String, String) {
    (
        std::cmp::Reverse(finding.severity),
        finding.finding_type.clone(),
        finding
            .aws_uid
            .clone()
            .or_else(|| finding.terraform_address.clone())
            .unwrap_or_default(),
    )
}

fn resource_label(resource: &AwsResource) -> String {
    let name = resource
        .name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or(&resource.id);
    format!("{} {} {}", resource.service, resource.resource_type, name)
}

fn finding_id(finding_type: &str, key: &str) -> String {
    format!("{finding_type}:{}", key.replace([' ', '\n', '\t'], "_"))
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn parse_json<T: serde::de::DeserializeOwned>(value: String) -> rusqlite::Result<T> {
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;
    use rusqlite::params;
    use serde_json::json;
    use tempfile::tempdir;

    use crate::db::{open_cloudmapper_db, write_inventory_db};
    use crate::model::{Evidence, Generator, Inventory, Relationship, Resource, SCHEMA_VERSION};
    use crate::terraform_state::import_terraform_state_file;

    use super::*;

    #[test]
    fn compare_reports_unmanaged_public_resource_with_blast_radius() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("map.db");
        let state_path = temp.path().join("terraform.tfstate");
        write_inventory_db(&db_path, &sample_inventory()).unwrap();
        std::fs::write(&state_path, SAMPLE_TFSTATE).unwrap();
        import_terraform_state_file(&db_path, &state_path, None).unwrap();

        let report = compare_infra(&db_path, None, None).unwrap();

        let public = report
            .findings
            .iter()
            .find(|finding| finding.finding_type == "unmanaged_public_resource")
            .unwrap();
        assert_eq!(public.severity, Severity::Critical);
        assert_eq!(
            public.aws_uid.as_deref(),
            Some("aws:123456789012:us-east-1:ec2:security-group:sg-public")
        );
        assert_eq!(
            public.blast_radius,
            vec!["aws:123456789012:us-east-1:ec2:instance:i-public"]
        );

        let connection = open_cloudmapper_db(&db_path).unwrap();
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM findings WHERE run_id = ?1",
                params![report.run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, report.findings.len() as i64);
    }

    #[test]
    fn compare_reports_state_only_resource() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("map.db");
        let state_path = temp.path().join("terraform.tfstate");
        write_inventory_db(&db_path, &sample_inventory()).unwrap();
        std::fs::write(&state_path, SAMPLE_TFSTATE).unwrap();
        import_terraform_state_file(&db_path, &state_path, None).unwrap();

        let report = compare_infra(&db_path, None, None).unwrap();
        let state_only = report
            .findings
            .iter()
            .find(|finding| finding.finding_type == "state_only_resource")
            .unwrap();

        assert_eq!(
            state_only.terraform_address.as_deref(),
            Some("aws_instance.missing")
        );
    }

    #[test]
    fn compare_reports_costed_ec2_instance_type_drift() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("map.db");
        let state_path = temp.path().join("terraform.tfstate");
        write_inventory_db(&db_path, &sample_drift_inventory()).unwrap();
        std::fs::write(&state_path, SAMPLE_DRIFT_TFSTATE).unwrap();
        import_terraform_state_file(&db_path, &state_path, None).unwrap();

        let report = compare_infra(&db_path, None, None).unwrap();

        let drift = report
            .findings
            .iter()
            .find(|finding| finding.finding_type == "terraform_instance_type_drift")
            .unwrap();
        assert_eq!(drift.severity, Severity::High);
        assert_eq!(
            drift.terraform_address.as_deref(),
            Some("aws_instance.worker")
        );
        assert_eq!(
            drift.attributes["drift"]["terraform_value"].as_str(),
            Some("t3.small")
        );
        assert_eq!(
            drift.attributes["drift"]["aws_value"].as_str(),
            Some("t3.2xlarge")
        );
        assert!(
            drift.attributes["cost"]["estimated_delta_monthly_usd"]
                .as_f64()
                .unwrap()
                > 200.0
        );
    }

    fn sample_inventory() -> Inventory {
        let collected_at = Utc::now();
        let public_sg_uid = "aws:123456789012:us-east-1:ec2:security-group:sg-public".to_string();
        let managed_sg_uid = "aws:123456789012:us-east-1:ec2:security-group:sg-managed".to_string();
        let instance_uid = "aws:123456789012:us-east-1:ec2:instance:i-public".to_string();

        Inventory {
            schema_version: SCHEMA_VERSION.to_string(),
            generator: Generator {
                name: "cloudmapper".to_string(),
                version: "test".to_string(),
            },
            account_id: "123456789012".to_string(),
            partition: "aws".to_string(),
            home_region: "us-east-1".to_string(),
            regions: vec!["us-east-1".to_string()],
            collected_at,
            resources: vec![
                Resource {
                    uid: public_sg_uid.clone(),
                    provider: "aws".to_string(),
                    account_id: "123456789012".to_string(),
                    partition: "aws".to_string(),
                    region: "us-east-1".to_string(),
                    service: "ec2".to_string(),
                    resource_type: "security-group".to_string(),
                    id: "sg-public".to_string(),
                    arn: Some(
                        "arn:aws:ec2:us-east-1:123456789012:security-group/sg-public".to_string(),
                    ),
                    name: Some("public".to_string()),
                    tags: BTreeMap::new(),
                    attributes: json!({
                        "ingress": [{
                            "ip_protocol": "tcp",
                            "from_port": 22,
                            "to_port": 22,
                            "ipv4_ranges": ["0.0.0.0/0"],
                            "ipv6_ranges": []
                        }]
                    }),
                    evidence: vec![Evidence {
                        service: "ec2".to_string(),
                        operation: "DescribeSecurityGroups".to_string(),
                        path: "$.SecurityGroups[]".to_string(),
                        collected_at,
                    }],
                    raw: None,
                },
                Resource {
                    uid: managed_sg_uid.clone(),
                    provider: "aws".to_string(),
                    account_id: "123456789012".to_string(),
                    partition: "aws".to_string(),
                    region: "us-east-1".to_string(),
                    service: "ec2".to_string(),
                    resource_type: "security-group".to_string(),
                    id: "sg-managed".to_string(),
                    arn: Some(
                        "arn:aws:ec2:us-east-1:123456789012:security-group/sg-managed".to_string(),
                    ),
                    name: Some("managed".to_string()),
                    tags: BTreeMap::new(),
                    attributes: json!({"ingress": []}),
                    evidence: Vec::new(),
                    raw: None,
                },
                Resource {
                    uid: instance_uid.clone(),
                    provider: "aws".to_string(),
                    account_id: "123456789012".to_string(),
                    partition: "aws".to_string(),
                    region: "us-east-1".to_string(),
                    service: "ec2".to_string(),
                    resource_type: "instance".to_string(),
                    id: "i-public".to_string(),
                    arn: Some("arn:aws:ec2:us-east-1:123456789012:instance/i-public".to_string()),
                    name: Some("public-instance".to_string()),
                    tags: BTreeMap::new(),
                    attributes: json!({}),
                    evidence: Vec::new(),
                    raw: None,
                },
            ],
            relationships: vec![Relationship {
                uid: "rel-uses-sg".to_string(),
                from: instance_uid,
                to: public_sg_uid,
                relationship_type: "uses_security_group".to_string(),
                attributes: json!({}),
                evidence: Vec::new(),
            }],
            errors: Vec::new(),
        }
    }

    fn sample_drift_inventory() -> Inventory {
        let collected_at = Utc::now();
        Inventory {
            schema_version: SCHEMA_VERSION.to_string(),
            generator: Generator {
                name: "cloudmapper".to_string(),
                version: "test".to_string(),
            },
            account_id: "123456789012".to_string(),
            partition: "aws".to_string(),
            home_region: "us-east-1".to_string(),
            regions: vec!["us-east-1".to_string()],
            collected_at,
            resources: vec![Resource {
                uid: "aws:123456789012:us-east-1:ec2:instance:i-worker".to_string(),
                provider: "aws".to_string(),
                account_id: "123456789012".to_string(),
                partition: "aws".to_string(),
                region: "us-east-1".to_string(),
                service: "ec2".to_string(),
                resource_type: "instance".to_string(),
                id: "i-worker".to_string(),
                arn: Some("arn:aws:ec2:us-east-1:123456789012:instance/i-worker".to_string()),
                name: Some("worker".to_string()),
                tags: BTreeMap::from([
                    ("Environment".to_string(), "prod".to_string()),
                    ("Application".to_string(), "drift-test".to_string()),
                ]),
                attributes: json!({
                    "instance_type": "t3.2xlarge",
                    "state": "running"
                }),
                evidence: Vec::new(),
                raw: None,
            }],
            relationships: Vec::new(),
            errors: Vec::new(),
        }
    }

    const SAMPLE_TFSTATE: &str = r#"
{
  "version": 4,
  "terraform_version": "1.8.0",
  "serial": 42,
  "lineage": "compare-test",
  "resources": [
    {
      "mode": "managed",
      "type": "aws_security_group",
      "name": "managed",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 1,
          "attributes": {
            "id": "sg-managed",
            "arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-managed"
          },
          "sensitive_attributes": [],
          "dependencies": []
        }
      ]
    },
    {
      "mode": "managed",
      "type": "aws_instance",
      "name": "missing",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 1,
          "attributes": {
            "id": "i-missing",
            "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-missing"
          },
          "sensitive_attributes": [],
          "dependencies": []
        }
      ]
    }
  ]
}
"#;

    const SAMPLE_DRIFT_TFSTATE: &str = r#"
{
  "version": 4,
  "terraform_version": "1.8.0",
  "serial": 7,
  "lineage": "compare-drift-test",
  "resources": [
    {
      "mode": "managed",
      "type": "aws_instance",
      "name": "worker",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 1,
          "attributes": {
            "id": "i-worker",
            "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-worker",
            "instance_type": "t3.small"
          },
          "sensitive_attributes": [],
          "dependencies": []
        }
      ]
    }
  ]
}
"#;
}
