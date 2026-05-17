use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use aws_sdk_costexplorer::Client as CostExplorerClient;
use aws_sdk_costexplorer::types::{
    DateInterval, Granularity, GroupDefinition, GroupDefinitionType,
};
use aws_types::region::Region;
use chrono::{Duration, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;

use crate::db::{open_cloudmapper_db, replace_resource_costs};
use crate::model::{Evidence, Resource, ResourceCost};

pub const COST_MODE_ESTIMATED: &str = "estimated";
pub const COST_MODE_ACTUAL: &str = "actual";
pub const HOURS_PER_MONTH: f64 = 730.0;

const DEFAULT_COST_TAGS: &[&str] = &["Environment", "Application", "Owner", "Name"];
const DEFAULT_COST_METRIC: &str = "UnblendedCost";

#[derive(Debug)]
pub struct CostEstimateSummary {
    pub scan_id: String,
    pub resources: usize,
    pub costed_resources: usize,
    pub monthly_usd: f64,
}

#[derive(Debug)]
pub struct CostActualOptions {
    pub db: PathBuf,
    pub scan_id: Option<String>,
    pub profile: Option<String>,
    pub billing_region: String,
    pub days: i64,
    pub tags: Vec<String>,
    pub metric: String,
}

#[derive(Debug)]
pub struct CostActualSummary {
    pub scan_id: String,
    pub period_start: String,
    pub period_end: String,
    pub tags: Vec<String>,
    pub resources: usize,
    pub costed_resources: usize,
    pub monthly_usd: f64,
}

#[derive(Clone, Debug)]
struct CostExplorerGroup {
    service: String,
    tag_key: String,
    tag_value: String,
    period_usd: f64,
}

pub fn default_cost_tags() -> Vec<String> {
    DEFAULT_COST_TAGS
        .iter()
        .map(|tag| (*tag).to_string())
        .collect()
}

pub fn default_cost_metric() -> &'static str {
    DEFAULT_COST_METRIC
}

pub fn write_estimated_costs(db_path: &Path, scan_id: Option<&str>) -> Result<CostEstimateSummary> {
    let connection = open_cloudmapper_db(db_path)?;
    let scan_id = match scan_id {
        Some(scan_id) => scan_id.to_string(),
        None => latest_scan_id(&connection)?.context("no scan found in map database")?,
    };
    let resources = load_resources(&connection, &scan_id)?;
    let costs = resources
        .iter()
        .filter_map(estimate_resource_cost)
        .collect::<Vec<_>>();
    let monthly_usd = costs.iter().map(|cost| cost.monthly_usd).sum();
    replace_resource_costs(db_path, &scan_id, COST_MODE_ESTIMATED, &costs)?;
    Ok(CostEstimateSummary {
        scan_id,
        resources: resources.len(),
        costed_resources: costs.len(),
        monthly_usd,
    })
}

pub async fn import_actual_costs(options: CostActualOptions) -> Result<CostActualSummary> {
    let connection = open_cloudmapper_db(&options.db)?;
    let scan_id = match options.scan_id.clone() {
        Some(scan_id) => scan_id,
        None => latest_scan_id(&connection)?.context("no scan found in map database")?,
    };
    let resources = load_resources(&connection, &scan_id)?;
    let tags = if options.tags.is_empty() {
        default_cost_tags()
    } else {
        dedupe_tags(options.tags)
    };
    let period_days = options.days.max(1);
    let end_date = Utc::now().date_naive() + Duration::days(1);
    let start_date = end_date - Duration::days(period_days);
    let period_start = start_date.format("%Y-%m-%d").to_string();
    let period_end = end_date.format("%Y-%m-%d").to_string();

    let mut loader = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(options.billing_region.clone()));
    if let Some(profile) = options.profile {
        loader = loader.profile_name(profile);
    }
    let config = loader.load().await;
    let client = CostExplorerClient::new(&config);

    let mut groups = Vec::new();
    for tag in &tags {
        let mut tag_groups =
            query_tag_costs(&client, &period_start, &period_end, tag, &options.metric)
                .await
                .with_context(|| format!("querying Cost Explorer grouped by tag {tag}"))?;
        groups.append(&mut tag_groups);
    }

    let costs = allocate_actual_costs(
        &resources,
        &groups,
        &tags,
        &options.metric,
        period_days as f64,
        &period_start,
        &period_end,
    );
    let monthly_usd = costs.iter().map(|cost| cost.monthly_usd).sum();
    replace_resource_costs(&options.db, &scan_id, COST_MODE_ACTUAL, &costs)?;

    Ok(CostActualSummary {
        scan_id,
        period_start,
        period_end,
        tags,
        resources: resources.len(),
        costed_resources: costs.len(),
        monthly_usd,
    })
}

pub fn estimate_resource_cost(resource: &Resource) -> Option<ResourceCost> {
    if resource.provider != "aws" {
        return None;
    }

    let region_multiplier = region_price_multiplier(&resource.region);
    let mut notes = Vec::new();
    notes.push("Estimated from inventory metadata; excludes discounts, credits, taxes, data transfer, and usage-dependent meters unless noted.".to_string());

    match (resource.service.as_str(), resource.resource_type.as_str()) {
        ("ec2", "instance") => {
            let state = string_attr(&resource.attributes, "state");
            if state.as_deref() == Some("stopped") || state.as_deref() == Some("terminated") {
                notes.push(format!(
                    "EC2 instance state is {}.",
                    state.unwrap_or_default()
                ));
                return Some(cost_from_hourly(
                    resource,
                    0.0,
                    "aws-list-price-estimate",
                    "medium",
                    notes,
                ));
            }
            let instance_type = string_attr(&resource.attributes, "instance_type")?;
            let hourly = estimate_ec2_instance_hourly(&instance_type, &resource.region)?;
            notes.push(format!("On-demand Linux EC2 baseline for {instance_type}."));
            Some(cost_from_hourly(
                resource,
                hourly,
                "aws-list-price-estimate",
                "medium",
                notes,
            ))
        }
        ("ec2", "volume") => {
            let size_gib = number_attr(&resource.attributes, "size_gib")?;
            let volume_type = string_attr(&resource.attributes, "volume_type")
                .unwrap_or_else(|| "gp3".to_string());
            let monthly_per_gib = ebs_monthly_per_gib(&volume_type)?;
            let monthly = size_gib * monthly_per_gib * region_multiplier;
            notes.push(format!("EBS {volume_type} storage only for {size_gib:.0} GiB; provisioned IOPS/throughput are not included."));
            Some(cost_from_monthly(
                resource,
                monthly,
                "aws-list-price-estimate",
                "medium",
                notes,
            ))
        }
        ("ec2", "nat-gateway") => {
            let hourly = 0.045 * region_multiplier;
            notes.push(
                "NAT Gateway hourly charge only; data processing is not included.".to_string(),
            );
            Some(cost_from_hourly(
                resource,
                hourly,
                "aws-list-price-estimate",
                "medium",
                notes,
            ))
        }
        ("rds", "db-instance") => {
            let instance_class = string_attr(&resource.attributes, "instance_class")?;
            let mut hourly = rds_instance_hourly(&instance_class)? * region_multiplier;
            if bool_attr(&resource.attributes, "multi_az") == Some(true) {
                hourly *= 2.0;
                notes
                    .push("Multi-AZ estimate doubles the DB instance hourly baseline.".to_string());
            }
            notes.push(format!("RDS on-demand instance baseline for {instance_class}; storage and IO are not included."));
            Some(cost_from_hourly(
                resource,
                hourly,
                "aws-list-price-estimate",
                "medium",
                notes,
            ))
        }
        ("s3", "bucket") => {
            let storage_gib = number_attr(&resource.attributes, "storage_gib")
                .or_else(|| number_attr(&resource.attributes, "storage_gb"))
                .or_else(|| {
                    number_attr(&resource.attributes, "storage_bytes")
                        .map(|bytes| bytes / 1024.0 / 1024.0 / 1024.0)
                })?;
            let monthly = storage_gib * 0.023 * region_multiplier;
            notes.push(format!("S3 Standard storage estimate for {storage_gib:.1} GiB; requests and transfer are not included."));
            Some(cost_from_monthly(
                resource,
                monthly,
                "aws-list-price-estimate",
                "medium",
                notes,
            ))
        }
        ("kms", "key") => {
            notes.push(
                "KMS customer-managed key monthly baseline; API requests are not included."
                    .to_string(),
            );
            Some(cost_from_monthly(
                resource,
                1.0 * region_multiplier,
                "aws-list-price-estimate",
                "medium",
                notes,
            ))
        }
        ("iam", _)
        | ("ec2", "vpc" | "subnet" | "security-group" | "route-table" | "internet-gateway") => {
            notes.push(
                "No direct hourly AWS resource charge is modeled for this resource type."
                    .to_string(),
            );
            Some(cost_from_hourly(
                resource,
                0.0,
                "aws-list-price-estimate",
                "high",
                notes,
            ))
        }
        _ => None,
    }
}

fn query_period_hours(days: f64) -> f64 {
    (days * 24.0).max(24.0)
}

async fn query_tag_costs(
    client: &CostExplorerClient,
    start: &str,
    end: &str,
    tag_key: &str,
    metric: &str,
) -> Result<Vec<CostExplorerGroup>> {
    let mut token = None;
    let mut groups = Vec::new();
    loop {
        let output = client
            .get_cost_and_usage()
            .time_period(
                DateInterval::builder()
                    .start(start)
                    .end(end)
                    .build()
                    .context("building Cost Explorer date interval")?,
            )
            .granularity(Granularity::Monthly)
            .metrics(metric)
            .group_by(
                GroupDefinition::builder()
                    .r#type(GroupDefinitionType::Dimension)
                    .key("SERVICE")
                    .build(),
            )
            .group_by(
                GroupDefinition::builder()
                    .r#type(GroupDefinitionType::Tag)
                    .key(tag_key)
                    .build(),
            )
            .set_next_page_token(token.clone())
            .send()
            .await
            .context("calling ce:GetCostAndUsage")?;

        for result in output.results_by_time() {
            for group in result.groups() {
                let keys = group.keys();
                if keys.len() < 2 {
                    continue;
                }
                let Some(tag_value) = normalize_cost_explorer_tag_value(tag_key, &keys[1]) else {
                    continue;
                };
                let Some(period_usd) = cost_metric_amount(group.metrics(), metric) else {
                    continue;
                };
                if period_usd <= 0.0 {
                    continue;
                }
                groups.push(CostExplorerGroup {
                    service: keys[0].clone(),
                    tag_key: tag_key.to_string(),
                    tag_value,
                    period_usd,
                });
            }
        }

        token = output.next_page_token().map(str::to_string);
        if token.is_none() {
            break;
        }
    }
    Ok(groups)
}

fn allocate_actual_costs(
    resources: &[Resource],
    groups: &[CostExplorerGroup],
    tags: &[String],
    metric: &str,
    period_days: f64,
    period_start: &str,
    period_end: &str,
) -> Vec<ResourceCost> {
    let mut group_costs = HashMap::<(String, String, String), f64>::new();
    for group in groups {
        *group_costs
            .entry((
                group.service.clone(),
                group.tag_key.clone(),
                group.tag_value.clone(),
            ))
            .or_default() += group.period_usd;
    }

    let mut group_counts = HashMap::<(String, String, String), usize>::new();
    for resource in resources {
        if resource.provider != "aws" {
            continue;
        }
        for tag_key in tags {
            let Some(tag_value) = tag_value(&resource.tags, tag_key) else {
                continue;
            };
            for service in cost_explorer_services(resource) {
                let key = (service.to_string(), tag_key.clone(), tag_value.clone());
                if group_costs.contains_key(&key) {
                    *group_counts.entry(key).or_default() += 1;
                }
            }
        }
    }

    let period_hours = query_period_hours(period_days);
    let mut costs = Vec::new();
    for resource in resources {
        if resource.provider != "aws" {
            continue;
        }
        let mut assigned = None;
        'outer: for tag_key in tags {
            let Some(tag_value) = tag_value(&resource.tags, tag_key) else {
                continue;
            };
            for service in cost_explorer_services(resource) {
                let key = (service.to_string(), tag_key.clone(), tag_value.clone());
                let Some(period_usd) = group_costs.get(&key) else {
                    continue;
                };
                let Some(count) = group_counts.get(&key).copied().filter(|count| *count > 0) else {
                    continue;
                };
                assigned = Some((
                    *period_usd / count as f64,
                    service.to_string(),
                    tag_key.clone(),
                    tag_value,
                    count,
                ));
                break 'outer;
            }
        }

        let Some((period_usd, service, tag_key, tag_value, count)) = assigned else {
            continue;
        };
        let hourly = period_usd / period_hours;
        costs.push(ResourceCost {
            uid: resource.uid.clone(),
            mode: COST_MODE_ACTUAL.to_string(),
            source: "aws-cost-explorer-tags".to_string(),
            currency: "USD".to_string(),
            hourly_usd: hourly,
            daily_usd: hourly * 24.0,
            monthly_usd: hourly * HOURS_PER_MONTH,
            confidence: "medium".to_string(),
            notes: vec![
                format!("Cost Explorer {metric} from {period_start} inclusive to {period_end} exclusive, normalized to {HOURS_PER_MONTH:.0} hours/month."),
                format!("Allocated SERVICE={service} TAG {tag_key}={tag_value} evenly across {count} matching inventoried resources."),
                "Untagged, shared, support, tax, credit, and unallocated billing lines are not assigned to graph nodes.".to_string(),
            ],
            updated_at: Utc::now(),
        });
    }
    costs
}

fn cost_metric_amount(
    metrics: Option<&HashMap<String, aws_sdk_costexplorer::types::MetricValue>>,
    metric: &str,
) -> Option<f64> {
    let metrics = metrics?;
    metrics
        .get(metric)
        .or_else(|| metrics.values().next())
        .and_then(|value| value.amount())
        .and_then(|amount| amount.parse::<f64>().ok())
}

fn normalize_cost_explorer_tag_value(tag_key: &str, raw: &str) -> Option<String> {
    let prefix = format!("{tag_key}$");
    let value = raw.strip_prefix(&prefix).unwrap_or(raw).trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn cost_explorer_services(resource: &Resource) -> &'static [&'static str] {
    match (resource.service.as_str(), resource.resource_type.as_str()) {
        ("ec2", "instance") => &["Amazon Elastic Compute Cloud - Compute"],
        ("ec2", "volume") => &["EC2 - Other"],
        ("ec2", "nat-gateway") => &["Amazon Virtual Private Cloud", "EC2 - Other"],
        ("s3", _) => &["Amazon Simple Storage Service"],
        ("lambda", _) => &["AWS Lambda"],
        ("rds", _) => &["Amazon Relational Database Service"],
        ("kms", _) => &["AWS Key Management Service"],
        _ => &[],
    }
}

pub fn estimate_ec2_instance_hourly(instance_type: &str, region: &str) -> Option<f64> {
    Some(ec2_instance_hourly(instance_type)? * region_price_multiplier(region))
}

fn load_resources(connection: &Connection, scan_id: &str) -> Result<Vec<Resource>> {
    let mut statement = connection.prepare(
        r#"
        SELECT uid, provider, account_id, partition, region, service, resource_type,
               resource_id, arn, name, tags_json, attributes_json, evidence_json, raw_json
        FROM resources
        WHERE scan_id = ?1
        ORDER BY service, resource_type, resource_id
        "#,
    )?;
    let rows = statement.query_map(params![scan_id], |row| {
        let tags_json: String = row.get(10)?;
        let attributes_json: String = row.get(11)?;
        let evidence_json: String = row.get(12)?;
        let raw_json: Option<String> = row.get(13)?;
        Ok(Resource {
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
            evidence: parse_json::<Vec<Evidence>>(evidence_json)?,
            raw: parse_optional_json(raw_json)?,
        })
    })?;

    rows.collect::<Result<Vec<_>, _>>()
        .context("loading resources for cost calculation")
}

fn latest_scan_id(connection: &Connection) -> Result<Option<String>> {
    connection
        .query_row(
            "SELECT id FROM scans ORDER BY collected_at DESC, id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("loading latest scan id")
}

fn parse_json<T: serde::de::DeserializeOwned>(value: String) -> rusqlite::Result<T> {
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

fn parse_optional_json<T: serde::de::DeserializeOwned>(
    value: Option<String>,
) -> rusqlite::Result<Option<T>> {
    value.map(parse_json).transpose()
}

fn cost_from_hourly(
    resource: &Resource,
    hourly_usd: f64,
    source: &str,
    confidence: &str,
    notes: Vec<String>,
) -> ResourceCost {
    ResourceCost {
        uid: resource.uid.clone(),
        mode: COST_MODE_ESTIMATED.to_string(),
        source: source.to_string(),
        currency: "USD".to_string(),
        hourly_usd,
        daily_usd: hourly_usd * 24.0,
        monthly_usd: hourly_usd * HOURS_PER_MONTH,
        confidence: confidence.to_string(),
        notes,
        updated_at: Utc::now(),
    }
}

fn cost_from_monthly(
    resource: &Resource,
    monthly_usd: f64,
    source: &str,
    confidence: &str,
    notes: Vec<String>,
) -> ResourceCost {
    let hourly_usd = monthly_usd / HOURS_PER_MONTH;
    ResourceCost {
        uid: resource.uid.clone(),
        mode: COST_MODE_ESTIMATED.to_string(),
        source: source.to_string(),
        currency: "USD".to_string(),
        hourly_usd,
        daily_usd: hourly_usd * 24.0,
        monthly_usd,
        confidence: confidence.to_string(),
        notes,
        updated_at: Utc::now(),
    }
}

fn ec2_instance_hourly(instance_type: &str) -> Option<f64> {
    Some(match instance_type {
        "t3.nano" => 0.0052,
        "t3.micro" => 0.0104,
        "t3.small" => 0.0208,
        "t3.medium" => 0.0416,
        "t3.large" => 0.0832,
        "t3.xlarge" => 0.1664,
        "t3.2xlarge" => 0.3328,
        "m5.large" => 0.096,
        "m5.xlarge" => 0.192,
        "m5.2xlarge" => 0.384,
        "m6i.large" => 0.096,
        "m6i.xlarge" => 0.192,
        "m6i.2xlarge" => 0.384,
        "m7i.large" => 0.1008,
        "m7i.xlarge" => 0.2016,
        "m7i.2xlarge" => 0.4032,
        "m7g.large" => 0.0816,
        "m7g.xlarge" => 0.1632,
        "m7g.2xlarge" => 0.3264,
        "c5.large" => 0.085,
        "c5.xlarge" => 0.17,
        "c6i.large" => 0.085,
        "c6i.xlarge" => 0.17,
        "c7g.large" => 0.0725,
        "c7g.xlarge" => 0.145,
        "r5.large" => 0.126,
        "r5.xlarge" => 0.252,
        "r6i.large" => 0.126,
        "r6i.xlarge" => 0.252,
        "r7g.large" => 0.107,
        "r7g.xlarge" => 0.214,
        _ => return None,
    })
}

fn rds_instance_hourly(instance_class: &str) -> Option<f64> {
    Some(match instance_class {
        "db.t4g.micro" => 0.016,
        "db.t4g.small" => 0.032,
        "db.t4g.medium" => 0.065,
        "db.m6g.large" => 0.152,
        "db.m6g.xlarge" => 0.304,
        "db.r6g.large" => 0.215,
        "db.r6g.xlarge" => 0.43,
        "db.r7g.large" => 0.239,
        "db.r7g.xlarge" => 0.478,
        _ => return None,
    })
}

fn ebs_monthly_per_gib(volume_type: &str) -> Option<f64> {
    Some(match volume_type {
        "gp3" => 0.08,
        "gp2" => 0.10,
        "io1" | "io2" => 0.125,
        "st1" => 0.045,
        "sc1" => 0.015,
        "standard" => 0.05,
        _ => return None,
    })
}

fn region_price_multiplier(region: &str) -> f64 {
    match region {
        "us-east-1" | "us-east-2" => 1.0,
        "us-west-1" | "us-west-2" => 1.05,
        "eu-west-1" => 1.10,
        "eu-central-1" => 1.14,
        "ap-southeast-1" => 1.16,
        "ap-northeast-1" => 1.18,
        _ => 1.0,
    }
}

fn string_attr(attributes: &Value, key: &str) -> Option<String> {
    attributes
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn number_attr(attributes: &Value, key: &str) -> Option<f64> {
    attributes.get(key).and_then(|value| {
        value
            .as_f64()
            .or_else(|| value.as_i64().map(|number| number as f64))
            .or_else(|| value.as_u64().map(|number| number as f64))
    })
}

fn bool_attr(attributes: &Value, key: &str) -> Option<bool> {
    attributes.get(key).and_then(Value::as_bool)
}

fn tag_value(tags: &BTreeMap<String, String>, key: &str) -> Option<String> {
    tags.iter()
        .find(|(tag_key, _)| tag_key.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn dedupe_tags(tags: Vec<String>) -> Vec<String> {
    let mut deduped = Vec::new();
    for tag in tags {
        let tag = tag.trim();
        if tag.is_empty() || deduped.iter().any(|existing: &String| existing == tag) {
            continue;
        }
        deduped.push(tag.to_string());
    }
    deduped
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn estimates_ec2_instance_monthly_price() {
        let resource = resource("ec2", "instance", json!({ "instance_type": "t3.small" }));

        let cost = estimate_resource_cost(&resource).unwrap();

        assert_eq!(cost.mode, "estimated");
        assert!((cost.hourly_usd - 0.0208).abs() < 0.0001);
        assert!((cost.monthly_usd - 15.184).abs() < 0.001);
    }

    #[test]
    fn estimates_ebs_volume_from_size() {
        let resource = resource(
            "ec2",
            "volume",
            json!({ "volume_type": "gp3", "size_gib": 100 }),
        );

        let cost = estimate_resource_cost(&resource).unwrap();

        assert!((cost.monthly_usd - 8.0).abs() < 0.001);
    }

    #[test]
    fn parses_cost_explorer_tag_key_prefix() {
        assert_eq!(
            normalize_cost_explorer_tag_value("Environment", "Environment$prod").as_deref(),
            Some("prod")
        );
        assert!(normalize_cost_explorer_tag_value("Environment", "Environment$").is_none());
    }

    #[test]
    fn allocates_actual_cost_by_service_and_tag() {
        let mut resource = resource("ec2", "instance", json!({ "instance_type": "t3.small" }));
        resource
            .tags
            .insert("Environment".to_string(), "prod".to_string());
        let groups = vec![CostExplorerGroup {
            service: "Amazon Elastic Compute Cloud - Compute".to_string(),
            tag_key: "Environment".to_string(),
            tag_value: "prod".to_string(),
            period_usd: 48.0,
        }];

        let costs = allocate_actual_costs(
            &[resource],
            &groups,
            &["Environment".to_string()],
            "UnblendedCost",
            2.0,
            "2026-05-14",
            "2026-05-16",
        );

        assert_eq!(costs.len(), 1);
        assert_eq!(costs[0].mode, "actual");
        assert!((costs[0].hourly_usd - 1.0).abs() < 0.001);
        assert!((costs[0].monthly_usd - 730.0).abs() < 0.001);
    }

    fn resource(service: &str, resource_type: &str, attributes: Value) -> Resource {
        Resource {
            uid: format!("aws:123:us-east-1:{service}:{resource_type}:id"),
            provider: "aws".to_string(),
            account_id: "123".to_string(),
            partition: "aws".to_string(),
            region: "us-east-1".to_string(),
            service: service.to_string(),
            resource_type: resource_type.to_string(),
            id: "id".to_string(),
            arn: None,
            name: None,
            tags: BTreeMap::new(),
            attributes,
            evidence: Vec::new(),
            raw: None,
        }
    }
}
