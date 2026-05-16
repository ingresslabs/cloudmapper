use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_iam::Client as IamClient;
use aws_sdk_lambda::Client as LambdaClient;
use aws_sdk_resourcegroupstagging::Client as TaggingClient;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_sts::Client as StsClient;
use aws_types::region::Region;
use chrono::Utc;
use serde_json::{Value, json};
use tracing::info;

use crate::model::{
    Evidence, GENERATOR_NAME, Generator, Inventory, Relationship, Resource, SCHEMA_VERSION,
    ScanError, empty_to_global, json_object, parse_arn, relationship_uid, resource_uid,
    uid_for_arn,
};

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub profile: Option<String>,
    pub regions: String,
    pub home_region: String,
    pub include_raw: bool,
}

struct InventoryBuilder {
    account_id: String,
    partition: String,
    home_region: String,
    regions: Vec<String>,
    collected_at: chrono::DateTime<Utc>,
    include_raw: bool,
    resources: BTreeMap<String, Resource>,
    relationships: BTreeMap<String, Relationship>,
    errors: Vec<ScanError>,
}

impl InventoryBuilder {
    fn new(
        account_id: String,
        partition: String,
        home_region: String,
        collected_at: chrono::DateTime<Utc>,
        include_raw: bool,
    ) -> Self {
        Self {
            account_id,
            partition,
            home_region,
            regions: Vec::new(),
            collected_at,
            include_raw,
            resources: BTreeMap::new(),
            relationships: BTreeMap::new(),
            errors: Vec::new(),
        }
    }

    fn evidence(&self, service: &str, operation: &str, path: &str) -> Evidence {
        Evidence {
            service: service.to_string(),
            operation: operation.to_string(),
            path: path.to_string(),
            collected_at: self.collected_at,
        }
    }

    fn add_resource(&mut self, resource: Resource) {
        match self.resources.get_mut(&resource.uid) {
            Some(existing) => {
                if existing.arn.is_none() {
                    existing.arn = resource.arn;
                }
                if existing.name.is_none() {
                    existing.name = resource.name;
                }
                existing.tags.extend(resource.tags);
                merge_attributes(&mut existing.attributes, resource.attributes);
                existing.evidence.extend(resource.evidence);
                if existing.raw.is_none() {
                    existing.raw = resource.raw;
                }
            }
            None => {
                self.resources.insert(resource.uid.clone(), resource);
            }
        }
    }

    fn add_relationship(
        &mut self,
        from: &str,
        relationship_type: &str,
        to: &str,
        evidence: Evidence,
        attributes: Value,
    ) {
        let uid = relationship_uid(from, relationship_type, to);
        self.relationships
            .entry(uid.clone())
            .and_modify(|relationship| relationship.evidence.push(evidence.clone()))
            .or_insert_with(|| Relationship {
                uid,
                from: from.to_string(),
                to: to.to_string(),
                relationship_type: relationship_type.to_string(),
                attributes,
                evidence: vec![evidence],
            });
    }

    fn add_error(&mut self, service: &str, region: &str, operation: &str, error: impl ToString) {
        self.errors.push(ScanError {
            service: service.to_string(),
            region: region.to_string(),
            operation: operation.to_string(),
            message: error.to_string(),
        });
    }

    fn finish(self) -> Inventory {
        Inventory {
            schema_version: SCHEMA_VERSION.to_string(),
            generator: Generator {
                name: GENERATOR_NAME.to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            account_id: self.account_id,
            partition: self.partition,
            home_region: self.home_region,
            regions: self.regions,
            collected_at: self.collected_at,
            resources: self.resources.into_values().collect(),
            relationships: self.relationships.into_values().collect(),
            errors: self.errors,
        }
    }
}

pub async fn scan_account(options: ScanOptions) -> Result<Inventory> {
    let collected_at = Utc::now();
    let home_config = aws_config_loader(&options.profile, &options.home_region)
        .load()
        .await;
    let sts = StsClient::new(&home_config);
    let identity = sts
        .get_caller_identity()
        .send()
        .await
        .context("calling sts:GetCallerIdentity")?;
    let account_id = identity
        .account()
        .context("sts:GetCallerIdentity did not return an account id")?
        .to_string();
    let partition = identity
        .arn()
        .and_then(|arn| arn.split(':').nth(1))
        .unwrap_or("aws")
        .to_string();

    let mut builder = InventoryBuilder::new(
        account_id.clone(),
        partition.clone(),
        options.home_region.clone(),
        collected_at,
        options.include_raw,
    );
    add_account_resource(&mut builder, identity.arn());

    let regions = resolve_regions(&options, &home_config, &mut builder).await;
    builder.regions = regions.clone();

    info!("scanning global services");
    if let Err(error) = scan_s3(&home_config, &mut builder).await {
        let home_region = builder.home_region.clone();
        builder.add_error("s3", &home_region, "ListBuckets", error);
    }
    if let Err(error) = scan_iam(&home_config, &mut builder).await {
        builder.add_error("iam", "global", "ListRoles/ListUsers/ListGroups", error);
    }

    for region in regions {
        info!(region = region.as_str(), "scanning regional services");
        let config = aws_config_loader(&options.profile, &region).load().await;
        if let Err(error) = scan_ec2_region(&config, &region, &mut builder).await {
            builder.add_error("ec2", &region, "regional scan", error);
        }
        if let Err(error) = scan_lambda_region(&config, &region, &mut builder).await {
            builder.add_error("lambda", &region, "ListFunctions", error);
        }
        if let Err(error) = scan_tagged_resources_region(&config, &region, &mut builder).await {
            builder.add_error("resourcegroupstagging", &region, "GetResources", error);
        }
    }

    Ok(builder.finish())
}

fn aws_config_loader(profile: &Option<String>, region: &str) -> aws_config::ConfigLoader {
    let mut loader =
        aws_config::defaults(BehaviorVersion::latest()).region(Region::new(region.to_string()));
    if let Some(profile) = profile {
        loader = loader.profile_name(profile);
    }
    loader
}

async fn resolve_regions(
    options: &ScanOptions,
    config: &aws_config::SdkConfig,
    builder: &mut InventoryBuilder,
) -> Vec<String> {
    if options.regions.trim() != "all" {
        return dedupe_regions(
            options
                .regions
                .split(',')
                .map(str::trim)
                .filter(|region| !region.is_empty())
                .map(str::to_string),
        );
    }

    match discover_enabled_regions(config).await {
        Ok(regions) if !regions.is_empty() => regions,
        Ok(_) => vec![options.home_region.clone()],
        Err(error) => {
            let home_region = builder.home_region.clone();
            builder.add_error("ec2", &home_region, "DescribeRegions", error);
            vec![options.home_region.clone()]
        }
    }
}

async fn discover_enabled_regions(config: &aws_config::SdkConfig) -> Result<Vec<String>> {
    let ec2 = Ec2Client::new(config);
    let response = ec2
        .describe_regions()
        .all_regions(false)
        .send()
        .await
        .context("calling ec2:DescribeRegions")?;
    Ok(dedupe_regions(
        response
            .regions()
            .iter()
            .filter_map(|region| region.region_name())
            .map(str::to_string),
    ))
}

fn dedupe_regions(regions: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    for region in regions {
        seen.insert(region);
    }
    seen.into_iter().collect()
}

fn add_account_resource(builder: &mut InventoryBuilder, arn: Option<&str>) {
    let uid = resource_uid(
        &builder.account_id,
        "global",
        "iam",
        "account",
        &builder.account_id,
    );
    builder.add_resource(Resource {
        uid,
        provider: "aws".to_string(),
        account_id: builder.account_id.clone(),
        partition: builder.partition.clone(),
        region: "global".to_string(),
        service: "iam".to_string(),
        resource_type: "account".to_string(),
        id: builder.account_id.clone(),
        arn: arn.map(str::to_string),
        name: None,
        tags: BTreeMap::new(),
        attributes: json_object([("caller_arn", opt_str(arn))]),
        evidence: vec![builder.evidence("sts", "GetCallerIdentity", "$")],
        raw: None,
    });
}

async fn scan_s3(config: &aws_config::SdkConfig, builder: &mut InventoryBuilder) -> Result<()> {
    let client = S3Client::new(config);
    let response = client
        .list_buckets()
        .send()
        .await
        .context("calling s3:ListBuckets")?;
    for bucket in response.buckets() {
        let Some(name) = bucket.name() else {
            continue;
        };
        let region = match client.get_bucket_location().bucket(name).send().await {
            Ok(location) => normalize_s3_region(
                location
                    .location_constraint()
                    .map(|constraint| constraint.as_str()),
            ),
            Err(error) => {
                builder.add_error("s3", "global", "GetBucketLocation", error);
                "unknown".to_string()
            }
        };
        let tags = get_s3_bucket_tags(&client, name, builder).await;
        let public_access_block = get_s3_public_access_block(&client, name, builder).await;
        let arn = format!("arn:{}:s3:::{name}", builder.partition);
        let uid = resource_uid(&builder.account_id, &region, "s3", "bucket", name);
        let attributes = json_object([
            (
                "created_at",
                opt_string(bucket.creation_date().map(|date| date.to_string())),
            ),
            ("public_access_block", public_access_block),
        ]);

        builder.add_resource(Resource {
            uid,
            provider: "aws".to_string(),
            account_id: builder.account_id.clone(),
            partition: builder.partition.clone(),
            region,
            service: "s3".to_string(),
            resource_type: "bucket".to_string(),
            id: name.to_string(),
            arn: Some(arn),
            name: Some(name.to_string()),
            tags,
            raw: maybe_raw(builder.include_raw, &attributes),
            attributes,
            evidence: vec![builder.evidence("s3", "ListBuckets", "$.Buckets[]")],
        });
    }
    Ok(())
}

async fn get_s3_bucket_tags(
    client: &S3Client,
    bucket: &str,
    builder: &mut InventoryBuilder,
) -> BTreeMap<String, String> {
    match client.get_bucket_tagging().bucket(bucket).send().await {
        Ok(response) => response
            .tag_set()
            .iter()
            .map(|tag| (tag.key().to_string(), tag.value().to_string()))
            .collect(),
        Err(error) => {
            let message = error.to_string();
            if !message.contains("NoSuchTagSet") && !message.contains("NoSuchBucket") {
                builder.add_error("s3", "global", "GetBucketTagging", message);
            }
            BTreeMap::new()
        }
    }
}

async fn get_s3_public_access_block(
    client: &S3Client,
    bucket: &str,
    builder: &mut InventoryBuilder,
) -> Value {
    match client.get_public_access_block().bucket(bucket).send().await {
        Ok(response) => response
            .public_access_block_configuration()
            .map(|config| {
                json!({
                    "block_public_acls": config.block_public_acls(),
                    "ignore_public_acls": config.ignore_public_acls(),
                    "block_public_policy": config.block_public_policy(),
                    "restrict_public_buckets": config.restrict_public_buckets()
                })
            })
            .unwrap_or(Value::Null),
        Err(error) => {
            let message = error.to_string();
            if !message.contains("NoSuchPublicAccessBlockConfiguration")
                && !message.contains("NoSuchBucket")
            {
                builder.add_error("s3", "global", "GetPublicAccessBlock", message);
            }
            Value::Null
        }
    }
}

fn normalize_s3_region(location_constraint: Option<&str>) -> String {
    match location_constraint {
        None | Some("") => "us-east-1".to_string(),
        Some("EU") => "eu-west-1".to_string(),
        Some(region) => region.to_string(),
    }
}

async fn scan_iam(config: &aws_config::SdkConfig, builder: &mut InventoryBuilder) -> Result<()> {
    let client = IamClient::new(config);
    scan_iam_roles(&client, builder).await?;
    scan_iam_users(&client, builder).await?;
    scan_iam_groups(&client, builder).await?;
    Ok(())
}

async fn scan_iam_roles(client: &IamClient, builder: &mut InventoryBuilder) -> Result<()> {
    let mut marker = None;
    loop {
        let response = client
            .list_roles()
            .set_marker(marker.clone())
            .send()
            .await
            .context("calling iam:ListRoles")?;
        for role in response.roles() {
            let name = role.role_name();
            let arn = Some(role.arn().to_string());
            let uid = arn
                .as_deref()
                .and_then(|arn| uid_for_arn(&builder.account_id, arn))
                .unwrap_or_else(|| {
                    resource_uid(&builder.account_id, "global", "iam", "role", name)
                });
            let attributes = json_object([
                ("role_id", opt_str(Some(role.role_id()))),
                ("path", opt_str(Some(role.path()))),
                (
                    "created_at",
                    opt_string(Some(role.create_date().to_string())),
                ),
                ("max_session_duration", opt_i32(role.max_session_duration())),
            ]);
            builder.add_resource(Resource {
                uid: uid.clone(),
                provider: "aws".to_string(),
                account_id: builder.account_id.clone(),
                partition: builder.partition.clone(),
                region: "global".to_string(),
                service: "iam".to_string(),
                resource_type: "role".to_string(),
                id: name.to_string(),
                arn,
                name: Some(name.to_string()),
                tags: BTreeMap::new(),
                raw: maybe_raw(builder.include_raw, &attributes),
                attributes,
                evidence: vec![builder.evidence("iam", "ListRoles", "$.Roles[]")],
            });

            if let Err(error) = scan_role_attached_policies(client, builder, name, &uid).await {
                builder.add_error("iam", "global", "ListAttachedRolePolicies", error);
            }
        }

        if response.is_truncated() {
            marker = response.marker().map(str::to_string);
        } else {
            break;
        }
    }
    Ok(())
}

async fn scan_role_attached_policies(
    client: &IamClient,
    builder: &mut InventoryBuilder,
    role_name: &str,
    role_uid: &str,
) -> Result<()> {
    let response = client
        .list_attached_role_policies()
        .role_name(role_name)
        .send()
        .await
        .with_context(|| format!("calling iam:ListAttachedRolePolicies for {role_name}"))?;
    for policy in response.attached_policies() {
        let Some(policy_arn) = policy.policy_arn() else {
            continue;
        };
        let policy_uid = uid_for_arn(&builder.account_id, policy_arn).unwrap_or_else(|| {
            resource_uid(
                &builder.account_id,
                "global",
                "iam",
                "policy",
                policy_arn.rsplit('/').next().unwrap_or(policy_arn),
            )
        });
        builder.add_resource(Resource {
            uid: policy_uid.clone(),
            provider: "aws".to_string(),
            account_id: builder.account_id.clone(),
            partition: builder.partition.clone(),
            region: "global".to_string(),
            service: "iam".to_string(),
            resource_type: "policy".to_string(),
            id: policy_arn.to_string(),
            arn: Some(policy_arn.to_string()),
            name: policy.policy_name().map(str::to_string),
            tags: BTreeMap::new(),
            attributes: json!({ "attached_policy": true }),
            evidence: vec![builder.evidence(
                "iam",
                "ListAttachedRolePolicies",
                "$.AttachedPolicies[]",
            )],
            raw: None,
        });
        builder.add_relationship(
            role_uid,
            "has_attached_policy",
            &policy_uid,
            builder.evidence("iam", "ListAttachedRolePolicies", "$.AttachedPolicies[]"),
            Value::Null,
        );
    }
    Ok(())
}

async fn scan_iam_users(client: &IamClient, builder: &mut InventoryBuilder) -> Result<()> {
    let mut marker = None;
    loop {
        let response = client
            .list_users()
            .set_marker(marker.clone())
            .send()
            .await
            .context("calling iam:ListUsers")?;
        for user in response.users() {
            let name = user.user_name();
            let arn = Some(user.arn().to_string());
            let uid = arn
                .as_deref()
                .and_then(|arn| uid_for_arn(&builder.account_id, arn))
                .unwrap_or_else(|| {
                    resource_uid(&builder.account_id, "global", "iam", "user", name)
                });
            let attributes = json_object([
                ("user_id", opt_str(Some(user.user_id()))),
                ("path", opt_str(Some(user.path()))),
                (
                    "created_at",
                    opt_string(Some(user.create_date().to_string())),
                ),
            ]);
            builder.add_resource(Resource {
                uid,
                provider: "aws".to_string(),
                account_id: builder.account_id.clone(),
                partition: builder.partition.clone(),
                region: "global".to_string(),
                service: "iam".to_string(),
                resource_type: "user".to_string(),
                id: name.to_string(),
                arn,
                name: Some(name.to_string()),
                tags: BTreeMap::new(),
                raw: maybe_raw(builder.include_raw, &attributes),
                attributes,
                evidence: vec![builder.evidence("iam", "ListUsers", "$.Users[]")],
            });
        }

        if response.is_truncated() {
            marker = response.marker().map(str::to_string);
        } else {
            break;
        }
    }
    Ok(())
}

async fn scan_iam_groups(client: &IamClient, builder: &mut InventoryBuilder) -> Result<()> {
    let mut marker = None;
    loop {
        let response = client
            .list_groups()
            .set_marker(marker.clone())
            .send()
            .await
            .context("calling iam:ListGroups")?;
        for group in response.groups() {
            let name = group.group_name();
            let arn = Some(group.arn().to_string());
            let uid = arn
                .as_deref()
                .and_then(|arn| uid_for_arn(&builder.account_id, arn))
                .unwrap_or_else(|| {
                    resource_uid(&builder.account_id, "global", "iam", "group", name)
                });
            let attributes = json_object([
                ("group_id", opt_str(Some(group.group_id()))),
                ("path", opt_str(Some(group.path()))),
                (
                    "created_at",
                    opt_string(Some(group.create_date().to_string())),
                ),
            ]);
            builder.add_resource(Resource {
                uid,
                provider: "aws".to_string(),
                account_id: builder.account_id.clone(),
                partition: builder.partition.clone(),
                region: "global".to_string(),
                service: "iam".to_string(),
                resource_type: "group".to_string(),
                id: name.to_string(),
                arn,
                name: Some(name.to_string()),
                tags: BTreeMap::new(),
                raw: maybe_raw(builder.include_raw, &attributes),
                attributes,
                evidence: vec![builder.evidence("iam", "ListGroups", "$.Groups[]")],
            });
        }

        if response.is_truncated() {
            marker = response.marker().map(str::to_string);
        } else {
            break;
        }
    }
    Ok(())
}

async fn scan_ec2_region(
    config: &aws_config::SdkConfig,
    region: &str,
    builder: &mut InventoryBuilder,
) -> Result<()> {
    let client = Ec2Client::new(config);
    scan_vpcs(&client, region, builder).await?;
    scan_subnets(&client, region, builder).await?;
    scan_security_groups(&client, region, builder).await?;
    scan_route_tables(&client, region, builder).await?;
    scan_internet_gateways(&client, region, builder).await?;
    scan_nat_gateways(&client, region, builder).await?;
    scan_volumes(&client, region, builder).await?;
    scan_instances(&client, region, builder).await?;
    Ok(())
}

async fn scan_vpcs(client: &Ec2Client, region: &str, builder: &mut InventoryBuilder) -> Result<()> {
    let mut next_token = None;
    loop {
        let response = client
            .describe_vpcs()
            .set_next_token(next_token.clone())
            .send()
            .await
            .context("calling ec2:DescribeVpcs")?;
        for vpc in response.vpcs() {
            let Some(id) = vpc.vpc_id() else {
                continue;
            };
            let tags = ec2_tags(vpc.tags());
            let attributes = json_object([
                ("cidr_block", opt_str(vpc.cidr_block())),
                (
                    "state",
                    opt_string(vpc.state().map(|state| state.as_str().to_string())),
                ),
                ("is_default", opt_bool(vpc.is_default())),
                ("owner_id", opt_str(vpc.owner_id())),
            ]);
            builder.add_resource(Resource {
                uid: resource_uid(&builder.account_id, region, "ec2", "vpc", id),
                provider: "aws".to_string(),
                account_id: builder.account_id.clone(),
                partition: builder.partition.clone(),
                region: region.to_string(),
                service: "ec2".to_string(),
                resource_type: "vpc".to_string(),
                id: id.to_string(),
                arn: Some(format!(
                    "arn:{}:ec2:{region}:{}:vpc/{id}",
                    builder.partition, builder.account_id
                )),
                name: tags.get("Name").cloned(),
                tags,
                raw: maybe_raw(builder.include_raw, &attributes),
                attributes,
                evidence: vec![builder.evidence("ec2", "DescribeVpcs", "$.Vpcs[]")],
            });
        }
        if let Some(token) = response.next_token() {
            next_token = Some(token.to_string());
        } else {
            break;
        }
    }
    Ok(())
}

async fn scan_subnets(
    client: &Ec2Client,
    region: &str,
    builder: &mut InventoryBuilder,
) -> Result<()> {
    let mut next_token = None;
    loop {
        let response = client
            .describe_subnets()
            .set_next_token(next_token.clone())
            .send()
            .await
            .context("calling ec2:DescribeSubnets")?;
        for subnet in response.subnets() {
            let Some(id) = subnet.subnet_id() else {
                continue;
            };
            let tags = ec2_tags(subnet.tags());
            let uid = resource_uid(&builder.account_id, region, "ec2", "subnet", id);
            let attributes = json_object([
                ("vpc_id", opt_str(subnet.vpc_id())),
                ("cidr_block", opt_str(subnet.cidr_block())),
                ("availability_zone", opt_str(subnet.availability_zone())),
                (
                    "availability_zone_id",
                    opt_str(subnet.availability_zone_id()),
                ),
                (
                    "map_public_ip_on_launch",
                    opt_bool(subnet.map_public_ip_on_launch()),
                ),
                (
                    "available_ip_address_count",
                    opt_i32(subnet.available_ip_address_count()),
                ),
            ]);
            builder.add_resource(Resource {
                uid: uid.clone(),
                provider: "aws".to_string(),
                account_id: builder.account_id.clone(),
                partition: builder.partition.clone(),
                region: region.to_string(),
                service: "ec2".to_string(),
                resource_type: "subnet".to_string(),
                id: id.to_string(),
                arn: Some(format!(
                    "arn:{}:ec2:{region}:{}:subnet/{id}",
                    builder.partition, builder.account_id
                )),
                name: tags.get("Name").cloned(),
                tags,
                raw: maybe_raw(builder.include_raw, &attributes),
                attributes,
                evidence: vec![builder.evidence("ec2", "DescribeSubnets", "$.Subnets[]")],
            });
            if let Some(vpc_id) = subnet.vpc_id() {
                let vpc_uid = resource_uid(&builder.account_id, region, "ec2", "vpc", vpc_id);
                builder.add_relationship(
                    &uid,
                    "in_vpc",
                    &vpc_uid,
                    builder.evidence("ec2", "DescribeSubnets", "$.Subnets[].VpcId"),
                    Value::Null,
                );
            }
        }
        if let Some(token) = response.next_token() {
            next_token = Some(token.to_string());
        } else {
            break;
        }
    }
    Ok(())
}

async fn scan_security_groups(
    client: &Ec2Client,
    region: &str,
    builder: &mut InventoryBuilder,
) -> Result<()> {
    let mut next_token = None;
    loop {
        let response = client
            .describe_security_groups()
            .set_next_token(next_token.clone())
            .send()
            .await
            .context("calling ec2:DescribeSecurityGroups")?;
        for group in response.security_groups() {
            let Some(id) = group.group_id() else {
                continue;
            };
            let tags = ec2_tags(group.tags());
            let uid = resource_uid(&builder.account_id, region, "ec2", "security-group", id);
            let attributes = json_object([
                ("group_name", opt_str(group.group_name())),
                ("description", opt_str(group.description())),
                ("vpc_id", opt_str(group.vpc_id())),
                ("owner_id", opt_str(group.owner_id())),
                ("ingress", security_permissions(group.ip_permissions())),
                (
                    "egress",
                    security_permissions(group.ip_permissions_egress()),
                ),
            ]);
            builder.add_resource(Resource {
                uid: uid.clone(),
                provider: "aws".to_string(),
                account_id: builder.account_id.clone(),
                partition: builder.partition.clone(),
                region: region.to_string(),
                service: "ec2".to_string(),
                resource_type: "security-group".to_string(),
                id: id.to_string(),
                arn: Some(format!(
                    "arn:{}:ec2:{region}:{}:security-group/{id}",
                    builder.partition, builder.account_id
                )),
                name: group
                    .group_name()
                    .map(str::to_string)
                    .or_else(|| tags.get("Name").cloned()),
                tags,
                raw: maybe_raw(builder.include_raw, &attributes),
                attributes,
                evidence: vec![builder.evidence(
                    "ec2",
                    "DescribeSecurityGroups",
                    "$.SecurityGroups[]",
                )],
            });
            if let Some(vpc_id) = group.vpc_id() {
                let vpc_uid = resource_uid(&builder.account_id, region, "ec2", "vpc", vpc_id);
                builder.add_relationship(
                    &uid,
                    "in_vpc",
                    &vpc_uid,
                    builder.evidence("ec2", "DescribeSecurityGroups", "$.SecurityGroups[].VpcId"),
                    Value::Null,
                );
            }
        }
        if let Some(token) = response.next_token() {
            next_token = Some(token.to_string());
        } else {
            break;
        }
    }
    Ok(())
}

async fn scan_route_tables(
    client: &Ec2Client,
    region: &str,
    builder: &mut InventoryBuilder,
) -> Result<()> {
    let mut next_token = None;
    loop {
        let response = client
            .describe_route_tables()
            .set_next_token(next_token.clone())
            .send()
            .await
            .context("calling ec2:DescribeRouteTables")?;
        for route_table in response.route_tables() {
            let Some(id) = route_table.route_table_id() else {
                continue;
            };
            let tags = ec2_tags(route_table.tags());
            let uid = resource_uid(&builder.account_id, region, "ec2", "route-table", id);
            let routes = route_table
                .routes()
                .iter()
                .map(|route| {
                    json_object([
                        (
                            "destination_cidr_block",
                            opt_str(route.destination_cidr_block()),
                        ),
                        (
                            "destination_ipv6_cidr_block",
                            opt_str(route.destination_ipv6_cidr_block()),
                        ),
                        ("gateway_id", opt_str(route.gateway_id())),
                        ("nat_gateway_id", opt_str(route.nat_gateway_id())),
                        ("transit_gateway_id", opt_str(route.transit_gateway_id())),
                        (
                            "vpc_peering_connection_id",
                            opt_str(route.vpc_peering_connection_id()),
                        ),
                        (
                            "state",
                            opt_string(route.state().map(|state| state.as_str().to_string())),
                        ),
                    ])
                })
                .collect::<Vec<_>>();
            let associations = route_table
                .associations()
                .iter()
                .map(|association| {
                    json_object([
                        (
                            "route_table_association_id",
                            opt_str(association.route_table_association_id()),
                        ),
                        ("subnet_id", opt_str(association.subnet_id())),
                        ("gateway_id", opt_str(association.gateway_id())),
                        ("main", opt_bool(association.main())),
                    ])
                })
                .collect::<Vec<_>>();
            let attributes = json_object([
                ("vpc_id", opt_str(route_table.vpc_id())),
                ("routes", json!(routes)),
                ("associations", json!(associations)),
            ]);
            builder.add_resource(Resource {
                uid: uid.clone(),
                provider: "aws".to_string(),
                account_id: builder.account_id.clone(),
                partition: builder.partition.clone(),
                region: region.to_string(),
                service: "ec2".to_string(),
                resource_type: "route-table".to_string(),
                id: id.to_string(),
                arn: Some(format!(
                    "arn:{}:ec2:{region}:{}:route-table/{id}",
                    builder.partition, builder.account_id
                )),
                name: tags.get("Name").cloned(),
                tags,
                raw: maybe_raw(builder.include_raw, &attributes),
                attributes,
                evidence: vec![builder.evidence("ec2", "DescribeRouteTables", "$.RouteTables[]")],
            });
            if let Some(vpc_id) = route_table.vpc_id() {
                let vpc_uid = resource_uid(&builder.account_id, region, "ec2", "vpc", vpc_id);
                builder.add_relationship(
                    &uid,
                    "in_vpc",
                    &vpc_uid,
                    builder.evidence("ec2", "DescribeRouteTables", "$.RouteTables[].VpcId"),
                    Value::Null,
                );
            }
            for association in route_table.associations() {
                if let Some(subnet_id) = association.subnet_id() {
                    let subnet_uid =
                        resource_uid(&builder.account_id, region, "ec2", "subnet", subnet_id);
                    builder.add_relationship(
                        &subnet_uid,
                        "uses_route_table",
                        &uid,
                        builder.evidence(
                            "ec2",
                            "DescribeRouteTables",
                            "$.RouteTables[].Associations[].SubnetId",
                        ),
                        Value::Null,
                    );
                }
            }
            for route in route_table.routes() {
                for target in route_targets(route) {
                    let target_uid = ec2_target_uid(&builder.account_id, region, &target);
                    builder.add_relationship(
                        &uid,
                        "routes_to",
                        &target_uid,
                        builder.evidence("ec2", "DescribeRouteTables", "$.RouteTables[].Routes[]"),
                        json_object([("target_id", Value::String(target))]),
                    );
                }
            }
        }
        if let Some(token) = response.next_token() {
            next_token = Some(token.to_string());
        } else {
            break;
        }
    }
    Ok(())
}

async fn scan_internet_gateways(
    client: &Ec2Client,
    region: &str,
    builder: &mut InventoryBuilder,
) -> Result<()> {
    let mut next_token = None;
    loop {
        let response = client
            .describe_internet_gateways()
            .set_next_token(next_token.clone())
            .send()
            .await
            .context("calling ec2:DescribeInternetGateways")?;
        for gateway in response.internet_gateways() {
            let Some(id) = gateway.internet_gateway_id() else {
                continue;
            };
            let tags = ec2_tags(gateway.tags());
            let uid = resource_uid(&builder.account_id, region, "ec2", "internet-gateway", id);
            let attachments = gateway
                .attachments()
                .iter()
                .map(|attachment| {
                    json_object([
                        ("vpc_id", opt_str(attachment.vpc_id())),
                        (
                            "state",
                            opt_string(attachment.state().map(|state| state.as_str().to_string())),
                        ),
                    ])
                })
                .collect::<Vec<_>>();
            let attributes = json_object([("attachments", json!(attachments))]);
            builder.add_resource(Resource {
                uid: uid.clone(),
                provider: "aws".to_string(),
                account_id: builder.account_id.clone(),
                partition: builder.partition.clone(),
                region: region.to_string(),
                service: "ec2".to_string(),
                resource_type: "internet-gateway".to_string(),
                id: id.to_string(),
                arn: Some(format!(
                    "arn:{}:ec2:{region}:{}:internet-gateway/{id}",
                    builder.partition, builder.account_id
                )),
                name: tags.get("Name").cloned(),
                tags,
                raw: maybe_raw(builder.include_raw, &attributes),
                attributes,
                evidence: vec![builder.evidence(
                    "ec2",
                    "DescribeInternetGateways",
                    "$.InternetGateways[]",
                )],
            });
            for attachment in gateway.attachments() {
                if let Some(vpc_id) = attachment.vpc_id() {
                    let vpc_uid = resource_uid(&builder.account_id, region, "ec2", "vpc", vpc_id);
                    builder.add_relationship(
                        &uid,
                        "attached_to_vpc",
                        &vpc_uid,
                        builder.evidence(
                            "ec2",
                            "DescribeInternetGateways",
                            "$.InternetGateways[].Attachments[].VpcId",
                        ),
                        Value::Null,
                    );
                }
            }
        }
        if let Some(token) = response.next_token() {
            next_token = Some(token.to_string());
        } else {
            break;
        }
    }
    Ok(())
}

async fn scan_nat_gateways(
    client: &Ec2Client,
    region: &str,
    builder: &mut InventoryBuilder,
) -> Result<()> {
    let mut next_token = None;
    loop {
        let response = client
            .describe_nat_gateways()
            .set_next_token(next_token.clone())
            .send()
            .await
            .context("calling ec2:DescribeNatGateways")?;
        for gateway in response.nat_gateways() {
            let Some(id) = gateway.nat_gateway_id() else {
                continue;
            };
            let tags = ec2_tags(gateway.tags());
            let uid = resource_uid(&builder.account_id, region, "ec2", "nat-gateway", id);
            let attributes = json_object([
                ("vpc_id", opt_str(gateway.vpc_id())),
                ("subnet_id", opt_str(gateway.subnet_id())),
                (
                    "state",
                    opt_string(gateway.state().map(|state| state.as_str().to_string())),
                ),
                (
                    "connectivity_type",
                    opt_string(
                        gateway
                            .connectivity_type()
                            .map(|kind| kind.as_str().to_string()),
                    ),
                ),
            ]);
            builder.add_resource(Resource {
                uid: uid.clone(),
                provider: "aws".to_string(),
                account_id: builder.account_id.clone(),
                partition: builder.partition.clone(),
                region: region.to_string(),
                service: "ec2".to_string(),
                resource_type: "nat-gateway".to_string(),
                id: id.to_string(),
                arn: Some(format!(
                    "arn:{}:ec2:{region}:{}:natgateway/{id}",
                    builder.partition, builder.account_id
                )),
                name: tags.get("Name").cloned(),
                tags,
                raw: maybe_raw(builder.include_raw, &attributes),
                attributes,
                evidence: vec![builder.evidence("ec2", "DescribeNatGateways", "$.NatGateways[]")],
            });
            if let Some(vpc_id) = gateway.vpc_id() {
                let vpc_uid = resource_uid(&builder.account_id, region, "ec2", "vpc", vpc_id);
                builder.add_relationship(
                    &uid,
                    "in_vpc",
                    &vpc_uid,
                    builder.evidence("ec2", "DescribeNatGateways", "$.NatGateways[].VpcId"),
                    Value::Null,
                );
            }
            if let Some(subnet_id) = gateway.subnet_id() {
                let subnet_uid =
                    resource_uid(&builder.account_id, region, "ec2", "subnet", subnet_id);
                builder.add_relationship(
                    &uid,
                    "in_subnet",
                    &subnet_uid,
                    builder.evidence("ec2", "DescribeNatGateways", "$.NatGateways[].SubnetId"),
                    Value::Null,
                );
            }
        }
        if let Some(token) = response.next_token() {
            next_token = Some(token.to_string());
        } else {
            break;
        }
    }
    Ok(())
}

async fn scan_volumes(
    client: &Ec2Client,
    region: &str,
    builder: &mut InventoryBuilder,
) -> Result<()> {
    let mut next_token = None;
    loop {
        let response = client
            .describe_volumes()
            .set_next_token(next_token.clone())
            .send()
            .await
            .context("calling ec2:DescribeVolumes")?;
        for volume in response.volumes() {
            let Some(id) = volume.volume_id() else {
                continue;
            };
            let tags = ec2_tags(volume.tags());
            let uid = resource_uid(&builder.account_id, region, "ec2", "volume", id);
            let attachments = volume
                .attachments()
                .iter()
                .map(|attachment| {
                    json_object([
                        ("instance_id", opt_str(attachment.instance_id())),
                        ("device", opt_str(attachment.device())),
                        (
                            "state",
                            opt_string(attachment.state().map(|state| state.as_str().to_string())),
                        ),
                        (
                            "attach_time",
                            opt_string(attachment.attach_time().map(|date| date.to_string())),
                        ),
                    ])
                })
                .collect::<Vec<_>>();
            let attributes = json_object([
                ("availability_zone", opt_str(volume.availability_zone())),
                ("size_gib", opt_i32(volume.size())),
                ("encrypted", opt_bool(volume.encrypted())),
                (
                    "state",
                    opt_string(volume.state().map(|state| state.as_str().to_string())),
                ),
                (
                    "volume_type",
                    opt_string(volume.volume_type().map(|kind| kind.as_str().to_string())),
                ),
                ("attachments", json!(attachments)),
            ]);
            builder.add_resource(Resource {
                uid: uid.clone(),
                provider: "aws".to_string(),
                account_id: builder.account_id.clone(),
                partition: builder.partition.clone(),
                region: region.to_string(),
                service: "ec2".to_string(),
                resource_type: "volume".to_string(),
                id: id.to_string(),
                arn: Some(format!(
                    "arn:{}:ec2:{region}:{}:volume/{id}",
                    builder.partition, builder.account_id
                )),
                name: tags.get("Name").cloned(),
                tags,
                raw: maybe_raw(builder.include_raw, &attributes),
                attributes,
                evidence: vec![builder.evidence("ec2", "DescribeVolumes", "$.Volumes[]")],
            });
            for attachment in volume.attachments() {
                if let Some(instance_id) = attachment.instance_id() {
                    let instance_uid =
                        resource_uid(&builder.account_id, region, "ec2", "instance", instance_id);
                    builder.add_relationship(
                        &instance_uid,
                        "attaches_volume",
                        &uid,
                        builder.evidence("ec2", "DescribeVolumes", "$.Volumes[].Attachments[]"),
                        Value::Null,
                    );
                }
            }
        }
        if let Some(token) = response.next_token() {
            next_token = Some(token.to_string());
        } else {
            break;
        }
    }
    Ok(())
}

async fn scan_instances(
    client: &Ec2Client,
    region: &str,
    builder: &mut InventoryBuilder,
) -> Result<()> {
    let mut next_token = None;
    loop {
        let response = client
            .describe_instances()
            .set_next_token(next_token.clone())
            .send()
            .await
            .context("calling ec2:DescribeInstances")?;
        for reservation in response.reservations() {
            for instance in reservation.instances() {
                let Some(id) = instance.instance_id() else {
                    continue;
                };
                let tags = ec2_tags(instance.tags());
                let uid = resource_uid(&builder.account_id, region, "ec2", "instance", id);
                let attributes = json_object([
                    (
                        "instance_type",
                        opt_string(
                            instance
                                .instance_type()
                                .map(|instance_type| instance_type.as_str().to_string()),
                        ),
                    ),
                    (
                        "state",
                        opt_string(
                            instance
                                .state()
                                .and_then(|state| state.name())
                                .map(|name| name.as_str().to_string()),
                        ),
                    ),
                    ("image_id", opt_str(instance.image_id())),
                    ("vpc_id", opt_str(instance.vpc_id())),
                    ("subnet_id", opt_str(instance.subnet_id())),
                    ("private_ip_address", opt_str(instance.private_ip_address())),
                    ("public_ip_address", opt_str(instance.public_ip_address())),
                    (
                        "availability_zone",
                        opt_str(
                            instance
                                .placement()
                                .and_then(|placement| placement.availability_zone()),
                        ),
                    ),
                    (
                        "launch_time",
                        opt_string(instance.launch_time().map(|date| date.to_string())),
                    ),
                ]);
                builder.add_resource(Resource {
                    uid: uid.clone(),
                    provider: "aws".to_string(),
                    account_id: builder.account_id.clone(),
                    partition: builder.partition.clone(),
                    region: region.to_string(),
                    service: "ec2".to_string(),
                    resource_type: "instance".to_string(),
                    id: id.to_string(),
                    arn: Some(format!(
                        "arn:{}:ec2:{region}:{}:instance/{id}",
                        builder.partition, builder.account_id
                    )),
                    name: tags.get("Name").cloned(),
                    tags,
                    raw: maybe_raw(builder.include_raw, &attributes),
                    attributes,
                    evidence: vec![builder.evidence(
                        "ec2",
                        "DescribeInstances",
                        "$.Reservations[].Instances[]",
                    )],
                });

                if let Some(vpc_id) = instance.vpc_id() {
                    let vpc_uid = resource_uid(&builder.account_id, region, "ec2", "vpc", vpc_id);
                    builder.add_relationship(
                        &uid,
                        "in_vpc",
                        &vpc_uid,
                        builder.evidence(
                            "ec2",
                            "DescribeInstances",
                            "$.Reservations[].Instances[].VpcId",
                        ),
                        Value::Null,
                    );
                }
                if let Some(subnet_id) = instance.subnet_id() {
                    let subnet_uid =
                        resource_uid(&builder.account_id, region, "ec2", "subnet", subnet_id);
                    builder.add_relationship(
                        &uid,
                        "in_subnet",
                        &subnet_uid,
                        builder.evidence(
                            "ec2",
                            "DescribeInstances",
                            "$.Reservations[].Instances[].SubnetId",
                        ),
                        Value::Null,
                    );
                }
                for group in instance.security_groups() {
                    if let Some(group_id) = group.group_id() {
                        let group_uid = resource_uid(
                            &builder.account_id,
                            region,
                            "ec2",
                            "security-group",
                            group_id,
                        );
                        builder.add_relationship(
                            &uid,
                            "uses_security_group",
                            &group_uid,
                            builder.evidence(
                                "ec2",
                                "DescribeInstances",
                                "$.Reservations[].Instances[].SecurityGroups[]",
                            ),
                            Value::Null,
                        );
                    }
                }
                if let Some(profile_arn) = instance
                    .iam_instance_profile()
                    .and_then(|profile| profile.arn())
                {
                    if let Some(profile_uid) = uid_for_arn(&builder.account_id, profile_arn) {
                        builder.add_relationship(
                            &uid,
                            "uses_iam_instance_profile",
                            &profile_uid,
                            builder.evidence(
                                "ec2",
                                "DescribeInstances",
                                "$.Reservations[].Instances[].IamInstanceProfile.Arn",
                            ),
                            Value::Null,
                        );
                    }
                }
            }
        }
        if let Some(token) = response.next_token() {
            next_token = Some(token.to_string());
        } else {
            break;
        }
    }
    Ok(())
}

async fn scan_lambda_region(
    config: &aws_config::SdkConfig,
    region: &str,
    builder: &mut InventoryBuilder,
) -> Result<()> {
    let client = LambdaClient::new(config);
    let mut marker = None;
    loop {
        let response = client
            .list_functions()
            .set_marker(marker.clone())
            .send()
            .await
            .context("calling lambda:ListFunctions")?;
        for function in response.functions() {
            let Some(function_name) = function.function_name() else {
                continue;
            };
            let arn = function.function_arn().map(str::to_string);
            let uid = arn
                .as_deref()
                .and_then(|arn| uid_for_arn(&builder.account_id, arn))
                .unwrap_or_else(|| {
                    resource_uid(
                        &builder.account_id,
                        region,
                        "lambda",
                        "function",
                        function_name,
                    )
                });
            let attributes = json_object([
                (
                    "runtime",
                    opt_string(
                        function
                            .runtime()
                            .map(|runtime| runtime.as_str().to_string()),
                    ),
                ),
                ("role", opt_str(function.role())),
                ("handler", opt_str(function.handler())),
                ("memory_size", opt_i32(function.memory_size())),
                ("timeout", opt_i32(function.timeout())),
                ("last_modified", opt_str(function.last_modified())),
                (
                    "state",
                    opt_string(function.state().map(|state| state.as_str().to_string())),
                ),
                (
                    "vpc_id",
                    opt_str(
                        function
                            .vpc_config()
                            .and_then(|vpc_config| vpc_config.vpc_id()),
                    ),
                ),
                (
                    "subnet_ids",
                    json!(
                        function
                            .vpc_config()
                            .map(|vpc_config| vpc_config.subnet_ids().to_vec())
                            .unwrap_or_default()
                    ),
                ),
                (
                    "security_group_ids",
                    json!(
                        function
                            .vpc_config()
                            .map(|vpc_config| vpc_config.security_group_ids().to_vec())
                            .unwrap_or_default()
                    ),
                ),
            ]);
            builder.add_resource(Resource {
                uid: uid.clone(),
                provider: "aws".to_string(),
                account_id: builder.account_id.clone(),
                partition: builder.partition.clone(),
                region: region.to_string(),
                service: "lambda".to_string(),
                resource_type: "function".to_string(),
                id: function_name.to_string(),
                arn,
                name: Some(function_name.to_string()),
                tags: BTreeMap::new(),
                raw: maybe_raw(builder.include_raw, &attributes),
                attributes,
                evidence: vec![builder.evidence("lambda", "ListFunctions", "$.Functions[]")],
            });
            if let Some(role_arn) = function.role() {
                if let Some(role_uid) = uid_for_arn(&builder.account_id, role_arn) {
                    builder.add_relationship(
                        &uid,
                        "assumes_role",
                        &role_uid,
                        builder.evidence("lambda", "ListFunctions", "$.Functions[].Role"),
                        Value::Null,
                    );
                }
            }
            if let Some(vpc_config) = function.vpc_config() {
                if let Some(vpc_id) = vpc_config.vpc_id() {
                    let vpc_uid = resource_uid(&builder.account_id, region, "ec2", "vpc", vpc_id);
                    builder.add_relationship(
                        &uid,
                        "in_vpc",
                        &vpc_uid,
                        builder.evidence(
                            "lambda",
                            "ListFunctions",
                            "$.Functions[].VpcConfig.VpcId",
                        ),
                        Value::Null,
                    );
                }
                for subnet_id in vpc_config.subnet_ids() {
                    let subnet_uid =
                        resource_uid(&builder.account_id, region, "ec2", "subnet", subnet_id);
                    builder.add_relationship(
                        &uid,
                        "uses_subnet",
                        &subnet_uid,
                        builder.evidence(
                            "lambda",
                            "ListFunctions",
                            "$.Functions[].VpcConfig.SubnetIds[]",
                        ),
                        Value::Null,
                    );
                }
                for group_id in vpc_config.security_group_ids() {
                    let group_uid = resource_uid(
                        &builder.account_id,
                        region,
                        "ec2",
                        "security-group",
                        group_id,
                    );
                    builder.add_relationship(
                        &uid,
                        "uses_security_group",
                        &group_uid,
                        builder.evidence(
                            "lambda",
                            "ListFunctions",
                            "$.Functions[].VpcConfig.SecurityGroupIds[]",
                        ),
                        Value::Null,
                    );
                }
            }
        }
        if let Some(next_marker) = response.next_marker() {
            marker = Some(next_marker.to_string());
        } else {
            break;
        }
    }
    Ok(())
}

async fn scan_tagged_resources_region(
    config: &aws_config::SdkConfig,
    region: &str,
    builder: &mut InventoryBuilder,
) -> Result<()> {
    let client = TaggingClient::new(config);
    let mut token = None;
    loop {
        let response = client
            .get_resources()
            .set_pagination_token(token.clone())
            .send()
            .await
            .context("calling resourcegroupstagging:GetResources")?;
        for mapping in response.resource_tag_mapping_list() {
            let Some(arn) = mapping.resource_arn() else {
                continue;
            };
            let Some(parsed) = parse_arn(arn) else {
                continue;
            };
            let account_id = if parsed.account_id.is_empty() {
                builder.account_id.clone()
            } else {
                parsed.account_id.clone()
            };
            let resource_region = empty_to_global(if parsed.region == "global" {
                region.to_string()
            } else {
                parsed.region.clone()
            });
            let tags = mapping
                .tags()
                .iter()
                .map(|tag| (tag.key().to_string(), tag.value().to_string()))
                .collect::<BTreeMap<_, _>>();
            let uid = resource_uid(
                &account_id,
                &resource_region,
                &parsed.service,
                &parsed.resource_type,
                &parsed.resource_id,
            );
            builder.add_resource(Resource {
                uid,
                provider: "aws".to_string(),
                account_id,
                partition: parsed.partition,
                region: resource_region,
                service: parsed.service,
                resource_type: parsed.resource_type,
                id: parsed.resource_id,
                arn: Some(arn.to_string()),
                name: tags.get("Name").cloned(),
                tags,
                attributes: json!({ "discovered_by": "resourcegroupstagging" }),
                evidence: vec![builder.evidence(
                    "resourcegroupstagging",
                    "GetResources",
                    "$.ResourceTagMappingList[]",
                )],
                raw: None,
            });
        }

        match response.pagination_token() {
            Some(next) if !next.is_empty() => token = Some(next.to_string()),
            _ => break,
        }
    }
    Ok(())
}

fn ec2_tags(tags: &[aws_sdk_ec2::types::Tag]) -> BTreeMap<String, String> {
    tags.iter()
        .filter_map(|tag| Some((tag.key()?.to_string(), tag.value()?.to_string())))
        .collect()
}

fn security_permissions(permissions: &[aws_sdk_ec2::types::IpPermission]) -> Value {
    Value::Array(
        permissions
            .iter()
            .map(|permission| {
                json_object([
                    ("ip_protocol", opt_str(permission.ip_protocol())),
                    ("from_port", opt_i32(permission.from_port())),
                    ("to_port", opt_i32(permission.to_port())),
                    (
                        "ipv4_ranges",
                        json!(
                            permission
                                .ip_ranges()
                                .iter()
                                .filter_map(|range| range.cidr_ip())
                                .collect::<Vec<_>>()
                        ),
                    ),
                    (
                        "ipv6_ranges",
                        json!(
                            permission
                                .ipv6_ranges()
                                .iter()
                                .filter_map(|range| range.cidr_ipv6())
                                .collect::<Vec<_>>()
                        ),
                    ),
                    (
                        "security_group_refs",
                        json!(
                            permission
                                .user_id_group_pairs()
                                .iter()
                                .filter_map(|pair| pair.group_id())
                                .collect::<Vec<_>>()
                        ),
                    ),
                ])
            })
            .collect(),
    )
}

fn route_targets(route: &aws_sdk_ec2::types::Route) -> Vec<String> {
    [
        route.gateway_id(),
        route.nat_gateway_id(),
        route.transit_gateway_id(),
        route.vpc_peering_connection_id(),
        route.egress_only_internet_gateway_id(),
    ]
    .into_iter()
    .flatten()
    .filter(|target| *target != "local")
    .map(str::to_string)
    .collect()
}

fn ec2_target_uid(account_id: &str, region: &str, target_id: &str) -> String {
    let resource_type = if target_id.starts_with("igw-") {
        "internet-gateway"
    } else if target_id.starts_with("nat-") {
        "nat-gateway"
    } else if target_id.starts_with("tgw-") {
        "transit-gateway"
    } else if target_id.starts_with("pcx-") {
        "vpc-peering-connection"
    } else if target_id.starts_with("eigw-") {
        "egress-only-internet-gateway"
    } else {
        "route-target"
    };
    resource_uid(account_id, region, "ec2", resource_type, target_id)
}

fn opt_str(value: Option<&str>) -> Value {
    value
        .map(|value| Value::String(value.to_string()))
        .unwrap_or(Value::Null)
}

fn opt_string(value: Option<String>) -> Value {
    value.map(Value::String).unwrap_or(Value::Null)
}

fn opt_bool(value: Option<bool>) -> Value {
    value.map(Value::Bool).unwrap_or(Value::Null)
}

fn opt_i32(value: Option<i32>) -> Value {
    value
        .map(|value| Value::Number(serde_json::Number::from(value)))
        .unwrap_or(Value::Null)
}

fn maybe_raw(include_raw: bool, value: &Value) -> Option<Value> {
    include_raw.then(|| value.clone())
}

fn merge_attributes(existing: &mut Value, incoming: Value) {
    if incoming.is_null() || incoming == json!({}) {
        return;
    }

    if existing.is_null() || *existing == json!({}) {
        *existing = incoming;
        return;
    }

    if let (Some(existing), Value::Object(incoming)) = (existing.as_object_mut(), incoming) {
        for (key, value) in incoming {
            existing.entry(key).or_insert(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_legacy_s3_eu_region() {
        assert_eq!(normalize_s3_region(Some("EU")), "eu-west-1");
    }

    #[test]
    fn infers_route_targets() {
        assert_eq!(
            ec2_target_uid("123456789012", "us-east-1", "igw-123"),
            "aws:123456789012:us-east-1:ec2:internet-gateway:igw-123"
        );
    }

    #[test]
    fn merge_attributes_preserves_existing_detail() {
        let mut existing = json!({
            "cidr_block": "10.0.0.0/16",
            "discovered_by": "ec2"
        });

        merge_attributes(
            &mut existing,
            json!({
                "discovered_by": "resourcegroupstagging",
                "owner": "team-a"
            }),
        );

        assert_eq!(existing["cidr_block"], "10.0.0.0/16");
        assert_eq!(existing["discovered_by"], "ec2");
        assert_eq!(existing["owner"], "team-a");
    }
}
