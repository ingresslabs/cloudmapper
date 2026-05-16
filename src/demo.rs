use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::{Value, json};

use crate::compare::compare_infra;
use crate::model::{
    Evidence, GENERATOR_NAME, Generator, Inventory, Relationship, Resource, SCHEMA_VERSION,
    ScanError, relationship_uid, resource_uid,
};
use crate::terraform_state::import_terraform_state_file;
use crate::writer::write_infra;

const ACCOUNT_ID: &str = "804977871902";
const HOME_REGION: &str = "us-east-1";
const AZ_SUFFIXES: [&str; 3] = ["a", "b", "c"];

#[derive(Clone, Copy)]
struct RegionProfile {
    name: &'static str,
    short: &'static str,
    cidr_octet: u8,
}

#[derive(Clone, Copy)]
struct EnvironmentProfile {
    name: &'static str,
    cidr_offset: u8,
    instances_per_app: usize,
}

#[derive(Clone, Copy)]
struct AppProfile {
    name: &'static str,
    short: &'static str,
    owner: &'static str,
    port: i64,
    managed_prod: bool,
    managed_instances: bool,
    lambda: bool,
}

#[derive(Clone)]
struct NetworkRefs {
    vpc_id: String,
    vpc_uid: String,
    subnet_ids: Vec<String>,
    subnet_uids: Vec<String>,
}

#[derive(Debug)]
pub struct DemoSummary {
    pub out: PathBuf,
    pub db_path: PathBuf,
    pub state_path: PathBuf,
    pub findings_path: PathBuf,
    pub resources: usize,
    pub relationships: usize,
    pub findings: usize,
    pub terraform_state_id: String,
}

const REGIONS: [RegionProfile; 3] = [
    RegionProfile {
        name: "us-east-1",
        short: "use1",
        cidr_octet: 10,
    },
    RegionProfile {
        name: "eu-west-1",
        short: "euw1",
        cidr_octet: 20,
    },
    RegionProfile {
        name: "ap-southeast-2",
        short: "apse2",
        cidr_octet: 30,
    },
];

const ENVIRONMENTS: [EnvironmentProfile; 3] = [
    EnvironmentProfile {
        name: "prod",
        cidr_offset: 0,
        instances_per_app: 3,
    },
    EnvironmentProfile {
        name: "stage",
        cidr_offset: 20,
        instances_per_app: 2,
    },
    EnvironmentProfile {
        name: "dev",
        cidr_offset: 40,
        instances_per_app: 1,
    },
];

const APPS: [AppProfile; 6] = [
    AppProfile {
        name: "payments",
        short: "pay",
        owner: "payments-platform",
        port: 8443,
        managed_prod: true,
        managed_instances: true,
        lambda: true,
    },
    AppProfile {
        name: "identity",
        short: "id",
        owner: "identity-platform",
        port: 9443,
        managed_prod: true,
        managed_instances: true,
        lambda: true,
    },
    AppProfile {
        name: "orders",
        short: "ord",
        owner: "commerce-platform",
        port: 8080,
        managed_prod: true,
        managed_instances: false,
        lambda: true,
    },
    AppProfile {
        name: "customer-edge",
        short: "edge",
        owner: "edge-platform",
        port: 443,
        managed_prod: true,
        managed_instances: false,
        lambda: false,
    },
    AppProfile {
        name: "analytics",
        short: "ana",
        owner: "data-platform",
        port: 9000,
        managed_prod: false,
        managed_instances: false,
        lambda: true,
    },
    AppProfile {
        name: "legacy-admin",
        short: "legacy",
        owner: "corporate-it",
        port: 22,
        managed_prod: false,
        managed_instances: false,
        lambda: false,
    },
];

pub fn write_demo_bundle(out: &Path, allow_non_empty_out: bool) -> Result<DemoSummary> {
    let inventory = demo_inventory();
    write_infra(out, &inventory, allow_non_empty_out)?;

    let db_path = out.join("map.db");
    let state_path = out.join("demo.tfstate");
    std::fs::write(&state_path, demo_tfstate())
        .with_context(|| format!("writing demo Terraform state {}", state_path.display()))?;

    let terraform_summary =
        import_terraform_state_file(&db_path, &state_path, Some("terraform:demo".to_string()))?;
    let report = compare_infra(&db_path, None, Some(&terraform_summary.state_id))?;
    let findings_path = out.join("findings.json");
    std::fs::write(
        &findings_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )
    .with_context(|| format!("writing demo findings {}", findings_path.display()))?;

    Ok(DemoSummary {
        out: out.to_path_buf(),
        db_path,
        state_path,
        findings_path,
        resources: inventory.resources.len(),
        relationships: inventory.relationships.len(),
        findings: report.findings.len(),
        terraform_state_id: terraform_summary.state_id,
    })
}

pub fn demo_inventory() -> Inventory {
    let mut resources = Vec::new();
    let mut relationships = Vec::new();
    let role_uids = add_iam_resources(&mut resources);
    add_s3_resources(&mut resources);

    for region in REGIONS {
        for env in ENVIRONMENTS {
            let network = add_network_resources(&mut resources, &mut relationships, region, env);
            for app in APPS {
                add_app_resources(
                    &mut resources,
                    &mut relationships,
                    &role_uids,
                    region,
                    env,
                    app,
                    &network,
                );
            }
        }
    }

    Inventory {
        schema_version: SCHEMA_VERSION.to_string(),
        generator: Generator {
            name: GENERATOR_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        account_id: ACCOUNT_ID.to_string(),
        partition: "aws".to_string(),
        home_region: HOME_REGION.to_string(),
        regions: REGIONS
            .iter()
            .map(|region| region.name.to_string())
            .collect(),
        collected_at: fixed_time(),
        resources,
        relationships,
        errors: vec![
            ScanError {
                service: "resourcegroupstaggingapi".to_string(),
                region: "ap-southeast-2".to_string(),
                operation: "GetResources".to_string(),
                message: "demo recoverable throttling event while listing tagged resources"
                    .to_string(),
            },
            ScanError {
                service: "lambda".to_string(),
                region: "eu-west-1".to_string(),
                operation: "ListTags".to_string(),
                message: "demo access gap for one legacy function tag read".to_string(),
            },
        ],
    }
}

fn add_network_resources(
    resources: &mut Vec<Resource>,
    relationships: &mut Vec<Relationship>,
    region: RegionProfile,
    env: EnvironmentProfile,
) -> NetworkRefs {
    let vpc_id = format!("vpc-{}{}", region.short, env.name);
    let vpc_uid = resource_uid(ACCOUNT_ID, region.name, "ec2", "vpc", &vpc_id);
    let cidr_base = region.cidr_octet + env.cidr_offset;

    resources.push(Resource {
        uid: vpc_uid.clone(),
        provider: "aws".to_string(),
        account_id: ACCOUNT_ID.to_string(),
        partition: "aws".to_string(),
        region: region.name.to_string(),
        service: "ec2".to_string(),
        resource_type: "vpc".to_string(),
        id: vpc_id.clone(),
        arn: Some(ec2_arn(region.name, "vpc", &vpc_id)),
        name: Some(format!("{}-{}-shared-vpc", env.name, region.short)),
        tags: tags(&[
            ("Environment", env.name),
            ("Owner", "network-platform"),
            ("CostCenter", "cc-network"),
            ("ManagedBy", "terraform"),
        ]),
        attributes: json!({
            "cidr_block": format!("10.{cidr_base}.0.0/16"),
            "is_default": false,
            "dns_hostnames": true,
            "dns_support": true
        }),
        evidence: vec![evidence("ec2", "DescribeVpcs", "$.Vpcs[*]")],
        raw: Some(json!({
            "VpcId": vpc_id,
            "CidrBlock": format!("10.{cidr_base}.0.0/16")
        })),
    });

    let mut subnet_ids = Vec::new();
    let mut subnet_uids = Vec::new();
    for (az_index, az_suffix) in AZ_SUFFIXES.iter().enumerate() {
        let subnet_id = format!("subnet-{}{}{}", region.short, env.name, az_index + 1);
        let subnet_uid = resource_uid(ACCOUNT_ID, region.name, "ec2", "subnet", &subnet_id);
        subnet_ids.push(subnet_id.clone());
        subnet_uids.push(subnet_uid.clone());
        resources.push(Resource {
            uid: subnet_uid.clone(),
            provider: "aws".to_string(),
            account_id: ACCOUNT_ID.to_string(),
            partition: "aws".to_string(),
            region: region.name.to_string(),
            service: "ec2".to_string(),
            resource_type: "subnet".to_string(),
            id: subnet_id.clone(),
            arn: Some(ec2_arn(region.name, "subnet", &subnet_id)),
            name: Some(format!(
                "{}-{}-app-{}",
                env.name,
                region.short,
                az_index + 1
            )),
            tags: tags(&[
                ("Environment", env.name),
                ("Tier", "application"),
                ("Owner", "network-platform"),
                ("ManagedBy", "terraform"),
            ]),
            attributes: json!({
                "cidr_block": format!("10.{}.{}.0/24", cidr_base, az_index + 10),
                "availability_zone": format!("{}{}", region.name, az_suffix),
                "vpc_id": vpc_id
            }),
            evidence: vec![evidence("ec2", "DescribeSubnets", "$.Subnets[*]")],
            raw: None,
        });
        relationships.push(relationship(&subnet_uid, "in_vpc", &vpc_uid));
    }

    let route_table_id = format!("rtb-{}{}", region.short, env.name);
    let route_table_uid = resource_uid(
        ACCOUNT_ID,
        region.name,
        "ec2",
        "route-table",
        &route_table_id,
    );
    resources.push(Resource {
        uid: route_table_uid.clone(),
        provider: "aws".to_string(),
        account_id: ACCOUNT_ID.to_string(),
        partition: "aws".to_string(),
        region: region.name.to_string(),
        service: "ec2".to_string(),
        resource_type: "route-table".to_string(),
        id: route_table_id.clone(),
        arn: Some(ec2_arn(region.name, "route-table", &route_table_id)),
        name: Some(format!("{}-{}-private", env.name, region.short)),
        tags: tags(&[
            ("Environment", env.name),
            ("Owner", "network-platform"),
            ("ManagedBy", "terraform"),
        ]),
        attributes: json!({
            "routes": [
                { "destination": "10.0.0.0/8", "target": "local" },
                { "destination": "0.0.0.0/0", "target": format!("nat-{}{}", region.short, env.name) }
            ]
        }),
        evidence: vec![evidence("ec2", "DescribeRouteTables", "$.RouteTables[*]")],
        raw: None,
    });
    relationships.push(relationship(&route_table_uid, "in_vpc", &vpc_uid));

    let igw_id = format!("igw-{}{}", region.short, env.name);
    let igw_uid = resource_uid(ACCOUNT_ID, region.name, "ec2", "internet-gateway", &igw_id);
    resources.push(Resource {
        uid: igw_uid.clone(),
        provider: "aws".to_string(),
        account_id: ACCOUNT_ID.to_string(),
        partition: "aws".to_string(),
        region: region.name.to_string(),
        service: "ec2".to_string(),
        resource_type: "internet-gateway".to_string(),
        id: igw_id.clone(),
        arn: Some(ec2_arn(region.name, "internet-gateway", &igw_id)),
        name: Some(format!("{}-{}-igw", env.name, region.short)),
        tags: tags(&[
            ("Environment", env.name),
            ("Owner", "network-platform"),
            ("ManagedBy", "terraform"),
        ]),
        attributes: json!({ "attachments": [{ "vpc_id": vpc_id, "state": "available" }] }),
        evidence: vec![evidence(
            "ec2",
            "DescribeInternetGateways",
            "$.InternetGateways[*]",
        )],
        raw: None,
    });
    relationships.push(relationship(&igw_uid, "attached_to_vpc", &vpc_uid));

    let nat_id = format!("nat-{}{}", region.short, env.name);
    let nat_uid = resource_uid(ACCOUNT_ID, region.name, "ec2", "nat-gateway", &nat_id);
    resources.push(Resource {
        uid: nat_uid.clone(),
        provider: "aws".to_string(),
        account_id: ACCOUNT_ID.to_string(),
        partition: "aws".to_string(),
        region: region.name.to_string(),
        service: "ec2".to_string(),
        resource_type: "nat-gateway".to_string(),
        id: nat_id.clone(),
        arn: Some(format!(
            "arn:aws:ec2:{}:{}:natgateway/{}",
            region.name, ACCOUNT_ID, nat_id
        )),
        name: Some(format!("{}-{}-nat-a", env.name, region.short)),
        tags: tags(&[
            ("Environment", env.name),
            ("Owner", "network-platform"),
            ("ManagedBy", "terraform"),
        ]),
        attributes: json!({
            "state": "available",
            "subnet_id": subnet_ids[0],
            "connectivity_type": "public"
        }),
        evidence: vec![evidence("ec2", "DescribeNatGateways", "$.NatGateways[*]")],
        raw: None,
    });
    relationships.push(relationship(&nat_uid, "in_subnet", &subnet_uids[0]));

    NetworkRefs {
        vpc_id,
        vpc_uid,
        subnet_ids,
        subnet_uids,
    }
}

fn add_app_resources(
    resources: &mut Vec<Resource>,
    relationships: &mut Vec<Relationship>,
    role_uids: &BTreeMap<String, String>,
    region: RegionProfile,
    env: EnvironmentProfile,
    app: AppProfile,
    network: &NetworkRefs,
) {
    let sg_id = security_group_id(region, env, app);
    let sg_uid = resource_uid(ACCOUNT_ID, region.name, "ec2", "security-group", &sg_id);
    resources.push(Resource {
        uid: sg_uid.clone(),
        provider: "aws".to_string(),
        account_id: ACCOUNT_ID.to_string(),
        partition: "aws".to_string(),
        region: region.name.to_string(),
        service: "ec2".to_string(),
        resource_type: "security-group".to_string(),
        id: sg_id.clone(),
        arn: Some(ec2_arn(region.name, "security-group", &sg_id)),
        name: Some(format!("{}-{}-{}-sg", env.name, region.short, app.name)),
        tags: app_tags(
            env,
            app,
            if terraform_manages_security_group(env, app) {
                "terraform"
            } else {
                "console"
            },
        ),
        attributes: json!({
            "description": format!("{} {} workload ingress", env.name, app.name),
            "vpc_id": network.vpc_id,
            "ingress": ingress_rules(env, app),
            "egress": [{
                "ip_protocol": "-1",
                "ipv4_ranges": ["0.0.0.0/0"],
                "ipv6_ranges": []
            }]
        }),
        evidence: vec![evidence(
            "ec2",
            "DescribeSecurityGroups",
            "$.SecurityGroups[*]",
        )],
        raw: Some(json!({
            "GroupId": sg_id,
            "GroupName": format!("{}-{}-{}-sg", env.name, region.short, app.name)
        })),
    });
    relationships.push(relationship(&sg_uid, "in_vpc", &network.vpc_uid));

    for instance_index in 0..env.instances_per_app {
        let instance_id = instance_id(region, env, app, instance_index);
        let instance_uid = resource_uid(ACCOUNT_ID, region.name, "ec2", "instance", &instance_id);
        let subnet_index = instance_index % network.subnet_uids.len();
        resources.push(Resource {
            uid: instance_uid.clone(),
            provider: "aws".to_string(),
            account_id: ACCOUNT_ID.to_string(),
            partition: "aws".to_string(),
            region: region.name.to_string(),
            service: "ec2".to_string(),
            resource_type: "instance".to_string(),
            id: instance_id.clone(),
            arn: Some(ec2_arn(region.name, "instance", &instance_id)),
            name: Some(format!(
                "{}-{}-{}-{:02}",
                env.name,
                region.short,
                app.name,
                instance_index + 1
            )),
            tags: app_tags(
                env,
                app,
                if terraform_manages_instance(env, app) {
                    "terraform"
                } else {
                    "autoscaling"
                },
            ),
            attributes: json!({
                "instance_type": instance_type(env, app),
                "state": "running",
                "private_ip_address": format!("10.{}.{}.{}", region.cidr_octet + env.cidr_offset, subnet_index + 10, instance_index + 20),
                "subnet_id": network.subnet_ids[subnet_index],
                "vpc_id": network.vpc_id,
                "iam_instance_profile": format!("cloudmapper-demo-{}-runtime", app.short)
            }),
            evidence: vec![evidence("ec2", "DescribeInstances", "$.Reservations[*]")],
            raw: None,
        });
        relationships.push(relationship(
            &instance_uid,
            "in_subnet",
            &network.subnet_uids[subnet_index],
        ));
        relationships.push(relationship(&instance_uid, "uses_security_group", &sg_uid));

        let volume_id = volume_id(region, env, app, instance_index);
        let volume_uid = resource_uid(ACCOUNT_ID, region.name, "ec2", "volume", &volume_id);
        resources.push(Resource {
            uid: volume_uid.clone(),
            provider: "aws".to_string(),
            account_id: ACCOUNT_ID.to_string(),
            partition: "aws".to_string(),
            region: region.name.to_string(),
            service: "ec2".to_string(),
            resource_type: "volume".to_string(),
            id: volume_id.clone(),
            arn: Some(ec2_arn(region.name, "volume", &volume_id)),
            name: Some(format!(
                "{}-{}-{}-data-{:02}",
                env.name,
                region.short,
                app.name,
                instance_index + 1
            )),
            tags: app_tags(env, app, "autoscaling"),
            attributes: json!({
                "availability_zone": format!("{}{}", region.name, AZ_SUFFIXES[subnet_index]),
                "size_gib": volume_size(env, app),
                "volume_type": "gp3",
                "encrypted": true,
                "attachments": [{ "instance_id": instance_id, "state": "attached" }]
            }),
            evidence: vec![evidence("ec2", "DescribeVolumes", "$.Volumes[*]")],
            raw: None,
        });
        relationships.push(relationship(&volume_uid, "attached_to", &instance_uid));
    }

    if app.lambda && env.name != "dev" {
        let function_id = format!("{}-{}-{}-worker", env.name, region.short, app.name);
        let function_uid =
            resource_uid(ACCOUNT_ID, region.name, "lambda", "function", &function_id);
        resources.push(Resource {
            uid: function_uid.clone(),
            provider: "aws".to_string(),
            account_id: ACCOUNT_ID.to_string(),
            partition: "aws".to_string(),
            region: region.name.to_string(),
            service: "lambda".to_string(),
            resource_type: "function".to_string(),
            id: function_id.clone(),
            arn: Some(format!(
                "arn:aws:lambda:{}:{}:function:{}",
                region.name, ACCOUNT_ID, function_id
            )),
            name: Some(function_id),
            tags: app_tags(env, app, "terraform"),
            attributes: json!({
                "runtime": "provided.al2023",
                "memory_size": 1024,
                "timeout": 30,
                "vpc_config": {
                    "subnet_ids": network.subnet_ids,
                    "security_group_ids": [sg_id]
                },
                "role": format!("arn:aws:iam::{ACCOUNT_ID}:role/cloudmapper-demo-{}-runtime", app.short)
            }),
            evidence: vec![evidence("lambda", "ListFunctions", "$.Functions[*]")],
            raw: None,
        });
        relationships.push(relationship(&function_uid, "uses_security_group", &sg_uid));
        if let Some(role_uid) = role_uids.get(app.short) {
            relationships.push(relationship(&function_uid, "assumes_role", role_uid));
        }
    }

    if matches!(app.short, "pay" | "id" | "ord" | "ana") && env.name != "dev" {
        let db_id = format!("{}-{}-{}-db", env.name, region.short, app.short);
        let db_uid = resource_uid(ACCOUNT_ID, region.name, "rds", "db-instance", &db_id);
        resources.push(Resource {
            uid: db_uid.clone(),
            provider: "aws".to_string(),
            account_id: ACCOUNT_ID.to_string(),
            partition: "aws".to_string(),
            region: region.name.to_string(),
            service: "rds".to_string(),
            resource_type: "db-instance".to_string(),
            id: db_id.clone(),
            arn: Some(format!(
                "arn:aws:rds:{}:{}:db:{}",
                region.name, ACCOUNT_ID, db_id
            )),
            name: Some(db_id),
            tags: app_tags(
                env,
                app,
                if env.name == "prod" && app.managed_prod {
                    "terraform"
                } else {
                    "console"
                },
            ),
            attributes: json!({
                "engine": if app.short == "ana" { "postgres" } else { "aurora-postgresql" },
                "instance_class": if env.name == "prod" { "db.r7g.large" } else { "db.t4g.medium" },
                "multi_az": env.name == "prod",
                "storage_encrypted": true,
                "vpc_id": network.vpc_id,
                "db_subnet_group": format!("{}-{}-db", env.name, region.short)
            }),
            evidence: vec![evidence("rds", "DescribeDBInstances", "$.DBInstances[*]")],
            raw: None,
        });
        relationships.push(relationship(&db_uid, "uses_security_group", &sg_uid));
        relationships.push(relationship(&db_uid, "in_vpc", &network.vpc_uid));
    }
}

fn add_iam_resources(resources: &mut Vec<Resource>) -> BTreeMap<String, String> {
    let mut role_uids = BTreeMap::new();
    for app in APPS {
        let role_name = format!("cloudmapper-demo-{}-runtime", app.short);
        let role_uid = resource_uid(ACCOUNT_ID, "global", "iam", "role", &role_name);
        role_uids.insert(app.short.to_string(), role_uid.clone());
        resources.push(Resource {
            uid: role_uid,
            provider: "aws".to_string(),
            account_id: ACCOUNT_ID.to_string(),
            partition: "aws".to_string(),
            region: "global".to_string(),
            service: "iam".to_string(),
            resource_type: "role".to_string(),
            id: role_name.clone(),
            arn: Some(format!("arn:aws:iam::{ACCOUNT_ID}:role/{role_name}")),
            name: Some(role_name),
            tags: tags(&[
                ("Environment", "shared"),
                ("Owner", app.owner),
                ("ManagedBy", "terraform"),
            ]),
            attributes: json!({
                "path": "/application/",
                "attached_policies": [
                    "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
                    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
                ]
            }),
            evidence: vec![evidence("iam", "ListRoles", "$.Roles[*]")],
            raw: None,
        });
    }

    for group in ["platform-admins", "read-only-auditors", "incident-response"] {
        let uid = resource_uid(ACCOUNT_ID, "global", "iam", "group", group);
        resources.push(Resource {
            uid,
            provider: "aws".to_string(),
            account_id: ACCOUNT_ID.to_string(),
            partition: "aws".to_string(),
            region: "global".to_string(),
            service: "iam".to_string(),
            resource_type: "group".to_string(),
            id: group.to_string(),
            arn: Some(format!("arn:aws:iam::{ACCOUNT_ID}:group/{group}")),
            name: Some(group.to_string()),
            tags: tags(&[("Environment", "shared"), ("Owner", "security")]),
            attributes: json!({ "users": 12, "mfa_required": group != "read-only-auditors" }),
            evidence: vec![evidence("iam", "ListGroups", "$.Groups[*]")],
            raw: None,
        });
    }

    for user in ["breakglass-ops", "ci-deploy-bot", "auditor-tableau"] {
        let uid = resource_uid(ACCOUNT_ID, "global", "iam", "user", user);
        resources.push(Resource {
            uid,
            provider: "aws".to_string(),
            account_id: ACCOUNT_ID.to_string(),
            partition: "aws".to_string(),
            region: "global".to_string(),
            service: "iam".to_string(),
            resource_type: "user".to_string(),
            id: user.to_string(),
            arn: Some(format!("arn:aws:iam::{ACCOUNT_ID}:user/{user}")),
            name: Some(user.to_string()),
            tags: tags(&[("Environment", "shared"), ("Owner", "security")]),
            attributes: json!({
                "mfa_active": user != "ci-deploy-bot",
                "access_key_1_last_rotated_days": if user == "ci-deploy-bot" { 412 } else { 32 }
            }),
            evidence: vec![evidence("iam", "ListUsers", "$.Users[*]")],
            raw: None,
        });
    }

    role_uids
}

fn add_s3_resources(resources: &mut Vec<Resource>) {
    for app in APPS {
        for env in ENVIRONMENTS {
            let bucket_name = format!("cm-demo-{}-{}-data-{}", app.short, env.name, ACCOUNT_ID);
            let bucket_uid = resource_uid(ACCOUNT_ID, "global", "s3", "bucket", &bucket_name);
            resources.push(Resource {
                uid: bucket_uid,
                provider: "aws".to_string(),
                account_id: ACCOUNT_ID.to_string(),
                partition: "aws".to_string(),
                region: "global".to_string(),
                service: "s3".to_string(),
                resource_type: "bucket".to_string(),
                id: bucket_name.clone(),
                arn: Some(format!("arn:aws:s3:::{bucket_name}")),
                name: Some(bucket_name),
                tags: app_tags(
                    env,
                    app,
                    if env.name == "prod" && app.managed_prod {
                        "terraform"
                    } else {
                        "console"
                    },
                ),
                attributes: json!({
                    "bucket_location": HOME_REGION,
                    "versioning": env.name == "prod",
                    "public_access_block": {
                        "block_public_acls": true,
                        "block_public_policy": true,
                        "ignore_public_acls": true,
                        "restrict_public_buckets": true
                    },
                    "encryption": "aws:kms"
                }),
                evidence: vec![evidence("s3", "ListBuckets", "$.Buckets[*]")],
                raw: None,
            });
        }
    }

    for region in REGIONS {
        let bucket_name = format!("cm-demo-audit-logs-{}-{}", region.short, ACCOUNT_ID);
        let bucket_uid = resource_uid(ACCOUNT_ID, "global", "s3", "bucket", &bucket_name);
        resources.push(Resource {
            uid: bucket_uid,
            provider: "aws".to_string(),
            account_id: ACCOUNT_ID.to_string(),
            partition: "aws".to_string(),
            region: "global".to_string(),
            service: "s3".to_string(),
            resource_type: "bucket".to_string(),
            id: bucket_name.clone(),
            arn: Some(format!("arn:aws:s3:::{bucket_name}")),
            name: Some(bucket_name),
            tags: tags(&[
                ("Environment", "shared"),
                ("Owner", "security"),
                ("DataClass", "audit"),
                ("ManagedBy", "terraform"),
            ]),
            attributes: json!({
                "bucket_location": region.name,
                "versioning": true,
                "object_lock": true,
                "retention_days": 365
            }),
            evidence: vec![evidence("s3", "ListBuckets", "$.Buckets[*]")],
            raw: None,
        });
    }
}

fn demo_tfstate() -> String {
    let mut resources = Vec::new();

    for region in REGIONS {
        for env in ENVIRONMENTS {
            let vpc_id = format!("vpc-{}{}", region.short, env.name);
            resources.push(terraform_resource(
                "aws_vpc",
                &format!("{}_{}", env.name, region.short),
                json!({
                    "id": vpc_id,
                    "arn": ec2_arn(region.name, "vpc", &vpc_id),
                    "cidr_block": format!("10.{}.0.0/16", region.cidr_octet + env.cidr_offset),
                    "tags": {
                        "Environment": env.name,
                        "Owner": "network-platform"
                    }
                }),
                json!([]),
            ));

            for (subnet_index, az_suffix) in AZ_SUFFIXES.iter().enumerate() {
                let subnet_id = format!("subnet-{}{}{}", region.short, env.name, subnet_index + 1);
                resources.push(terraform_resource(
                    "aws_subnet",
                    &format!("{}_{}_app_{}", env.name, region.short, subnet_index + 1),
                    json!({
                        "id": subnet_id,
                        "arn": ec2_arn(region.name, "subnet", &subnet_id),
                        "availability_zone": format!("{}{}", region.name, az_suffix),
                        "cidr_block": format!("10.{}.{}.0/24", region.cidr_octet + env.cidr_offset, subnet_index + 10),
                        "vpc_id": vpc_id
                    }),
                    json!([format!("aws_vpc.{}_{}", env.name, region.short)]),
                ));
            }

            for app in APPS {
                if terraform_manages_security_group(env, app) {
                    let sg_id = security_group_id(region, env, app);
                    resources.push(terraform_resource(
                        "aws_security_group",
                        &format!("{}_{}_{}", env.name, region.short, app.short),
                        json!({
                            "id": sg_id,
                            "arn": ec2_arn(region.name, "security-group", &sg_id),
                            "name": format!("{}-{}-{}-sg", env.name, region.short, app.name),
                            "vpc_id": vpc_id
                        }),
                        json!([format!("aws_vpc.{}_{}", env.name, region.short)]),
                    ));
                }

                if terraform_manages_instance(env, app) {
                    for instance_index in 0..env.instances_per_app {
                        let instance_id = instance_id(region, env, app, instance_index);
                        resources.push(terraform_resource(
                            "aws_instance",
                            &format!(
                                "{}_{}_{}_{:02}",
                                env.name,
                                region.short,
                                app.short,
                                instance_index + 1
                            ),
                            json!({
                                "id": instance_id,
                                "arn": ec2_arn(region.name, "instance", &instance_id),
                                "instance_type": instance_type(env, app),
                                "subnet_id": format!("subnet-{}{}{}", region.short, env.name, (instance_index % AZ_SUFFIXES.len()) + 1)
                            }),
                            json!([
                                format!("aws_security_group.{}_{}_{}", env.name, region.short, app.short)
                            ]),
                        ));
                    }
                }

                if app.lambda && env.name != "dev" {
                    let function_id = format!("{}-{}-{}-worker", env.name, region.short, app.name);
                    resources.push(terraform_resource(
                        "aws_lambda_function",
                        &format!("{}_{}_{}_worker", env.name, region.short, app.short),
                        json!({
                            "id": function_id,
                            "arn": format!("arn:aws:lambda:{}:{}:function:{}", region.name, ACCOUNT_ID, function_id),
                            "function_name": function_id,
                            "runtime": "provided.al2023",
                            "role": format!("arn:aws:iam::{ACCOUNT_ID}:role/cloudmapper-demo-{}-runtime", app.short)
                        }),
                        json!([
                            format!("aws_iam_role.{}_runtime", app.short),
                            format!("aws_security_group.{}_{}_{}", env.name, region.short, app.short)
                        ]),
                    ));
                }
            }
        }
    }

    for app in APPS.iter().filter(|app| app.managed_prod) {
        let bucket_name = format!("cm-demo-{}-prod-data-{}", app.short, ACCOUNT_ID);
        resources.push(terraform_resource(
            "aws_s3_bucket",
            &format!("{}_prod_data", app.short),
            json!({
                "id": bucket_name,
                "arn": format!("arn:aws:s3:::{bucket_name}"),
                "bucket": bucket_name
            }),
            json!([]),
        ));
    }

    for app in APPS.iter().filter(|app| app.managed_prod || app.lambda) {
        let role_name = format!("cloudmapper-demo-{}-runtime", app.short);
        resources.push(terraform_resource(
            "aws_iam_role",
            &format!("{}_runtime", app.short),
            json!({
                "id": role_name,
                "arn": format!("arn:aws:iam::{ACCOUNT_ID}:role/{role_name}"),
                "name": role_name
            }),
            json!([]),
        ));
    }

    resources.push(terraform_resource(
        "aws_ebs_volume",
        "deleted_batch_cache",
        json!({
            "id": "vol-deleted-batch-cache",
            "arn": ec2_arn("us-east-1", "volume", "vol-deleted-batch-cache"),
            "availability_zone": "us-east-1a",
            "size": 500
        }),
        json!([]),
    ));

    let state = json!({
        "version": 4,
        "terraform_version": "1.8.0",
        "serial": 42,
        "lineage": "cloudmapper-large-org-demo",
        "resources": resources
    });
    format!(
        "{}\n",
        serde_json::to_string_pretty(&state).expect("demo state is serializable")
    )
}

fn terraform_resource(
    resource_type: &str,
    name: &str,
    attributes: Value,
    dependencies: Value,
) -> Value {
    json!({
        "mode": "managed",
        "type": resource_type,
        "name": name,
        "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
        "instances": [{
            "schema_version": 1,
            "attributes": attributes,
            "sensitive_attributes": [],
            "dependencies": dependencies
        }]
    })
}

fn terraform_manages_security_group(env: EnvironmentProfile, app: AppProfile) -> bool {
    env.name == "prod" && app.managed_prod
}

fn terraform_manages_instance(env: EnvironmentProfile, app: AppProfile) -> bool {
    env.name == "prod" && app.managed_instances
}

fn security_group_id(region: RegionProfile, env: EnvironmentProfile, app: AppProfile) -> String {
    format!("sg-{}{}{}", region.short, env.name, app.short)
}

fn instance_id(
    region: RegionProfile,
    env: EnvironmentProfile,
    app: AppProfile,
    instance_index: usize,
) -> String {
    format!(
        "i-{}{}{}{:02}",
        region.short,
        env.name,
        app.short,
        instance_index + 1
    )
}

fn volume_id(
    region: RegionProfile,
    env: EnvironmentProfile,
    app: AppProfile,
    instance_index: usize,
) -> String {
    format!(
        "vol-{}{}{}{:02}",
        region.short,
        env.name,
        app.short,
        instance_index + 1
    )
}

fn ec2_arn(region: &str, resource_type: &str, id: &str) -> String {
    format!("arn:aws:ec2:{region}:{ACCOUNT_ID}:{resource_type}/{id}")
}

fn ingress_rules(env: EnvironmentProfile, app: AppProfile) -> Vec<Value> {
    if app.short == "edge" {
        return vec![json!({
            "ip_protocol": "tcp",
            "from_port": 443,
            "to_port": 443,
            "ipv4_ranges": ["0.0.0.0/0"],
            "ipv6_ranges": ["::/0"]
        })];
    }

    if app.short == "legacy" {
        return vec![json!({
            "ip_protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "ipv4_ranges": ["0.0.0.0/0"],
            "ipv6_ranges": []
        })];
    }

    vec![json!({
        "ip_protocol": "tcp",
        "from_port": app.port,
        "to_port": app.port,
        "ipv4_ranges": if env.name == "prod" { vec!["10.0.0.0/8"] } else { vec!["10.0.0.0/8", "172.16.0.0/12"] },
        "ipv6_ranges": []
    })]
}

fn instance_type(env: EnvironmentProfile, app: AppProfile) -> &'static str {
    match (env.name, app.short) {
        ("prod", "ana") => "m7i.2xlarge",
        ("prod", "pay" | "id" | "ord") => "m7i.large",
        ("prod", _) => "t3.large",
        ("stage", _) => "t3.medium",
        _ => "t3.small",
    }
}

fn volume_size(env: EnvironmentProfile, app: AppProfile) -> i64 {
    match (env.name, app.short) {
        ("prod", "ana") => 1024,
        ("prod", "pay" | "id") => 500,
        ("prod", _) => 200,
        ("stage", _) => 100,
        _ => 50,
    }
}

fn relationship(from: &str, relationship_type: &str, to: &str) -> Relationship {
    Relationship {
        uid: relationship_uid(from, relationship_type, to),
        from: from.to_string(),
        to: to.to_string(),
        relationship_type: relationship_type.to_string(),
        attributes: json!({}),
        evidence: vec![evidence("cloudmapper", "demo", "$")],
    }
}

fn app_tags(
    env: EnvironmentProfile,
    app: AppProfile,
    managed_by: &str,
) -> BTreeMap<String, String> {
    tags(&[
        ("Environment", env.name),
        ("Application", app.name),
        ("Owner", app.owner),
        ("CostCenter", cost_center(app)),
        ("ManagedBy", managed_by),
    ])
}

fn cost_center(app: AppProfile) -> &'static str {
    match app.short {
        "pay" => "cc-110-payments",
        "id" => "cc-120-identity",
        "ord" => "cc-130-commerce",
        "edge" => "cc-140-edge",
        "ana" => "cc-210-data",
        _ => "cc-900-corp-it",
    }
}

fn fixed_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 16, 0, 0, 0)
        .single()
        .expect("demo timestamp is valid")
}

fn evidence(service: &str, operation: &str, path: &str) -> Evidence {
    Evidence {
        service: service.to_string(),
        operation: operation.to_string(),
        path: path.to_string(),
        collected_at: fixed_time(),
    }
}

fn tags(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn writes_demo_bundle_with_state_and_findings() {
        let temp = tempdir().unwrap();
        let summary = write_demo_bundle(temp.path(), false).unwrap();

        assert!(summary.db_path.exists());
        assert!(summary.state_path.exists());
        assert!(summary.findings_path.exists());
        assert_eq!(summary.resources, 414);
        assert_eq!(summary.relationships, 528);
        assert_eq!(summary.findings, 327);
        assert_eq!(summary.terraform_state_id, "terraform:demo");

        let connection = Connection::open(summary.db_path).unwrap();
        let finding_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0))
            .unwrap();
        let critical_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM findings WHERE severity = 'critical'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let high_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM findings WHERE severity = 'high'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let terraform_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM terraform_resource_instances",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(finding_count, summary.findings as i64);
        assert_eq!(critical_count, 15);
        assert_eq!(high_count, 3);
        assert_eq!(terraform_count, 100);
    }
}
