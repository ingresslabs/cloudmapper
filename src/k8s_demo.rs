use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::{Value, json};

use crate::k8s_scan::{build_scan_output, write_k8s_findings};
use crate::model::ScanError;
use crate::writer::write_infra;

const CLUSTER_ID: &str = "prod-platform-us-east-1";

#[derive(Debug)]
pub struct K8sDemoSummary {
    pub out: PathBuf,
    pub db_path: PathBuf,
    pub findings_path: PathBuf,
    pub resources: usize,
    pub relationships: usize,
    pub findings: usize,
    pub run_id: String,
}

#[derive(Clone, Copy)]
struct NamespaceProfile {
    name: &'static str,
    environment: &'static str,
    owner: &'static str,
    network_policy: bool,
}

#[derive(Clone, Copy)]
struct WorkloadProfile {
    name: &'static str,
    short: &'static str,
    owner: &'static str,
    port: i64,
    public: bool,
    storage: bool,
    sensitive_config: bool,
}

const NAMESPACES: &[NamespaceProfile] = &[
    NamespaceProfile {
        name: "prod-payments",
        environment: "prod",
        owner: "payments-platform",
        network_policy: true,
    },
    NamespaceProfile {
        name: "prod-commerce",
        environment: "prod",
        owner: "commerce-platform",
        network_policy: true,
    },
    NamespaceProfile {
        name: "prod-edge",
        environment: "prod",
        owner: "edge-platform",
        network_policy: true,
    },
    NamespaceProfile {
        name: "stage-apps",
        environment: "stage",
        owner: "platform-engineering",
        network_policy: true,
    },
    NamespaceProfile {
        name: "dev-apps",
        environment: "dev",
        owner: "developer-experience",
        network_policy: false,
    },
    NamespaceProfile {
        name: "data-platform",
        environment: "prod",
        owner: "data-platform",
        network_policy: true,
    },
    NamespaceProfile {
        name: "observability",
        environment: "shared",
        owner: "sre",
        network_policy: true,
    },
    NamespaceProfile {
        name: "security",
        environment: "shared",
        owner: "security",
        network_policy: true,
    },
    NamespaceProfile {
        name: "legacy-admin",
        environment: "prod",
        owner: "corporate-it",
        network_policy: false,
    },
];

const WORKLOADS: &[WorkloadProfile] = &[
    WorkloadProfile {
        name: "payments-api",
        short: "pay",
        owner: "payments-platform",
        port: 8443,
        public: true,
        storage: true,
        sensitive_config: true,
    },
    WorkloadProfile {
        name: "billing-api",
        short: "bill",
        owner: "payments-platform",
        port: 8444,
        public: false,
        storage: true,
        sensitive_config: true,
    },
    WorkloadProfile {
        name: "fraud-detector",
        short: "fraud",
        owner: "risk-platform",
        port: 8088,
        public: false,
        storage: true,
        sensitive_config: true,
    },
    WorkloadProfile {
        name: "checkout-api",
        short: "chk",
        owner: "commerce-platform",
        port: 8080,
        public: true,
        storage: false,
        sensitive_config: false,
    },
    WorkloadProfile {
        name: "notifications-api",
        short: "notif",
        owner: "communications-platform",
        port: 8081,
        public: false,
        storage: false,
        sensitive_config: false,
    },
    WorkloadProfile {
        name: "search-api",
        short: "search",
        owner: "search-platform",
        port: 8082,
        public: true,
        storage: true,
        sensitive_config: false,
    },
    WorkloadProfile {
        name: "identity-api",
        short: "id",
        owner: "identity-platform",
        port: 9443,
        public: false,
        storage: true,
        sensitive_config: true,
    },
    WorkloadProfile {
        name: "customer-edge",
        short: "edge",
        owner: "edge-platform",
        port: 443,
        public: true,
        storage: false,
        sensitive_config: false,
    },
    WorkloadProfile {
        name: "orders-worker",
        short: "ord",
        owner: "commerce-platform",
        port: 9090,
        public: false,
        storage: true,
        sensitive_config: false,
    },
    WorkloadProfile {
        name: "analytics-api",
        short: "ana",
        owner: "data-platform",
        port: 9000,
        public: false,
        storage: true,
        sensitive_config: true,
    },
];

pub fn write_k8s_demo_bundle(out: &Path, allow_non_empty_out: bool) -> Result<K8sDemoSummary> {
    let output = k8s_demo_output();
    let scan_id = write_infra(out, &output.inventory, allow_non_empty_out)?;
    let db_path = out.join("map.db");
    let run_id = write_k8s_findings(&db_path, &scan_id, &output.findings)?;
    let findings_path = out.join("findings.json");
    std::fs::write(
        &findings_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&json!({
                "schema_version": "cloudmapper.infra.v1.k8s-findings.v1",
                "run_id": run_id,
                "scan_id": scan_id,
                "generated_at": fixed_time().to_rfc3339(),
                "findings": output.findings,
            }))?
        ),
    )
    .with_context(|| {
        format!(
            "writing Kubernetes demo findings {}",
            findings_path.display()
        )
    })?;

    Ok(K8sDemoSummary {
        out: out.to_path_buf(),
        db_path,
        findings_path,
        resources: output.inventory.resources.len(),
        relationships: output.inventory.relationships.len(),
        findings: output.findings.len(),
        run_id,
    })
}

fn k8s_demo_output() -> crate::k8s_scan::K8sScanOutput {
    build_scan_output(
        CLUSTER_ID,
        fixed_time(),
        true,
        demo_objects(),
        vec![
            ScanError {
                service: "kubernetes".to_string(),
                region: "dev-apps".to_string(),
                operation: "get events".to_string(),
                message: "demo RBAC denies event listing in one development namespace".to_string(),
            },
            ScanError {
                service: "kubernetes".to_string(),
                region: "cluster".to_string(),
                operation: "get customresourcedefinitions".to_string(),
                message: "demo scanner skipped CRDs that are outside normalized coverage"
                    .to_string(),
            },
        ],
    )
}

fn demo_objects() -> Vec<Value> {
    let mut objects = Vec::new();
    add_namespaces(&mut objects);
    add_nodes(&mut objects);
    add_storage_classes(&mut objects);
    add_cluster_rbac(&mut objects);

    for namespace in NAMESPACES {
        add_namespace_basics(&mut objects, *namespace);
        if namespace.network_policy {
            add_network_policy(&mut objects, *namespace);
        }
    }

    for namespace in NAMESPACES
        .iter()
        .filter(|namespace| !matches!(namespace.name, "security" | "observability"))
    {
        for workload in workloads_for_namespace(namespace) {
            add_workload_stack(&mut objects, *namespace, workload);
        }
    }

    add_observability_stack(&mut objects);
    add_security_stack(&mut objects);
    add_legacy_stack(&mut objects);
    objects
}

fn add_namespaces(objects: &mut Vec<Value>) {
    objects.push(json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": "kube-system",
            "uid": "ns-kube-system",
            "labels": { "kubernetes.io/metadata.name": "kube-system" }
        }
    }));
    for namespace in NAMESPACES {
        objects.push(json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": namespace.name,
                "uid": uid("ns", namespace.name),
                "labels": {
                    "environment": namespace.environment,
                    "team": namespace.owner,
                    "app.kubernetes.io/managed-by": "Terraform"
                }
            }
        }));
    }
}

fn add_nodes(objects: &mut Vec<Value>) {
    let pools = [
        ("core", "m7i.large", 4),
        ("memory", "r7g.xlarge", 4),
        ("gpu", "g5.xlarge", 2),
        ("legacy", "m5.large", 2),
    ];
    for (pool, instance_type, count) in pools {
        for index in 0..count {
            let name = format!("ip-10-42-{pool}-{}", index + 10);
            objects.push(json!({
                "apiVersion": "v1",
                "kind": "Node",
                "metadata": {
                    "name": name,
                    "uid": uid("node", &format!("{pool}-{index}")),
                    "labels": {
                        "node.kubernetes.io/instance-type": instance_type,
                        "topology.kubernetes.io/region": "us-east-1",
                        "topology.kubernetes.io/zone": format!("us-east-1{}", ["a", "b", "c"][index % 3]),
                        "cloudmapper.io/node-pool": pool,
                        "app.kubernetes.io/managed-by": "EKS"
                    }
                },
                "spec": {
                    "providerID": format!("aws:///us-east-1{}/i-demo{}{}", ["a", "b", "c"][index % 3], pool, index),
                    "taints": if pool == "gpu" { json!([{ "key": "workload", "value": "gpu", "effect": "NoSchedule" }]) } else { json!([]) }
                },
                "status": {
                    "capacity": { "cpu": "8", "memory": "32Gi", "pods": "110" },
                    "allocatable": { "cpu": "7600m", "memory": "29Gi", "pods": "100" }
                }
            }));
        }
    }
}

fn add_storage_classes(objects: &mut Vec<Value>) {
    for (name, provisioner, reclaim_policy, binding_mode) in [
        (
            "gp3-encrypted",
            "ebs.csi.aws.com",
            "Delete",
            "WaitForFirstConsumer",
        ),
        (
            "io2-retain",
            "ebs.csi.aws.com",
            "Retain",
            "WaitForFirstConsumer",
        ),
        ("efs-shared", "efs.csi.aws.com", "Retain", "Immediate"),
    ] {
        objects.push(json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "StorageClass",
            "metadata": {
                "name": name,
                "uid": uid("sc", name),
                "labels": { "app.kubernetes.io/managed-by": "Terraform" }
            },
            "provisioner": provisioner,
            "reclaimPolicy": reclaim_policy,
            "volumeBindingMode": binding_mode
        }));
    }
}

fn add_cluster_rbac(objects: &mut Vec<Value>) {
    for (name, rules) in [
        (
            "platform-readonly",
            json!([{ "apiGroups": ["", "apps", "networking.k8s.io"], "resources": ["pods", "services", "deployments", "ingresses"], "verbs": ["get", "list", "watch"] }]),
        ),
        (
            "namespace-admin",
            json!([{ "apiGroups": ["", "apps"], "resources": ["pods", "services", "deployments"], "verbs": ["*"] }]),
        ),
        (
            "secret-reader",
            json!([{ "apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"] }]),
        ),
        (
            "cluster-admin",
            json!([{ "apiGroups": ["*"], "resources": ["*"], "verbs": ["*"] }]),
        ),
    ] {
        objects.push(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {
                "name": name,
                "uid": uid("clusterrole", name),
                "labels": { "app.kubernetes.io/managed-by": "Terraform" }
            },
            "rules": rules
        }));
    }

    objects.push(json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {
            "name": "incident-response-admin",
            "uid": "crb-incident-response-admin",
            "labels": { "app.kubernetes.io/managed-by": "Terraform" }
        },
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin" },
        "subjects": [
            { "kind": "ServiceAccount", "namespace": "security", "name": "incident-response" }
        ]
    }));
    objects.push(json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "legacy-admin-default", "uid": "crb-legacy-admin-default" },
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin" },
        "subjects": [
            { "kind": "ServiceAccount", "namespace": "legacy-admin", "name": "default" }
        ]
    }));
}

fn add_namespace_basics(objects: &mut Vec<Value>, namespace: NamespaceProfile) {
    for name in ["default", "deployer", "reader"] {
        objects.push(json!({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "namespace": namespace.name,
                "name": name,
                "uid": uid("sa", &format!("{}-{name}", namespace.name)),
                "labels": {
                    "environment": namespace.environment,
                    "team": namespace.owner,
                    "app.kubernetes.io/managed-by": if namespace.name == "legacy-admin" { "console" } else { "Terraform" }
                }
            }
        }));
    }

    objects.push(json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {
            "namespace": namespace.name,
            "name": "namespace-reader",
            "uid": uid("role", &format!("{}-reader", namespace.name)),
            "labels": { "app.kubernetes.io/managed-by": "Terraform" }
        },
        "rules": [{ "apiGroups": ["", "apps"], "resources": ["pods", "services", "deployments"], "verbs": ["get", "list", "watch"] }]
    }));
    objects.push(json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {
            "namespace": namespace.name,
            "name": "reader-binding",
            "uid": uid("rb", &format!("{}-reader", namespace.name)),
            "labels": { "app.kubernetes.io/managed-by": "Terraform" }
        },
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "namespace-reader" },
        "subjects": [{ "kind": "ServiceAccount", "namespace": namespace.name, "name": "reader" }]
    }));
}

fn add_network_policy(objects: &mut Vec<Value>, namespace: NamespaceProfile) {
    objects.push(json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "namespace": namespace.name,
            "name": "default-deny",
            "uid": uid("netpol", &format!("{}-default-deny", namespace.name)),
            "labels": {
                "environment": namespace.environment,
                "team": namespace.owner,
                "app.kubernetes.io/managed-by": "Terraform"
            }
        },
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            "egress": [{ "to": [{ "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": "kube-system" } } }] }]
        }
    }));
}

fn workloads_for_namespace(namespace: &NamespaceProfile) -> Vec<WorkloadProfile> {
    match namespace.name {
        "prod-payments" => profiles(&[
            "payments-api",
            "billing-api",
            "identity-api",
            "fraud-detector",
        ]),
        "prod-commerce" => profiles(&[
            "checkout-api",
            "orders-worker",
            "notifications-api",
            "search-api",
        ]),
        "prod-edge" => profiles(&["customer-edge"]),
        "data-platform" => profiles(&["analytics-api", "fraud-detector"]),
        "stage-apps" => WORKLOADS.to_vec(),
        "dev-apps" => profiles(&[
            "payments-api",
            "billing-api",
            "checkout-api",
            "orders-worker",
            "search-api",
        ]),
        "legacy-admin" => Vec::new(),
        _ => Vec::new(),
    }
}

fn profiles(names: &[&str]) -> Vec<WorkloadProfile> {
    names
        .iter()
        .filter_map(|name| {
            WORKLOADS
                .iter()
                .find(|workload| workload.name == *name)
                .copied()
        })
        .collect()
}

fn add_workload_stack(
    objects: &mut Vec<Value>,
    namespace: NamespaceProfile,
    workload: WorkloadProfile,
) {
    let replicas = replicas_for(namespace, workload);
    let managed_by = if namespace.name == "dev-apps" && workload.short == "ord" {
        "kubectl"
    } else {
        "Helm"
    };
    let risky = namespace.name == "legacy-admin"
        || (namespace.name == "dev-apps" && workload.short == "ord");
    add_service_account(objects, namespace, workload, managed_by);
    add_config_map(objects, namespace, workload, managed_by);
    add_secret(objects, namespace, workload, managed_by);
    if workload.storage {
        add_storage(objects, namespace, workload, managed_by);
    }
    add_role_and_binding(objects, namespace, workload, managed_by);
    add_deployment(objects, namespace, workload, replicas, managed_by, risky);
    add_replicaset(objects, namespace, workload, replicas);
    for index in 0..replicas {
        add_pod(objects, namespace, workload, index, managed_by, risky);
    }
    add_service(objects, namespace, workload, managed_by);
    if workload.public || namespace.environment == "stage" {
        add_ingress(objects, namespace, workload, managed_by);
    }
}

fn add_service_account(
    objects: &mut Vec<Value>,
    namespace: NamespaceProfile,
    workload: WorkloadProfile,
    managed_by: &str,
) {
    objects.push(json!({
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": metadata(namespace, workload, "sa", workload.name, managed_by)
    }));
}

fn add_config_map(
    objects: &mut Vec<Value>,
    namespace: NamespaceProfile,
    workload: WorkloadProfile,
    managed_by: &str,
) {
    objects.push(json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": metadata(namespace, workload, "cm", &format!("{}-config", workload.name), managed_by),
        "data": {
            "LOG_LEVEL": if namespace.environment == "prod" { "info" } else { "debug" },
            "FEATURE_FLAGS": "risk-ui,billing-v2"
        }
    }));
}

fn add_secret(
    objects: &mut Vec<Value>,
    namespace: NamespaceProfile,
    workload: WorkloadProfile,
    managed_by: &str,
) {
    objects.push(json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": metadata(namespace, workload, "secret", &format!("{}-runtime", workload.name), managed_by),
        "type": if workload.sensitive_config { "Opaque" } else { "kubernetes.io/basic-auth" },
        "data": {
            "DATABASE_URL": "cmVkYWN0ZWQ=",
            "API_TOKEN": "cmVkYWN0ZWQ="
        }
    }));
}

fn add_storage(
    objects: &mut Vec<Value>,
    namespace: NamespaceProfile,
    workload: WorkloadProfile,
    managed_by: &str,
) {
    let pvc = format!("{}-data", workload.name);
    let pv = format!("pv-{}-{}", namespace.name, workload.short);
    objects.push(json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": metadata(namespace, workload, "pvc", &pvc, managed_by),
        "spec": {
            "storageClassName": if namespace.environment == "prod" { "io2-retain" } else { "gp3-encrypted" },
            "volumeName": pv,
            "accessModes": ["ReadWriteOnce"],
            "resources": { "requests": { "storage": if workload.short == "ana" { "2Ti" } else { "200Gi" } } }
        },
        "status": { "phase": "Bound" }
    }));
    objects.push(json!({
        "apiVersion": "v1",
        "kind": "PersistentVolume",
        "metadata": {
            "name": pv,
            "uid": uid("pv", &pv),
            "labels": {
                "environment": namespace.environment,
                "team": workload.owner,
                "app": workload.name,
                "app.kubernetes.io/managed-by": managed_by
            }
        },
        "spec": {
            "storageClassName": if namespace.environment == "prod" { "io2-retain" } else { "gp3-encrypted" },
            "capacity": { "storage": if workload.short == "ana" { "2Ti" } else { "200Gi" } },
            "accessModes": ["ReadWriteOnce"]
        },
        "status": { "phase": "Bound" }
    }));
}

fn add_role_and_binding(
    objects: &mut Vec<Value>,
    namespace: NamespaceProfile,
    workload: WorkloadProfile,
    managed_by: &str,
) {
    let broad = namespace.name == "dev-apps" && workload.short == "ord";
    objects.push(json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": metadata(namespace, workload, "role", &format!("{}-runtime", workload.name), managed_by),
        "rules": if broad {
            json!([{ "apiGroups": ["*"], "resources": ["*"], "verbs": ["*"] }])
        } else {
            json!([{ "apiGroups": [""], "resources": ["configmaps", "secrets"], "verbs": ["get"] }])
        }
    }));
    objects.push(json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": metadata(namespace, workload, "rb", &format!("{}-runtime", workload.name), managed_by),
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": format!("{}-runtime", workload.name) },
        "subjects": [{ "kind": "ServiceAccount", "namespace": namespace.name, "name": workload.name }]
    }));
}

fn add_deployment(
    objects: &mut Vec<Value>,
    namespace: NamespaceProfile,
    workload: WorkloadProfile,
    replicas: usize,
    managed_by: &str,
    risky: bool,
) {
    objects.push(json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": metadata(namespace, workload, "deploy", workload.name, managed_by),
        "spec": {
            "replicas": replicas,
            "selector": { "matchLabels": selector(workload) },
            "template": {
                "metadata": { "labels": pod_labels(namespace, workload, managed_by) },
                "spec": pod_spec(namespace, workload, risky)
            }
        }
    }));
}

fn add_replicaset(
    objects: &mut Vec<Value>,
    namespace: NamespaceProfile,
    workload: WorkloadProfile,
    replicas: usize,
) {
    objects.push(json!({
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "namespace": namespace.name,
            "name": replicaset_name(workload),
            "uid": uid("rs", &format!("{}-{}", namespace.name, workload.short)),
            "labels": pod_labels(namespace, workload, "Helm"),
            "ownerReferences": [{
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "name": workload.name,
                "uid": uid("deploy", &format!("{}-{}", namespace.name, workload.name)),
                "controller": true
            }]
        },
        "spec": { "replicas": replicas, "selector": { "matchLabels": selector(workload) } }
    }));
}

fn add_pod(
    objects: &mut Vec<Value>,
    namespace: NamespaceProfile,
    workload: WorkloadProfile,
    index: usize,
    managed_by: &str,
    risky: bool,
) {
    let name = format!("{}-{}-{:02}", workload.name, workload.short, index + 1);
    let mut labels = pod_labels(namespace, workload, managed_by);
    labels["pod-template-hash"] = json!("demo");
    objects.push(json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "namespace": namespace.name,
            "name": name,
            "uid": uid("pod", &format!("{}-{name}", namespace.name)),
            "labels": labels,
            "ownerReferences": [{
                "apiVersion": "apps/v1",
                "kind": "ReplicaSet",
                "name": replicaset_name(workload),
                "uid": uid("rs", &format!("{}-{}", namespace.name, workload.short)),
                "controller": true
            }]
        },
        "spec": pod_spec(namespace, workload, risky),
        "status": { "phase": "Running" }
    }));
}

fn add_service(
    objects: &mut Vec<Value>,
    namespace: NamespaceProfile,
    workload: WorkloadProfile,
    managed_by: &str,
) {
    let public_lb = workload.public && namespace.environment == "prod";
    objects.push(json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": metadata(namespace, workload, "svc", workload.name, managed_by),
        "spec": {
            "type": if public_lb { "LoadBalancer" } else { "ClusterIP" },
            "selector": selector(workload),
            "ports": [{ "name": "http", "port": if public_lb { 443 } else { workload.port }, "targetPort": workload.port }],
            "externalTrafficPolicy": if public_lb { "Local" } else { "Cluster" }
        },
        "status": {
            "loadBalancer": if public_lb { json!({ "ingress": [{ "hostname": format!("{}-{}.elb.amazonaws.com", workload.short, namespace.name) }] }) } else { json!({}) }
        }
    }));
}

fn add_ingress(
    objects: &mut Vec<Value>,
    namespace: NamespaceProfile,
    workload: WorkloadProfile,
    managed_by: &str,
) {
    objects.push(json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": metadata(namespace, workload, "ing", workload.name, managed_by),
        "spec": {
            "ingressClassName": if namespace.environment == "prod" { "internet" } else { "internal" },
            "rules": [{
                "host": format!("{}-{}.demo.example.com", workload.short, namespace.environment),
                "http": { "paths": [{
                    "path": "/",
                    "pathType": "Prefix",
                    "backend": { "service": { "name": workload.name, "port": { "number": if workload.public { 443 } else { workload.port } } } }
                }] }
            }]
        }
    }));
}

fn add_observability_stack(objects: &mut Vec<Value>) {
    let namespace = *NAMESPACES
        .iter()
        .find(|namespace| namespace.name == "observability")
        .unwrap();
    let workload = WorkloadProfile {
        name: "otel-collector",
        short: "otel",
        owner: "sre",
        port: 4317,
        public: false,
        storage: false,
        sensitive_config: false,
    };
    add_workload_stack(objects, namespace, workload);
}

fn add_security_stack(objects: &mut Vec<Value>) {
    let namespace = *NAMESPACES
        .iter()
        .find(|namespace| namespace.name == "security")
        .unwrap();
    add_service_account(
        objects,
        namespace,
        WorkloadProfile {
            name: "incident-response",
            short: "ir",
            owner: "security",
            port: 9443,
            public: false,
            storage: false,
            sensitive_config: true,
        },
        "Terraform",
    );
}

fn add_legacy_stack(objects: &mut Vec<Value>) {
    let namespace = *NAMESPACES
        .iter()
        .find(|namespace| namespace.name == "legacy-admin")
        .unwrap();
    let workload = WorkloadProfile {
        name: "breakglass-console",
        short: "legacy",
        owner: "corporate-it",
        port: 8443,
        public: true,
        storage: true,
        sensitive_config: true,
    };
    add_workload_stack(objects, namespace, workload);
    objects.push(json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "namespace": namespace.name,
            "name": "default-token-legacy",
            "uid": "secret-default-token-legacy"
        },
        "type": "kubernetes.io/service-account-token",
        "data": { "token": "cmVkYWN0ZWQ=" }
    }));
}

fn metadata(
    namespace: NamespaceProfile,
    workload: WorkloadProfile,
    prefix: &str,
    name: &str,
    managed_by: &str,
) -> Value {
    json!({
        "namespace": namespace.name,
        "name": name,
        "uid": uid(prefix, &format!("{}-{name}", namespace.name)),
        "labels": {
            "app": workload.name,
            "app.kubernetes.io/name": workload.name,
            "app.kubernetes.io/part-of": workload.owner,
            "app.kubernetes.io/managed-by": managed_by,
            "environment": namespace.environment,
            "team": workload.owner
        },
        "annotations": if managed_by == "Helm" {
            json!({ "meta.helm.sh/release-name": workload.name, "meta.helm.sh/release-namespace": namespace.name })
        } else {
            json!({})
        }
    })
}

fn pod_spec(namespace: NamespaceProfile, workload: WorkloadProfile, risky: bool) -> Value {
    let mut volumes = vec![
        json!({ "name": "config", "configMap": { "name": format!("{}-config", workload.name) } }),
        json!({ "name": "runtime-secret", "secret": { "secretName": format!("{}-runtime", workload.name) } }),
    ];
    if workload.storage {
        volumes.push(json!({ "name": "data", "persistentVolumeClaim": { "claimName": format!("{}-data", workload.name) } }));
    }
    if risky {
        volumes.push(json!({ "name": "host-docker", "hostPath": { "path": "/var/run/docker.sock", "type": "Socket" } }));
    }

    json!({
        "serviceAccountName": if risky { "default" } else { workload.name },
        "hostNetwork": risky && namespace.name == "legacy-admin",
        "hostPID": risky,
        "containers": [{
            "name": workload.short,
            "image": format!("registry.example.com/{}/{}:2026.05.16", namespace.environment, workload.name),
            "ports": [{ "containerPort": workload.port }],
            "envFrom": [
                { "configMapRef": { "name": format!("{}-config", workload.name) } },
                { "secretRef": { "name": format!("{}-runtime", workload.name) } }
            ],
            "securityContext": {
                "privileged": risky,
                "allowPrivilegeEscalation": risky,
                "readOnlyRootFilesystem": !risky
            },
            "resources": {
                "requests": { "cpu": "250m", "memory": "256Mi" },
                "limits": { "cpu": "1", "memory": "1Gi" }
            }
        }],
        "volumes": volumes
    })
}

fn pod_labels(namespace: NamespaceProfile, workload: WorkloadProfile, managed_by: &str) -> Value {
    json!({
        "app": workload.name,
        "app.kubernetes.io/name": workload.name,
        "app.kubernetes.io/part-of": workload.owner,
        "app.kubernetes.io/managed-by": managed_by,
        "environment": namespace.environment,
        "team": workload.owner
    })
}

fn selector(workload: WorkloadProfile) -> Value {
    json!({ "app": workload.name })
}

fn replicas_for(namespace: NamespaceProfile, workload: WorkloadProfile) -> usize {
    match namespace.environment {
        "prod" if workload.short == "edge" => 4,
        "prod" => 3,
        "stage" => 2,
        _ => 1,
    }
}

fn replicaset_name(workload: WorkloadProfile) -> String {
    format!("{}-7c9d88f7d9", workload.name)
}

fn uid(prefix: &str, value: &str) -> String {
    format!("{prefix}-{}", value.replace(['/', '_', ' '], "-"))
}

fn fixed_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 16, 0, 0, 0)
        .single()
        .expect("demo timestamp is valid")
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn writes_advanced_k8s_demo_bundle() {
        let temp = tempdir().unwrap();
        let summary = write_k8s_demo_bundle(temp.path(), false).unwrap();

        assert!(summary.db_path.exists());
        assert!(summary.findings_path.exists());
        assert_eq!(summary.resources, 430);
        assert_eq!(summary.relationships, 567);
        assert_eq!(summary.findings, 69);

        let connection = Connection::open(summary.db_path).unwrap();
        let resource_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM resources", [], |row| row.get(0))
            .unwrap();
        let relationship_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM relationships", [], |row| row.get(0))
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

        assert_eq!(resource_count, summary.resources as i64);
        assert_eq!(relationship_count, summary.relationships as i64);
        assert_eq!(critical_count, 10);
        assert_eq!(high_count, 36);
    }

    #[test]
    fn k8s_demo_redacts_secret_and_configmap_raw() {
        let output = k8s_demo_output();

        assert!(output.inventory.resources.iter().any(|resource| {
            matches!(resource.resource_type.as_str(), "secret" | "configmap")
                && resource.raw.is_none()
                && resource.attributes["redacted"] == true
        }));
        assert!(output.findings.iter().any(|finding| {
            finding.finding_type == "cluster_admin_binding"
                && finding.resource_uid.contains("legacy-admin-default")
        }));
    }
}
