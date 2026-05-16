use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use rusqlite::params;
use serde::Serialize;
use serde_json::{Value, json};

use crate::db::open_cloudmapper_db;
use crate::model::{
    Evidence, GENERATOR_NAME, Generator, Inventory, Relationship, Resource, SCHEMA_VERSION,
    ScanError, provider_resource_uid, relationship_uid,
};

#[derive(Clone, Debug)]
pub struct K8sScanOptions {
    pub context: Option<String>,
    pub kubeconfig: Option<PathBuf>,
    pub namespace: String,
    pub kubectl: PathBuf,
    pub include_raw: bool,
}

#[derive(Debug)]
pub struct K8sScanOutput {
    pub inventory: Inventory,
    pub findings: Vec<K8sFinding>,
}

#[derive(Clone, Debug, Serialize)]
pub struct K8sFinding {
    pub id: String,
    pub finding_type: String,
    pub severity: &'static str,
    pub resource_uid: String,
    pub reason: String,
    pub recommended_action: String,
    pub blast_radius: Vec<String>,
    pub evidence: Vec<Value>,
    pub attributes: Value,
}

#[derive(Clone, Copy)]
struct K8sTarget {
    name: &'static str,
    namespaced: bool,
    operation: &'static str,
}

#[derive(Clone)]
struct K8sObject {
    value: Value,
    api_version: String,
    kind: String,
    namespace: Option<String>,
    name: String,
    kube_uid: Option<String>,
    cloud_uid: String,
    service: String,
    resource_type: String,
    labels: BTreeMap<String, String>,
    annotations: BTreeMap<String, String>,
}

const CLUSTER_REGION: &str = "cluster";

const TARGETS: &[K8sTarget] = &[
    K8sTarget {
        name: "namespaces",
        namespaced: false,
        operation: "get namespaces",
    },
    K8sTarget {
        name: "nodes",
        namespaced: false,
        operation: "get nodes",
    },
    K8sTarget {
        name: "deployments.apps",
        namespaced: true,
        operation: "get deployments.apps",
    },
    K8sTarget {
        name: "daemonsets.apps",
        namespaced: true,
        operation: "get daemonsets.apps",
    },
    K8sTarget {
        name: "statefulsets.apps",
        namespaced: true,
        operation: "get statefulsets.apps",
    },
    K8sTarget {
        name: "replicasets.apps",
        namespaced: true,
        operation: "get replicasets.apps",
    },
    K8sTarget {
        name: "pods",
        namespaced: true,
        operation: "get pods",
    },
    K8sTarget {
        name: "services",
        namespaced: true,
        operation: "get services",
    },
    K8sTarget {
        name: "ingresses.networking.k8s.io",
        namespaced: true,
        operation: "get ingresses.networking.k8s.io",
    },
    K8sTarget {
        name: "networkpolicies.networking.k8s.io",
        namespaced: true,
        operation: "get networkpolicies.networking.k8s.io",
    },
    K8sTarget {
        name: "serviceaccounts",
        namespaced: true,
        operation: "get serviceaccounts",
    },
    K8sTarget {
        name: "roles.rbac.authorization.k8s.io",
        namespaced: true,
        operation: "get roles.rbac.authorization.k8s.io",
    },
    K8sTarget {
        name: "rolebindings.rbac.authorization.k8s.io",
        namespaced: true,
        operation: "get rolebindings.rbac.authorization.k8s.io",
    },
    K8sTarget {
        name: "clusterroles.rbac.authorization.k8s.io",
        namespaced: false,
        operation: "get clusterroles.rbac.authorization.k8s.io",
    },
    K8sTarget {
        name: "clusterrolebindings.rbac.authorization.k8s.io",
        namespaced: false,
        operation: "get clusterrolebindings.rbac.authorization.k8s.io",
    },
    K8sTarget {
        name: "secrets",
        namespaced: true,
        operation: "get secrets",
    },
    K8sTarget {
        name: "configmaps",
        namespaced: true,
        operation: "get configmaps",
    },
    K8sTarget {
        name: "persistentvolumeclaims",
        namespaced: true,
        operation: "get persistentvolumeclaims",
    },
    K8sTarget {
        name: "persistentvolumes",
        namespaced: false,
        operation: "get persistentvolumes",
    },
    K8sTarget {
        name: "storageclasses.storage.k8s.io",
        namespaced: false,
        operation: "get storageclasses.storage.k8s.io",
    },
];

pub fn scan_cluster(options: K8sScanOptions) -> Result<K8sScanOutput> {
    let collected_at = Utc::now();
    let cluster_id = cluster_id(&options);
    let mut objects = Vec::new();
    let mut errors = Vec::new();

    for target in TARGETS {
        match kubectl_get(&options, *target) {
            Ok(value) => objects.extend(list_items(value)),
            Err(error) => errors.push(ScanError {
                service: "kubernetes".to_string(),
                region: if target.namespaced {
                    options.namespace.clone()
                } else {
                    CLUSTER_REGION.to_string()
                },
                operation: target.operation.to_string(),
                message: error.to_string(),
            }),
        }
    }

    Ok(build_scan_output(
        &cluster_id,
        collected_at,
        options.include_raw,
        objects,
        errors,
    ))
}

pub fn write_k8s_findings(
    db_path: &Path,
    scan_id: &str,
    findings: &[K8sFinding],
) -> Result<String> {
    let connection = open_cloudmapper_db(db_path)?;
    let run_id = format!("k8s:{scan_id}");
    let generated_at = Utc::now().to_rfc3339();
    connection.execute("DELETE FROM findings WHERE run_id = ?1", params![run_id])?;
    let mut statement = connection.prepare(
        r#"
        INSERT INTO findings (
          run_id, id, finding_type, severity, aws_uid, terraform_address, reason,
          recommended_action, blast_radius_json, evidence_json, attributes_json, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
    )?;
    for finding in findings {
        statement.execute(params![
            run_id,
            finding.id,
            finding.finding_type,
            finding.severity,
            finding.resource_uid,
            finding.reason,
            finding.recommended_action,
            serde_json::to_string(&finding.blast_radius)?,
            serde_json::to_string(&finding.evidence)?,
            serde_json::to_string(&finding.attributes)?,
            generated_at,
        ])?;
    }
    Ok(run_id)
}

fn kubectl_get(options: &K8sScanOptions, target: K8sTarget) -> Result<Value> {
    let mut command = kubectl_command(options);
    command.arg("get").arg(target.name);
    if target.namespaced {
        if options.namespace == "all" {
            command.arg("--all-namespaces");
        } else {
            command.arg("--namespace").arg(&options.namespace);
        }
    }
    command.arg("-o").arg("json");
    let output = command
        .output()
        .with_context(|| format!("running {}", command_line(&command)))?;
    if !output.status.success() {
        bail!(
            "{} failed: {}",
            command_line(&command),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout).with_context(|| format!("parsing {}", target.operation))
}

fn kubectl_command(options: &K8sScanOptions) -> Command {
    let mut command = Command::new(&options.kubectl);
    if let Some(kubeconfig) = &options.kubeconfig {
        command.arg("--kubeconfig").arg(kubeconfig);
    }
    if let Some(context) = &options.context {
        command.arg("--context").arg(context);
    }
    command
}

fn cluster_id(options: &K8sScanOptions) -> String {
    if let Some(context) = &options.context {
        return sanitize_cluster_id(context);
    }

    let mut command = Command::new(&options.kubectl);
    if let Some(kubeconfig) = &options.kubeconfig {
        command.arg("--kubeconfig").arg(kubeconfig);
    }
    command.arg("config").arg("current-context");
    command
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|context| sanitize_cluster_id(context.trim()))
        .filter(|context| !context.is_empty())
        .unwrap_or_else(|| "kubernetes".to_string())
}

fn command_line(command: &Command) -> String {
    let program = command.get_program().to_string_lossy();
    let args = command
        .get_args()
        .map(|arg| arg.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    if args.is_empty() {
        program.to_string()
    } else {
        format!("{program} {args}")
    }
}

fn list_items(value: Value) -> Vec<Value> {
    if value.get("kind").and_then(Value::as_str) == Some("List") {
        return value
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
    }
    if value.get("kind").and_then(Value::as_str).is_some() {
        return vec![value];
    }
    Vec::new()
}

pub(crate) fn build_scan_output(
    cluster_id: &str,
    collected_at: DateTime<Utc>,
    include_raw: bool,
    values: Vec<Value>,
    errors: Vec<ScanError>,
) -> K8sScanOutput {
    let objects = values
        .into_iter()
        .filter_map(|value| K8sObject::from_value(cluster_id, value))
        .collect::<Vec<_>>();
    let indexes = K8sIndexes::new(&objects);

    let resources = objects
        .iter()
        .map(|object| object.resource(cluster_id, collected_at, include_raw))
        .collect::<Vec<_>>();
    let relationships = build_relationships(&objects, &indexes, collected_at);
    let findings = build_findings(&objects, &indexes);
    let regions = objects
        .iter()
        .filter_map(|object| object.namespace.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    K8sScanOutput {
        inventory: Inventory {
            schema_version: SCHEMA_VERSION.to_string(),
            generator: Generator {
                name: GENERATOR_NAME.to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            account_id: cluster_id.to_string(),
            partition: "kubernetes".to_string(),
            home_region: CLUSTER_REGION.to_string(),
            regions,
            collected_at,
            resources,
            relationships,
            errors,
        },
        findings,
    }
}

struct K8sIndexes {
    by_kube_uid: BTreeMap<String, String>,
    by_key: BTreeMap<(String, String, String), String>,
    objects_by_cloud_uid: BTreeMap<String, K8sObject>,
}

impl K8sIndexes {
    fn new(objects: &[K8sObject]) -> Self {
        let mut by_kube_uid = BTreeMap::new();
        let mut by_key = BTreeMap::new();
        let mut objects_by_cloud_uid = BTreeMap::new();
        for object in objects {
            if let Some(kube_uid) = &object.kube_uid {
                by_kube_uid.insert(kube_uid.clone(), object.cloud_uid.clone());
            }
            by_key.insert(
                key(&object.kind, object.namespace.as_deref(), &object.name),
                object.cloud_uid.clone(),
            );
            objects_by_cloud_uid.insert(object.cloud_uid.clone(), object.clone());
        }
        Self {
            by_kube_uid,
            by_key,
            objects_by_cloud_uid,
        }
    }

    fn lookup(&self, kind: &str, namespace: Option<&str>, name: &str) -> Option<String> {
        self.by_key.get(&key(kind, namespace, name)).cloned()
    }

    fn lookup_owner(&self, owner: &Value, namespace: Option<&str>) -> Option<String> {
        owner
            .get("uid")
            .and_then(Value::as_str)
            .and_then(|uid| self.by_kube_uid.get(uid).cloned())
            .or_else(|| {
                let kind = owner.get("kind").and_then(Value::as_str)?;
                let name = owner.get("name").and_then(Value::as_str)?;
                self.lookup(kind, namespace, name)
            })
    }
}

impl K8sObject {
    fn from_value(cluster_id: &str, value: Value) -> Option<Self> {
        let kind = str_field(&value, "kind")?.to_string();
        let api_version = str_field(&value, "apiVersion").unwrap_or("v1").to_string();
        let name = pointer_str(&value, "/metadata/name")?.to_string();
        let namespace = pointer_str(&value, "/metadata/namespace").map(ToString::to_string);
        let region = namespace.as_deref().unwrap_or(CLUSTER_REGION);
        let resource_type = resource_type_for(&kind);
        let service = service_for(&api_version, &kind);
        let id = object_id(namespace.as_deref(), &name);
        let cloud_uid =
            provider_resource_uid("k8s", cluster_id, region, &service, &resource_type, &id);

        Some(Self {
            value,
            api_version,
            kind,
            namespace,
            name,
            kube_uid: None,
            cloud_uid,
            service,
            resource_type,
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
        })
        .map(|mut object| {
            object.kube_uid = pointer_str(&object.value, "/metadata/uid").map(ToString::to_string);
            object.labels = string_map(object.value.pointer("/metadata/labels"));
            object.annotations = string_map(object.value.pointer("/metadata/annotations"));
            object
        })
    }

    fn resource(
        &self,
        cluster_id: &str,
        collected_at: DateTime<Utc>,
        include_raw: bool,
    ) -> Resource {
        Resource {
            uid: self.cloud_uid.clone(),
            provider: "k8s".to_string(),
            account_id: cluster_id.to_string(),
            partition: "kubernetes".to_string(),
            region: self
                .namespace
                .clone()
                .unwrap_or_else(|| CLUSTER_REGION.to_string()),
            service: self.service.clone(),
            resource_type: self.resource_type.clone(),
            id: object_id(self.namespace.as_deref(), &self.name),
            arn: None,
            name: Some(self.name.clone()),
            tags: tags_for(self),
            attributes: attributes_for(self),
            evidence: vec![evidence(
                collected_at,
                "get",
                &self.kind,
                self.namespace.as_deref(),
            )],
            raw: raw_for(self, include_raw),
        }
    }

    fn pod_spec(&self) -> Option<&Value> {
        if self.kind == "Pod" {
            return self.value.get("spec");
        }
        if matches!(
            self.kind.as_str(),
            "Deployment" | "DaemonSet" | "StatefulSet" | "ReplicaSet"
        ) {
            return self.value.pointer("/spec/template/spec");
        }
        None
    }

    fn owner_references(&self) -> &[Value] {
        self.value
            .pointer("/metadata/ownerReferences")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

fn build_relationships(
    objects: &[K8sObject],
    indexes: &K8sIndexes,
    collected_at: DateTime<Utc>,
) -> Vec<Relationship> {
    let mut relationships = BTreeMap::new();
    let mut replica_set_to_deployment = BTreeMap::new();

    for object in objects {
        for owner in object.owner_references() {
            if let Some(owner_uid) = indexes.lookup_owner(owner, object.namespace.as_deref()) {
                add_relationship(
                    &mut relationships,
                    &owner_uid,
                    "owns",
                    &object.cloud_uid,
                    relationship_evidence(collected_at),
                    json!({
                        "owner_kind": owner.get("kind").and_then(Value::as_str),
                        "owner_name": owner.get("name").and_then(Value::as_str),
                    }),
                );
                if object.kind == "ReplicaSet"
                    && owner.get("kind").and_then(Value::as_str) == Some("Deployment")
                {
                    replica_set_to_deployment.insert(object.cloud_uid.clone(), owner_uid);
                }
            }
        }
    }

    for object in objects {
        match object.kind.as_str() {
            "Pod" => {
                add_pod_relationships(
                    &mut relationships,
                    object,
                    indexes,
                    &replica_set_to_deployment,
                    collected_at,
                );
            }
            "Service" => {
                add_service_relationships(&mut relationships, object, objects, collected_at)
            }
            "Ingress" => {
                add_ingress_relationships(&mut relationships, object, indexes, collected_at)
            }
            "RoleBinding" | "ClusterRoleBinding" => {
                add_rbac_binding_relationships(&mut relationships, object, indexes, collected_at);
            }
            "PersistentVolumeClaim" => {
                add_pvc_relationships(&mut relationships, object, indexes, collected_at);
            }
            _ => {}
        }
    }

    relationships.into_values().collect()
}

fn add_pod_relationships(
    relationships: &mut BTreeMap<String, Relationship>,
    pod: &K8sObject,
    indexes: &K8sIndexes,
    replica_set_to_deployment: &BTreeMap<String, String>,
    collected_at: DateTime<Utc>,
) {
    let namespace = pod.namespace.as_deref();
    let service_account = pod
        .value
        .pointer("/spec/serviceAccountName")
        .and_then(Value::as_str)
        .unwrap_or("default");
    if let Some(service_account_uid) = indexes.lookup("ServiceAccount", namespace, service_account)
    {
        add_relationship(
            relationships,
            &pod.cloud_uid,
            "uses_service_account",
            &service_account_uid,
            relationship_evidence(collected_at),
            Value::Null,
        );
    }

    for owner in pod.owner_references() {
        if owner.get("kind").and_then(Value::as_str) != Some("ReplicaSet") {
            continue;
        }
        if let Some(replica_set_uid) = indexes.lookup_owner(owner, namespace)
            && let Some(deployment_uid) = replica_set_to_deployment.get(&replica_set_uid)
        {
            add_relationship(
                relationships,
                deployment_uid,
                "owns",
                &pod.cloud_uid,
                relationship_evidence(collected_at),
                json!({ "through": replica_set_uid }),
            );
        }
    }

    for reference in pod_volume_references(pod) {
        if let Some(target_uid) = indexes.lookup(reference.kind, namespace, &reference.name) {
            add_relationship(
                relationships,
                &pod.cloud_uid,
                reference.relationship_type,
                &target_uid,
                relationship_evidence(collected_at),
                json!({ "source": reference.source }),
            );
        }
    }
}

fn add_service_relationships(
    relationships: &mut BTreeMap<String, Relationship>,
    service: &K8sObject,
    objects: &[K8sObject],
    collected_at: DateTime<Utc>,
) {
    let selector = service
        .value
        .pointer("/spec/selector")
        .and_then(Value::as_object);
    let Some(selector) = selector else {
        return;
    };
    if selector.is_empty() {
        return;
    }
    for pod in objects
        .iter()
        .filter(|object| object.kind == "Pod" && object.namespace == service.namespace)
    {
        if selector_matches(selector, &pod.labels) {
            add_relationship(
                relationships,
                &service.cloud_uid,
                "selects",
                &pod.cloud_uid,
                relationship_evidence(collected_at),
                json!({ "selector": selector }),
            );
        }
    }
}

fn add_ingress_relationships(
    relationships: &mut BTreeMap<String, Relationship>,
    ingress: &K8sObject,
    indexes: &K8sIndexes,
    collected_at: DateTime<Utc>,
) {
    for service_name in ingress_backend_services(&ingress.value) {
        if let Some(service_uid) =
            indexes.lookup("Service", ingress.namespace.as_deref(), &service_name)
        {
            add_relationship(
                relationships,
                &ingress.cloud_uid,
                "routes_to",
                &service_uid,
                relationship_evidence(collected_at),
                Value::Null,
            );
        }
    }
}

fn add_rbac_binding_relationships(
    relationships: &mut BTreeMap<String, Relationship>,
    binding: &K8sObject,
    indexes: &K8sIndexes,
    collected_at: DateTime<Utc>,
) {
    if let Some(role_ref) = binding.value.get("roleRef") {
        let role_kind = role_ref
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let role_name = role_ref
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let role_namespace = if role_kind == "Role" {
            binding.namespace.as_deref()
        } else {
            None
        };
        if let Some(role_uid) = indexes.lookup(role_kind, role_namespace, role_name) {
            add_relationship(
                relationships,
                &binding.cloud_uid,
                "grants_role",
                &role_uid,
                relationship_evidence(collected_at),
                Value::Null,
            );
        }
    }

    for subject in binding
        .value
        .get("subjects")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        if subject.get("kind").and_then(Value::as_str) != Some("ServiceAccount") {
            continue;
        }
        let Some(name) = subject.get("name").and_then(Value::as_str) else {
            continue;
        };
        let namespace = subject
            .get("namespace")
            .and_then(Value::as_str)
            .or(binding.namespace.as_deref());
        if let Some(subject_uid) = indexes.lookup("ServiceAccount", namespace, name) {
            add_relationship(
                relationships,
                &binding.cloud_uid,
                "grants_to",
                &subject_uid,
                relationship_evidence(collected_at),
                Value::Null,
            );
        }
    }
}

fn add_pvc_relationships(
    relationships: &mut BTreeMap<String, Relationship>,
    pvc: &K8sObject,
    indexes: &K8sIndexes,
    collected_at: DateTime<Utc>,
) {
    let Some(volume_name) = pvc
        .value
        .pointer("/spec/volumeName")
        .and_then(Value::as_str)
    else {
        return;
    };
    if let Some(pv_uid) = indexes.lookup("PersistentVolume", None, volume_name) {
        add_relationship(
            relationships,
            &pvc.cloud_uid,
            "binds",
            &pv_uid,
            relationship_evidence(collected_at),
            Value::Null,
        );
    }
}

fn add_relationship(
    relationships: &mut BTreeMap<String, Relationship>,
    from: &str,
    relationship_type: &str,
    to: &str,
    evidence: Evidence,
    attributes: Value,
) {
    let uid = relationship_uid(from, relationship_type, to);
    relationships.entry(uid.clone()).or_insert(Relationship {
        uid,
        from: from.to_string(),
        to: to.to_string(),
        relationship_type: relationship_type.to_string(),
        attributes,
        evidence: vec![evidence],
    });
}

fn build_findings(objects: &[K8sObject], indexes: &K8sIndexes) -> Vec<K8sFinding> {
    let mut findings = Vec::new();
    let network_policy_namespaces = objects
        .iter()
        .filter(|object| object.kind == "NetworkPolicy")
        .filter_map(|object| object.namespace.clone())
        .collect::<BTreeSet<_>>();
    let pod_namespaces = objects
        .iter()
        .filter(|object| object.kind == "Pod")
        .filter_map(|object| object.namespace.clone())
        .collect::<BTreeSet<_>>();

    for object in objects {
        if let Some(spec) = object.pod_spec() {
            findings.extend(pod_spec_findings(object, spec));
        }
        match object.kind.as_str() {
            "Service" => service_findings(object, objects, &mut findings),
            "Ingress" => findings.push(finding(
                "public_ingress",
                "high",
                object,
                format!("Ingress {} can expose cluster workloads externally.", object_label(object)),
                "Review ingress class, hosts, and upstream services; restrict public exposure if not intended.",
                json!({ "rules": ingress_rules(&object.value) }),
                Vec::new(),
            )),
            "Role" | "ClusterRole" => rbac_role_findings(object, &mut findings),
            "RoleBinding" | "ClusterRoleBinding" => {
                rbac_binding_findings(object, indexes, &mut findings);
            }
            "Secret" => secret_findings(object, &mut findings),
            _ => {}
        }
        if is_unmanaged_candidate(object) && !has_iac_manager(object) {
            findings.push(finding(
                "unmanaged_kubernetes_resource",
                "medium",
                object,
                format!(
                    "{} has no Helm, Kustomize, Terraform, or GitOps ownership metadata.",
                    object_label(object)
                ),
                "Add ownership labels/annotations or reconcile this resource into the intended deployment system.",
                json!({
                    "labels": object.labels,
                    "annotations": annotation_keys(object),
                }),
                Vec::new(),
            ));
        }
    }

    for namespace in pod_namespaces {
        if system_namespace(&namespace) || network_policy_namespaces.contains(&namespace) {
            continue;
        }
        if let Some(namespace_uid) = indexes.lookup("Namespace", None, &namespace)
            && let Some(namespace_object) = indexes.objects_by_cloud_uid.get(&namespace_uid)
        {
            findings.push(finding(
                "missing_network_policy",
                "medium",
                namespace_object,
                format!("Namespace {namespace} has pods but no NetworkPolicy resources."),
                "Add default-deny and workload-specific NetworkPolicy resources for this namespace.",
                json!({ "namespace": namespace }),
                Vec::new(),
            ));
        }
    }

    findings.sort_by_key(|finding| {
        (
            severity_sort_rank(finding.severity),
            finding.finding_type.clone(),
            finding.resource_uid.clone(),
        )
    });
    findings
}

fn pod_spec_findings(object: &K8sObject, spec: &Value) -> Vec<K8sFinding> {
    let mut findings = Vec::new();
    let privileged = privileged_containers(spec);
    if !privileged.is_empty() {
        findings.push(finding(
            "privileged_container",
            "critical",
            object,
            format!("{} runs privileged containers.", object_label(object)),
            "Remove privileged mode or isolate this workload onto a hardened node pool with a documented exception.",
            json!({ "containers": privileged }),
            Vec::new(),
        ));
    }

    let host_paths = host_path_volumes(spec);
    if !host_paths.is_empty() {
        findings.push(finding(
            "host_path_mount",
            "high",
            object,
            format!("{} mounts hostPath volumes.", object_label(object)),
            "Replace hostPath mounts with scoped PersistentVolumes or remove host filesystem access.",
            json!({ "volumes": host_paths }),
            Vec::new(),
        ));
    }

    let host_namespaces = host_namespace_flags(spec);
    if !host_namespaces.is_empty() {
        findings.push(finding(
            "host_namespace_enabled",
            "high",
            object,
            format!("{} enables host namespace access.", object_label(object)),
            "Disable hostNetwork, hostPID, and hostIPC unless the workload is a tightly controlled system daemon.",
            json!({ "enabled": host_namespaces }),
            Vec::new(),
        ));
    }

    let service_account = spec
        .get("serviceAccountName")
        .and_then(Value::as_str)
        .unwrap_or("default");
    if service_account == "default" && !system_namespace_opt(object.namespace.as_deref()) {
        findings.push(finding(
            "default_service_account_used",
            "medium",
            object,
            format!("{} uses the default service account.", object_label(object)),
            "Create a workload-specific service account with only the RBAC permissions this workload needs.",
            json!({ "service_account": service_account }),
            Vec::new(),
        ));
    }

    findings
}

fn service_findings(object: &K8sObject, objects: &[K8sObject], findings: &mut Vec<K8sFinding>) {
    let service_type = object
        .value
        .pointer("/spec/type")
        .and_then(Value::as_str)
        .unwrap_or("ClusterIP");
    if !matches!(service_type, "LoadBalancer" | "NodePort") {
        return;
    }
    let selector = object
        .value
        .pointer("/spec/selector")
        .and_then(Value::as_object);
    let blast_radius = selector
        .map(|selector| {
            objects
                .iter()
                .filter(|candidate| {
                    candidate.kind == "Pod"
                        && candidate.namespace == object.namespace
                        && selector_matches(selector, &candidate.labels)
                })
                .map(|pod| pod.cloud_uid.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    findings.push(finding(
        "public_service",
        if service_type == "LoadBalancer" {
            "high"
        } else {
            "medium"
        },
        object,
        format!("Service {} is type {service_type}.", object_label(object)),
        "Confirm the service is intentionally reachable outside the cluster and restrict source ranges where supported.",
        json!({
            "type": service_type,
            "ports": object.value.pointer("/spec/ports").cloned().unwrap_or(Value::Null),
        }),
        blast_radius,
    ));
}

fn rbac_role_findings(object: &K8sObject, findings: &mut Vec<K8sFinding>) {
    let Some(rules) = object.value.get("rules").and_then(Value::as_array) else {
        return;
    };
    let wildcard_rules = rules
        .iter()
        .filter(rule_is_overbroad)
        .cloned()
        .collect::<Vec<_>>();
    if wildcard_rules.is_empty() {
        return;
    }
    let critical = wildcard_rules.iter().any(rule_is_cluster_admin_like);
    findings.push(finding(
        "overbroad_rbac",
        if critical { "critical" } else { "high" },
        object,
        format!("{} grants wildcard RBAC permissions.", object_label(object)),
        "Replace wildcard verbs/resources with the minimum API groups, resources, verbs, and resource names required.",
        json!({ "rules": wildcard_rules }),
        Vec::new(),
    ));
}

fn rbac_binding_findings(object: &K8sObject, indexes: &K8sIndexes, findings: &mut Vec<K8sFinding>) {
    let role_name = object
        .value
        .pointer("/roleRef/name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if role_name != "cluster-admin" {
        return;
    }
    let blast_radius = object
        .value
        .get("subjects")
        .and_then(Value::as_array)
        .map(|subjects| {
            subjects
                .iter()
                .filter_map(|subject| {
                    if subject.get("kind").and_then(Value::as_str) != Some("ServiceAccount") {
                        return None;
                    }
                    let name = subject.get("name").and_then(Value::as_str)?;
                    let namespace = subject
                        .get("namespace")
                        .and_then(Value::as_str)
                        .or(object.namespace.as_deref());
                    indexes.lookup("ServiceAccount", namespace, name)
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    findings.push(finding(
        "cluster_admin_binding",
        "critical",
        object,
        format!("{} binds subjects to cluster-admin.", object_label(object)),
        "Remove cluster-admin from workload identities and bind narrow roles to explicit service accounts.",
        json!({
            "role_ref": object.value.get("roleRef").cloned().unwrap_or(Value::Null),
            "subjects": object.value.get("subjects").cloned().unwrap_or(Value::Null),
        }),
        blast_radius,
    ));
}

fn secret_findings(object: &K8sObject, findings: &mut Vec<K8sFinding>) {
    let secret_type = object
        .value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("Opaque");
    if secret_type != "kubernetes.io/service-account-token" {
        return;
    }
    findings.push(finding(
        "legacy_service_account_token_secret",
        "medium",
        object,
        format!("{} is a persisted service-account token Secret.", object_label(object)),
        "Prefer projected bound service-account tokens and verify Secret encryption at rest and RBAC access.",
        json!({ "type": secret_type }),
        Vec::new(),
    ));
}

fn finding(
    finding_type: &str,
    severity: &'static str,
    object: &K8sObject,
    reason: String,
    recommended_action: &str,
    attributes: Value,
    blast_radius: Vec<String>,
) -> K8sFinding {
    K8sFinding {
        id: format!(
            "{finding_type}:{}",
            object.cloud_uid.replace([' ', '\n', '\t', '/', ':'], "_")
        ),
        finding_type: finding_type.to_string(),
        severity,
        resource_uid: object.cloud_uid.clone(),
        reason,
        recommended_action: recommended_action.to_string(),
        blast_radius,
        evidence: vec![json!({
            "service": "kubernetes",
            "operation": "get",
            "kind": object.kind,
            "namespace": object.namespace,
            "name": object.name,
        })],
        attributes,
    }
}

fn attributes_for(object: &K8sObject) -> Value {
    let base = json!({
        "api_version": object.api_version,
        "kind": object.kind,
        "namespace": object.namespace,
        "owner_references": object.owner_references(),
        "labels": object.labels,
        "annotation_keys": annotation_keys(object),
    });
    match object.kind.as_str() {
        "Pod" => merge_json(base, pod_attributes(object.value.get("spec"))),
        "Deployment" | "DaemonSet" | "StatefulSet" | "ReplicaSet" => {
            merge_json(base, workload_attributes(object))
        }
        "Service" => merge_json(
            base,
            json!({
                "type": object.value.pointer("/spec/type").and_then(Value::as_str).unwrap_or("ClusterIP"),
                "selector": object.value.pointer("/spec/selector").cloned().unwrap_or(Value::Null),
                "ports": object.value.pointer("/spec/ports").cloned().unwrap_or(Value::Null),
                "external_ips": object.value.pointer("/spec/externalIPs").cloned().unwrap_or(Value::Null),
                "load_balancer": object.value.pointer("/status/loadBalancer/ingress").cloned().unwrap_or(Value::Null),
            }),
        ),
        "Ingress" => merge_json(
            base,
            json!({
                "ingress_class_name": object.value.pointer("/spec/ingressClassName").cloned().unwrap_or(Value::Null),
                "rules": ingress_rules(&object.value),
                "backend_services": ingress_backend_services(&object.value),
            }),
        ),
        "NetworkPolicy" => merge_json(
            base,
            json!({
                "pod_selector": object.value.pointer("/spec/podSelector").cloned().unwrap_or(Value::Null),
                "policy_types": object.value.pointer("/spec/policyTypes").cloned().unwrap_or(Value::Null),
                "ingress_rule_count": object.value.pointer("/spec/ingress").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
                "egress_rule_count": object.value.pointer("/spec/egress").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
            }),
        ),
        "ServiceAccount" => merge_json(
            base,
            json!({
                "automount_service_account_token": object.value.pointer("/automountServiceAccountToken").cloned().unwrap_or(Value::Null),
                "secrets": object.value.get("secrets").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
                "image_pull_secrets": object.value.get("imagePullSecrets").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
            }),
        ),
        "Role" | "ClusterRole" => merge_json(
            base,
            json!({
                "rules": object.value.get("rules").cloned().unwrap_or(Value::Null),
            }),
        ),
        "RoleBinding" | "ClusterRoleBinding" => merge_json(
            base,
            json!({
                "role_ref": object.value.get("roleRef").cloned().unwrap_or(Value::Null),
                "subjects": object.value.get("subjects").cloned().unwrap_or(Value::Null),
            }),
        ),
        "Secret" => merge_json(
            base,
            json!({
                "type": object.value.get("type").and_then(Value::as_str).unwrap_or("Opaque"),
                "data_keys": object.value.get("data").and_then(Value::as_object).map(|data| data.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
                "redacted": true,
            }),
        ),
        "ConfigMap" => merge_json(
            base,
            json!({
                "data_keys": object.value.get("data").and_then(Value::as_object).map(|data| data.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
                "binary_data_keys": object.value.get("binaryData").and_then(Value::as_object).map(|data| data.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
                "redacted": true,
            }),
        ),
        "PersistentVolumeClaim" => merge_json(
            base,
            json!({
                "storage_class_name": object.value.pointer("/spec/storageClassName").cloned().unwrap_or(Value::Null),
                "volume_name": object.value.pointer("/spec/volumeName").cloned().unwrap_or(Value::Null),
                "access_modes": object.value.pointer("/spec/accessModes").cloned().unwrap_or(Value::Null),
                "requests": object.value.pointer("/spec/resources/requests").cloned().unwrap_or(Value::Null),
                "phase": object.value.pointer("/status/phase").cloned().unwrap_or(Value::Null),
            }),
        ),
        "PersistentVolume" => merge_json(
            base,
            json!({
                "storage_class_name": object.value.pointer("/spec/storageClassName").cloned().unwrap_or(Value::Null),
                "capacity": object.value.pointer("/spec/capacity").cloned().unwrap_or(Value::Null),
                "access_modes": object.value.pointer("/spec/accessModes").cloned().unwrap_or(Value::Null),
                "phase": object.value.pointer("/status/phase").cloned().unwrap_or(Value::Null),
            }),
        ),
        "StorageClass" => merge_json(
            base,
            json!({
                "provisioner": object.value.get("provisioner").cloned().unwrap_or(Value::Null),
                "reclaim_policy": object.value.get("reclaimPolicy").cloned().unwrap_or(Value::Null),
                "volume_binding_mode": object.value.get("volumeBindingMode").cloned().unwrap_or(Value::Null),
            }),
        ),
        "Node" => merge_json(
            base,
            json!({
                "provider_id": object.value.pointer("/spec/providerID").cloned().unwrap_or(Value::Null),
                "taints": object.value.pointer("/spec/taints").cloned().unwrap_or(Value::Null),
                "capacity": object.value.pointer("/status/capacity").cloned().unwrap_or(Value::Null),
                "allocatable": object.value.pointer("/status/allocatable").cloned().unwrap_or(Value::Null),
            }),
        ),
        _ => base,
    }
}

fn pod_attributes(spec: Option<&Value>) -> Value {
    let Some(spec) = spec else {
        return json!({});
    };
    json!({
        "node_name": spec.get("nodeName").cloned().unwrap_or(Value::Null),
        "service_account": spec.get("serviceAccountName").and_then(Value::as_str).unwrap_or("default"),
        "host_network": spec.get("hostNetwork").and_then(Value::as_bool).unwrap_or(false),
        "host_pid": spec.get("hostPID").and_then(Value::as_bool).unwrap_or(false),
        "host_ipc": spec.get("hostIPC").and_then(Value::as_bool).unwrap_or(false),
        "containers": container_summaries(spec),
        "volumes": volume_summaries(spec),
        "mounts": pod_reference_summaries(spec),
    })
}

fn workload_attributes(object: &K8sObject) -> Value {
    json!({
        "replicas": object.value.pointer("/spec/replicas").cloned().unwrap_or(Value::Null),
        "selector": object.value.pointer("/spec/selector").cloned().unwrap_or(Value::Null),
        "template": pod_attributes(object.value.pointer("/spec/template/spec")),
    })
}

fn container_summaries(spec: &Value) -> Vec<Value> {
    all_containers(spec)
        .into_iter()
        .map(|container| {
            json!({
                "name": container.get("name").and_then(Value::as_str),
                "image": container.get("image").and_then(Value::as_str),
                "ports": container.get("ports").cloned().unwrap_or(Value::Null),
                "env_keys": container.get("env").and_then(Value::as_array).map(|env| {
                    env.iter().filter_map(|entry| entry.get("name").and_then(Value::as_str).map(ToString::to_string)).collect::<Vec<_>>()
                }).unwrap_or_default(),
                "security_context": container.get("securityContext").cloned().unwrap_or(Value::Null),
            })
        })
        .collect()
}

fn volume_summaries(spec: &Value) -> Vec<Value> {
    spec.get("volumes")
        .and_then(Value::as_array)
        .map(|volumes| {
            volumes
                .iter()
                .map(|volume| {
                    json!({
                        "name": volume.get("name").and_then(Value::as_str),
                        "type": volume_type(volume),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn all_containers(spec: &Value) -> Vec<&Value> {
    ["initContainers", "containers", "ephemeralContainers"]
        .iter()
        .flat_map(|field| {
            spec.get(*field)
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[])
                .iter()
        })
        .collect()
}

fn privileged_containers(spec: &Value) -> Vec<Value> {
    all_containers(spec)
        .into_iter()
        .filter(|container| {
            container
                .pointer("/securityContext/privileged")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .map(|container| {
            json!({
                "name": container.get("name").and_then(Value::as_str),
                "image": container.get("image").and_then(Value::as_str),
            })
        })
        .collect()
}

fn host_path_volumes(spec: &Value) -> Vec<Value> {
    spec.get("volumes")
        .and_then(Value::as_array)
        .map(|volumes| {
            volumes
                .iter()
                .filter_map(|volume| {
                    let host_path = volume.get("hostPath")?;
                    Some(json!({
                        "name": volume.get("name").and_then(Value::as_str),
                        "path": host_path.get("path").and_then(Value::as_str),
                        "type": host_path.get("type").and_then(Value::as_str),
                    }))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn host_namespace_flags(spec: &Value) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if spec
        .get("hostNetwork")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        flags.push("hostNetwork");
    }
    if spec
        .get("hostPID")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        flags.push("hostPID");
    }
    if spec
        .get("hostIPC")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        flags.push("hostIPC");
    }
    flags
}

struct VolumeReference {
    kind: &'static str,
    name: String,
    relationship_type: &'static str,
    source: &'static str,
}

fn pod_volume_references(pod: &K8sObject) -> Vec<VolumeReference> {
    let mut references = Vec::new();
    let Some(spec) = pod.value.get("spec") else {
        return references;
    };
    if let Some(volumes) = spec.get("volumes").and_then(Value::as_array) {
        for volume in volumes {
            if let Some(name) = volume.pointer("/secret/secretName").and_then(Value::as_str) {
                references.push(VolumeReference {
                    kind: "Secret",
                    name: name.to_string(),
                    relationship_type: "mounts",
                    source: "volume",
                });
            }
            if let Some(name) = volume.pointer("/configMap/name").and_then(Value::as_str) {
                references.push(VolumeReference {
                    kind: "ConfigMap",
                    name: name.to_string(),
                    relationship_type: "mounts",
                    source: "volume",
                });
            }
            if let Some(name) = volume
                .pointer("/persistentVolumeClaim/claimName")
                .and_then(Value::as_str)
            {
                references.push(VolumeReference {
                    kind: "PersistentVolumeClaim",
                    name: name.to_string(),
                    relationship_type: "mounts_persistent_volume_claim",
                    source: "volume",
                });
            }
        }
    }

    for container in all_containers(spec) {
        if let Some(env_from) = container.get("envFrom").and_then(Value::as_array) {
            for entry in env_from {
                if let Some(name) = entry.pointer("/secretRef/name").and_then(Value::as_str) {
                    references.push(VolumeReference {
                        kind: "Secret",
                        name: name.to_string(),
                        relationship_type: "mounts",
                        source: "envFrom",
                    });
                }
                if let Some(name) = entry.pointer("/configMapRef/name").and_then(Value::as_str) {
                    references.push(VolumeReference {
                        kind: "ConfigMap",
                        name: name.to_string(),
                        relationship_type: "mounts",
                        source: "envFrom",
                    });
                }
            }
        }
        if let Some(env) = container.get("env").and_then(Value::as_array) {
            for entry in env {
                if let Some(name) = entry
                    .pointer("/valueFrom/secretKeyRef/name")
                    .and_then(Value::as_str)
                {
                    references.push(VolumeReference {
                        kind: "Secret",
                        name: name.to_string(),
                        relationship_type: "mounts",
                        source: "env",
                    });
                }
                if let Some(name) = entry
                    .pointer("/valueFrom/configMapKeyRef/name")
                    .and_then(Value::as_str)
                {
                    references.push(VolumeReference {
                        kind: "ConfigMap",
                        name: name.to_string(),
                        relationship_type: "mounts",
                        source: "env",
                    });
                }
            }
        }
    }
    references
}

fn pod_reference_summaries(spec: &Value) -> Vec<Value> {
    let mut references = Vec::new();
    if let Some(volumes) = spec.get("volumes").and_then(Value::as_array) {
        for volume in volumes {
            if let Some(name) = volume.pointer("/secret/secretName").and_then(Value::as_str) {
                references.push(json!({
                    "kind": "Secret",
                    "name": name,
                    "source": "volume",
                    "volume": volume.get("name").and_then(Value::as_str),
                }));
            }
            if let Some(name) = volume.pointer("/configMap/name").and_then(Value::as_str) {
                references.push(json!({
                    "kind": "ConfigMap",
                    "name": name,
                    "source": "volume",
                    "volume": volume.get("name").and_then(Value::as_str),
                }));
            }
            if let Some(name) = volume
                .pointer("/persistentVolumeClaim/claimName")
                .and_then(Value::as_str)
            {
                references.push(json!({
                    "kind": "PersistentVolumeClaim",
                    "name": name,
                    "source": "volume",
                    "volume": volume.get("name").and_then(Value::as_str),
                }));
            }
        }
    }

    for container in all_containers(spec) {
        let container_name = container.get("name").and_then(Value::as_str);
        if let Some(env_from) = container.get("envFrom").and_then(Value::as_array) {
            for entry in env_from {
                if let Some(name) = entry.pointer("/secretRef/name").and_then(Value::as_str) {
                    references.push(json!({
                        "kind": "Secret",
                        "name": name,
                        "source": "envFrom",
                        "container": container_name,
                    }));
                }
                if let Some(name) = entry.pointer("/configMapRef/name").and_then(Value::as_str) {
                    references.push(json!({
                        "kind": "ConfigMap",
                        "name": name,
                        "source": "envFrom",
                        "container": container_name,
                    }));
                }
            }
        }
        if let Some(env) = container.get("env").and_then(Value::as_array) {
            for entry in env {
                if let Some(name) = entry
                    .pointer("/valueFrom/secretKeyRef/name")
                    .and_then(Value::as_str)
                {
                    references.push(json!({
                        "kind": "Secret",
                        "name": name,
                        "source": "env",
                        "container": container_name,
                        "env": entry.get("name").and_then(Value::as_str),
                    }));
                }
                if let Some(name) = entry
                    .pointer("/valueFrom/configMapKeyRef/name")
                    .and_then(Value::as_str)
                {
                    references.push(json!({
                        "kind": "ConfigMap",
                        "name": name,
                        "source": "env",
                        "container": container_name,
                        "env": entry.get("name").and_then(Value::as_str),
                    }));
                }
            }
        }
    }
    references
}

fn ingress_backend_services(value: &Value) -> Vec<String> {
    let mut services = BTreeSet::new();
    if let Some(name) = value
        .pointer("/spec/defaultBackend/service/name")
        .and_then(Value::as_str)
    {
        services.insert(name.to_string());
    }
    for rule in value
        .pointer("/spec/rules")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        for path in rule
            .pointer("/http/paths")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            if let Some(name) = path
                .pointer("/backend/service/name")
                .and_then(Value::as_str)
            {
                services.insert(name.to_string());
            }
        }
    }
    services.into_iter().collect()
}

fn ingress_rules(value: &Value) -> Value {
    value.pointer("/spec/rules").cloned().unwrap_or(Value::Null)
}

fn selector_matches(
    selector: &serde_json::Map<String, Value>,
    labels: &BTreeMap<String, String>,
) -> bool {
    selector.iter().all(|(key, value)| {
        value
            .as_str()
            .and_then(|expected| labels.get(key).map(|actual| actual == expected))
            .unwrap_or(false)
    })
}

fn rule_is_overbroad(rule: &&Value) -> bool {
    rule_is_cluster_admin_like(rule)
        || json_array_contains(rule, "verbs", "*")
        || json_array_contains(rule, "resources", "*")
}

fn rule_is_cluster_admin_like(rule: &Value) -> bool {
    json_array_contains(rule, "verbs", "*") && json_array_contains(rule, "resources", "*")
}

fn json_array_contains(value: &Value, field: &str, needle: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|values| values.iter().any(|value| value.as_str() == Some(needle)))
        .unwrap_or(false)
}

fn is_unmanaged_candidate(object: &K8sObject) -> bool {
    !system_namespace_opt(object.namespace.as_deref())
        && matches!(
            object.kind.as_str(),
            "Namespace"
                | "Deployment"
                | "DaemonSet"
                | "StatefulSet"
                | "Service"
                | "Ingress"
                | "NetworkPolicy"
                | "ServiceAccount"
                | "Role"
                | "RoleBinding"
                | "ClusterRoleBinding"
                | "Secret"
                | "ConfigMap"
                | "PersistentVolumeClaim"
                | "StorageClass"
        )
}

fn has_iac_manager(object: &K8sObject) -> bool {
    let managed_by = object
        .labels
        .get("app.kubernetes.io/managed-by")
        .or_else(|| object.labels.get("managed-by"))
        .or_else(|| object.labels.get("ManagedBy"))
        .map(String::as_str)
        .unwrap_or_default();
    matches!(
        managed_by,
        "Helm" | "helm" | "Terraform" | "terraform" | "Kustomize" | "kustomize"
    ) || object.annotations.contains_key("meta.helm.sh/release-name")
        || object
            .annotations
            .contains_key("kustomize.toolkit.fluxcd.io/name")
        || object
            .annotations
            .contains_key("config.kubernetes.io/owning-inventory")
}

fn raw_for(object: &K8sObject, include_raw: bool) -> Option<Value> {
    if !include_raw || matches!(object.kind.as_str(), "Secret" | "ConfigMap") {
        return None;
    }
    Some(object.value.clone())
}

fn tags_for(object: &K8sObject) -> BTreeMap<String, String> {
    let mut tags = object.labels.clone();
    if let Some(namespace) = &object.namespace {
        tags.entry("Namespace".to_string())
            .or_insert_with(|| namespace.clone());
        tags.entry("Environment".to_string())
            .or_insert_with(|| inferred_environment(object, namespace));
    }
    if let Some(application) = first_label(
        &object.labels,
        &["app.kubernetes.io/name", "app", "k8s-app", "application"],
    ) {
        tags.entry("Application".to_string())
            .or_insert_with(|| application.to_string());
    }
    if let Some(owner) = first_label(
        &object.labels,
        &["owner", "team", "app.kubernetes.io/part-of"],
    ) {
        tags.entry("Owner".to_string())
            .or_insert_with(|| owner.to_string());
    }
    tags
}

fn first_label<'a>(labels: &'a BTreeMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| labels.get(*key).map(String::as_str))
}

fn inferred_environment(object: &K8sObject, namespace: &str) -> String {
    first_label(&object.labels, &["environment", "env", "stage"])
        .unwrap_or(namespace)
        .to_string()
}

fn service_for(api_version: &str, kind: &str) -> String {
    let group = api_version.split('/').next().unwrap_or("core");
    match group {
        "v1" => "core",
        "apps" => "apps",
        "networking.k8s.io" => "networking",
        "rbac.authorization.k8s.io" => "rbac",
        "storage.k8s.io" => "storage",
        _ if kind == "StorageClass" => "storage",
        _ => group,
    }
    .to_string()
}

fn resource_type_for(kind: &str) -> String {
    match kind {
        "ConfigMap" => "configmap".to_string(),
        "ClusterRole" => "cluster-role".to_string(),
        "ClusterRoleBinding" => "cluster-role-binding".to_string(),
        "NetworkPolicy" => "network-policy".to_string(),
        "PersistentVolume" => "persistent-volume".to_string(),
        "PersistentVolumeClaim" => "persistent-volume-claim".to_string(),
        "ReplicaSet" => "replica-set".to_string(),
        "RoleBinding" => "role-binding".to_string(),
        "ServiceAccount" => "service-account".to_string(),
        "StatefulSet" => "stateful-set".to_string(),
        "StorageClass" => "storage-class".to_string(),
        other => kebab_case(other),
    }
}

fn volume_type(volume: &Value) -> Option<String> {
    volume.as_object().and_then(|object| {
        object
            .keys()
            .find(|key| key.as_str() != "name")
            .map(ToString::to_string)
    })
}

fn key(kind: &str, namespace: Option<&str>, name: &str) -> (String, String, String) {
    (
        kind.to_string(),
        namespace.unwrap_or_default().to_string(),
        name.to_string(),
    )
}

fn object_id(namespace: Option<&str>, name: &str) -> String {
    namespace
        .map(|namespace| format!("{namespace}/{name}"))
        .unwrap_or_else(|| name.to_string())
}

fn object_label(object: &K8sObject) -> String {
    object
        .namespace
        .as_deref()
        .map(|namespace| format!("{} {namespace}/{}", object.kind, object.name))
        .unwrap_or_else(|| format!("{} {}", object.kind, object.name))
}

fn evidence(
    collected_at: DateTime<Utc>,
    operation: &str,
    kind: &str,
    namespace: Option<&str>,
) -> Evidence {
    Evidence {
        service: "kubernetes".to_string(),
        operation: operation.to_string(),
        path: namespace
            .map(|namespace| format!("{kind}/{namespace}"))
            .unwrap_or_else(|| kind.to_string()),
        collected_at,
    }
}

fn relationship_evidence(collected_at: DateTime<Utc>) -> Evidence {
    evidence(collected_at, "derived graph relationship", "Object", None)
}

fn string_map(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .map(|object| {
            object
                .iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn str_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn pointer_str<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

fn annotation_keys(object: &K8sObject) -> Vec<String> {
    object.annotations.keys().cloned().collect()
}

fn merge_json(mut base: Value, overlay: Value) -> Value {
    if let (Some(base), Some(overlay)) = (base.as_object_mut(), overlay.as_object()) {
        for (key, value) in overlay {
            base.insert(key.clone(), value.clone());
        }
    }
    base
}

fn system_namespace(namespace: &str) -> bool {
    matches!(namespace, "kube-system" | "kube-public" | "kube-node-lease")
}

fn system_namespace_opt(namespace: Option<&str>) -> bool {
    namespace.map(system_namespace).unwrap_or(false)
}

fn severity_sort_rank(severity: &str) -> i32 {
    match severity {
        "critical" => 0,
        "high" => 1,
        _ => 2,
    }
}

fn kebab_case(value: &str) -> String {
    let mut output = String::new();
    for (index, character) in value.chars().enumerate() {
        if character.is_uppercase() {
            if index > 0 {
                output.push('-');
            }
            output.extend(character.to_lowercase());
        } else {
            output.push(character);
        }
    }
    output
}

fn sanitize_cluster_id(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            ':' | '/' | '\\' | ' ' | '\n' | '\t' => '_',
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;

    #[test]
    fn builds_kubernetes_inventory_relationships_and_findings() {
        let output = build_scan_output("kind-demo", Utc::now(), true, sample_objects(), Vec::new());

        assert!(output.inventory.resources.iter().any(|resource| {
            resource.provider == "k8s"
                && resource.service == "apps"
                && resource.resource_type == "deployment"
                && resource.id == "prod/payments"
        }));
        assert!(output.inventory.resources.iter().any(|resource| {
            resource.resource_type == "secret"
                && resource.name.as_deref() == Some("legacy-token")
                && resource.raw.is_none()
                && resource.attributes["redacted"] == true
        }));
        assert!(output.inventory.relationships.iter().any(|relationship| {
            relationship.relationship_type == "owns"
                && relationship.from.contains(":deployment:prod/payments")
                && relationship.to.contains(":pod:prod/payments-abc-1")
        }));
        assert!(output.inventory.relationships.iter().any(|relationship| {
            relationship.relationship_type == "uses_service_account"
                && relationship.from.contains(":pod:prod/payments-abc-1")
                && relationship.to.contains(":service-account:prod/default")
        }));
        assert!(output.inventory.relationships.iter().any(|relationship| {
            relationship.relationship_type == "routes_to"
                && relationship.from.contains(":ingress:prod/payments")
                && relationship.to.contains(":service:prod/payments")
        }));
        assert!(output.inventory.relationships.iter().any(|relationship| {
            relationship.relationship_type == "mounts"
                && relationship.from.contains(":pod:prod/payments-abc-1")
                && relationship.to.contains(":secret:prod/legacy-token")
        }));

        let finding_types = output
            .findings
            .iter()
            .map(|finding| finding.finding_type.as_str())
            .collect::<BTreeSet<_>>();
        for expected in [
            "privileged_container",
            "host_path_mount",
            "host_namespace_enabled",
            "default_service_account_used",
            "public_service",
            "public_ingress",
            "overbroad_rbac",
            "cluster_admin_binding",
            "legacy_service_account_token_secret",
            "missing_network_policy",
            "unmanaged_kubernetes_resource",
        ] {
            assert!(finding_types.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn writes_kubernetes_findings_to_map_db() {
        let temp = tempfile::tempdir().unwrap();
        let output =
            build_scan_output("kind-demo", Utc::now(), false, sample_objects(), Vec::new());
        let db_path = temp.path().join("map.db");
        let scan_id = crate::db::write_inventory_db(&db_path, &output.inventory).unwrap();

        let run_id = write_k8s_findings(&db_path, &scan_id, &output.findings).unwrap();

        let connection = Connection::open(db_path).unwrap();
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM findings WHERE run_id = ?1",
                params![run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, output.findings.len() as i64);
    }

    fn sample_objects() -> Vec<Value> {
        vec![
            json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "prod", "uid": "ns-prod" }
            }),
            json!({
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": { "namespace": "prod", "name": "default", "uid": "sa-default" }
            }),
            json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "namespace": "prod",
                    "name": "payments",
                    "uid": "deploy-payments",
                    "labels": { "app": "payments", "team": "payments-platform" }
                },
                "spec": {
                    "selector": { "matchLabels": { "app": "payments" } },
                    "template": {
                        "metadata": { "labels": { "app": "payments" } },
                        "spec": {
                            "hostNetwork": true,
                            "containers": [{
                                "name": "api",
                                "image": "payments:v1",
                                "securityContext": { "privileged": true }
                            }],
                            "volumes": [{ "name": "host", "hostPath": { "path": "/var/run" } }]
                        }
                    }
                }
            }),
            json!({
                "apiVersion": "apps/v1",
                "kind": "ReplicaSet",
                "metadata": {
                    "namespace": "prod",
                    "name": "payments-abc",
                    "uid": "rs-payments",
                    "ownerReferences": [{ "kind": "Deployment", "name": "payments", "uid": "deploy-payments" }]
                }
            }),
            json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "namespace": "prod",
                    "name": "payments-abc-1",
                    "uid": "pod-payments",
                    "labels": { "app": "payments" },
                    "ownerReferences": [{ "kind": "ReplicaSet", "name": "payments-abc", "uid": "rs-payments" }]
                },
                "spec": {
                    "hostPID": true,
                    "containers": [{
                        "name": "api",
                        "image": "payments:v1",
                        "envFrom": [{ "secretRef": { "name": "legacy-token" } }]
                    }],
                    "volumes": [
                        { "name": "config", "configMap": { "name": "payments-config" } },
                        { "name": "secret", "secret": { "secretName": "legacy-token" } },
                        { "name": "data", "persistentVolumeClaim": { "claimName": "payments-data" } }
                    ]
                }
            }),
            json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": { "namespace": "prod", "name": "payments", "uid": "svc-payments" },
                "spec": {
                    "type": "LoadBalancer",
                    "selector": { "app": "payments" },
                    "ports": [{ "port": 443, "targetPort": 8443 }]
                }
            }),
            json!({
                "apiVersion": "networking.k8s.io/v1",
                "kind": "Ingress",
                "metadata": { "namespace": "prod", "name": "payments", "uid": "ing-payments" },
                "spec": {
                    "rules": [{
                        "host": "payments.example.com",
                        "http": { "paths": [{ "backend": { "service": { "name": "payments" } } }] }
                    }]
                }
            }),
            json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": { "namespace": "prod", "name": "legacy-token", "uid": "secret-token" },
                "type": "kubernetes.io/service-account-token",
                "data": { "token": "redacted" }
            }),
            json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": { "namespace": "prod", "name": "payments-config", "uid": "cm-payments" },
                "data": { "config.yaml": "value" }
            }),
            json!({
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": { "namespace": "prod", "name": "payments-data", "uid": "pvc-payments" },
                "spec": { "volumeName": "pv-payments" }
            }),
            json!({
                "apiVersion": "v1",
                "kind": "PersistentVolume",
                "metadata": { "name": "pv-payments", "uid": "pv-payments" }
            }),
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": { "name": "cluster-admin", "uid": "cr-admin" },
                "rules": [{ "apiGroups": ["*"], "resources": ["*"], "verbs": ["*"] }]
            }),
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRoleBinding",
                "metadata": { "name": "default-admin", "uid": "crb-admin" },
                "roleRef": { "kind": "ClusterRole", "name": "cluster-admin" },
                "subjects": [{ "kind": "ServiceAccount", "namespace": "prod", "name": "default" }]
            }),
        ]
    }
}
