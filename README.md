# cloudmapper

`cloudmapper` is a standalone Rust CLI that exports AWS account reality into an
agent-readable `infra/` bundle and SQLite knowledge store. It is designed to
feed agents structured resources, relationships, Terraform state mappings,
drift findings, and a local Cytoscape graph UI.

AI-generated documentation is intentionally out of scope for this phase; it can
be layered on top of the structured store later.

## Development

```bash
make build
make test
make check
```

Useful local targets:

- `make build` builds the CLI.
- `make test` runs unit tests.
- `make check` runs formatting, type checking, and tests.
- `make ui DB=infra/infra.sqlite` serves the local Cytoscape UI.
- `make clean` removes Cargo build output.

## Usage

```bash
cargo run -- scan --profile default --regions all --out infra
```

Useful options:

- `--profile <name>` uses a named AWS profile. If omitted, the normal AWS
  credential chain is used.
- `--regions all` scans every enabled EC2 region returned by
  `DescribeRegions`.
- `--regions us-east-1,eu-west-1` scans an explicit comma-separated region set.
- `--home-region us-east-1` controls STS, region discovery, and global-service
  client bootstrap.
- `--out infra` writes the generated bundle to the `infra/` directory.
- `--include-raw` mirrors normalized detail blocks into `raw` fields where the
  scanner supports it.
- `--allow-non-empty-out` allows writing into a non-empty directory that does
  not already contain a cloudmapper manifest.

## Bundle Layout

```text
infra/
  manifest.json
  inventory.json
  infra.sqlite
  resources.jsonl
  relationships.jsonl
  errors.jsonl
  graph.json
  schemas/
    resource.schema.json
    relationship.schema.json
```

`inventory.json` is the complete document. The JSONL files are optimized for
agent ingestion and indexing. `graph.json` contains nodes and edges derived from
the same source facts. `infra.sqlite` stores the same scan as queryable local
state and can also hold imported Terraform state snapshots.

Every resource has a stable `uid`:

```json
{
  "uid": "aws:123456789012:us-east-1:ec2:instance:i-abc123",
  "provider": "aws",
  "account_id": "123456789012",
  "region": "us-east-1",
  "service": "ec2",
  "type": "instance",
  "id": "i-abc123"
}
```

Relationships are explicit facts with evidence pointers:

```json
{
  "from": "aws:123456789012:us-east-1:ec2:instance:i-abc123",
  "to": "aws:123456789012:us-east-1:ec2:security-group:sg-123",
  "type": "uses_security_group"
}
```

## Current Coverage

The core scanner collects:

- STS account identity
- EC2 regions
- EC2 instances, VPCs, subnets, security groups, route tables, internet
  gateways, NAT gateways, and EBS volumes
- S3 buckets, bucket tags, bucket location, and public-access-block settings
- IAM roles, users, groups, and attached role policies
- Lambda functions and VPC/security-group/role relationships
- Broad tagged-resource discovery through the AWS Resource Groups Tagging API

Recoverable failures are written to `errors.jsonl` so an account scan can still
produce a usable inventory when a service, region, or permission fails.

## SQLite

Every scan writes `infra.sqlite` alongside the JSON files. The first schema
stores:

- `scans`
- `resources`
- `relationships`
- `scan_errors`
- `terraform_states`
- `terraform_resource_instances`

This is the local knowledge store that later compare, drift, graph, and MCP
commands can query without reloading the full JSON bundle.

## Terraform State

Import a Terraform state file into the SQLite store:

```bash
cloudmapper terraform import \
  --state terraform.tfstate \
  --db infra/infra.sqlite
```

Export the imported Terraform state as normalized JSON:

```bash
cloudmapper terraform export \
  --db infra/infra.sqlite \
  --out terraform-resources.json
```

The importer stores each Terraform resource instance with its address, module,
mode, type, provider, index key, attributes, dependencies, and inferred AWS UID
when an ARN is present. It does not write a Terraform-native `tfstate` file;
the export format is a cloudmapper-normalized state view for compare and agent
workflows.

Terraform state can contain secrets. Treat `infra.sqlite` and Terraform export
files as local sensitive artifacts unless they have been explicitly reviewed and
redacted.

## Compare

After a scan and Terraform import, compare AWS reality with Terraform state:

```bash
cloudmapper compare \
  --db infra/infra.sqlite \
  --out findings.json
```

The first compare engine emits structured findings for:

- AWS resources absent from imported Terraform state
- unmanaged public security groups, including reverse relationship blast radius
- Terraform-managed public security groups
- Terraform state resources absent from the AWS scan

Findings are written to the JSON report and persisted in the SQLite `findings`
table for later query, context, and MCP workflows.

## UI

Serve the local SQLite store as a Cytoscape graph:

```bash
cloudmapper ui --db infra/infra.sqlite --bind 127.0.0.1:8765
```

Open `http://127.0.0.1:8765` to inspect the latest AWS scan, Terraform state
mapping, relationships, and compare findings. Critical and high findings are
overlaid directly on graph nodes, and the side panels provide service filters,
Terraform-managed filtering, finding navigation, blast radius, and recommended
actions.

## Verification

```bash
make build
make test
make check
```

On small local disks, the AWS SDK crates are much lighter with debug info
disabled. The Makefile uses that setting by default; with Cargo directly:

```bash
CARGO_PROFILE_DEV_DEBUG=0 CARGO_BUILD_JOBS=1 cargo test
```

## CI

GitHub Actions runs on `main` pushes and pull requests:

- `cargo fmt --check`
- `cargo check --locked`
- `cargo test --locked`
- `cargo build --locked`

Release builds run when a `v*` tag is pushed and publish Linux and macOS CLI
archives to the GitHub release.

## Git Tagging

Use annotated SemVer tags:

```bash
git tag -a v0.1.0 -m "cloudmapper v0.1.0"
git push origin main
git push origin v0.1.0
```

Do not move published tags. If a release tag is wrong, create the next patch tag.
