mod aws_scan;
mod compare;
mod db;
mod model;
mod terraform_state;
mod ui;
mod writer;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use tracing_subscriber::FmtSubscriber;

use crate::aws_scan::{ScanOptions, scan_account};
use crate::compare::compare_infra;
use crate::terraform_state::{export_terraform_state, import_terraform_state_file};
use crate::ui::serve_ui;
use crate::writer::write_infra;

#[derive(Debug, Parser)]
#[command(name = "cloudmapper")]
#[command(about = "Export AWS account infrastructure as agent-readable JSON")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Scan an AWS account and write an infra/ JSON bundle.
    Scan(ScanArgs),
    /// Compare AWS reality with imported Terraform state and emit findings.
    Compare(CompareArgs),
    /// Import or export Terraform state data in infra.sqlite.
    Terraform {
        #[command(subcommand)]
        command: TerraformCommand,
    },
    /// Serve a local Cytoscape infrastructure graph UI.
    Ui(UiArgs),
}

#[derive(Debug, Parser)]
struct ScanArgs {
    /// AWS profile name. Falls back to AWS_PROFILE or the default credential chain.
    #[arg(long)]
    profile: Option<String>,

    /// Regions to scan: "all" or a comma-separated list such as "us-east-1,eu-west-1".
    #[arg(long, default_value = "all")]
    regions: String,

    /// Region used for global APIs and region discovery.
    #[arg(long, default_value = "us-east-1")]
    home_region: String,

    /// Directory for the generated infrastructure bundle.
    #[arg(long, default_value = "infra")]
    out: PathBuf,

    /// Service set to scan.
    #[arg(long, value_enum, default_value_t = ServiceSet::Core)]
    services: ServiceSet,

    /// Include normalized raw detail blocks where the scanner supports them.
    #[arg(long)]
    include_raw: bool,

    /// Allow writing cloudmapper files into a non-empty directory that was not created by cloudmapper.
    #[arg(long)]
    allow_non_empty_out: bool,
}

#[derive(Debug, Parser)]
struct CompareArgs {
    /// SQLite database path.
    #[arg(long, default_value = "infra/infra.sqlite")]
    db: PathBuf,

    /// AWS scan id. Defaults to the latest scan in the database.
    #[arg(long)]
    scan_id: Option<String>,

    /// Terraform state id. Defaults to the latest imported Terraform state.
    #[arg(long)]
    terraform_state_id: Option<String>,

    /// Output file. If omitted, JSON is printed to stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, clap::Subcommand)]
enum TerraformCommand {
    /// Import a Terraform state file into infra.sqlite.
    Import(TerraformImportArgs),
    /// Export imported Terraform state from infra.sqlite as normalized JSON.
    Export(TerraformExportArgs),
}

#[derive(Debug, Parser)]
struct TerraformImportArgs {
    /// Terraform state JSON file to import.
    #[arg(long)]
    state: PathBuf,

    /// SQLite database path.
    #[arg(long, default_value = "infra/infra.sqlite")]
    db: PathBuf,

    /// Optional stable state id. Defaults to lineage/serial when available.
    #[arg(long)]
    state_id: Option<String>,
}

#[derive(Debug, Parser)]
struct TerraformExportArgs {
    /// SQLite database path.
    #[arg(long, default_value = "infra/infra.sqlite")]
    db: PathBuf,

    /// State id to export. Defaults to the latest imported Terraform state.
    #[arg(long)]
    state_id: Option<String>,

    /// Output file. If omitted, JSON is printed to stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct UiArgs {
    /// SQLite database path.
    #[arg(long, default_value = "infra/infra.sqlite")]
    db: PathBuf,

    /// Local address to bind.
    #[arg(long, default_value = "127.0.0.1:8765")]
    bind: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ServiceSet {
    /// Account identity, regions, EC2/VPC, S3, IAM, Lambda, and tagged-resource discovery.
    Core,
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_target(false)
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => {
            let options = ScanOptions {
                profile: args.profile,
                regions: args.regions,
                home_region: args.home_region,
                include_raw: args.include_raw,
            };
            let inventory = scan_account(options).await?;
            write_infra(&args.out, &inventory, args.allow_non_empty_out)?;
            println!(
                "wrote {} resources, {} relationships, and {} scan errors to {}",
                inventory.resources.len(),
                inventory.relationships.len(),
                inventory.errors.len(),
                args.out.display()
            );
        }
        Command::Compare(args) => {
            let report = compare_infra(
                &args.db,
                args.scan_id.as_deref(),
                args.terraform_state_id.as_deref(),
            )?;
            let json = serde_json::to_string_pretty(&report)?;
            if let Some(out) = args.out {
                std::fs::write(&out, format!("{json}\n"))?;
                println!(
                    "wrote {} compare findings from {} to {}",
                    report.findings.len(),
                    args.db.display(),
                    out.display()
                );
            } else {
                println!("{json}");
            }
        }
        Command::Terraform { command } => match command {
            TerraformCommand::Import(args) => {
                let summary = import_terraform_state_file(&args.db, &args.state, args.state_id)?;
                println!(
                    "imported {} Terraform resource instances into {} as {}",
                    summary.resource_instances,
                    args.db.display(),
                    summary.state_id
                );
            }
            TerraformCommand::Export(args) => {
                let export = export_terraform_state(&args.db, args.state_id.as_deref())?;
                let json = serde_json::to_string_pretty(&export)?;
                if let Some(out) = args.out {
                    std::fs::write(&out, format!("{json}\n"))?;
                    println!(
                        "exported {} Terraform resource instances from {} to {}",
                        export.resource_instances.len(),
                        args.db.display(),
                        out.display()
                    );
                } else {
                    println!("{json}");
                }
            }
        },
        Command::Ui(args) => {
            serve_ui(&args.db, &args.bind)?;
        }
    }

    Ok(())
}
