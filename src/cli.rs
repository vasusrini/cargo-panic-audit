use clap::Parser;

const VERSION: &str = "0.5.0";
const TAGLINE: &str = "Find panic patterns that can take down production Rust services";

#[derive(Parser, Debug)]
#[command(name = "cargo-panic-audit")]
#[command(version = VERSION)]
#[command(about = TAGLINE, long_about = None)]
pub struct Args {
    /// Crate name to audit (from crates.io) or local path to scan
    pub crate_name: String,

    /// Specific version (defaults to latest) - ignored for local paths
    pub version: Option<String>,

    /// Show all severity levels including low-risk patterns
    #[arg(short, long)]
    pub verbose: bool,

    /// Show detailed explanations of each pattern class
    #[arg(short, long)]
    pub explain: bool,

    /// Output JSON instead of human readable
    #[arg(long)]
    pub json: bool,

    /// Fail with non-zero exit code if critical findings exist
    #[arg(long)]
    pub fail_on_findings: bool,

    /// Print rule legend and exit
    #[arg(long)]
    pub legend: bool,

    /// Print summary only
    #[arg(long)]
    pub summary: bool,

    /// Scan local path instead of downloading from crates.io
    #[arg(short, long)]
    pub local: bool,
}

pub fn parse() -> Args {
    Args::parse()
}
