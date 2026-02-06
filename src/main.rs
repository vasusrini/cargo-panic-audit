mod audit;
mod cli;
mod download;
mod report;
mod rules;
mod scanner;
mod types;

use anyhow::Result;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<()> {
    let args = cli::parse();

    // Handle legend display
    if args.legend {
        report::print_legend();
        return Ok(());
    }

    report::print_banner();
    report::print_what_we_detect(args.explain);

    let (scan_path, crate_name, version, cleanup_needed) = if args.local {
        // Scan local path
        let path = PathBuf::from(&args.crate_name);
        if !path.exists() {
            anyhow::bail!("Path does not exist: {}", args.crate_name);
        }
        
        let crate_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&args.crate_name)
            .to_string();
        
        println!("\n📂 Scanning local path: {}", path.display());
        (path, crate_name, "local".to_string(), false)
    } else {
        // Download from crates.io
        let crate_name = &args.crate_name;
        
        let version = if let Some(v) = args.version.clone() {
            v
        } else {
            println!("\n🔎 Finding latest version...");
            download::get_latest_version(crate_name)?
        };

        println!();
        let temp_dir = download::download_crate(crate_name, &version)?;
        (temp_dir, crate_name.clone(), version, true)
    };

    let mut vulnerabilities = audit::scan_directory(&scan_path, &crate_name);

    if cleanup_needed {
        println!("\n🧹 Cleaning up...");
        fs::remove_dir_all(&scan_path)?;
    }

    report::print_report(&mut vulnerabilities, &crate_name, &version, &args);

    println!("\n{}", "═".repeat(80));

    let has_critical = vulnerabilities
        .iter()
        .any(|v| matches!(v.severity, types::Severity::Critical));
    
    if has_critical && args.fail_on_findings {
        println!("\n{}", "⚠️  CRITICAL: This crate contains patterns that can take down production!".to_string().as_str());
        println!("{}", "    Review and fix critical issues before deploying.");
        std::process::exit(1);
    } else {
        println!("\n{}", "✅ Audit complete!");
        if vulnerabilities.is_empty() {
            println!("{}", "   No panic patterns detected.");
        } else if has_critical {
            println!("{}", "   ⚠️  Critical issues found - review before production deployment.");
        } else {
            println!("{}", "   No critical issues found, but review high/medium patterns.");
        }
    }

    Ok(())
}
