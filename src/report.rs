use crate::cli::Args;
use crate::rules;
use crate::types::{Severity, Vulnerability};
use colored::*;
use std::collections::HashMap;

pub fn print_banner() {
    println!("\n{}", "╔═══════════════════════════════════════════════════════════════════════════════╗".bright_black());
    println!("{}", "║                                                                               ║".bright_black());
    println!(
        "{}{}{}",
        "║  ".bright_black(),
        "cargo-panic-audit v0.5.0".bold().cyan(),
        "                                                    ║".bright_black()
    );
    println!(
        "{}{}{}",
        "║  ".bright_black(),
        "Find panic patterns that can take down production Rust services".italic(),
        " ║".bright_black()
    );
    println!("{}", "║                                                                               ║".bright_black());
    println!("{}", "╚═══════════════════════════════════════════════════════════════════════════════╝".bright_black());
}

pub fn print_legend() {
    println!("\n{}", "PANIC AUDIT RULE LEGEND".bold().white());
    println!("{}", "═".repeat(80).bright_black());
    println!();

    for r in rules::all_rules() {
        println!(
            "{} | {:<18} | {:<8} | {}",
            r.id.cyan().bold(), 
            r.kind, 
            r.severity.yellow(), 
            r.message
        );
    }
}

pub fn print_what_we_detect(show_details: bool) {
    if !show_details {
        return;
    }

    println!("\n{}", "WHAT WE DETECT".bold().white());
    println!("{}", "═".repeat(80).bright_black());
    println!("\nNot a style linter. Not just unwrap police.");
    println!("{} answers:", "cargo-panic-audit".cyan().bold());
    println!("  • Can this take down prod?");
    println!("  • Is this on a hot path?");
    println!("  • Can one panic cascade into many failures?");
    println!("  • Is this reachable from untrusted input?");
    
    println!("\n{}", "8 CRITICAL PANIC CLASSES".bold());
    println!("{}", "─".repeat(80).bright_black());
    
    println!("\n{}. {} - unwrap(), expect(), unwrap_unchecked()", 
             "1".bold(), "Assumption Panics".cyan());
    println!("   Flags logic that assumes 'this can't fail' on real-world input");
    
    println!("\n{}. {} - Indexing [i], todo!(), unimplemented!()", 
             "2".bold(), "Implicit Panics".cyan());
    println!("   Panics hidden in normal-looking code");
    
    println!("\n{}. {} - Mutex::lock().unwrap(), panics in Drop", 
             "3".bold(), "Panic Amplification".cyan());
    println!("   Single panic → cascading failure across threads");
    
    println!("\n{}. {} - Deserialization + size/bounds + unwrap", 
             "4".bold(), "Cloudflare-Class".cyan().bold());
    println!("   The exact pattern that caused Cloudflare's global outage");
    
    println!("\n{}. {} - assert!() in non-test code", 
             "5".bold(), "Assertion Failures".cyan());
    println!("   Turns unexpected input into crashes");
    
    println!("\n{}. {} - Vec::with_capacity(untrusted)", 
             "6".bold(), "Allocation & OOM".cyan());
    println!("   Memory-driven panics and restarts");
    
    println!("\n{}. {} - Panics in extern \"C\" paths", 
             "7".bold(), "FFI Boundary Panics".cyan());
    println!("   Can abort the entire process");
    
    println!("\n{}. {} - std::process::exit() in libraries", 
             "8".bold(), "Process-Killing Calls".cyan());
    println!("   One code path kills the whole service");
}

pub fn print_severity_legend() {
    println!("\n{}", "SEVERITY LEVELS & ACTIONS".bold());
    println!("{}", "─".repeat(80).bright_black());
    
    println!(
        "\n  {} {} - Can cause cascading outages (Cloudflare-class)",
        "🔴".red(),
        "CRITICAL".red().bold()
    );
    println!("     {} External I/O, network, config loading, panic amplification", "Examples:".bold());
    println!("     {} Add error handling, implement fallback, return Result", "Action:".bold().red());
    
    println!(
        "\n  {} {} - Can crash request handlers or worker threads",
        "🟠".yellow(),
        "HIGH".yellow().bold()
    );
    println!("     {} Parsing untrusted data, database ops, large allocations", "Examples:".bold());
    println!("     {} Validate input, return Result, add size limits", "Action:".bold().yellow());
    
    println!(
        "\n  {} {} - Can fail under specific runtime conditions",
        "🟡",
        "MEDIUM".bold()
    );
    println!("     {} Environment variables, assertions, array indexing", "Examples:".bold());
    println!("     {} Provide defaults, add bounds checking, validate assumptions", "Action:".bold());
    
    println!(
        "\n  {} {} - Low-risk internal operations",
        "⚪".bright_black(),
        "LOW".bright_black()
    );
    println!("     {} Arc unwrap, internal field access, after explicit validation", "Examples:".bold().bright_black());
    println!("     {} Review context - usually intentional and safe", "Action:".bold().bright_black());
}

pub fn print_report(
    vulnerabilities: &mut Vec<Vulnerability>,
    crate_name: &str,
    version: &str,
    args: &Args,
) {
    if args.json {
        println!("{}", serde_json::to_string_pretty(vulnerabilities).unwrap());
        return;
    }

    println!("\n{}", "═".repeat(80).bright_black());
    let version_display = if version == "local" {
        version.to_string()
    } else {
        format!("v{}", version)
    };
    println!(
        "{} {} {}",
        "AUDIT REPORT:".bold().white(),
        crate_name.yellow().bold(),
        version_display.bright_black()
    );
    println!("{}\n", "═".repeat(80).bright_black());

    if vulnerabilities.is_empty() {
        println!("{}", "✅ No panic patterns detected!".green().bold());
        println!("\nThis crate appears to handle errors gracefully.");
        return;
    }

    vulnerabilities.sort_by(|a, b| a.severity.cmp(&b.severity));

    let total = vulnerabilities.len();
    
    let critical_count = vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::Critical)).count();
    let high_count = vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::High)).count();
    let medium_count = vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::Medium)).count();
    let low_count = vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::Low)).count();

    if !args.summary {
        println!("⚠️  {} panic patterns detected:\n", total.to_string().bold());
        
        if critical_count > 0 {
            println!("   {} {} {}", 
                     "🔴".red(), 
                     format!("Critical: {}", critical_count).red().bold(),
                     "(Can cause outages)".red());
        }
        if high_count > 0 {
            println!("   {} {} {}", 
                     "🟠".yellow(), 
                     format!("High:     {}", high_count).yellow().bold(),
                     "(Can crash handlers)".yellow());
        }
        if medium_count > 0 {
            println!("   {} {} {}", 
                     "🟡", 
                     format!("Medium:   {}", medium_count),
                     "(Conditional failures)");
        }
        if low_count > 0 {
            println!("   {} {} {}", 
                     "⚪", 
                     format!("Low:      {}", low_count).bright_black(),
                     "(Low risk)".bright_black());
        }

        print_severity_legend();

        println!("\n{}", "═".repeat(80).bright_black());
        println!("{}", "PANIC PATTERNS BY CLASS & SEVERITY".bold());
        println!("{}", "─".repeat(80).bright_black());

        print_panic_class_breakdown(vulnerabilities, Severity::Critical);
        print_panic_class_breakdown(vulnerabilities, Severity::High);
        print_panic_class_breakdown(vulnerabilities, Severity::Medium);
        if args.verbose {
            print_panic_class_breakdown(vulnerabilities, Severity::Low);
        }

        let critical_high: Vec<_> = vulnerabilities
            .iter()
            .filter(|v| matches!(v.severity, Severity::Critical | Severity::High))
            .collect();

        if !critical_high.is_empty() {
            println!("\n{}", "═".repeat(80).bright_black());
            println!("{}", "DETAILED FINDINGS (Critical & High Risk)".bold());
            println!("{}", "─".repeat(80).bright_black());
            
            for (i, vuln) in critical_high.iter().enumerate() {
                let badge = match vuln.severity {
                    Severity::Critical => "🔴 CRITICAL".red().bold(),
                    Severity::High => "🟠 HIGH    ".yellow().bold(),
                    _ => unreachable!(),
                };

                println!("\n{}. {}", i + 1, badge);
                println!("   Class:   {:?}", vuln.panic_class);
                println!("   Pattern: {}", vuln.pattern.cyan());
                println!("   File:    {}:{}", vuln.file.bright_black(), vuln.line.yellow());
                println!("   Code:    {}", vuln.code.bright_white());
            }
        }

        if args.verbose && (medium_count + low_count > 0) {
            println!("\n{}", "═".repeat(80).bright_black());
            println!("{}", "OTHER FINDINGS (Medium & Low Risk)".bold());
            println!("{}", "─".repeat(80).bright_black());
            
            let other: Vec<_> = vulnerabilities
                .iter()
                .filter(|v| matches!(v.severity, Severity::Medium | Severity::Low))
                .collect();

            // In verbose mode, show ALL findings (no limit)
            for (i, vuln) in other.iter().enumerate() {
                println!(
                    "  {}. {:?} - {} in {}:{}",
                    i + 1,
                    vuln.severity,
                    vuln.pattern.cyan(),
                    vuln.file.bright_black(),
                    vuln.line.yellow()
                );
            }
        } else if medium_count + low_count > 0 {
            println!(
                "\n{}", 
                "═".repeat(80).bright_black()
            );
            println!(
                "💡 {} lower-risk patterns hidden. Use --verbose to see all findings.",
                medium_count + low_count
            );
        }
    } else {
        // Summary mode
        print_summary(vulnerabilities);
    }
}

fn print_panic_class_breakdown(vulnerabilities: &[Vulnerability], severity: Severity) {
    let items: Vec<_> = vulnerabilities
        .iter()
        .filter(|v| v.severity == severity)
        .collect();

    if items.is_empty() {
        return;
    }

    let mut class_counts: HashMap<String, usize> = HashMap::new();
    for vuln in &items {
        let class_name = format!("{:?}", vuln.panic_class);
        *class_counts.entry(class_name).or_insert(0) += 1;
    }

    let mut class_list: Vec<_> = class_counts.into_iter().collect();
    class_list.sort_by(|a, b| b.1.cmp(&a.1));

    let label = match severity {
        Severity::Critical => format!("🔴 CRITICAL ({})", items.len()).red().bold(),
        Severity::High => format!("🟠 HIGH ({})", items.len()).yellow().bold(),
        Severity::Medium => format!("🟡 MEDIUM ({})", items.len()).bold(),
        Severity::Low => format!("⚪ LOW ({})", items.len()).bright_black(),
    };
    
    println!("\n{}", label);
    
    for (class, count) in class_list {
        println!("  • {}: {}", class.replace("Class", "").cyan(), count);
    }
}

fn print_summary(findings: &[Vulnerability]) {
    let mut by_severity: HashMap<&str, usize> = HashMap::new();

    for f in findings {
        let sev = match f.severity {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        };
        *by_severity.entry(sev).or_insert(0) += 1;
    }

    println!("\n{}", "SUMMARY".bold());
    println!("{}", "─".repeat(80).bright_black());

    for (sev, count) in by_severity {
        println!("{:<10}: {}", sev, count);
    }

    println!("\nTotal findings: {}", findings.len());
}
