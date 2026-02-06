use crate::scanner::Scanner;
use crate::types::Vulnerability;
use std::fs;
use std::path::Path;
use syn::visit::Visit;
use walkdir::WalkDir;

pub fn scan_directory(path: &Path, crate_name: &str) -> Vec<Vulnerability> {
    println!("🔍 Auditing for production panic patterns...");
    
    let mut scanner = Scanner::new(crate_name.to_string());

    let rs_files: Vec<_> = WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "rs"))
        .collect();

    println!("   Scanning {} Rust source files", rs_files.len());

    for entry in rs_files {
        scanner.current_file = entry
            .path()
            .strip_prefix(path)
            .unwrap_or(entry.path())
            .display()
            .to_string();

        if let Ok(content) = fs::read_to_string(entry.path()) {
            // Store the source content for line number lookups
            scanner.current_source = content.clone();
            
            if let Ok(syntax) = syn::parse_file(&content) {
                scanner.visit_file(&syntax);
            }
        }
    }

    scanner.vulnerabilities
}
