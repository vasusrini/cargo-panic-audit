use anyhow::{Context, Result};
use colored::*;
use flate2::read::GzDecoder;
use std::fs;
use std::path::PathBuf;
use tar::Archive;

pub fn get_latest_version(crate_name: &str) -> Result<String> {
    let url = format!("https://crates.io/api/v1/crates/{}", crate_name);
    
    let client = reqwest::blocking::Client::new();
    let response: serde_json::Value = client
        .get(&url)
        .header("User-Agent", "cargo-panic-audit/1.0.0")
        .send()?
        .json()?;

    response["crate"]["newest_version"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("Could not find latest version"))
}

pub fn download_crate(name: &str, version: &str) -> Result<PathBuf> {
    println!("{}", format!("📥 Downloading {} v{}...", name, version).cyan());

    let url = format!(
        "https://crates.io/api/v1/crates/{}/{}/download",
        name, version
    );

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let response = client
        .get(&url)
        .header("User-Agent", "cargo-panic-audit/1.0.0")
        .send()
        .context("Failed to download crate")?;

    if !response.status().is_success() {
        anyhow::bail!("Download failed: HTTP {}", response.status());
    }

    let bytes = response.bytes()?;
    
    println!("📦 Extracting...");

    let temp_dir = PathBuf::from(format!("./temp_{}_{}", name, version));
    fs::create_dir_all(&temp_dir)?;

    let tar = GzDecoder::new(&bytes[..]);
    let mut archive = Archive::new(tar);
    archive.unpack(&temp_dir)?;

    Ok(temp_dir)
}
