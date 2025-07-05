#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unused_variables)]

use colored::*;
use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, exit};
use indicatif::{ProgressBar, ProgressStyle, self};
use dialoguer::{Input, Select, Confirm, theme, self};
use std::time::Duration;
use serde::{Serialize, Deserialize};
use serde_json::{Value, json};
use reqwest::blocking::Client;

fn get_lym_dir() -> io::Result<PathBuf> {
    let home_dir = dirs::home_dir().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Could not find home directory"))?;
    let lym_dir = home_dir.join(".lym");
    Ok(lym_dir)
}

fn ensure_lym_dirs() -> io::Result<()> {
    let lym_dir = get_lym_dir()?;

    if !lym_dir.exists() {
        fs::create_dir_all(&lym_dir)?;
    }

    let config_path = lym_dir.join("config.json");
    if !config_path.exists() {
        File::create(&config_path)?.write_all(b"{}")?;
    }

    let logs_dir = lym_dir.join("logs");
    if !logs_dir.exists() {
        fs::create_dir_all(&logs_dir)?;
    }

    Ok(())
}

fn github_repo_exists(client: &Client, repo: &str) -> bool {
    let url = format!("https://api.github.com/repos/{}", repo);
    let resp = client
        .head(&url)
        .header("User-Agent", "lym-checker")
        .send();

    match resp {
        Ok(r) => r.status().is_success(),
        Err(_) => false,
    }
}

fn update_config_with_lucia_info(config_path: &Path) -> io::Result<()> {
    #[cfg(target_os = "windows")]
    let lucia_path = {
        let output = Command::new("where").arg("lucia").output()?;
        if !output.status.success() {
            println!("Warning: Lucia not installed. Please install it to use lym.");
            exit(1);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.lines().next().map(PathBuf::from).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "lucia executable not found"))?
    };
    #[cfg(not(target_os = "windows"))]
    let lucia_path = {
        let output = Command::new("which").arg("lucia").output()?;
        if !output.status.success() {
            println!("Warning: Lucia not installed. Please install it to use lym.");
            exit(1);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.lines().next().map(PathBuf::from).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "lucia executable not found"))?
    };

    let output = Command::new(&lucia_path)
        .arg("--build-info")
        .output()?;

    if !output.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "Failed to run lucia --build-info"));
    }

    let build_info_str = String::from_utf8_lossy(&output.stdout);
    let build_info: Value = serde_json::from_str(&build_info_str)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse lucia build-info JSON: {}", e)))?;

    let repository_url = build_info.get("repository")
        .and_then(Value::as_str)
        .unwrap_or("https://github.com/SirPigari/lym");

    let repo = if let Some(stripped) = repository_url.strip_prefix("https://github.com/") {
        let parts: Vec<&str> = stripped.trim_end_matches('/').split('/').collect();
        if parts.len() >= 2 {
            format!("{}/{}", parts[0], parts[1])
        } else {
            "SirPigari/lym".to_string()
        }
    } else {
        "SirPigari/lym".to_string()
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to build reqwest client: {}", e)))?;

    let final_repo = if github_repo_exists(&client, &repo) {
        repo
    } else {
        "SirPigari/lym".to_string()
    };

    let mut config_json: Value = if config_path.exists() {
        let data = fs::read_to_string(config_path)?;
        serde_json::from_str(&data).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    config_json["lucia_path"] = json!(lucia_path.to_string_lossy());
    config_json["build_info"] = build_info;
    config_json["repository"] = json!(final_repo);

    let serialized = serde_json::to_string_pretty(&config_json)?;
    fs::write(config_path, serialized)?;

    Ok(())
}

fn print_help() {
    println!("
lym - Lucia package manager

Usage:
  lym <command> [args]

Commands:
 - install   Install a package
 - list      List installed packages
 - download  Download a package
 - remove    Remove a package
 - disable   Disable a package
 - enable    Enable a package
 - config    Set configuration options (lucia or lym)
 - modify    Modify package manifest
 - new       Create a new package/project

Use 'lym <command> --help' for more info on a command.
");
}

fn install(args: &[String]) {
    todo!();
}

fn list(args: &[String]) {
    todo!();
}

fn download(args: &[String]) {
    todo!();
}

fn remove(args: &[String]) {
    todo!();
}

fn disable(args: &[String]) {
    todo!();
}

fn enable(args: &[String]) {
    todo!();
}

fn config(args: &[String]) {
    todo!();
}

fn modify(args: &[String]) {
    todo!();
}

fn new(args: &[String]) {
    todo!();
}

fn main() {
    if let Err(e) = ensure_lym_dirs() {
        eprintln!("{}", format!("Failed to setup ~/.lym directory: {}", e).red());
        exit(1);
    }

    let lym_dir = get_lym_dir().expect("Failed to get lym dir");
    let config_path = lym_dir.join("config.json");

    if let Err(e) = update_config_with_lucia_info(&config_path) {
        eprintln!("{}", format!("Warning: Could not update config with lucia info: {}", e).yellow());
        exit(1);
    }

    let mut args: Vec<String> = env::args().collect();
    if args.len() > 0 {
        args.remove(0);
    }

    if args.is_empty() || args[0] == "--help" {
        print_help();
        exit(0);
    }

    let command = args.remove(0);
    let command_args = args.as_slice();

    match command.as_str() {
        "install" => install(command_args),
        "list" => list(command_args),
        "download" => download(command_args),
        "remove" => remove(command_args),
        "disable" => disable(command_args),
        "enable" => enable(command_args),
        "config" => config(command_args),
        "modify" => modify(command_args),
        "new" => new(command_args),
        "--help" => print_help(),
        _ => {
            eprintln!("{}", format!("Unknown command: '{}'\n", command).red());
            print_help();
            exit(1);
        }
    }
}
