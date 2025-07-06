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
use serde_json::{Value as JsonValue, json};
use reqwest::blocking::Client;
use base64::{engine::general_purpose, Engine as _};
use std::sync::atomic::{AtomicBool, Ordering};

mod db;
mod utils;

use db::{LibInfo, STD_LIBS};
use utils::check_version;

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
            println!("{}", "Warning: Lucia not installed. Please install it to use lym.".yellow());
            exit(1);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.lines().next().map(PathBuf::from).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "lucia executable not found")
        })?
    };

    #[cfg(not(target_os = "windows"))]
    let lucia_path = {
        let output = Command::new("which").arg("lucia").output()?;
        if !output.status.success() {
            println!("{}", "Warning: Lucia not installed. Please install it to use lym.".yellow());
            exit(1);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.lines().next().map(PathBuf::from).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "lucia executable not found")
        })?
    };

    let output = Command::new(&lucia_path)
        .arg("--build-info")
        .output()?;

    if !output.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "Failed to run lucia --build-info"));
    }

    let build_info_str = String::from_utf8_lossy(&output.stdout);
    let build_info: JsonValue = serde_json::from_str(&build_info_str)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse lucia build-info JSON: {}", e)))?;

    let original_repo_url = build_info.get("repository")
        .and_then(JsonValue::as_str)
        .unwrap_or("https://github.com/SirPigari/lym");

    let (repo_slug, final_repo_url) = {
        let url = original_repo_url.trim_end_matches('/');

        if let Some(user_and_repo) = url.strip_prefix("https://github.com/") {
            let parts: Vec<&str> = user_and_repo.split('/').collect();
            if parts.len() >= 1 {
                let user = parts[0];
                let slug = format!("{}/lym", user);
                let full_url = format!("https://github.com/{}", slug);

                let client = Client::builder()
                    .timeout(Duration::from_secs(3))
                    .build()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to build reqwest client: {}", e)))?;

                if github_repo_exists(&client, &slug) {
                    (slug, full_url)
                } else {
                    ("SirPigari/lym".to_string(), "https://github.com/SirPigari/lym".to_string())
                }
            } else {
                ("SirPigari/lym".to_string(), "https://github.com/SirPigari/lym".to_string())
            }
        } else {
            ("SirPigari/lym".to_string(), "https://github.com/SirPigari/lym".to_string())
        }
    };

    let mut config_json: JsonValue = if config_path.exists() {
        let data = fs::read_to_string(config_path)?;
        serde_json::from_str(&data).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    config_json["lucia_path"] = json!(lucia_path.to_string_lossy());
    config_json["build_info"] = build_info;
    config_json["repository"] = json!(final_repo_url);
    config_json["repository_slug"] = json!(repo_slug);

    let serialized = serde_json::to_string_pretty(&config_json)?;
    fs::write(config_path, serialized)?;

    Ok(())
}

fn print_help() {
    println!(
        "{} - {}\n\n{}:\n  {} <command> [args]\n\n{}:\n  {}   Install a package\n  {}      List installed packages\n  {}  Download a package\n  {}    Remove a package\n  {}   Disable a package\n  {}    Enable a package\n  {}    Set configuration options (lucia or lym)\n  {}     Modify package manifest\n  {}       Create a new package\n\n{} 'lym <command> --help' {} for more info on a command.\n",
        "lym".bright_blue().bold(),
        "Lucia package manager".bright_white(),
        "Usage".bright_green().bold(),
        "lym".bright_yellow(),
        "Commands".bright_green().bold(),
        "install".bright_cyan(),
        "list".bright_cyan(),
        "download".bright_cyan(),
        "remove".bright_cyan(),
        "disable".bright_cyan(),
        "enable".bright_cyan(),
        "config".bright_cyan(),
        "modify".bright_cyan(),
        "new".bright_cyan(),
        "Use".bright_green(),
        "'lym <command> --help'".bright_yellow()
    );
}

fn command_help(cmd: &str) {
    match cmd {
        "list" => {
            println!(
                "{} {} {} {}\n\n{}",
                "Usage:".bright_green().bold(),
                "lym".bright_cyan().bold(),
                "list".bright_cyan(),
                "[--remote | --local] [--no-desc] [--no-ver] [--no-std]".bright_yellow(),
                "Lists installed packages or remote packages.".bright_white()
            );
        }
        "install" => {
            println!(
                "{} {} {} {}\n\n{}",
                "Usage:".bright_green().bold(),
                "lym".bright_cyan().bold(),
                "install".bright_cyan(),
                "[package_name] [--no-confirm] [-v] [--help]".bright_yellow(),
                "Installs a package from the remote repository.".bright_white()
            );
        }
        _ => {
            eprintln!("{}", format!("Unknown command: '{}'", cmd).red().bold());
            print_help();
        }
    }
}

fn install_single_package(pkg_name: &str, no_confirm: bool, verbose: bool) -> Result<(), String> {
    let lym_dir = get_lym_dir().map_err(|e| format!("Failed to get lym dir: {}", e))?;
    let config_path = lym_dir.join("config.json");
    let config_json: JsonValue = fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config.json: {}", e))
        .and_then(|data| serde_json::from_str(&data).map_err(|e| format!("Invalid config.json: {}", e)))?;

    let lucia_path_str = config_json.get("lucia_path")
        .and_then(JsonValue::as_str)
        .ok_or("Lucia path not set in config. Run lym config or reinstall lucia.")?;
    let lucia_path = Path::new(lucia_path_str);

    let libs_dir = lucia_path
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(lucia_path)
        .join("libs");

    if !libs_dir.exists() {
        if verbose {
            println!("{}", format!("libs directory not found at {}, creating it", libs_dir.display()).yellow());
        }
        fs::create_dir_all(&libs_dir).map_err(|e| format!("Failed to create libs dir: {}", e))?;
    }

    let repo_slug = config_json.get("repository_slug")
        .and_then(JsonValue::as_str)
        .ok_or("Repository slug not set in config.")?;

    let local_pkg_path = libs_dir.join(pkg_name);
    let already_installed = local_pkg_path.exists();

    if already_installed && !no_confirm {
        let override_confirm = Confirm::new()
            .with_prompt(format!("Package '{}' is already installed. Override? (Y/n)", pkg_name))
            .default(false)
            .interact()
            .map_err(|e| format!("Prompt error: {}", e))?;

        if !override_confirm {
            if verbose {
                println!("{}", "Install cancelled by user.".yellow());
            }
            return Ok(());
        }
    }

    let manifest_url = format!("https://api.github.com/repos/{}/contents/libs/{}/manifest.json", repo_slug, pkg_name);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let resp = client.get(&manifest_url)
        .header("User-Agent", "lym-install")
        .send()
        .map_err(|e| format!("Failed to send request: {}", e))?;

    if !resp.status().is_success() {
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(format!("Package '{}' not found in the remote repository. Please check the package name and try again.", pkg_name));
        }
        return Err(format!("Failed to get manifest.json: HTTP {}", resp.status()));
    }

    let manifest_json: JsonValue = resp.json()
        .map_err(|e| format!("Failed to parse manifest.json from remote: {}", e))?;

    let encoded_content = manifest_json.get("content")
        .and_then(JsonValue::as_str)
        .ok_or("manifest.json content missing in remote response.")?
        .replace('\n', "");

    let decoded_bytes = general_purpose::STANDARD.decode(&encoded_content)
        .map_err(|e| format!("Failed to decode manifest.json content: {}", e))?;

    let manifest_str = String::from_utf8(decoded_bytes)
        .map_err(|e| format!("manifest.json is not valid UTF-8: {}", e))?;

    let manifest: JsonValue = serde_json::from_str(&manifest_str)
        .map_err(|e| format!("Failed to parse manifest.json: {}", e))?;

    let required_version = manifest.get("required_lucia_version")
        .and_then(JsonValue::as_str)
        .unwrap_or("0.0.0");

    let current_version = config_json.get("build_info")
        .and_then(|b| b.get("version"))
        .and_then(JsonValue::as_str)
        .unwrap_or("0.0.0");

    if verbose {
        println!("{}", format!("Checking lucia version: required '{}' vs current '{}'", required_version, current_version));
    }

    if !check_version(current_version, required_version) {
        eprintln!("{}", format!("Warning: Package '{}' requires lucia version '{}', but current version is '{}'", pkg_name, required_version, current_version).yellow());

        if !no_confirm {
            let cont = Confirm::new()
                .with_prompt("Continue installation anyway? (Y/n)")
                .default(false)
                .interact()
                .map_err(|e| format!("Prompt error: {}", e))?;

            if !cont {
                if verbose {
                    println!("{}", "Install cancelled due to version mismatch.".yellow());
                }
                return Ok(());
            }
        }
    }

    let api_url = format!("https://api.github.com/repos/{}/contents/libs/{}", repo_slug, pkg_name);
    let resp = client.get(&api_url)
        .header("User-Agent", "lym-install")
        .send()
        .map_err(|e| format!("Failed to send request: {}", e))?;

    if !resp.status().is_success() {
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(format!("Package '{}' not found in the remote repository. Please check the package name and try again.", pkg_name));
        }
        return Err(format!("Failed to get remote package contents: HTTP {}", resp.status()));
    }

    let contents = resp.json::<Vec<JsonValue>>()
        .map_err(|e| format!("Failed to parse remote package directory listing: {}", e))?;

    if verbose {
        println!("{}", format!("Found {} files/directories to download", contents.len()));
    }

    if local_pkg_path.exists() {
        if verbose {
            println!("{}", format!("Removing existing package directory {}", local_pkg_path.display()));
        }
        fs::remove_dir_all(&local_pkg_path).map_err(|e| format!("Failed to remove existing package directory: {}", e))?;
    }
    fs::create_dir_all(&local_pkg_path).map_err(|e| format!("Failed to create package directory: {}", e))?;

    for item in contents {
        let name = match item.get("name").and_then(JsonValue::as_str) {
            Some(n) => n,
            None => continue,
        };

        let item_type = item.get("type").and_then(JsonValue::as_str).unwrap_or("");

        if item_type == "file" {
            let download_url = match item.get("download_url").and_then(JsonValue::as_str) {
                Some(url) => url,
                None => {
                    eprintln!("{}", format!("File '{}' has no download_url", name).red());
                    continue;
                }
            };

            if verbose {
                println!("{}", format!("Downloading file {}", name));
            }

            let file_resp = client.get(download_url)
                .header("User-Agent", "lym-install")
                .send()
                .map_err(|e| format!("Failed to download file {}: {}", name, e))?;

            if !file_resp.status().is_success() {
                eprintln!("{}", format!("Failed to download file {}: HTTP {}", name, file_resp.status()).red());
                continue;
            }

            let file_bytes = file_resp.bytes()
                .map_err(|e| format!("Failed to read bytes of file {}: {}", name, e))?;

            let local_file_path = local_pkg_path.join(name);
            fs::write(&local_file_path, &file_bytes)
                .map_err(|e| format!("Failed to write file {}: {}", local_file_path.display(), e))?;
        }
        else if item_type == "dir" {
            let sub_dir = local_pkg_path.join(name);
            fs::create_dir_all(&sub_dir)
                .map_err(|e| format!("Failed to create directory {}: {}", sub_dir.display(), e))?;
        }
    }

    if verbose {
        println!("{}", format!("Package '{}' installed successfully.", pkg_name).bright_green());
    }

    Ok(())
}

fn install(args: &[String]) {
    use dialoguer::Confirm;

    let mut no_confirm = false;
    let mut verbose = false;

    // Separate package names (before flags) and flags (starting with '-')
    let mut packages = Vec::new();
    let mut flags = Vec::new();

    let mut flag_mode = false;
    for arg in args {
        if flag_mode || arg.starts_with('-') {
            flag_mode = true;
            flags.push(arg.clone());
        } else {
            packages.push(arg.clone());
        }
    }

    // Parse flags
    for arg in &flags {
        match arg.as_str() {
            "--no-confirm" => no_confirm = true,
            "-v" => verbose = true,
            "--help" | "-h" => {
                command_help("install");
                return;
            }
            _ => {
                eprintln!("{}", format!("Unknown argument: '{}'", arg).red());
                command_help("install");
                return;
            }
        }
    }

    if packages.is_empty() {
        eprintln!("{}", "You must specify at least one package to install.".red());
        command_help("install");
        return;
    }

    for pkg_name in packages {
        if verbose {
            println!("{}", format!("Installing package '{}'", pkg_name).bright_green());
        }

        if let Err(e) = install_single_package(&pkg_name, no_confirm, verbose) {
            eprintln!("{}", format!("Failed to install '{}': {}", pkg_name, e).red());
        }
    }
}

fn list(args: &[String]) {
    let mut show_desc = true;
    let mut show_ver = true;
    let mut list_remote = false;
    let mut list_local = true;
    let mut show_std = true;

    for arg in args {
        match arg.as_str() {
            "--remote" => {
                list_remote = true;
                list_local = false;
            }
            "--no-desc" => show_desc = false,
            "--no-ver" => show_ver = false,
            "--local" => {
                list_local = true;
                list_remote = false;
            }
            "--no-std" => show_std = false,
            "--help" | "-h" => {
                command_help("list");
                return;
            }
            _ => {
                eprintln!("{}", format!("Unknown argument: '{}'", arg).red());
                command_help("list");
                return;
            }
        }
    }

    let lym_dir = match get_lym_dir() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", format!("Failed to get lym dir: {}", e).red());
            return;
        }
    };

    let config_path = lym_dir.join("config.json");
    let config_json: JsonValue = fs::read_to_string(&config_path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_else(|| json!({}));

    let lucia_path_str = config_json.get("lucia_path").and_then(JsonValue::as_str);

    if list_local {
        if lucia_path_str.is_none() {
            eprintln!("{}", "Lucia path not set in config. Run lym config or reinstall lucia.".red());
            return;
        }

        let lucia_path = Path::new(lucia_path_str.unwrap());

        let libs_dir = lucia_path
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or(lucia_path)
            .join("libs");

        if !libs_dir.exists() || !libs_dir.is_dir() {
            eprintln!("{}", format!("libs directory not found at {}", libs_dir.display()).red());
            return;
        }

        println!("{}", "Local modules:".bright_green().bold());

        let mut found_any = false;

        for entry in fs::read_dir(&libs_dir).unwrap() {
            if let Ok(entry) = entry {
                let path = entry.path();

                let module_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("<unknown>");

                let is_std = STD_LIBS.contains_key(module_name)
                    || module_name == "std"
                    || module_name == "requests";

                if !show_std && is_std {
                    continue;
                }

                found_any = true;

                let mut version: Option<String> = None;
                let mut description: Option<String> = None;

                if path.is_dir() {
                    let manifest_path = path.join("manifest.json");
                    if manifest_path.exists() {
                        if let Ok(manifest_str) = fs::read_to_string(&manifest_path) {
                            if let Ok(manifest_json) = serde_json::from_str::<JsonValue>(&manifest_str) {
                                version = manifest_json.get("version").and_then(JsonValue::as_str).map(|s| s.to_string());
                                description = manifest_json.get("description").and_then(JsonValue::as_str).map(|s| s.to_string());
                            }
                        }
                    }
                } else if path.is_file() {
                    if module_name.ends_with(".lc") || module_name.ends_with(".lucia") {
                        version = None;
                        description = None;
                    }
                }

                if is_std {
                    if let Some(std_info) = STD_LIBS.get(module_name) {
                        description = Some(std_info.description.to_string());
                        version = Some(std_info.version.to_string());
                    }
                }

                let mut line = if is_std {
                    format!("  {} {}", module_name.bright_blue().bold(), "[standard lib]".purple())
                } else {
                    format!("  {}", module_name.bright_cyan())
                };

                if show_ver {
                    line += &format!(" v{}", version.as_deref().unwrap_or("unknown"));
                }
                if show_desc {
                    if let Some(desc) = &description {
                        if !desc.is_empty() {
                            line += &format!(" - {}", desc);
                        }
                    }
                }

                println!("{}", line);
            }
        }

        if !found_any {
            println!("{}", "No local modules found ".yellow());
        }
    }

    if list_remote {
        let repo_url = config_json.get("repository").and_then(JsonValue::as_str);
        if repo_url.is_none() {
            eprintln!("{}", "Repository URL not set in config.".red());
            return;
        }

        let repo_url = repo_url.unwrap();

        let repo_slug = config_json.get("repository_slug").and_then(JsonValue::as_str);
        if repo_slug.is_none() {
            eprintln!("{}", "Repository slug not set in config.".red());
            return;
        }

        let repo_slug = repo_slug.unwrap();

        let api_url = format!("https://api.github.com/repos/{}/contents/libs", repo_slug);

        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let resp = client.get(&api_url)
            .header("User-Agent", "lym-list")
            .send();

        if let Ok(resp) = resp {
            if resp.status().is_success() {
                let contents: Result<Vec<JsonValue>, _> = resp.json();

                if let Ok(contents) = contents {
                    println!("{}", "Remote modules:".bright_green().bold());

                    let mut found_any = false;

                    for item in contents {
                        let name = item.get("name").and_then(JsonValue::as_str).unwrap_or("");
                        let item_type = item.get("type").and_then(JsonValue::as_str).unwrap_or("");

                        if item_type == "dir" {
                            found_any = true;

                            let manifest_url = format!("https://api.github.com/repos/{}/contents/libs/{}/manifest.json", repo_slug, name);

                            let manifest_resp = client.get(&manifest_url)
                                .header("User-Agent", "lym-list")
                                .send();

                            if let Ok(manifest_resp) = manifest_resp {
                                if manifest_resp.status().is_success() {
                                    if let Ok(manifest_json) = manifest_resp.json::<JsonValue>() {
                                        if let Some(content_encoded) = manifest_json.get("content").and_then(JsonValue::as_str) {
                                            let decoded_bytes = general_purpose::STANDARD.decode(content_encoded.replace('\n', "")).unwrap_or_default();
                                            if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                                                if let Ok(manifest) = serde_json::from_str::<JsonValue>(&decoded_str) {
                                                    let version = manifest.get("version").and_then(JsonValue::as_str).unwrap_or("unknown");
                                                    let desc = manifest.get("description").and_then(JsonValue::as_str).unwrap_or("");
                                                    let mut line = format!("  {}", name.bright_cyan());
                                                    if show_ver {
                                                        line += &format!(" v{}", version);
                                                    }
                                                    if show_desc && !desc.is_empty() {
                                                        line += &format!(" - {}", desc);
                                                    }
                                                    println!("{}", line);
                                                    continue;
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            println!("  {}", name.bright_cyan());
                        } else if item_type == "file" {
                            if name.ends_with(".lc") || name.ends_with(".lucia") {
                                found_any = true;
                                println!("  {}", name.bright_cyan());
                            }
                        }
                    }

                    if !found_any {
                        println!("{}", "No remote modules found".yellow());
                    }
                } else {
                    eprintln!("{}", "Failed to parse GitHub API response.".red());
                }
            } else {
                if resp.status() == reqwest::StatusCode::NOT_FOUND {
                    println!("{}", "The repository doesn't have a 'libs' directory.".red());
                    return;
                }                
                eprintln!("{}", format!("GitHub API error: {}", resp.status()).red());
            }
        } else {
            eprintln!("{}", "Failed to connect to GitHub API.".red());
        }
    }
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

    let should_update = match fs::read_to_string(&config_path) {
        Ok(data) => {
            if let Ok(json) = serde_json::from_str::<JsonValue>(&data) {
                !(json.get("lucia_path").is_some() &&
                json.get("build_info").is_some() &&
                json.get("repository").is_some() &&
                json.get("repository_slug").is_some())
            } else {
                true
            }
        }
        Err(_) => true,
    };

    if should_update {
        if let Err(e) = update_config_with_lucia_info(&config_path) {
            eprintln!("{}", format!("Warning: Could not update config with lucia info: {}", e).yellow());
            exit(1);
        }
    }

    let config_json: JsonValue = fs::read_to_string(&config_path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_else(|| json!({}));

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
