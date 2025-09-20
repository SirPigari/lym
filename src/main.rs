use colored::*;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, exit};
use indicatif::{ProgressBar, ProgressStyle, self};
use dialoguer::{Confirm, self};
use std::time::Duration;
use serde_json::{Value as JsonValue, json};
use reqwest::blocking::Client;
use base64::{engine::general_purpose, Engine as _};

mod db;
mod utils;

use db::{STD_LIBS, load_std_libs};
use utils::check_version;

// lym - Lucia package manager
// 'lym' isnt an acronym if you were wondering
// (maybe its lymphoma idk)

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

    if !lym_dir.is_dir() {
        return Err(io::Error::new(io::ErrorKind::Other, format!("{} exists and is not a directory", lym_dir.display())));
    }

    let config_path = lym_dir.join("config.json");
    if !config_path.exists() {
        update_config_with_lucia_info(&config_path)?;
    }

    let logs_dir = lym_dir.join("logs");
    if !logs_dir.exists() {
        fs::create_dir_all(&logs_dir)?;
    }
    let store_dir = lym_dir.join("store");
    if !store_dir.exists() {
        fs::create_dir_all(&store_dir)?;
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
        "{} - {}\n\n{}:\n  {} <command> [args]\n\n{}:\n  {}   Install a package\n  {}      List installed packages\n  {}  Download a package\n  {}    Remove a package\n  {}   Disable a package\n  {}    Enable a package\n  {}    Set configuration options (lucia or lym)\n  {}    Modify package manifest\n  {}       Create a new package\n\n{} 'lym <command> --help' {} for more info on a command.\n",
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
                "[--remote | --local | --store] [--no-desc] [--no-ver] [--no-std] [--help]".bright_yellow(),
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
        "remove" => {
            println!(
                "{} {} {} {}\n\n{}",
                "Usage:".bright_green().bold(),
                "lym".bright_cyan().bold(),
                "remove".bright_cyan(),
                "[package_name] [--no-confirm] [-v] [--help]".bright_yellow(),
                "Removes a package from the local installation.".bright_white()
            );
        }
        "disable" => {
            println!(
                "{} {} {} {}\n\n{}",
                "Usage:".bright_green().bold(),
                "lym".bright_cyan().bold(),
                "disable".bright_cyan(),
                "[package_name] [--no-confirm] [-v] [--help]".bright_yellow(),
                "Disables a package, moving it to the store directory.".bright_white()
            );
        }
        "enable" => {
            println!(
                "{} {} {} {}\n\n{}",
                "Usage:".bright_green().bold(),
                "lym".bright_cyan().bold(),
                "enable".bright_cyan(),
                "[package_name] [--no-confirm] [-v] [--help]".bright_yellow(),
                "Enables a package, moving it back to the libs directory.".bright_white()
            );
        }
        "download" => {
            println!(
                "{} {} {} {}\n\n{}",
                "Usage:".bright_green().bold(),
                "lym".bright_cyan().bold(),
                "download".bright_cyan(),
                "[package_name] [output_path] [--no-confirm] [-v] [--help]".bright_yellow(),
                "Downloads a package from the remote repository.".bright_white()
            );
        }
        "config" => {
            println!(
                "{} {} {} {}\n\n{}",
                "Usage:".bright_green().bold(),
                "lym".bright_cyan().bold(),
                "config".bright_cyan(),
                "[ lym | lucia | fetch ] [--set <key=value>] [--get <key>] [--help] [--no-confirm]".bright_yellow(),
                "Sets or gets configuration options for lym or lucia.".bright_white()
            );
        }
        "modify" => {
            println!(
                "{} {} {} {}\n\n{}",
                "Usage:".bright_green().bold(),
                "lym".bright_cyan().bold(),
                "modify".bright_cyan(),
                "[package_name] [--stored] <key> [value1 [value2 ...]] [--no-confirm] [--help]".bright_yellow(),
                "Modifies the manifest.json of a package.".bright_white()
            );
        }
        "new" => {
            println!(
                "{} {} {} {}\n\n{}",
                "Usage:".bright_green().bold(),
                "lym".bright_cyan().bold(),
                "new".bright_cyan(),
                "[package | module] [name] [path] [--no-confirm] [--help] [--main-file:<name>]".bright_yellow(),
                "Creates a new package/module with a basic manifest.json.".bright_white()
            );
        }
        _ => {
            eprintln!("{}", format!("Unknown command: '{}'", cmd).red().bold());
            print_help();
        }
    }
}

fn install_single_package(pkg_name: &str, no_confirm: bool, verbose: bool) -> Result<(), String> {
    if cfg!(target_os = "windows") {
        let output = Command::new("tasklist")
            .output()
            .map_err(|e| format!("Failed to execute tasklist: {}", e))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.lines().any(|line| line.to_lowercase().starts_with("lucia.exe")) {
            return Err("Lucia is currently running. Please close it before installing packages.".to_string());
        }
    } else {
        let output = Command::new("pgrep")
            .arg("lucia")
            .output()
            .map_err(|e| format!("Failed to execute pgrep: {}", e))?;
        if !output.stdout.is_empty() {
            return Err("Lucia is currently running. Please close it before installing packages.".to_string());
        }
    }

    let lym_dir = get_lym_dir().map_err(|e| format!("Failed to get lym dir: {}", e))?;
    let config_path = lym_dir.join("config.json");
    let config_json: JsonValue = fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config.json: {}", e))
        .and_then(|data| serde_json::from_str(&data).map_err(|e| format!("Invalid config.json: {}", e)))?;

    let lucia_path_str = config_json.get("lucia_path")
        .and_then(JsonValue::as_str)
        .ok_or("Lucia path not set in config. Run lym config or reinstall lucia.")?;
        let lucia_path = Path::new(lucia_path_str);
        let lucia_real = lucia_path.canonicalize().unwrap_or_else(|_| lucia_path.to_path_buf());
        let libs_dir = lucia_real
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or(&lucia_real)
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

    let fetch_pb = ProgressBar::new_spinner();
    fetch_pb.set_message("Fetching manifest.json...");
    fetch_pb.enable_steady_tick(Duration::from_millis(100));

    let manifest_url = format!("https://api.github.com/repos/{}/contents/libs/{}/manifest.json", repo_slug, pkg_name);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let resp = client.get(&manifest_url)
        .header("User-Agent", "lym-install")
        .send()
        .map_err(|e| format!("Failed to send request: {}", e))?;

    fetch_pb.finish_and_clear();

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
        println!("{}", format!("Checking lucia version: required '{}' vs current '{}'", required_version.to_string().bright_green(), current_version.to_string().bright_green()));
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
        let del_pb = ProgressBar::new_spinner();
        del_pb.set_message(format!("Removing existing package directory {}", local_pkg_path.display()));
        del_pb.enable_steady_tick(Duration::from_millis(100));

        fs::remove_dir_all(&local_pkg_path).map_err(|e| format!("Failed to remove existing package directory: {}", e))?;

        del_pb.finish_with_message("Existing package directory removed");
    }
    fs::create_dir_all(&local_pkg_path).map_err(|e| format!("Failed to create package directory: {}", e))?;

    let pb = ProgressBar::new(contents.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    for item in contents {
        let name = match item.get("name").and_then(JsonValue::as_str) {
            Some(n) => n,
            None => {
                pb.inc(1);
                continue;
            },
        };

        let item_type = item.get("type").and_then(JsonValue::as_str).unwrap_or("");

        if item_type == "file" {
            let download_url = match item.get("download_url").and_then(JsonValue::as_str) {
                Some(url) => url,
                None => {
                    eprintln!("{}", format!("File '{}' has no download_url", name).red());
                    pb.inc(1);
                    continue;
                }
            };

            if verbose {
                pb.set_message(format!("Downloading file {}", name));
            }

            let file_resp = client.get(download_url)
                .header("User-Agent", "lym-install")
                .send()
                .map_err(|e| format!("Failed to download file {}: {}", name, e))?;

            if !file_resp.status().is_success() {
                eprintln!("{}", format!("Failed to download file {}: HTTP {}", name, file_resp.status()).red());
                pb.inc(1);
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
        pb.inc(1);
    }
    pb.finish_with_message("Download complete");

    println!("{}", format!("Package '{}' installed successfully.", pkg_name.bright_cyan()).bright_green());

    Ok(())
}

fn move_packages(args: &[String], disable: bool) {
    let no_confirm = args.iter().any(|a| a == "--no-confirm");
    let verbose = args.iter().any(|a| a == "-v");

    if args.iter().any(|a| a == "--help" || a == "-h") {
        let cmd_name = if disable { "disable" } else { "enable" };
        command_help(cmd_name);
        return;
    }

    let pkgs: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();

    if pkgs.is_empty() {
        eprintln!("{}", "Error: no packages specified".red());
        exit(1);
    }

    let lym_dir = match get_lym_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{}", format!("Failed to get lym dir: {}", e).red());
            exit(1);
        }
    };

    let config_path = lym_dir.join("config.json");
    let config_json: JsonValue = match fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config.json: {}", e))
        .and_then(|data| serde_json::from_str(&data).map_err(|e| format!("Invalid config.json: {}", e)))
    {
        Ok(j) => j,
        Err(e) => {
            eprintln!("{}", e.red());
            exit(1);
        }
    };

    let lucia_path_str = config_json.get("lucia_path")
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| {
            eprintln!("{}", "Lucia path not set in config.".red());
            exit(1);
        });

    let lucia_path = Path::new(lucia_path_str);
    let lucia_real = lucia_path.canonicalize().unwrap_or_else(|_| lucia_path.to_path_buf());
    let libs_dir = lucia_real
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(&lucia_real)
        .join("libs");

    let store_dir = lym_dir.join("store");

    if !store_dir.exists() {
        if let Err(e) = fs::create_dir_all(&store_dir) {
            eprintln!("{}", format!("Failed to create store dir: {}", e).red());
            exit(1);
        }
    }

    let mut valid_moves = vec![];

    for pkg_name in &pkgs {
        let (src_dir, dest_dir) = if disable {
            (libs_dir.join(pkg_name), store_dir.join(pkg_name))
        } else {
            (store_dir.join(pkg_name), libs_dir.join(pkg_name))
        };

        if !src_dir.exists() {
            if verbose {
                eprintln!("{}", format!("Skipping '{}': not found at {}", pkg_name, src_dir.display()).yellow());
            }
            continue;
        }

        let is_std = STD_LIBS.contains_key(pkg_name.as_str()) || *pkg_name == "std" || *pkg_name == "requests";

        if is_std && disable {
            // [Intentional Game Design]
            let cont = Confirm::new()
                .with_prompt(format!("'{}' is a standard library package. Disable anyway?", pkg_name.bright_cyan()))
                .default(false)
                .interact()
                .unwrap_or(false);

            if !cont {
                if verbose {
                    println!("{}", format!("Skipping '{}'", pkg_name).yellow());
                }
                continue;
            }
        }

        if is_std && !disable && !no_confirm {
            let cont = Confirm::new()
                .with_prompt(format!("Re-enabling stdlib package '{}'. Proceed?", pkg_name))
                .default(true)
                .interact()
                .unwrap_or(false);

            if !cont {
                if verbose {
                    println!("{}", format!("Skipping '{}'", pkg_name).yellow());
                }
                continue;
            }
        }

        valid_moves.push((pkg_name, src_dir, dest_dir));
    }

    if valid_moves.is_empty() {
        eprintln!("{}", "No valid packages to process.".bright_red());
        for pkg_name in &pkgs {
            let is_std = STD_LIBS.contains_key(pkg_name.as_str());
            let (src_dir, _) = if disable {
                (libs_dir.join(pkg_name), store_dir.join(pkg_name))
            } else {
                (store_dir.join(pkg_name), libs_dir.join(pkg_name))
            };
    
            if !src_dir.exists() {
                eprintln!("{}", format!("'{}' not found at {}", pkg_name, src_dir.display()).bright_red());
            } else if disable && is_std {
                eprintln!("{}", format!("'{}' is a standard library package — skipping disable (no confirm)", pkg_name).bright_red());
            } else if !disable && is_std {
                eprintln!("{}", format!("'{}' is a standard library package — skipping enable (no confirm)", pkg_name).bright_red());
            } else {
                eprintln!("{}", format!("'{}' was skipped", pkg_name).bright_red());
            }
        }
        exit(1);
    }    

    let pb = ProgressBar::new(valid_moves.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    for (pkg_name, src_dir, dest_dir) in valid_moves {
        pb.set_message(format!("Moving '{}'", pkg_name));
        if let Err(e) = fs::rename(&src_dir, &dest_dir) {
            pb.println(format!("{}", format!("Failed to move '{}': {}", pkg_name, e).red()));
        } else if verbose {
            pb.println(format!("{}", format!("Moved '{}'", pkg_name).green()));
        }
        pb.inc(1);
    }

    pb.finish_with_message("Move complete");
}

fn install(args: &[String]) {
    let mut no_confirm = false;
    let mut verbose = false;

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
            println!("Installing package '{}'", pkg_name.bright_cyan());
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
    let mut list_store = false;
    let mut show_std = true;

    for arg in args {
        match arg.as_str() {
            "--remote" => {
                list_remote = true;
                list_local = false;
                list_store = false;
            }
            "--no-desc" => show_desc = false,
            "--no-ver" => show_ver = false,
            "--local" => {
                list_local = true;
                list_remote = false;
                list_store = false;
            }
            "--store" => {
                list_store = true;
                list_local = false;
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
        let lucia_real = lucia_path.canonicalize().unwrap_or_else(|_| lucia_path.to_path_buf());
        let libs_dir = lucia_real
            .parent()
            .and_then(|p| p.parent())
            .map(|env_root| env_root.join("libs"))
            .unwrap_or_else(|| lucia_real.join("libs"));

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

    if list_store {
        let store_dir = lym_dir.join("store");
    
        if !store_dir.exists() || !store_dir.is_dir() {
            eprintln!("{}", format!("store directory not found at {}", store_dir.display()).red());
            return;
        }
    
        println!("{}", "Stored (disabled) modules:".bright_green().bold());
    
        let mut found_any = false;
    
        for entry in fs::read_dir(&store_dir).unwrap_or_else(|_| {
            eprintln!("{}", format!("Failed to read store dir at {}", store_dir.display()).red());
            exit(1);
        }) {
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
            println!("{}", "No stored modules found".yellow());
        }
    }

    if list_remote {
        let repo_url = config_json.get("repository").and_then(JsonValue::as_str);
        if repo_url.is_none() {
            eprintln!("{}", "Repository URL not set in config.".red());
            return;
        }

        let _repo_url = repo_url.unwrap();

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
    let mut no_confirm = false;
    let mut verbose = false;

    let mut positional_args = Vec::new();

    for arg in args {
        match arg.as_str() {
            "--no-confirm" => no_confirm = true,
            "-v" => verbose = true,
            "--help" | "-h" => {
                command_help("download");
                return;
            }
            _ if arg.starts_with('-') => {
                eprintln!("{}", format!("Unknown flag '{}'", arg).red());
                command_help("download");
                return;
            }
            _ => positional_args.push(arg.clone()),
        }
    }

    if positional_args.is_empty() {
        eprintln!("{}", "You must provide a package name.".red());
        command_help("download");
        return;
    }

    let package_name = &positional_args[0];
    let output_path = if positional_args.len() >= 2 {
        PathBuf::from(&positional_args[1])
    } else {
        PathBuf::from(format!("./{}/", package_name))
    };

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

    let repo_slug = match config_json.get("repository_slug").and_then(JsonValue::as_str) {
        Some(s) => s,
        None => {
            eprintln!("{}", "Repository slug not set in config.".red());
            return;
        }
    };

    let api_url = format!(
        "https://api.github.com/repos/{}/contents/libs/{}",
        repo_slug, package_name
    );

    let client = match Client::builder().timeout(Duration::from_secs(5)).build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", format!("Failed to build HTTP client: {}", e).red());
            return;
        }
    };

    let resp = match client.get(&api_url).header("User-Agent", "lym-download").send() {
        Ok(r) => r,
        Err(_) => {
            eprintln!("{}", "Failed to connect to GitHub API.".red());
            return;
        }
    };

    if !resp.status().is_success() {
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            eprintln!("{}", format!("Package '{}' not found in repository.", package_name).red());
        } else {
            eprintln!("{}", format!("GitHub API error: {}", resp.status()).red());
        }
        return;
    }

    let files: Vec<JsonValue> = match resp.json() {
        Ok(f) => f,
        Err(_) => {
            eprintln!("{}", "Failed to parse GitHub API response.".red());
            return;
        }
    };

    if !no_confirm {
        let confirm = Confirm::new()
            .with_prompt(format!("Download package '{}' into '{}'", package_name, output_path.display()))
            .default(true)
            .interact();

        if let Ok(false) | Err(_) = confirm {
            println!("{}", "Aborted.".yellow());
            return;
        }
    }

    if output_path.exists() && !output_path.is_dir() {
        eprintln!("{}", format!("Output path '{}' already exists and is not a directory.", output_path.display()).red());
        return;
    }

    if !output_path.exists() {
        if let Err(e) = fs::create_dir_all(&output_path) {
            eprintln!("{}", format!("Failed to create output directory '{}': {}", output_path.display(), e).red());
            return;
        }
    }

    for file in files {
        let name = file.get("name").and_then(JsonValue::as_str).unwrap_or("unknown");
        let download_url = file.get("download_url").and_then(JsonValue::as_str);
        if download_url.is_none() {
            if verbose {
                eprintln!("{}", format!("Skipping '{}': no download URL", name).red());
            }
            continue;
        }

        let url = download_url.unwrap();
        let dest_path = output_path.join(name);

        let file_resp = match client.get(url).header("User-Agent", "lym-download").send() {
            Ok(r) => r,
            Err(_) => {
                eprintln!("{}", format!("Failed to download '{}'", name).red());
                continue;
            }
        };

        if !file_resp.status().is_success() {
            eprintln!("{}", format!("Failed to fetch '{}': {}", name, file_resp.status()).red());
            continue;
        }

        let bytes = match file_resp.bytes() {
            Ok(b) => b,
            Err(_) => {
                eprintln!("{}", format!("Failed to read content of '{}'", name).red());
                continue;
            }
        };

        if let Err(e) = fs::write(&dest_path, &bytes) {
            eprintln!("{}", format!("Failed to write to {}: {}", dest_path.display(), e).red());
            continue;
        }

        if verbose {
            println!("{}", format!("Downloaded '{}'", dest_path.display()).bright_green());
        }
    }
    if verbose {
        println!("{}", format!("All files downloaded to '{}'", output_path.display()).bright_green());
    } else {
        println!("{}", "Download complete.".bright_green());
    }
}

fn remove(args: &[String]) {
    if args.is_empty() {
        eprintln!("{}", "Error: No package names provided.".red());
        command_help("remove");
        exit(1);
    }

    if cfg!(target_os = "windows") {
        let output = match Command::new("tasklist")
            .output()
            .map_err(|e| format!("Failed to execute tasklist: {}", e)) {
            Ok(output) => output,
            Err(e) => {
                eprintln!("{}", e.red());
                exit(1);
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.lines().any(|line| line.to_lowercase().starts_with("lucia.exe")) {
            eprintln!("{}", "Lucia is currently running. Please close it before removing packages.".red());
            exit(1);
        }
    } else {
        let output = match Command::new("pgrep")
            .arg("lucia")
            .output()
            .map_err(|e| format!("Failed to execute pgrep: {}", e)) {
            Ok(output) => output,
            Err(e) => {
                eprintln!("{}", e.red());
                exit(1);
            }
        };
        if !output.stdout.is_empty() {
            eprintln!("{}", "Lucia is currently running. Please close it before removing packages.".red());
            exit(1);
        }
    }

    let mut verbose = false;
    let mut no_confirm = false;
    let mut packages = vec![];

    for arg in args {
        match arg.as_str() {
            "-v" | "--verbose" => verbose = true,
            "--no-confirm" => no_confirm = true,
            "--help" | "-h" => {
                command_help("remove");
                return;
            }
            pkg => packages.push(pkg.to_string()),
        }
    }

    if packages.is_empty() {
        eprintln!("{}", "Error: No package names provided after flags.".red());
        command_help("remove");
        exit(1);
    }

    let lym_dir = match get_lym_dir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("{} {}", "Failed to get lym dir:".red(), e);
            exit(1);
        }
    };

    let config_path = lym_dir.join("config.json");
    let config_json = match fs::read_to_string(&config_path) {
        Ok(data) => match serde_json::from_str::<JsonValue>(&data) {
            Ok(json) => json,
            Err(e) => {
                eprintln!("{} {}", "Invalid config.json:".red(), e);
                exit(1);
            }
        },
        Err(e) => {
            eprintln!("{} {}", "Failed to read config.json:".red(), e);
            exit(1);
        }
    };

    let lucia_path_str = match config_json.get("lucia_path").and_then(JsonValue::as_str) {
        Some(path) => path,
        None => {
            eprintln!("{}", "Lucia path not set in config. Run lym config or reinstall lucia.".red());
            exit(1);
        }
    };

    let lucia_path = Path::new(lucia_path_str);
    let lucia_real = lucia_path.canonicalize().unwrap_or_else(|_| lucia_path.to_path_buf());
    let libs_dir = lucia_real
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(&lucia_real)
        .join("libs");

    for pkg_name in packages {
        if STD_LIBS.contains_key(pkg_name.as_str()) || pkg_name == "std" || pkg_name == "requests" {
            eprintln!("{}",
                format!("Error: Package '{}' is part of the standard library and cannot be removed.", pkg_name.bright_cyan())
                    .red()
            );
            continue;
        }

        let local_pkg_path = libs_dir.join(&pkg_name);

        if !local_pkg_path.exists() {
            println!("Package '{}' is not installed, skipping.", pkg_name.bright_cyan());
            if verbose {
                println!("{} {}", "Package not found at:".yellow(), local_pkg_path.display());
            }
            continue;
        }

        if !no_confirm {
            let confirm = match Confirm::new()
                .with_prompt(format!("Remove package '{}' ? (Y/n)", pkg_name.bright_cyan()))
                .default(false)
                .interact()
            {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{} {}", "Prompt error:".red(), e);
                    exit(1);
                }
            };

            if !confirm {
                if verbose {
                    println!("Removal of package '{}' cancelled by user.", pkg_name);
                }
                continue;
            }
        }

        if verbose {
            println!("Removing package directory {}", local_pkg_path.display());
        }

        let pb = ProgressBar::new_spinner();
        pb.set_message(format!("Removing package '{}'", pkg_name.bright_cyan()));
        pb.enable_steady_tick(Duration::from_millis(100));

        if let Err(e) = fs::remove_dir_all(&local_pkg_path) {
            pb.finish_and_clear();
            eprintln!("{} {}", format!("Failed to remove package directory '{}':", local_pkg_path.display()).red(), e);
            exit(1);
        }

        pb.finish_with_message(format!("Package '{}' removed", pkg_name));
    }
}

fn disable(args: &[String]) {
    move_packages(args, true);
}

fn enable(args: &[String]) {
    move_packages(args, false);
}

fn config(args: &[String]) {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        command_help("config");
        return;
    }

    let target = args[0].as_str();
    if target != "lym" && target != "lucia" && target != "fetch" {
        eprintln!("{}", "First argument must be 'lym', 'lucia', or 'fetch'.".red());
        command_help("config");
        return;
    }

    let mut set_pair: Option<(String, String)> = None;
    let mut get_key: Option<String> = None;
    let mut no_confirm = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--no-confirm" => {
                no_confirm = true;
                i += 1;
            }
            "--set" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("{}", "--set requires a <key=value> argument.".red());
                    return;
                }
                let kv = &args[i];
                if let Some(pos) = kv.find('=') {
                    let key = kv[..pos].to_string();
                    let value = kv[pos + 1..].to_string();
                    set_pair = Some((key, value));
                } else {
                    eprintln!("{}", "--set argument must be in key=value format.".red());
                    return;
                }
                i += 1;
            }
            "--get" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("{}", "--get requires a <key> argument.".red());
                    return;
                }
                get_key = Some(args[i].clone());
                i += 1;
            }
            _ => {
                eprintln!("{}", format!("Unknown argument '{}'.", args[i]).red());
                return;
            }
        }
    }

    if set_pair.is_some() && get_key.is_some() && target != "fetch" {
        eprintln!("{}", "Cannot use --set and --get together.".red());
        return;
    }

    if set_pair.is_none() && get_key.is_none() && target != "fetch" {
        eprintln!("{}", "You must provide either --set or --get.".red());
        return;
    }

    let lym_dir = match get_lym_dir() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", format!("Failed to get lym dir: {}", e).red());
            return;
        }
    };

    let config_path = match target {
        "lucia" => {
            let main_config_path = lym_dir.join("config.json");
            let main_config_json: JsonValue = fs::read_to_string(&main_config_path)
                .ok()
                .and_then(|data| serde_json::from_str(&data).ok())
                .unwrap_or_else(|| json!({}));

            let lucia_path_str = match main_config_json.get("lucia_path").and_then(JsonValue::as_str) {
                Some(p) => p,
                None => {
                    eprintln!("{}", "Failed to get lucia path from main config.".red());
                    return;
                }
            };

            let lucia_path = Path::new(lucia_path_str);
            let lucia_real = lucia_path.canonicalize().unwrap_or_else(|_| lucia_path.to_path_buf());
            match lucia_real.parent().map(|parent| parent.join("config.json")) {
                Some(path) => path,
                None => {
                    eprintln!("{}", "Could not resolve lucia config path.".red());
                    return;
                }
            }
        }
        "lym" | "fetch" => lym_dir.join("config.json"),
        _ => unreachable!(),
    };

    if target == "fetch" {
        let old_uuid = fs::read_to_string(&config_path)
            .ok()
            .and_then(|s| serde_json::from_str::<JsonValue>(&s).ok())
            .and_then(|json| json.get("build_info")?.get("uuid")?.as_str().map(|s| s.to_string()));
    
        fs::remove_file(&config_path).ok();
        fs::write(&config_path, "{}").ok();
    
        match update_config_with_lucia_info(&config_path) {
            Ok(_) => {
                let new_uuid = fs::read_to_string(&config_path)
                    .ok()
                    .and_then(|s| serde_json::from_str::<JsonValue>(&s).ok())
                    .and_then(|json| json.get("build_info")?.get("uuid")?.as_str().map(|s| s.to_string()));
    
                println!("{}", format!("Successfully fetched config at {}", config_path.display()).green());
    
                match (old_uuid, new_uuid) {
                    (Some(old), Some(new)) if old != new => {
                        println!(
                            "{}",
                            format!("Lucia UUID changed from '{}' to '{}'", old.bold(), new.bold()).blue()
                        );
                    }
                    (Some(old), Some(_new)) => {
                        println!("{}", format!("Lucia UUID remained '{}'", old.bold()).blue());
                    }
                    _ => {
                        println!("{}", "Could not compare build_info.uuid".dimmed());
                    }
                }
            }
            Err(e) => {
                eprintln!("{}", format!("Failed to update fetch config: {}", e).red());
                return;
            }
        }
        return;
    }    

    if let Some((key, value)) = set_pair {
        let mut config_json: serde_json::Map<String, JsonValue> = if config_path.exists() {
            match fs::read_to_string(&config_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
            {
                Some(JsonValue::Object(map)) => map,
                _ => {
                    eprintln!("{}", "Failed to read or parse config file.".red());
                    return;
                }
            }
        } else {
            serde_json::Map::new()
        };

        if config_json.contains_key(&key) && !no_confirm {
            let confirm = Confirm::new()
                .with_prompt(format!("Key '{}' exists, overwrite?", key))
                .default(false)
                .interact()
                .unwrap_or(false);

            if !confirm {
                println!("{}", "Aborted.".yellow());
                return;
            }
        }

        config_json.insert(key, JsonValue::String(value));

        let json_str = match serde_json::to_string_pretty(&config_json) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("{}", "Failed to serialize config.".red());
                return;
            }
        };

        if let Err(e) = fs::write(&config_path, json_str) {
            eprintln!("{}", format!("Failed to write config: {}", e).red());
        } else {
            println!("{}", format!("Config updated at {}", config_path.display()).green());
        }

    } else if let Some(key) = get_key {
        let config_json: JsonValue = fs::read_to_string(&config_path)
            .ok()
            .and_then(|data| serde_json::from_str(&data).ok())
            .unwrap_or_else(|| json!({}));

        match config_json.get(&key) {
            Some(val) => println!("{}", val),
            None => eprintln!("{}", format!("Key '{}' not found in config.", key).yellow()),
        }
    }
}

fn modify(args: &[String]) {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        command_help("modify");
        return;
    }

    let mut args = args.iter();
    let name = match args.next() {
        Some(n) => n,
        None => {
            eprintln!("{}", "Package name is required.".red());
            command_help("modify");
            return;
        }
    };

    let mut stored = false;
    let mut no_confirm = false;
    let mut key_path = Vec::new();
    let mut value_path = Vec::new();
    let mut key_found = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--stored" => stored = true,
            "--no-confirm" => no_confirm = true,
            "--help" | "-h" => {
                command_help("modify");
                return;
            }
            _ => {
                if !key_found {
                    key_path.push(arg.clone());
                    key_found = true;
                } else {
                    value_path.push(arg.clone());
                }
            }
        }
    }

    if key_path.is_empty() {
        eprintln!("{}", "Missing key.".red());
        return;
    }

    let lym_dir = match get_lym_dir() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", format!("Failed to get lym dir: {}", e).red());
            return;
        }
    };

    let package_path = if stored {
        lym_dir.join("store").join(name)
    } else {
        let main_config_path = lym_dir.join("config.json");
        let main_config_json: JsonValue = fs::read_to_string(&main_config_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| json!({}));
    
        match main_config_json
            .get("lucia_path")
            .and_then(JsonValue::as_str)
            .map(PathBuf::from)
            .and_then(|p| {
                let real = p.canonicalize().unwrap_or_else(|_| p);
                real.parent().and_then(|p| p.parent()).map(|env_root| env_root.join("libs").join(name))
            })
        {
            Some(path) => path,
            None => {
                eprintln!("{}", "Failed to locate lucia libs path.".red());
                return;
            }
        }
    };
    
    if !package_path.exists() {
        eprintln!(
            "{}",
            format!("Package '{}' is not installed (no directory at {})", name, package_path.display()).red()
        );
        return;
    }
    
    let manifest_path = package_path.join("manifest.json");
    if !manifest_path.exists() {
        eprintln!("{}", format!("No manifest found at {}", manifest_path.display()).red());
        return;
    }    

    let manifest_path = package_path.join("manifest.json");
    if !manifest_path.exists() {
        eprintln!("{}", format!("No manifest found at {}", manifest_path.display()).red());
        return;
    }

    let mut manifest_json: JsonValue = match fs::read_to_string(&manifest_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(json) => json,
        None => {
            eprintln!("{}", "Failed to read or parse manifest.".red());
            return;
        }
    };

    let mut current = &mut manifest_json;
    for (i, part) in key_path.iter().enumerate() {
        if i == key_path.len() - 1 {
            break;
        }

        current = current
            .as_object_mut()
            .and_then(|map| {
                if !map.contains_key(part) {
                    map.insert(part.clone(), json!({}));
                }
                map.get_mut(part)
            })
            .unwrap_or_else(|| {
                eprintln!("{}", "Invalid path in manifest.".red());
                std::process::exit(1);
            });
    }

    let last_key = key_path.last().unwrap();

    if value_path.is_empty() {
        match current.get(last_key) {
            Some(v) => println!("{}", v),
            None => eprintln!("{}", format!("Key '{}' not found.", last_key).yellow()),
        }
    } else {
        let new_value = if value_path.len() == 1 {
            JsonValue::String(value_path[0].clone())
        } else {
            JsonValue::Array(value_path.into_iter().map(JsonValue::String).collect())
        };

        let exists = current.get(last_key).is_some();
        if exists && !no_confirm {
            let confirm = Confirm::new()
                .with_prompt(format!("Key '{}' exists, overwrite?", last_key))
                .default(false)
                .interact()
                .unwrap_or(false);

            if !confirm {
                println!("{}", "Aborted.".yellow());
                return;
            }
        }

        if let Some(map) = current.as_object_mut() {
            map.insert(last_key.clone(), new_value);
        } else {
            eprintln!("{}", "Failed to write to manifest.".red());
            return;
        }

        match serde_json::to_string_pretty(&manifest_json) {
            Ok(json_str) => {
                if let Err(e) = fs::write(&manifest_path, json_str) {
                    eprintln!("{}", format!("Failed to write manifest: {}", e).red());
                } else {
                    println!("{}", format!("Manifest updated at {}", manifest_path.display()).green());
                }
            }
            Err(_) => eprintln!("{}", "Failed to serialize updated manifest.".red()),
        }
    }
}

fn new(args: &[String]) {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        command_help("new");
        return;
    }

    let mut args = args.iter();
    let kind = match args.next() {
        Some(k) if k == "package" || k == "module" => k.as_str(),
        _ => {
            eprintln!("{}", "First argument must be 'package' or 'module'.".red());
            command_help("new");
            return;
        }
    };

    let name = match args.next() {
        Some(n) => n,
        None => {
            eprintln!("{}", "Missing name argument.".red());
            command_help("new");
            return;
        }
    };

    let path = match args.next() {
        Some(p) => PathBuf::from(p),
        None => {
            let current_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            current_dir.join(name)
        }
    };

    let mut no_confirm = false;
    let mut main_file = String::from("__init__.lc");

    for arg in args {
        if arg == "--no-confirm" {
            no_confirm = true;
        } else if let Some(file) = arg.strip_prefix("--main-file:") {
            main_file = file.to_string();
        } else if arg == "--help" || arg == "-h" {
            command_help("new");
            return;
        } else {
            eprintln!("{}", format!("Unknown option '{}'", arg).yellow());
            command_help("new");
            return;
        }
    }

    if path.exists() && !no_confirm {
        let confirm = Confirm::new()
            .with_prompt(format!("Path '{}' already exists. Overwrite?", path.display()))
            .default(false)
            .interact()
            .unwrap_or(false);
        if !confirm {
            println!("{}", "Aborted.".yellow());
            return;
        }
        fs::remove_dir_all(&path).ok();
    }

    if let Err(e) = fs::create_dir_all(&path) {
        eprintln!("{}", format!("Failed to create path: {}", e).red());
        return;
    }

    let lym_dir = match get_lym_dir() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", format!("Failed to get lym dir: {}", e).red());
            return;
        }
    };

    match kind {
        "package" => {
            let manifest_path = path.join("manifest.json");
            let main_config_path = lym_dir.join("config.json");
            let main_config_json: JsonValue = fs::read_to_string(&main_config_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_else(|| json!({}));
            
            let required_version = main_config_json
                .get("build_info")
                .and_then(|bi| bi.get("version"))
                .and_then(JsonValue::as_str)
                .unwrap_or("0.0.0")
                .to_string();
            
            let manifest = json!({
                "name": name,
                "version": "0.1.0",
                "description": "",
                "required_lucia_version": format!("^{}", required_version),
            });            

            if let Err(e) = fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap()) {
                eprintln!("{}", format!("Failed to write manifest: {}", e).red());
                return;
            }

            if fs::write(path.join(&main_file), r#"print("Hello world")"#).is_err() {
                eprintln!("{}", "Failed to create main file.".red());
            }

            println!("{}", format!("New package created at {}", path.display()).green());
        }

        "module" => {
            let module_path = path.join(format!("{}.lc", name));
            if let Err(e) = fs::create_dir_all(&path) {
                eprintln!("{}", format!("Failed to create module directory: {}", e).red());
                return;
            }

            if fs::write(&module_path, "fun main() -> void:\n    print(\"Hello world\")\nend\n\nmain()\n".as_bytes()).is_err() {
                eprintln!("{}", "Failed to create module file.".red());
                return;
            }

            println!("{}", format!("New module '{}' created at {}", name, module_path.display()).green());
        }

        _ => unreachable!(),
    }
}

fn main() {
    if let Err(e) = ensure_lym_dirs() {
        eprintln!("{}", format!("Failed to setup ~/.lym directory: {}", e).red());
        exit(1);
    }

    let lym_dir = get_lym_dir().expect("Failed to get lym dir");
    let config_path = lym_dir.join("config.json");

    let main_config_json: JsonValue = fs::read_to_string(&config_path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_else(|| json!({}));

    let lucia_path_str = match main_config_json.get("lucia_path").and_then(JsonValue::as_str) {
        Some(p) => p,
        None => {
            eprintln!("{}", "Failed to get lucia path from main config.".red());
            return;
        }
    };

    let lucia_path = Path::new(lucia_path_str);
    // Resolve symlinks for lucia_path
    let lucia_real_path = match lucia_path.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", format!("Failed to resolve lucia symlink: {}", e).red());
            return;
        }
    };
    let libs_path = match lucia_real_path.parent().and_then(|p| p.parent()) {
        Some(env_root) => env_root.join("libs.json"),
        None => {
            eprintln!("{}", "Could not resolve lucia config path.".red());
            return;
        }
    };

    if let Err(err) = load_std_libs(&libs_path) {
        eprintln!("{}", format!("Failed to load standard libraries: {}", err).red());
        exit(1);
    }

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
