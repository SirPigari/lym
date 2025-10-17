use base64::{engine::general_purpose, Engine as _};
use colored::*;
use dialoguer::{Confirm, self};

use getch_rs::{Getch, Key};
use indicatif::{ProgressBar, ProgressStyle, self};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, AUTHORIZATION};
use serde_json::{Value as JsonValue, Value, json};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::io::{stdout, stdin, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, exit};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::time::{interval, Duration as TokioDuration};

mod db;
mod utils;

use db::{STD_LIBS, load_std_libs};
use utils::{check_version, parse_bytes, format_bytes, json_type, is_next_version, find_closest_match, cmp_version, git_blob_hash, get_current_platform, should_ignore_file, LymConfig};

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

    let lym_auth_path = lym_dir.join("lym_auth.json");
    if !lym_auth_path.exists() {
        fs::write(&lym_auth_path, "{}")?;
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
        .unwrap_or("https://github.com/SirPigari/lym-libs");

    let (repo_slug, final_repo_url) = {
        let url = original_repo_url.trim_end_matches('/');

        if let Some(user_and_repo) = url.strip_prefix("https://github.com/") {
            let parts: Vec<&str> = user_and_repo.split('/').collect();
            if parts.len() >= 1 {
                let user = parts[0];
                let slug = format!("{}/lym-libs", user);
                let full_url = format!("https://github.com/{}", slug);

                let mut headers = HeaderMap::new();
                headers.insert(USER_AGENT, HeaderValue::from_static("lym-checker"));

                if let Some((username, token)) = get_lym_auth() {
                    let auth_val = general_purpose::STANDARD.encode(format!("{}:{}", username, token));
                    let auth_header = format!("Basic {}", auth_val);
                    headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_header).unwrap());
                }

                let client = Client::builder()
                    .default_headers(headers)
                    .timeout(Duration::from_secs(30))
                    .build()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to build reqwest client: {}", e)))?;

                if github_repo_exists(&client, &slug) {
                    (slug, full_url)
                } else {
                    ("SirPigari/lym-libs".to_string(), "https://github.com/SirPigari/lym-libs".to_string())
                }
            } else {
                ("SirPigari/lym-libs".to_string(), "https://github.com/SirPigari/lym-libs".to_string())
            }
        } else {
            ("SirPigari/lym-libs".to_string(), "https://github.com/SirPigari/lym-libs".to_string())
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

fn update_lym_auth(username: &str, token: &str) -> io::Result<()> {
    let lym_dir = get_lym_dir()?;
    let lym_auth_path = lym_dir.join("lym_auth.json");

    let mut auth_json: JsonValue = if lym_auth_path.exists() {
        let data = fs::read_to_string(&lym_auth_path)?;
        serde_json::from_str(&data).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    auth_json["username"] = json!(username);
    auth_json["token"] = json!(token);

    let serialized = serde_json::to_string_pretty(&auth_json)?;
    fs::write(lym_auth_path, serialized)?;

    Ok(())
}

fn get_lym_auth() -> Option<(String, String)> {
    let lym_dir = get_lym_dir().ok()?;
    let auth_path = lym_dir.join("lym_auth.json");
    let data = fs::read_to_string(auth_path).ok()?;
    let json: Value = serde_json::from_str(&data).ok()?;
    let username = json.get("username")?.as_str()?.to_string();
    let token = json.get("token")?.as_str()?.to_string();
    Some((username, token))
}

fn collect_files(base: &Path, current: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(current).unwrap_or_else(|_| {
        eprintln!("{}", "Failed to read directory contents".red());
        exit(1);
    }) {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() {
            files.push(path.strip_prefix(base).unwrap().to_path_buf());
        } else if path.is_dir() {
            files.extend(collect_files(base, &path));
        }
    }
    files
}

fn print_help() {
    println!(
        "{} - {}\n\n{}:\n  {} <command> [args]\n\n{}:\n  {}   Install a package\n  {}      List installed packages\n  {}  Download a package\n  {}    Remove a package\n  {}   Disable a package\n  {}    Enable a package\n  {}    Set configuration options (lucia or lym)\n  {}    Modify package manifest\n  {}   Publish a package\n  {}     Login a user\n  {}       Create a new package\n\n{} 'lym <command> --help' {} for more info on a command.\n",
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
        "publish".bright_cyan(),
        "login".bright_cyan(),
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
                "[--remote | --local | --store] [--no-desc] [-u] [-i] [--no-ver] [--no-std] [--help] [package_name]".bright_yellow(),
                "Lists installed packages or remote packages.\nUse -u for ultra-fast listing without descriptions.\nUse -i/--info-all for comprehensive information about all packages.".bright_white()
            );
        }
        "install" => {
            println!(
                "{} {} {} {}\n\n{}",
                "Usage:".bright_green().bold(),
                "lym".bright_cyan().bold(),
                "install".bright_cyan(),
                "[package_name] [--no-confirm] [-v] [--target <platform>] [-t <platform>] [--help]".bright_yellow(),
                "Installs a package from the remote repository.".bright_white()
            );
            println!("{}", "Options:".bright_green());
            println!("  --no-confirm        Skip confirmation prompts");
            println!("  -v                  Enable verbose output");
            println!("  --target <platform> Target specific platform(s) (can be used multiple times)");
            println!("  -t <platform>       Short form of --target");
            println!("  -t<platform>        Compact form (e.g., -twindows)");
            println!("  -t all / -tall      Target all platforms (windows, linux, macos)");
            println!("  --help, -h          Show this help message");
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
        "publish" => {
            println!(
                "{} {} {} {}\n\n{}",
                "Usage:".bright_green().bold(),
                "lym".bright_cyan().bold(),
                "publish".bright_cyan(),
                "[path] [--no-confirm] [-v] [--help]".bright_yellow(),
                "Publishes a package to the remote repository.".bright_white()
            );
        }
        "login" => {
            println!(
                "{} {} {} {}\n\n{}",
                "Usage:".bright_green().bold(),
                "lym".bright_cyan().bold(),
                "login".bright_cyan(),
                "[--help]".bright_yellow(),
                "Logs in a user by storing their GitHub username and Personal Access Token.".bright_white()
            );
        }
        _ => {
            eprintln!("{}", format!("Unknown command: '{}'", cmd).red().bold());
            print_help();
        }
    }
}

pub fn check_and_close_lucia(no_confirm: bool) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let processes: Vec<u32> = {
        let output = Command::new("tasklist")
            .output()
            .map_err(|e| format!("Failed to execute tasklist: {}", e))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.lines()
            .filter(|line| line.to_lowercase().starts_with("lucia.exe"))
            .filter_map(|line| line.split_whitespace().nth(1)?.parse::<u32>().ok())
            .collect()
    };

    #[cfg(not(target_os = "windows"))]
    let processes: Vec<u32> = {
        let output = Command::new("pgrep")
            .arg("lucia")
            .output()
            .map_err(|e| format!("Failed to execute pgrep: {}", e))?;
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .collect()
    };

    if processes.is_empty() {
        return Ok(());
    }

    if no_confirm {
        for pid in &processes {
            #[cfg(target_os = "windows")]
            { let _ = Command::new("taskkill").args(&["/PID", &pid.to_string(), "/F"]).status(); }
            #[cfg(not(target_os = "windows"))]
            { let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status(); }
        }
        println!("All running Lucia processes were closed automatically.");
        return Ok(());
    }

    let mut close_all = false;
    let g = Getch::new();

    for pid in &processes {
        if close_all {
            #[cfg(target_os = "windows")]
            { let _ = Command::new("taskkill").args(&["/PID", &pid.to_string(), "/F"]).status(); }
            #[cfg(not(target_os = "windows"))]
            { let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status(); }
            continue;
        }

        loop {
            print!("Lucia process {} is running. Close it? ([Y]es/[A]ll/[N]one) ", pid);
            stdout().flush().unwrap();

            let choice = match g.getch() {
                Ok(Key::Char(c)) => c.to_ascii_lowercase(),
                Ok(Key::Esc) => 'n',
                _ => continue,
            };
            println!();

            match choice {
                'y' => {
                    #[cfg(target_os = "windows")]
                    { let _ = Command::new("taskkill").args(&["/PID", &pid.to_string(), "/F"]).status(); }
                    #[cfg(not(target_os = "windows"))]
                    { let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status(); }
                    break;
                }
                'a' => {
                    close_all = true;
                    #[cfg(target_os = "windows")]
                    { let _ = Command::new("taskkill").args(&["/PID", &pid.to_string(), "/F"]).status(); }
                    #[cfg(not(target_os = "windows"))]
                    { let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status(); }
                    break;
                }
                'n' => return Err("Lucia is currently running. Please close it before installing packages.".to_string()),
                _ => {
                    println!("Please press Y, A, or N.");
                    continue;
                }
            }
        }
    }

    Ok(())
}

async fn download_files_async(
    _client: &Client,
    files_to_download: Vec<(String, String, PathBuf, String, u64)>,
    pb: &ProgressBar,
) -> Result<(), String> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("lym/1.0"));
    
    let config_json = std::fs::read_to_string(&get_lym_dir().unwrap().join("config.json")).ok()
        .and_then(|content| serde_json::from_str::<JsonValue>(&content).ok());
    
    if let Some(config) = &config_json {
        if let (Some(username), Some(token)) = (
            config.get("github_username").and_then(JsonValue::as_str),
            config.get("github_token").and_then(JsonValue::as_str)
        ) {
            let auth_val = general_purpose::STANDARD.encode(format!("{}:{}", username, token));
            let auth_header = format!("Basic {}", auth_val);
            headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_header).unwrap());
        }
    }
    
    let async_client = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(120))
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(30))
        .tcp_keepalive(Duration::from_secs(60))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .http2_keep_alive_timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to build async HTTP client: {}", e))?;
    
    let download_progress = Arc::new(Mutex::new(HashMap::<String, (u64, u64)>::new()));
    
    let download_tasks: Vec<_> = files_to_download.into_iter().map(|(download_url, relative_path, local_file_path, _sha, size)| {
        let client = async_client.clone();
        let pb_clone = pb.clone();
        let rel_path_clone = relative_path.clone();
        let progress_clone = download_progress.clone();
        
        async move {
            if let Some(parent) = local_file_path.parent() {
                if let Err(e) = tokio::fs::create_dir_all(parent).await {
                    eprintln!("Failed to create directory '{}': {}", parent.display(), e);
                    pb_clone.inc(1);
                    return;
                }
            }
            
            let timeout_secs = std::cmp::max(30, std::cmp::min(300, 30 + (size / (1024 * 1024)) * 10));
            
            let (resume_from, file_mode) = match tokio::fs::metadata(&local_file_path).await {
                Ok(metadata) => {
                    let existing_size = metadata.len();
                    if existing_size < size {
                        (existing_size, "append")
                    } else if existing_size == size {
                        pb_clone.inc(1);
                        return;
                    } else {
                        (0, "create")
                    }
                },
                Err(_) => (0, "create"),
            };
            
            let mut request = client.get(&download_url)
                .timeout(Duration::from_secs(timeout_secs));
            
            if resume_from > 0 {
                request = request.header("Range", format!("bytes={}-", resume_from));
            }
            
            {
                let mut progress = progress_clone.lock().unwrap();
                progress.insert(rel_path_clone.clone(), (resume_from, size));
            }
            
            match request.send().await {
                Ok(resp) => {
                    let is_partial_content = resp.status().as_u16() == 206;
                    let is_success = resp.status().is_success() || is_partial_content;
                    
                    if !is_success {
                        eprintln!("{}", format!("Failed to download file {}: HTTP {}", relative_path, resp.status()).red());
                        pb_clone.inc(1);
                        return;
                    }
                    
                    let mut downloaded = resume_from;
                    let mut stream = resp.bytes_stream();
                    
                    let file_result = if file_mode == "append" && resume_from > 0 {
                        tokio::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&local_file_path).await
                    } else {
                        tokio::fs::File::create(&local_file_path).await
                    };
                    
                    match file_result {
                        Ok(mut file) => {
                            use tokio::io::AsyncWriteExt;
                            let mut write_success = true;
                            
                            while let Some(chunk) = stream.next().await {
                                match chunk {
                                    Ok(bytes) => {
                                        downloaded += bytes.len() as u64;
                                        
                                        if let Err(e) = file.write_all(&bytes).await {
                                            eprintln!("Failed to write chunk to '{}': {}", local_file_path.display(), e);
                                            write_success = false;
                                            break;
                                        }
                                        
                                        {
                                            let mut progress = progress_clone.lock().unwrap();
                                            progress.insert(rel_path_clone.clone(), (downloaded, size));
                                        }
                                    },
                                    Err(e) => {
                                        eprintln!("Error downloading '{}': {}", relative_path, e);
                                        write_success = false;
                                        break;
                                    }
                                }
                            }
                            
                            if write_success {
                                if let Err(e) = file.flush().await {
                                    eprintln!("Failed to flush file '{}': {}", local_file_path.display(), e);
                                }
                            }
                        },
                        Err(e) => {
                            eprintln!("Failed to create file '{}': {}", local_file_path.display(), e);
                        }
                    }
                },
                Err(e) => {
                    eprintln!("Failed to download '{}': {}", relative_path, e);
                }
            }
            
            pb_clone.inc(1);
        }
    }).collect();
    
    let progress_updater = {
        let progress_clone = download_progress.clone();
        let pb_clone = pb.clone();
        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_millis(200));
            tokio::time::sleep(TokioDuration::from_millis(10)).await;
            
            loop {
                interval.tick().await;
                
                let mut progress_map = progress_clone.lock().unwrap();
                if progress_map.is_empty() {
                    break;
                }
                
                let mut file_statuses = Vec::new();
                let mut completed_files = Vec::new();
                
                let mut active_downloads: Vec<(String, u64, u64, u64)> = Vec::new();
                
                for (filename, (downloaded, total)) in progress_map.iter() {
                    if *downloaded >= *total {
                        completed_files.push(filename.clone());
                    } else {
                        active_downloads.push((filename.clone(), *downloaded, *total, *total));
                    }
                }
                
                active_downloads.sort_by(|a, b| b.3.cmp(&a.3));
                
                for (filename, downloaded, total, _) in active_downloads {
                    file_statuses.push(format!("{} ({}/{})", 
                        filename, 
                        format_bytes(downloaded), 
                        format_bytes(total)
                    ));
                }
                
                for filename in completed_files {
                    progress_map.remove(&filename);
                }
                
                if file_statuses.is_empty() {
                    break;
                }
                
                drop(progress_map);
                
                let message = if file_statuses.len() <= 3 {
                    file_statuses.join(", ")
                } else {
                    format!("{}, {} more...", 
                        file_statuses[..2].join(", "), 
                        file_statuses.len() - 2
                    )
                };
                
                pb_clone.set_message(message);
            }
        })
    };
    
    let mut stream = FuturesUnordered::new();
    let mut tasks = download_tasks.into_iter();
    
    let concurrency_limit = if tasks.len() <= 5 {
        std::cmp::min(3, tasks.len())
    } else if tasks.len() <= 20 {
        std::cmp::min(6, tasks.len())
    } else if tasks.len() <= 50 {
        std::cmp::min(10, tasks.len())
    } else {
        std::cmp::min(15, tasks.len())
    };
    
    for _ in 0..concurrency_limit {
        if let Some(task) = tasks.next() {
            stream.push(task);
        }
    }
    
    while let Some(_) = stream.next().await {
        if let Some(task) = tasks.next() {
            stream.push(task);
        }
    }
    
    progress_updater.abort();
    
    Ok(())
}

fn install_single_package(
    pkg_name: &str,
    no_confirm: bool,
    verbose: bool,
    output_path: Option<&Path>,
    target_platforms: &[String],
) -> Result<(), String> {
    check_and_close_lucia(no_confirm)?;

    let (package_name, requested_version) = if let Some(at_pos) = pkg_name.rfind('@') {
        let name = &pkg_name[..at_pos];
        let version = &pkg_name[at_pos + 1..];
        (name, Some(version))
    } else {
        (pkg_name, None)
    };

    if !no_confirm {
        let result = Confirm::new()
            .with_prompt(format!("Install package '{}'?", package_name))
            .default(true)
            .interact()
            .map_err(|e| format!("Failed to read user input: {}", e))?;
        if !result {
            return Err("Installation cancelled by user.".to_string());
        }
    }

    let lym_dir = get_lym_dir().map_err(|e| format!("Failed to get lym dir: {}", e))?;
    let config_path = lym_dir.join("config.json");
    let config_json: JsonValue = fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config.json: {}", e))
        .and_then(|data| serde_json::from_str(&data).map_err(|e| format!("Invalid config.json: {}", e)))?;

    let lucia_path = Path::new(
        config_json.get("lucia_path")
            .and_then(JsonValue::as_str)
            .ok_or("Lucia path not set in config. Run lym config or reinstall lucia.")?
    );
    let lucia_real = lucia_path.canonicalize().unwrap_or_else(|_| lucia_path.to_path_buf());
    let libs_dir = lucia_real.parent()
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

    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("lym-install"));

    if let Some((username, token)) = get_lym_auth() {
        let auth_val = general_purpose::STANDARD.encode(format!("{}:{}", username, token));
        let auth_header = format!("Basic {}", auth_val);
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_header).unwrap());
    }

    let client = Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let versions_url = format!("https://api.github.com/repos/{}/contents/{}", repo_slug, package_name);
    let resp = client.get(&versions_url)
        .send()
        .map_err(|e| format!("Failed to fetch package versions: {}", e))?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        let root_url = format!("https://api.github.com/repos/{}/contents/", repo_slug);
        let all_packages: Vec<String> = client.get(&root_url)
            .send().ok()
            .and_then(|r| r.json::<Vec<JsonValue>>().ok())
            .map(|items| items.iter()
                .filter_map(|item| item.get("name").and_then(JsonValue::as_str).map(|s| s.to_string()))
                .collect())
            .unwrap_or_default();

        if let Some(s) = find_closest_match(package_name, &all_packages) {
            return Err(format!("Package '{}' not found. Did you mean '{}'?", package_name, s));
        } else {
            return Err(format!("Package '{}' not found.", package_name));
        }
    }

    let resp_val: JsonValue = resp.json::<JsonValue>()
        .map_err(|e| format!("Failed to parse remote versions: {}", e))?;

    let remote_items: Vec<JsonValue> = match resp_val {
        JsonValue::Array(arr) => arr,
        JsonValue::Object(obj) => {
            if let Some(msg) = obj.get("message") {
                return Err(format!("Failed to fetch package '{}': {}", package_name, msg));
            } else {
                return Err(format!("Unexpected response when fetching package '{}'", package_name));
            }
        },
        _ => return Err(format!("Unexpected response type when fetching package '{}'", package_name)),
    };

    let mut version_dirs: Vec<String> = remote_items.iter()
        .filter_map(|item| {
            let name = item.get("name")?.as_str()?;
            if name.starts_with('@') { Some(name[1..].to_string()) } else { None }
        })
        .collect();

    if version_dirs.is_empty() {
        return Err(format!("No versions found for package '{}'", package_name));
    }

    version_dirs.sort_by(|a, b| cmp_version(a, b).unwrap_or(Ordering::Equal));
    
    let chosen_version = if let Some(req_ver) = requested_version {
        if version_dirs.contains(&req_ver.to_string()) {
            req_ver.to_string()
        } else {
            return Err(format!("Version '{}' not found for package '{}'. Available versions: {:?}", 
                req_ver, package_name, version_dirs));
        }
    } else {
        version_dirs.last().unwrap().clone()
    };
    if verbose {
        println!("{}", format!("Installing '{}' version '{}'", package_name, chosen_version).bright_cyan());
    }

    let local_pkg_path = output_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| libs_dir.join(package_name));

    let mut installed_version: Option<String> = None;
    if local_pkg_path.exists() {
        let manifest_file = local_pkg_path.join("manifest.json");
        if manifest_file.exists() {
            if let Ok(data) = fs::read_to_string(&manifest_file) {
                if let Ok(manifest_json) = serde_json::from_str::<JsonValue>(&data) {
                    if let Some(ver) = manifest_json.get("version").and_then(JsonValue::as_str) {
                        installed_version = Some(ver.to_string());
                    }
                }
            }
        }
    }

    if let Some(inst_ver) = installed_version.clone() {
        if cmp_version(&chosen_version, &inst_ver) == Some(Ordering::Greater) {
            println!("{}", format!("Upgrading '{}' from version '{}' -> '{}'", package_name, inst_ver, chosen_version).bright_blue());
        } else if cmp_version(&chosen_version, &inst_ver) == Some(Ordering::Less) {
            if !no_confirm {
                print!("Installed version '{}' is newer than '{}'. Downgrade? ([Y]/n) ", inst_ver, chosen_version);
                stdout().flush().unwrap();
                let g = Getch::new();
                let c = match g.getch() {
                    Ok(Key::Char(c)) => c.to_ascii_lowercase(),
                    Ok(Key::Esc) => 'n',
                    _ => 'n',
                };
                println!();
                if c != 'y' { return Ok(()); }
            }
            println!("{}", format!("Downgrading '{}' from version '{}' -> '{}'", package_name, inst_ver, chosen_version).bright_yellow());
        } else {
            if !no_confirm {
                let download = Confirm::new()
                    .with_prompt(format!("Package '{}' is already at version '{}'. Install anyway?", package_name, chosen_version))
                    .default(true)
                    .interact()
                    .map_err(|e| format!("Failed to read user input: {}", e))?;
                if !download {
                    println!("{}", format!("Skipping '{}'", package_name).bright_green());
                    return Ok(());
                }
            } else {
                println!("{}", format!("Package '{}' already at version '{}', proceeding with download due to no-confirm", package_name, chosen_version).bright_yellow());
            }
        }
        fs::remove_dir_all(&local_pkg_path)
            .map_err(|e| format!("Failed to remove existing package directory: {}", e))?;
    }

    fs::create_dir_all(&local_pkg_path)
        .map_err(|e| format!("Failed to create package directory: {}", e))?;

    let lym_config_url = format!(
        "https://api.github.com/repos/{}/contents/{}/@{}/lym.json",
        repo_slug, package_name, chosen_version
    );
    
    let mut lym_config = LymConfig::default();

    if let Ok(lym_resp) = client.get(&lym_config_url).send() {
        if lym_resp.status().is_success() {
            if let Ok(lym_json) = lym_resp.json::<JsonValue>() {
                if let Some(encoded_content) = lym_json.get("content").and_then(JsonValue::as_str) {
                    let content = encoded_content.replace('\n', "");
                    if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(&content) {
                        if let Ok(config_str) = String::from_utf8(decoded_bytes) {
                            if let Ok(config_json) = serde_json::from_str::<JsonValue>(&config_str) {
                                if verbose {
                                    println!("{}", "Found lym.json configuration".bright_cyan());
                                }
                                
                                if let Some(ignore) = config_json.get("ignore").and_then(JsonValue::as_array) {
                                    lym_config.ignore = ignore.iter()
                                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                        .collect();
                                }
                                
                                if let Some(platforms) = config_json.get("supported_platforms").and_then(JsonValue::as_array) {
                                    lym_config.supported_platforms = platforms.iter()
                                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                        .collect();
                                }
                                
                                if let Some(platform_ignore) = config_json.get("platform_ignore").and_then(JsonValue::as_object) {
                                    for (platform, patterns) in platform_ignore {
                                        if let Some(pattern_arr) = patterns.as_array() {
                                            lym_config.platform_ignore.insert(
                                                platform.clone(),
                                                pattern_arr.iter()
                                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                                    .collect()
                                            );
                                        }
                                    }
                                }
                                
                                if let Some(scripts) = config_json.get("scripts").and_then(JsonValue::as_object) {
                                    for (script_name, script_path) in scripts {
                                        if let Some(path) = script_path.as_str() {
                                            lym_config.scripts.insert(script_name.clone(), path.to_string());
                                        }
                                    }
                                }
                                
                                if let Some(options) = config_json.get("options").and_then(JsonValue::as_object) {
                                    if let Some(overwrite) = options.get("overwrite_existing").and_then(JsonValue::as_bool) {
                                        lym_config.overwrite_existing = overwrite;
                                    }
                                    if let Some(update_fresh) = options.get("update_fresh").and_then(JsonValue::as_bool) {
                                        lym_config.update_fresh = update_fresh;
                                    }
                                }
                                
                                if let Some(ignore_hashes) = config_json.get("ignore_hashes").and_then(JsonValue::as_object) {
                                    for (path_or_hash, hash) in ignore_hashes {
                                        if let Some(hash_str) = hash.as_str() {
                                            lym_config.ignore_hashes.insert(path_or_hash.clone(), hash_str.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let current_platform = get_current_platform();
    
    let all_platforms = vec!["windows".to_string(), "linux".to_string(), "macos".to_string(), "freebsd".to_string()];
    let is_all_specified = target_platforms.len() == 4 && 
        all_platforms.iter().all(|p| target_platforms.contains(p));
    
    let mut platforms_to_check = if target_platforms.is_empty() {
        vec![current_platform.to_string()]
    } else {
        target_platforms.to_vec()
    };
    
    if !lym_config.supported_platforms.contains(&current_platform.to_string()) {
        return Err(format!(
            "Package '{}' does not support current platform '{}'. Supported platforms: {:?}",
            package_name, current_platform, lym_config.supported_platforms
        ));
    }
    
    if is_all_specified {
        let mut filtered_platforms = Vec::new();
        
        for platform in &platforms_to_check {
            if lym_config.supported_platforms.contains(platform) {
                filtered_platforms.push(platform.clone());
            } else if verbose {
                println!("{}", format!("Skipping unsupported platform: {}", platform).yellow());
            }
        }
        
        platforms_to_check = filtered_platforms;
        
        if platforms_to_check.is_empty() {
            return Err(format!(
                "Package '{}' does not support any of the requested platforms. Supported platforms: {}",
                package_name, lym_config.supported_platforms.join(", ")
            ));
        }
    } else {
        for platform in &platforms_to_check {
            if !lym_config.supported_platforms.contains(platform) {
                return Err(format!(
                    "Package '{}' does not support platform '{}'. Supported platforms: {}",
                    package_name, platform, lym_config.supported_platforms.join(", ")
                ));
            }
        }
    }
    
    if verbose && !target_platforms.is_empty() {
        if platforms_to_check.len() == 1 {
            println!("{}", format!("Installing for target platform: {}", platforms_to_check[0]).bright_cyan());
        } else {
            println!("{}", format!("Installing for target platforms: {}", platforms_to_check.join(", ")).bright_cyan());
        }
    }

    if lym_config.update_fresh && local_pkg_path.exists() {
        if verbose {
            println!("{}", "Fresh install enabled - cleaning package directory".bright_yellow());
        }
        fs::remove_dir_all(&local_pkg_path)
            .map_err(|e| format!("Failed to clean package directory for fresh install: {}", e))?;
        fs::create_dir_all(&local_pkg_path)
            .map_err(|e| format!("Failed to recreate package directory: {}", e))?;
    }

    let manifest_url = format!(
        "https://api.github.com/repos/{}/contents/{}/@{}/manifest.json",
        repo_slug, package_name, chosen_version
    );
    let fetch_pb = ProgressBar::new_spinner();
    fetch_pb.set_message("Fetching manifest.json...");
    fetch_pb.enable_steady_tick(Duration::from_millis(100));

    let resp = client.get(&manifest_url)
        .send()
        .map_err(|e| format!("Failed to fetch manifest.json: {}", e))?;

    fetch_pb.finish_and_clear();
    if !resp.status().is_success() {
        return Err(format!("Failed to fetch manifest.json: HTTP {}", resp.status()));
    }

    let manifest_json: JsonValue = resp.json()
        .map_err(|e| format!("Failed to parse manifest.json from remote: {}", e))?;

    let encoded_content = manifest_json.get("content")
        .and_then(JsonValue::as_str)
        .ok_or("manifest.json content missing in remote response")?
        .replace('\n', "");

    let decoded_bytes = general_purpose::STANDARD.decode(&encoded_content)
        .map_err(|e| format!("Failed to decode manifest.json content: {}", e))?;

    let manifest_str = String::from_utf8(decoded_bytes.clone())
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
        println!("{}", format!("Checking lucia version: required '{}' vs current '{}'",
            required_version.bright_green(), current_version.bright_green()));
    }

    if !check_version(current_version, required_version) {
        eprintln!("{}", format!(
            "Warning: Package '{}' requires lucia version '{}', but current version is '{}'",
            package_name, required_version, current_version
        ).yellow());

        if !no_confirm {
            let cont = Confirm::new()
                .with_prompt("Continue installation anyway? (Y/n)")
                .default(false)
                .interact()
                .map_err(|e| format!("Prompt error: {}", e))?;

            if !cont {
                if verbose { println!("{}", "Install cancelled due to version mismatch.".yellow()); }
                return Ok(());
            }
        }
    }

    if let Some(deps) = manifest.get("dependencies").and_then(JsonValue::as_object) {
        let deps = deps.iter().filter(|(name, _)| !STD_LIBS.contains_key(name.as_str())).collect::<Vec<(&String, &JsonValue)>>();
        if !deps.is_empty() {
            println!("{}", "Dependencies found:".bright_yellow());
            for (dep_name, dep_version_val) in &deps {
                let dep_version = dep_version_val.as_str().unwrap_or("*");
                println!("  {}@{}", dep_name, dep_version);
            }

            let g = Getch::new();
            let mut install_all = false;
            let mut install_each = false;

            loop {
                print!("Install dependencies? ([Y]es/[A]ll/[N]one) ");
                stdout().flush().unwrap();

                let choice = match g.getch() {
                    Ok(Key::Char(c)) => c.to_ascii_lowercase(),
                    Ok(Key::Esc) => 'n',
                    _ => continue,
                };
                println!();

                match choice {
                    'y' => { install_each = true; break; },
                    'a' => { install_all = true; break; },
                    'n' => break,
                    _ => { println!("Please press Y, A, or N."); continue; }
                }
            }

            if install_each || install_all {
                let mut deps_to_install = Vec::new();
                
                for (dep_name, dep_version_val) in deps {
                    let dep_version = dep_version_val.as_str().unwrap_or("*");
                    let dep_path = libs_dir.join(dep_name);
                    let mut dep_installed_version: Option<String> = None;
                    if dep_path.exists() {
                        let dep_manifest = dep_path.join("manifest.json");
                        if dep_manifest.exists() {
                            if let Ok(data) = fs::read_to_string(&dep_manifest) {
                                if let Ok(json) = serde_json::from_str::<JsonValue>(&data) {
                                    dep_installed_version = json.get("version").and_then(JsonValue::as_str).map(|s| s.to_string());
                                }
                            }
                        }
                    }

                    if let Some(inst_ver) = dep_installed_version.clone() {
                        if inst_ver == dep_version {
                            if verbose { println!("Dependency '{}' already at version '{}', skipping", dep_name, inst_ver); }
                            continue;
                        }
                        if cmp_version(&dep_version, &inst_ver) == Some(Ordering::Greater) {
                            println!("{}", format!("Upgrading dependency '{}' from '{}' -> '{}'", dep_name, inst_ver, dep_version).bright_blue());
                        } else if cmp_version(&dep_version, &inst_ver) == Some(Ordering::Less) {
                            if !no_confirm {
                                print!("Installed version '{}' of '{}' is newer than '{}'. Downgrade? ([Y]/n) ", inst_ver, dep_name, dep_version);
                                stdout().flush().unwrap();
                                let c = match g.getch() {
                                    Ok(Key::Char(c)) => c.to_ascii_lowercase(),
                                    Ok(Key::Esc) => 'n',
                                    _ => 'n',
                                };
                                println!();
                                if c != 'y' { continue; }
                            }
                            println!("{}", format!("Downgrading dependency '{}' from '{}' -> '{}'", dep_name, inst_ver, dep_version).bright_yellow());
                        } else {
                            if !no_confirm {
                                let download = Confirm::new()
                                    .with_prompt(format!("Dependency '{}' is already at version '{}'. Install anyway?", dep_name, inst_ver))
                                    .default(true)
                                    .interact()
                                    .map_err(|e| format!("Failed to read user input: {}", e))?;
                                if !download {
                                    println!("{}", format!("Skipping '{}'", dep_name).bright_green());
                                    continue;
                                }
                            } else {
                                println!("{}", format!("Dependency '{}' already at version '{}', proceeding with download due to no-confirm", dep_name, inst_ver).bright_yellow());
                            }
                        }
                        fs::remove_dir_all(&dep_path).ok();
                    }
                    
                    deps_to_install.push(dep_name.clone());
                }
                
                if !deps_to_install.is_empty() {
                    let runtime = tokio::runtime::Runtime::new()
                        .map_err(|e| format!("Failed to create async runtime for dependencies: {}", e))?;
                    
                    runtime.block_on(async {
                        use futures::stream::{FuturesUnordered, StreamExt};
                        let mut stream = FuturesUnordered::new();
                        let mut dep_tasks = deps_to_install.into_iter();
                        
                        for _ in 0..std::cmp::min(3, dep_tasks.len()) {
                            if let Some(dep_name) = dep_tasks.next() {
                                let platforms_clone = platforms_to_check.clone();
                                stream.push(tokio::task::spawn_blocking(move || {
                                    install_single_package(&dep_name, no_confirm, verbose, None, &platforms_clone)
                                }));
                            }
                        }
                        
                        while let Some(result) = stream.next().await {
                            match result {
                                Ok(install_result) => {
                                    if let Err(e) = install_result {
                                        return Err(e);
                                    }
                                },
                                Err(e) => return Err(format!("Dependency installation task failed: {}", e)),
                            }
                            
                            if let Some(dep_name) = dep_tasks.next() {
                                let platforms_clone = platforms_to_check.clone();
                                stream.push(tokio::task::spawn_blocking(move || {
                                    install_single_package(&dep_name, no_confirm, verbose, None, &platforms_clone)
                                }));
                            }
                        }
                        
                        Ok::<(), String>(())
                    })?;
                }
            }
        }
    }

    let mut all_ignore_patterns = lym_config.ignore.clone();
    
    if is_all_specified {
        if verbose {
            println!("{}", "Targeting all platforms - skipping platform-specific ignore patterns".bright_cyan());
        }
    } else {
        for platform in &platforms_to_check {
            if let Some(platform_patterns) = lym_config.platform_ignore.get(platform) {
                all_ignore_patterns.extend(platform_patterns.clone());
            }
        }
    }

    fn should_download_file(
        relative_path: &str, 
        ignore_patterns: &[String],
        local_file_path: &Path,
        remote_sha: &str,
        overwrite_existing: bool,
        ignore_hashes: &HashMap<String, String>
    ) -> bool {
        if should_ignore_file(relative_path, ignore_patterns) {
            return false;
        }

        if ignore_hashes.contains_key(remote_sha) {
            return false;
        }

        if let Some(ignored_hash) = ignore_hashes.get(relative_path) {
            if ignored_hash == remote_sha {
                return false;
            }
        }

        if !overwrite_existing && local_file_path.exists() {
            if let Ok(local_hash) = git_blob_hash(local_file_path) {
                if local_hash == remote_sha {
                    return false;
                }
            }
        }

        true
    }

    fn collect_files_to_download(
        client: &Client,
        repo_slug: &str,
        remote_path: &str,
        local_base_path: &Path,
        package_root: &str,
        ignore_patterns: &[String],
        overwrite_existing: bool,
        ignore_hashes: &HashMap<String, String>,
    ) -> Result<Vec<(String, String, PathBuf, String, u64)>, String> {
        let mut files_to_download = Vec::new();
        let mut stack = vec![(remote_path.to_string(), local_base_path.to_path_buf())];

        while let Some((current_remote_path, current_local_path)) = stack.pop() {
            let items: Vec<JsonValue> = client
                .get(&format!("https://api.github.com/repos/{}/contents/{}", repo_slug, current_remote_path))
                .send()
                .map_err(|e| format!("Failed to fetch '{}': {}", current_remote_path, e))?
                .json()
                .map_err(|e| format!("Failed to parse JSON for '{}': {}", current_remote_path, e))?;

            for item in items {
                let name = item.get("name").and_then(JsonValue::as_str).ok_or("Missing name")?;
                let item_type = item.get("type").and_then(JsonValue::as_str).unwrap_or("");
                let local_item_path = current_local_path.join(name);

                let relative_path = if current_remote_path == package_root {
                    format!("./{}", name)
                } else {
                    let relative_dir = current_remote_path.strip_prefix(&format!("{}/", package_root))
                        .unwrap_or(current_remote_path.strip_prefix(package_root).unwrap_or(""));
                    if relative_dir.is_empty() {
                        format!("./{}", name)
                    } else {
                        format!("{}/{}", relative_dir, name)
                    }
                };

                if item_type == "file" {
                    let sha = item.get("sha").and_then(JsonValue::as_str).unwrap_or("");
                    let download_url = item.get("download_url").and_then(JsonValue::as_str)
                        .ok_or_else(|| format!("File '{}' missing download_url", name))?;
                    let size = item.get("size").and_then(JsonValue::as_u64).unwrap_or(0);

                    if should_download_file(&relative_path, ignore_patterns, &local_item_path, sha, overwrite_existing, ignore_hashes) {
                        files_to_download.push((
                            download_url.to_string(),
                            relative_path,
                            local_item_path,
                            sha.to_string(),
                            size
                        ));
                    }
                } else if item_type == "dir" {
                    stack.push((format!("{}/{}", current_remote_path, name), local_item_path));
                }
            }
        }

        Ok(files_to_download)
    }

    let api_url = format!("{}/@{}", package_name, chosen_version);
    
    let lucia_executable = Path::new(
        config_json.get("lucia_path")
            .and_then(JsonValue::as_str)
            .ok_or("Lucia path not set in config. Cannot run scripts.")?
    );

    let execute_script = |script_name: &str, script_file: &str| -> Result<(), String> {
        let script_path = local_pkg_path.join(script_file);
        if !script_path.exists() {
            if verbose {
                println!("{}", format!("Script '{}' not found at {}", script_name, script_path.display()).yellow());
            }
            return Ok(());
        }

        if verbose {
            println!("{}", format!("Running {} script: {}", script_name, script_file).bright_cyan());
        }

        let original_dir = std::env::current_dir()
            .map_err(|e| format!("Failed to get current directory: {}", e))?;

        std::env::set_current_dir(&local_pkg_path)
            .map_err(|e| format!("Failed to change to package directory: {}", e))?;

        let output = Command::new(&lucia_executable)
            .arg(&script_file)
            .output()
            .map_err(|e| format!("Failed to execute {} script: {}", script_name, e))?;

        std::env::set_current_dir(&original_dir)
            .map_err(|e| format!("Failed to restore original directory: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let exit_code = output.status.code().unwrap_or(-1);
            
            if script_name == "test" {
                return Err(format!("{} script failed with exit code {}: {}", 
                    script_name, exit_code, stderr));
            } else {
                eprintln!("{}", format!("Warning: {} script failed with exit code {}: {}", 
                    script_name, exit_code, stderr).yellow());
                if verbose {
                    println!("{}", format!("{} script failed but continuing installation", script_name).yellow());
                }
                return Ok(());
            }
        }

        if verbose {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.trim().is_empty() {
                println!("{} output: {}", script_name, stdout.trim());
            }
            println!("{}", format!("{} script completed successfully", script_name).bright_green());
        }

        Ok(())
    };

    let all_files_to_download = collect_files_to_download(
        &client,
        repo_slug,
        &api_url,
        &local_pkg_path,
        &api_url,
        &all_ignore_patterns,
        lym_config.overwrite_existing,
        &lym_config.ignore_hashes,
    )?;

    let script_names: Vec<String> = lym_config.scripts.values().cloned().collect();
    let mut script_files = Vec::new();
    let mut other_files = Vec::new();

    for file_info in all_files_to_download {
        let (download_url, relative_path, local_file_path, sha, size) = file_info;
        let filename = Path::new(&relative_path).file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
            
        if script_names.iter().any(|script| script == filename || relative_path.ends_with(script)) {
            script_files.push((download_url, relative_path, local_file_path, sha, size));
        } else {
            other_files.push((download_url, relative_path, local_file_path, sha, size));
        }
    }

    if !script_files.is_empty() {
        if verbose {
            println!("{}", "Downloading script files...".bright_cyan());
        }
        
        if !script_files.is_empty() {
            if verbose {
                println!("{}", format!("Downloading {} script files...", script_files.len()).cyan());
            }
            let script_pb = ProgressBar::new(script_files.len() as u64);
            script_pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|e| format!("Failed to create async runtime for scripts: {}", e))?;
            
            runtime.block_on(async {
                download_files_async(&client, script_files, &script_pb).await
            })?;
            
            script_pb.finish_with_message("Script download complete");
        }
    }

    if let Some(pre_install_script) = lym_config.scripts.get("pre_install") {
        let _ = execute_script("pre-install", pre_install_script);
    }

    let files_to_download = other_files;

    let total_files = files_to_download.len() as u64;
    if verbose {
        println!("{}", format!("Found {} files to download", total_files).bright_cyan());
        if !all_ignore_patterns.is_empty() {
            println!("{}", format!("Ignoring patterns: {:?}", all_ignore_patterns).yellow());
        }
    }

    let pb = ProgressBar::new(total_files);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message("Starting downloads...");

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Failed to create async runtime: {}", e))?;
    
    runtime.block_on(async {
        download_files_async(&client, files_to_download, &pb).await
    })?;

    pb.finish_with_message("All downloads completed");

    if let Some(post_install_script) = lym_config.scripts.get("post_install") {
        execute_script("post-install", post_install_script)?;
    }

    if let Some(test_script) = lym_config.scripts.get("test") {
        execute_script("test", test_script)?;
    }

    println!("{}", format!("Package '{}@{}' installed successfully.", package_name, chosen_version).bright_green());

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
    let mut target_platforms = Vec::new();

    let mut packages = Vec::new();
    let mut i = 0;
    
    while i < args.len() {
        let arg = &args[i];
        
        match arg.as_str() {
            "--no-confirm" => no_confirm = true,
            "-v" => verbose = true,
            "--help" | "-h" => {
                command_help("install");
                return;
            }
            "--target" => {
                if i + 1 < args.len() {
                    i += 1;
                    let platform = &args[i];
                    if platform == "all" {
                        target_platforms.extend_from_slice(&["windows".to_string(), "linux".to_string(), "macos".to_string(), "freebsd".to_string()]);
                    } else {
                        target_platforms.push(platform.clone());
                    }
                } else {
                    eprintln!("{}", "Error: --target requires a platform argument".red());
                    command_help("install");
                    return;
                }
            }
            arg if arg.starts_with("-t") => {
                if arg == "-t" {
                    if i + 1 < args.len() {
                        i += 1;
                        let platform = &args[i];
                        if platform == "all" {
                            target_platforms.extend_from_slice(&["windows".to_string(), "linux".to_string(), "macos".to_string(), "freebsd".to_string()]);
                        } else {
                            target_platforms.push(platform.clone());
                        }
                    } else {
                        eprintln!("{}", "Error: -t requires a platform argument".red());
                        command_help("install");
                        return;
                    }
                } else {
                    let platform = &arg[2..];
                    if platform == "all" {
                        target_platforms.extend_from_slice(&["windows".to_string(), "linux".to_string(), "macos".to_string(), "freebsd".to_string()]);
                    } else if !platform.is_empty() {
                        target_platforms.push(platform.to_string());
                    } else {
                        eprintln!("{}", "Error: -t requires a platform argument".red());
                        command_help("install");
                        return;
                    }
                }
            }
            arg if arg.starts_with('-') => {
                eprintln!("{}", format!("Unknown argument: '{}'", arg).red());
                command_help("install");
                return;
            }
            _ => packages.push(arg.clone()),
        }
        i += 1;
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

        if let Err(e) = install_single_package(&pkg_name, no_confirm, verbose, None, &target_platforms) {
            eprintln!("{}", format!("Failed to install '{}': {}", pkg_name, e).red());
        }
    }
}

async fn list_remote_packages_async(repo_slug: &str, module_name_filter: &Option<String>, show_desc: bool, show_ver: bool, show_info_all: bool) {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("lym-list"));
    if let Some((username, token)) = get_lym_auth() {
        let auth_val = general_purpose::STANDARD.encode(format!("{}:{}", username, token));
        if let Ok(auth_header) = HeaderValue::from_str(&format!("Basic {}", auth_val)) {
            headers.insert(AUTHORIZATION, auth_header);
        }
    }

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(10)
        .tcp_keepalive(Duration::from_secs(60))
        .build()
        .unwrap_or_else(|e| {
            eprintln!("{}", format!("Failed to build HTTP client: {}", e).red());
            exit(1);
        });

    let api_url = format!("https://api.github.com/repos/{}/contents/", repo_slug);
    
    let resp = match client.get(&api_url).send().await {
        Ok(resp) if resp.status().is_success() => resp,
        Ok(resp) => {
            eprintln!("{}", format!("GitHub API error: HTTP {}", resp.status()).red());
            return;
        },
        Err(e) => {
            eprintln!("{}", format!("Failed to fetch package list: {}", e).red());
            return;
        }
    };

    let contents: Vec<JsonValue> = match resp.json().await {
        Ok(contents) => contents,
        Err(_) => {
            eprintln!("{}", "Failed to parse GitHub API response.".red());
            return;
        }
    };

    println!("{}", "Remote modules:".bright_green().bold());

    let mut package_names = Vec::new();
    for item in contents.iter() {
        let name = item.get("name").and_then(JsonValue::as_str).unwrap_or("");
        let item_type = item.get("type").and_then(JsonValue::as_str).unwrap_or("");
        
        if item_type != "dir" { continue; }
        if let Some(filter) = &module_name_filter {
            if name != filter { continue; }
        }
        
        package_names.push(name.to_string());
    }

    if package_names.is_empty() {
        return;
    }

    use futures::stream::{FuturesUnordered, StreamExt};
    let mut stream = FuturesUnordered::new();
    let mut pkg_iter = package_names.into_iter();

    for _ in 0..std::cmp::min(6, pkg_iter.len()) {
        if let Some(pkg_name) = pkg_iter.next() {
            let client_clone = client.clone();
            let repo_slug_clone = repo_slug.to_string();
            let filter_clone = module_name_filter.clone();
            
            stream.push(tokio::spawn(async move {
                process_remote_package_async(&client_clone, &repo_slug_clone, &pkg_name, &filter_clone, show_desc, show_ver, show_info_all).await
            }));
        }
    }

    while let Some(result) = stream.next().await {
        if let Ok(package_info) = result {
            if let Some(info) = package_info {
                println!("{}", info);
            }
        }

        if let Some(pkg_name) = pkg_iter.next() {
            let client_clone = client.clone();
            let repo_slug_clone = repo_slug.to_string();
            let filter_clone = module_name_filter.clone();
            
            stream.push(tokio::spawn(async move {
                process_remote_package_async(&client_clone, &repo_slug_clone, &pkg_name, &filter_clone, show_desc, show_ver, show_info_all).await
            }));
        }
    }
}

async fn process_remote_package_async(
    client: &reqwest::Client, 
    repo_slug: &str, 
    pkg_name: &str,
    module_name_filter: &Option<String>,
    show_desc: bool,
    show_ver: bool,
    show_info_all: bool
) -> Option<String> {
    let versions_url = format!("https://api.github.com/repos/{}/contents/{}", repo_slug, pkg_name);
    
    let versions_resp = match client.get(&versions_url).send().await {
        Ok(resp) if resp.status().is_success() => resp,
        _ => return None,
    };

    let version_dirs: Vec<JsonValue> = versions_resp.json().await.unwrap_or_default();
    let mut latest_version: Option<String> = None;
    let mut all_versions = vec![];

    for vdir in version_dirs.iter() {
        let vname = vdir.get("name").and_then(JsonValue::as_str).unwrap_or("");
        if !vname.starts_with('@') { continue; }
        let ver = &vname[1..];
        all_versions.push(ver.to_string());
        
        if let Some(lat) = &latest_version {
            if cmp_version(lat, ver) == Some(std::cmp::Ordering::Less) {
                latest_version = Some(ver.to_string());
            }
        } else { 
            latest_version = Some(ver.to_string()); 
        }
    }

    let latest_ver = latest_version?;

    if module_name_filter.is_some() || show_info_all {
        let manifest_url = format!(
            "https://api.github.com/repos/{}/contents/{}/@{}/manifest.json",
            repo_slug, pkg_name, latest_ver
        );

        if let Ok(manifest_resp) = client.get(&manifest_url).send().await {
            if let Ok(manifest_json) = manifest_resp.json::<JsonValue>().await {
                if let Some(content_encoded) = manifest_json.get("content").and_then(JsonValue::as_str) {
                    if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(content_encoded.replace('\n', "")) {
                        if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                            if let Ok(manifest) = serde_json::from_str::<JsonValue>(&decoded_str) {
                                let authors = manifest.get("authors")
                                    .and_then(JsonValue::as_array)
                                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect::<Vec<_>>())
                                    .unwrap_or_default();

                                let author_str = if authors.is_empty() { 
                                    "unknown".to_string() 
                                } else {
                                    authors.iter().map(|a| a.yellow().to_string()).collect::<Vec<_>>().join(", ")
                                };

                                println!("{} - {}", pkg_name.bright_cyan(), author_str);
                                
                                let versions_to_show = if all_versions.len() <= 5 {
                                    all_versions.clone()
                                } else {
                                    all_versions[all_versions.len()-5..].to_vec()
                                };
                                
                                use futures::stream::{FuturesUnordered, StreamExt};
                                let mut version_tasks = FuturesUnordered::new();
                                
                                for ver in &versions_to_show {
                                    let ver_manifest_url = format!(
                                        "https://api.github.com/repos/{}/contents/{}/@{}/manifest.json",
                                        repo_slug, pkg_name, ver
                                    );
                                    let client_clone = client.clone();
                                    let ver_clone = ver.clone();
                                    let latest_ver_clone = latest_ver.clone();
                                    
                                    version_tasks.push(async move {
                                        if let Ok(ver_resp) = client_clone.get(&ver_manifest_url).send().await {
                                            if let Ok(ver_json) = ver_resp.json::<JsonValue>().await {
                                                if let Some(ver_content) = ver_json.get("content").and_then(JsonValue::as_str) {
                                                    if let Ok(ver_decoded) = general_purpose::STANDARD.decode(ver_content.replace('\n', "")) {
                                                        if let Ok(ver_decoded_str) = String::from_utf8(ver_decoded) {
                                                            if let Ok(ver_manifest) = serde_json::from_str::<JsonValue>(&ver_decoded_str) {
                                                                let desc = ver_manifest.get("description").and_then(JsonValue::as_str).unwrap_or("");
                                                                let mut result = format!("   {} - {}", format!("v{}", ver_clone).green(), desc);
                                                                
                                                                if ver_clone == latest_ver_clone {
                                                                    if let Some(deps_obj) = ver_manifest.get("dependencies").and_then(JsonValue::as_object) {
                                                                        if !deps_obj.is_empty() {
                                                                            result += "\n   Dependencies:";
                                                                            for (dep_name, dep_version) in deps_obj {
                                                                                if let Some(dep_ver_str) = dep_version.as_str() {
                                                                                    result += &format!("\n     {} {}", dep_name.bright_magenta(), dep_ver_str.green());
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                                return Some((ver_clone, result));
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        None
                                    });
                                }
                                
                                let mut version_results = Vec::new();
                                while let Some(result) = version_tasks.next().await {
                                    if let Some((ver, output)) = result {
                                        version_results.push((ver, output));
                                    }
                                }
                                
                                version_results.sort_by(|a, b| {
                                    cmp_version(&b.0, &a.0).unwrap_or(std::cmp::Ordering::Equal)
                                });
                                
                                for (_, output) in version_results {
                                    println!("{}", output);
                                }
                                
                                return Some(String::new());
                            }
                        }
                    }
                }
            }
        }
    }

    let mut line = format!("  {}", pkg_name.bright_cyan());
    if show_ver {
        line += &format!(" v{}", latest_ver);
    }
    
    if show_desc {
        let manifest_url = format!(
            "https://api.github.com/repos/{}/contents/{}/@{}/manifest.json",
            repo_slug, pkg_name, latest_ver
        );

        if let Ok(manifest_resp) = client.get(&manifest_url).send().await {
            if let Ok(manifest_json) = manifest_resp.json::<JsonValue>().await {
                if let Some(content_encoded) = manifest_json.get("content").and_then(JsonValue::as_str) {
                    if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(content_encoded.replace('\n', "")) {
                        if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                            if let Ok(manifest) = serde_json::from_str::<JsonValue>(&decoded_str) {
                                if let Some(desc) = manifest.get("description").and_then(JsonValue::as_str) {
                                    if !desc.is_empty() {
                                        line += &format!(" - {}", desc);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Some(line)
}

fn list(args: &[String]) {
    let mut show_desc = true;
    let mut show_ver = true;
    let mut list_remote = false;
    let mut list_local = true;
    let mut list_store = false;
    let mut show_std = true;
    let mut show_info_all = false;
    let mut module_name_filter: Option<String> = None;

    for arg in args {
        match arg.as_str() {
            "--remote" => {
                list_remote = true;
                list_local = false;
                list_store = false;
            }
            "--no-desc" | "-u" | "--ultra-fast" => show_desc = false,
            "--no-ver" => show_ver = false,
            "--info-all" | "-i" => {
                show_info_all = true;
                show_desc = true;
                show_ver = true;
            },
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
                if arg.starts_with('-') {
                    eprintln!("{}", format!("Unknown argument: '{}'", arg).red());
                    command_help("list");
                    return;
                } else {
                    module_name_filter = Some(arg.clone());
                }
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

    let process_modules = |dir: &Path, list_std: bool, show_all_versions: bool| {
        if !dir.exists() || !dir.is_dir() {
            return;
        }

        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                let module_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("<unknown>");

                if let Some(ref filter) = module_name_filter {
                    if module_name != filter {
                        continue;
                    }
                }

                let is_std = STD_LIBS.contains_key(module_name);
                if !list_std && is_std {
                    continue;
                }

                let mut versions = vec![];
                let mut description: Option<String> = None;

                if path.is_dir() {
                    let manifest_path = path.join("manifest.json");
                    if manifest_path.exists() {
                        if let Ok(manifest_str) = fs::read_to_string(&manifest_path) {
                            if let Ok(manifest_json) = serde_json::from_str::<JsonValue>(&manifest_str) {
                                let current_version = manifest_json.get("version").and_then(JsonValue::as_str).unwrap_or("unknown").to_string();
                                versions.push(current_version);
                                description = manifest_json.get("description").and_then(JsonValue::as_str).map(|s| s.to_string());
                                
                                if show_all_versions {
                                    if let Some(authors_array) = manifest_json.get("authors").and_then(JsonValue::as_array) {
                                        let authors: Vec<String> = authors_array.iter()
                                            .filter_map(|v| v.as_str())
                                            .map(|s| s.to_string())
                                            .collect();
                                        if !authors.is_empty() {
                                            let author_str = authors.iter().map(|a| a.yellow().to_string()).collect::<Vec<_>>().join(", ");
                                            println!("   Authors: {}", author_str);
                                        }
                                    }
                                    
                                    if let Some(deps_obj) = manifest_json.get("dependencies").and_then(JsonValue::as_object) {
                                        if !deps_obj.is_empty() {
                                            println!("   Dependencies:");
                                            for (dep_name, dep_version) in deps_obj {
                                                if let Some(ver_str) = dep_version.as_str() {
                                                    println!("     {} {}", dep_name.bright_magenta(), ver_str.green());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if is_std {
                    if let Some(std_info) = STD_LIBS.get(module_name) {
                        versions.push(std_info.version.to_string());
                        description = Some(std_info.description.to_string());
                    }
                }

                for ver in versions {
                    let mut line = if is_std {
                        format!("  {} [standard lib]", module_name.bright_blue().bold())
                    } else {
                        format!("  {}", module_name.bright_cyan())
                    };

                    if show_ver {
                        line += &format!(" v{}", ver);
                    }
                    if show_desc {
                        if let Some(ref desc) = description {
                            if !desc.is_empty() {
                                line += &format!(" - {}", desc);
                            }
                        }
                    }

                    println!("{}", line);
                }
            }
        }
    };

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
        process_modules(&libs_dir, show_std, module_name_filter.is_some() || show_info_all);
    }

    if list_store {
        let store_dir = lym_dir.join("store");
        if !store_dir.exists() || !store_dir.is_dir() {
            eprintln!("{}", format!("store directory not found at {}", store_dir.display()).red());
            return;
        }

        println!("{}", "Stored modules:".bright_green().bold());
        process_modules(&store_dir, show_std, module_name_filter.is_some() || show_info_all);
    }

    if list_remote {
        let repo_slug = config_json.get("repository_slug").and_then(JsonValue::as_str);
        if repo_slug.is_none() {
            eprintln!("{}", "Repository slug not set in config.".red());
            return;
        }
        let repo_slug = repo_slug.unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap_or_else(|e| {
            eprintln!("{}", format!("Failed to create async runtime: {}", e).red());
            exit(1);
        });
        
        runtime.block_on(async {
            list_remote_packages_async(repo_slug, &module_name_filter, show_desc, show_ver, show_info_all).await;
        });
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

    let package_arg = &positional_args[0];
    let (package_name, requested_version) = match package_arg.split_once('@') {
        Some((name, version)) => (name, Some(version)),
        None => (package_arg.as_str(), None),
    };

    let output_path = if positional_args.len() >= 2 {
        std::path::PathBuf::from(&positional_args[1])
    } else {
        match get_lym_dir() {
            Ok(p) => p.join("libs").join(package_name),
            Err(e) => {
                eprintln!("{}", format!("Failed to get lym dir: {}", e).red());
                return;
            }
        }
    };

    let lym_dir = match get_lym_dir() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", format!("Failed to get lym dir: {}", e).red());
            return;
        }
    };

    let config_path = lym_dir.join("config.json");
    let config_json: serde_json::Value = fs::read_to_string(&config_path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    let repo_slug = match config_json.get("repository_slug").and_then(serde_json::Value::as_str) {
        Some(s) => s,
        None => {
            eprintln!("{}", "Repository slug not set in config.".red());
            return;
        }
    };

    let headers = {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("lym-download"));

        if let Some((username, token)) = get_lym_auth() {
            let auth_val = format!("Basic {}", general_purpose::STANDARD.encode(format!("{}:{}", username, token)));
            if let Ok(h) = HeaderValue::from_str(&auth_val) {
                headers.insert(AUTHORIZATION, h);
            }
        }

        headers
    };

    let client = match Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", format!("Failed to build HTTP client: {}", e).red());
            return;
        }
    };

    let version_folder = match requested_version {
        Some(v) => format!("@{}", v),
        None => {
            let api_url = format!("https://api.github.com/repos/{}/contents/{}", repo_slug, package_name);
            let resp = match client.get(&api_url).send() {
                Ok(r) => r,
                Err(_) => {
                    eprintln!("{}", "Failed to connect to GitHub API.".red());
                    return;
                }
            };
            if !resp.status().is_success() {
                eprintln!("{}", format!("GitHub API error: {}", resp.status()).red());
                return;
            }

            let items: Vec<serde_json::Value> = match resp.json() {
                Ok(f) => f,
                Err(_) => {
                    eprintln!("{}", "Failed to parse GitHub API response.".red());
                    return;
                }
            };

            let mut versions: Vec<String> = items
                .iter()
                .filter_map(|i| i.get("name").and_then(serde_json::Value::as_str))
                .filter(|n| n.starts_with('@'))
                .map(|s| s.to_string())
                .collect();

            versions.sort_by(|a, b| {
                cmp_version(&a[1..], &b[1..]).unwrap_or(std::cmp::Ordering::Equal)
            });

            if let Some(latest) = versions.last() {
                latest.clone()
            } else {
                eprintln!("{}", "No versions found for package.".red());
                return;
            }
        }
    };

    let final_output_path = output_path.join(&version_folder)
        .canonicalize()
        .unwrap_or(output_path.join(&version_folder));

    if !no_confirm {
        let confirm = dialoguer::Confirm::new()
            .with_prompt(format!("Download package '{}' into '{}'? ", package_name, final_output_path.display()))
            .default(true)
            .interact();

        if let Ok(false) | Err(_) = confirm {
            println!("{}", "Aborted.".yellow());
            return;
        }
    }

    if !final_output_path.exists() {
        if let Err(e) = fs::create_dir_all(&final_output_path) {
            eprintln!("{}", format!("Failed to create directory '{}': {}", final_output_path.display(), e).red());
            return;
        }
    }

    let api_url = format!("https://api.github.com/repos/{}/contents/{}/{}", repo_slug, package_name, version_folder);
    let resp = match client.get(&api_url).send() {
        Ok(r) => r,
        Err(_) => {
            eprintln!("{}", "Failed to connect to GitHub API.".red());
            return;
        }
    };
    if !resp.status().is_success() {
        eprintln!("{}", format!("Failed to fetch remote package: {}", resp.status()).red());
        return;
    }

    let files: Vec<serde_json::Value> = match resp.json() {
        Ok(f) => f,
        Err(_) => {
            eprintln!("{}", "Failed to parse remote package directory.".red());
            return;
        }
    };

    fn download_item(client: &Client, item: &serde_json::Value, dest: &Path, verbose: bool) {
        if let Some(name) = item.get("name").and_then(serde_json::Value::as_str) {
            let item_type = item.get("type").and_then(serde_json::Value::as_str).unwrap_or("");
            if item_type == "file" {
                if let Some(url) = item.get("download_url").and_then(serde_json::Value::as_str) {
                    let dest_path = dest.join(name);
                    let pb = ProgressBar::new_spinner();
                    pb.set_message(format!("Downloading {}", name));
                    pb.enable_steady_tick(Duration::from_millis(100));

                    if let Ok(resp) = client.get(url).send() {
                        if resp.status().is_success() {
                            if let Ok(bytes) = resp.bytes() {
                                let _ = fs::write(&dest_path, &bytes);
                                if verbose {
                                    pb.finish_with_message(format!("Downloaded '{}'", dest_path.display()));
                                } else {
                                    pb.finish_and_clear();
                                }
                            }
                        }
                    }
                }
            } else if item_type == "dir" {
                let sub_dir = dest.join(name);
                let _ = fs::create_dir_all(&sub_dir);

                if let Some(url) = item.get("url").and_then(serde_json::Value::as_str) {
                    if let Ok(resp) = client.get(url).send() {
                        if let Ok(children) = resp.json::<Vec<serde_json::Value>>() {
                            for child in children {
                                download_item(client, &child, &sub_dir, verbose);
                            }
                        }
                    }
                }
            }
        }
    }

    for file in &files {
        download_item(&client, file, &final_output_path, verbose);
    }

    println!("{}", format!("Package '{}' downloaded to '{}'", package_name, final_output_path.display()).bright_green());
}

fn remove(args: &[String]) {
    if args.is_empty() {
        eprintln!("{}", "Error: No package names provided.".red());
        command_help("remove");
        exit(1);
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

    match check_and_close_lucia(no_confirm) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{} {}", "Error:".red(), e);
            exit(1);
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

        let lym_config_path = local_pkg_path.join("lym.json");
        let mut uninstall_scripts = HashMap::new();
        
        if lym_config_path.exists() {
            if let Ok(config_str) = fs::read_to_string(&lym_config_path) {
                if let Ok(config_json) = serde_json::from_str::<JsonValue>(&config_str) {
                    if let Some(scripts) = config_json.get("scripts").and_then(JsonValue::as_object) {
                        for (script_name, script_path) in scripts {
                            if script_name == "pre_uninstall" || script_name == "post_uninstall" {
                                if let Some(path) = script_path.as_str() {
                                    uninstall_scripts.insert(script_name.clone(), path.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        let lucia_executable = Path::new(lucia_path_str);

        let execute_uninstall_script = |script_name: &str, script_file: &str| -> Result<(), String> {
            let script_path = local_pkg_path.join(script_file);
            if !script_path.exists() {
                if verbose {
                    println!("{}", format!("Script '{}' not found at {}", script_name, script_path.display()).yellow());
                }
                return Ok(());
            }

            if verbose {
                println!("{}", format!("Running {} script: {}", script_name, script_file).bright_cyan());
            }

            let original_dir = std::env::current_dir()
                .map_err(|e| format!("Failed to get current directory: {}", e))?;

            std::env::set_current_dir(&local_pkg_path)
                .map_err(|e| format!("Failed to change to package directory: {}", e))?;

            let output = Command::new(&lucia_executable)
                .arg(&script_file)
                .output()
                .map_err(|e| format!("Failed to execute {} script: {}", script_name, e))?;

            std::env::set_current_dir(&original_dir)
                .map_err(|e| format!("Failed to restore original directory: {}", e))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let exit_code = output.status.code().unwrap_or(-1);
                
                eprintln!("{}", format!("Warning: {} script failed with exit code {}: {}", 
                    script_name, exit_code, stderr).yellow());
                if verbose {
                    println!("{}", format!("{} script failed but continuing removal", script_name).yellow());
                }
                return Ok(());
            }

            if verbose {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.trim().is_empty() {
                    println!("{} output: {}", script_name, stdout.trim());
                }
                println!("{}", format!("{} script completed successfully", script_name).bright_green());
            }

            Ok(())
        };

        if let Some(pre_uninstall_script) = uninstall_scripts.get("pre_uninstall") {
            let _ = execute_uninstall_script("pre-uninstall", pre_uninstall_script);
        }

        if verbose {
            println!("Removing package directory {}", local_pkg_path.display());
        }

        let pb = ProgressBar::new_spinner();
        pb.set_message(format!("Removing package '{}'", pkg_name.bright_cyan()));
        pb.enable_steady_tick(Duration::from_millis(100));

        if let Some(post_uninstall_script) = uninstall_scripts.get("post_uninstall") {
            let _ = execute_uninstall_script("post-uninstall", post_uninstall_script);
        }

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

    let mut set_pairs: Vec<(String, String)> = Vec::new();
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
                while i < args.len() && !args[i].starts_with("--") {
                    let kv = &args[i];
                    if let Some(pos) = kv.find('=') {
                        let key = kv[..pos].to_string();
                        let value = kv[pos + 1..].to_string();
                        set_pairs.push((key, value));
                    } else {
                        eprintln!("{}", "--set arguments must be in key=value format.".red());
                        return;
                    }
                    i += 1;
                }
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

    if !set_pairs.is_empty() && get_key.is_some() && target != "fetch" {
        eprintln!("{}", "Cannot use --set and --get together.".red());
        return;
    }

    if set_pairs.is_empty() && get_key.is_none() && target != "fetch" {
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
            match lucia_real.parent().and_then(|p| p.parent()).map(|p| p.join("config.json")) {
                Some(path) => {
                    if !path.exists() {
                        eprintln!("{}", format!("Lucia config not found at {}", path.display()).red());
                        return;
                    }
                    path
                }
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
                        println!("{}", format!("Lucia UUID changed from '{}' to '{}'", old.bold(), new.bold()).blue());
                    }
                    (Some(old), Some(_)) => {
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

    let config_json: serde_json::Map<String, JsonValue> = if config_path.exists() {
        match fs::read_to_string(&config_path).ok().and_then(|s| serde_json::from_str(&s).ok()) {
            Some(JsonValue::Object(map)) => map,
            _ => {
                eprintln!("{}", "Failed to read or parse config file.".red());
                return;
            }
        }
    } else {
        serde_json::Map::new()
    };

    let mut key_order: Vec<String> = config_json.keys().cloned().collect();

    for (key_path, value) in set_pairs {
        if config_json.contains_key(&key_path) && !no_confirm {
            let confirm = Confirm::new()
                .with_prompt(format!("Key '{}' exists, overwrite?", key_path))
                .default(false)
                .interact()
                .unwrap_or(false);
            if !confirm {
                println!("{}", "Aborted.".yellow());
                return;
            }
        }

        let parsed_val = if let Some(num) = parse_bytes(&value) {
            if num <= u64::MAX as u128 {
                JsonValue::Number(serde_json::Number::from(num as u64))
            } else {
                JsonValue::String(value.clone())
            }
        } else if let Ok(num) = value.parse::<i64>() {
            JsonValue::Number(serde_json::Number::from(num))
        } else {
            JsonValue::String(value.clone())
        };

        let parts: Vec<&str> = key_path.split('.').collect();
        let last = parts.last().unwrap();
        let mut cur = &mut JsonValue::Object(config_json.clone());

        for part in &parts[..parts.len() - 1] {
            cur = match cur {
                JsonValue::Object(map) => map.entry(*part).or_insert(json!({})),
                JsonValue::Array(arr) => {
                    let idx = part.parse::<usize>().unwrap_or_else(|_| { eprintln!("Invalid index {}", part); exit(1); });
                    while arr.len() <= idx {
                        arr.push(json!({}));
                    }
                    &mut arr[idx]
                }
                _ => { eprintln!("Cannot traverse non-object/array for '{}'", part); return; }
            };
        }

        match cur {
            JsonValue::Object(map) => {
                map.insert(last.to_string(), parsed_val);
            }
            JsonValue::Array(arr) => {
                let idx = last.parse::<usize>().unwrap_or_else(|_| { eprintln!("Invalid index {}", last); exit(1); });
                while arr.len() <= idx {
                    arr.push(JsonValue::Null);
                }
                arr[idx] = parsed_val;
            }
            _ => { eprintln!("Cannot set value on non-object/array at '{}'", last); return; }
        }

        if !key_order.contains(&parts[0].to_string()) {
            key_order.push(parts[0].to_string());
        }
    }

    let mut ordered_json = serde_json::Map::new();
    for k in key_order {
        if let Some(v) = config_json.get(&k) {
            ordered_json.insert(k, v.clone());
        }
    }

    if let Err(e) = fs::write(&config_path, serde_json::to_string_pretty(&ordered_json).unwrap_or_else(|_| "{}".to_string())) {
        eprintln!("{}", format!("Failed to write config: {}", e).red());
    } else {
        println!("{}", format!("Config updated at {}", config_path.display()).green());
    }

    if let Some(key_path) = get_key {
        let mut cur: &JsonValue = &JsonValue::Object(config_json.clone());
        for part in key_path.split('.') {
            cur = match cur {
                JsonValue::Object(map) => map.get(part).unwrap_or(&JsonValue::Null),
                JsonValue::Array(arr) => arr.get(part.parse::<usize>().unwrap_or(usize::MAX)).unwrap_or(&JsonValue::Null),
                _ => &JsonValue::Null,
            };
        }
        if cur.is_null() {
            eprintln!("{}", format!("Key '{}' not found in config.", key_path).yellow());
        } else {
            println!("{} ({})", cur, json_type(cur));
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
                "description": "A simple Lucia package",
                "required_lucia_version": format!("^{}", required_version),
                "license": "MIT",
            });            

            if let Err(e) = fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap()) {
                eprintln!("{}", format!("Failed to write manifest: {}", e).red());
                return;
            }

            if fs::write(path.join(&main_file), "fun main() -> void:\n    print(\"Hello world\")\nend\n\nmain()\n").is_err() {
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

fn publish(args: &[String]) {
    let verbose = args.iter().any(|s| s == "-v" || s == "--verbose");
    let no_confirm = args.iter().any(|s| s == "--no-confirm");
    let path_arg = args.iter().find(|s| !s.starts_with('-')).map_or(".", |s| s.as_str());
    if args.iter().any(|s| s == "--help" || s == "-h") {
        command_help("publish");
        return;
    }
    let path = Path::new(path_arg);

    if !path.exists() || !path.is_dir() {
        eprintln!("{}", "Provided path does not exist or is not a directory.".red());
        return;
    }

    let manifest_path = path.join("manifest.json");
    if !manifest_path.exists() {
        eprintln!("{}", "manifest.json not found in the directory.".red());
        return;
    }

    let manifest_data = fs::read_to_string(&manifest_path).unwrap_or_else(|e| {
        eprintln!("{}", format!("Failed to read manifest.json: {}", e).red());
        exit(1);
    });

    let manifest: Value = serde_json::from_str(&manifest_data).unwrap_or_else(|e| {
        eprintln!("{}", format!("Invalid manifest.json: {}", e).red());
        exit(1);
    });

    let lib_name = manifest.get("name").and_then(Value::as_str).unwrap_or_else(|| {
        eprintln!("{}", "manifest.json missing 'name' field.".red());
        exit(1);
    });

    let version = manifest.get("version").and_then(Value::as_str).unwrap_or_else(|| {
        eprintln!("{}", "manifest.json missing 'version' field.".red());
        exit(1);
    });

    let (username, token) = get_lym_auth().unwrap_or_else(|| {
        eprintln!("{}", "No Lym auth found. Run `lym login` first.".red());
        exit(1);
    });

    if !no_confirm {
        let confirm = Confirm::new()
            .with_prompt(format!("You are about to publish {}@{} to the remote repository. Continue?", lib_name, version))
            .default(true)
            .interact()
            .unwrap_or(false);

        if !confirm {
            println!("{}", "Publish cancelled by user.".yellow());
            return;
        }
    }

    let lym_dir = get_lym_dir().unwrap_or_else(|e| {
        eprintln!("{}", format!("Failed to get Lym dir: {}", e).red());
        exit(1);
    });
    let config_path = lym_dir.join("config.json");
    let config: Value = fs::read_to_string(&config_path)
        .map(|s| serde_json::from_str(&s))
        .unwrap_or_else(|_| {
            eprintln!("{}", "Failed to read config.json".red());
            exit(1);
        })
        .unwrap();

    let repo_slug = config.get("repository_slug").and_then(Value::as_str).unwrap_or_else(|| {
        eprintln!("{}", "repository_slug missing in config.json".red());
        exit(1);
    });

    let client = Client::new();
    let package_url = format!("https://api.github.com/repos/{}/contents/{}", repo_slug, lib_name);

    let resp = client.get(&package_url)
        .header("User-Agent", "lym-publish")
        .basic_auth(&username, Some(&token))
        .send();

    if let Ok(r) = resp {
        if r.status().is_success() {
            let remote: Vec<Value> = r.json().unwrap_or_else(|_| {
                eprintln!("{}", "Failed to parse remote contents".red());
                exit(1);
            });

            let mut versions: Vec<String> = remote.iter()
                .filter_map(|item| item.get("name")?.as_str())
                .filter(|name| name.starts_with('@'))
                .map(|s| s[1..].to_string())
                .collect();

            if !versions.is_empty() {
                versions.sort_by(|a, b| {
                    cmp_version(a, b).unwrap_or(std::cmp::Ordering::Equal)
                });

                let last_version = versions.last().unwrap();
                if !is_next_version(version, last_version) {
                    eprintln!("{}", format!("Version {} is not valid after last published version {}", version, last_version).red());
                    return;
                }

                if versions.contains(&version.to_string()) {
                    eprintln!("{}", format!("Version {} already exists remotely.", version).red());
                    return;
                }
            }
        } else if r.status() != reqwest::StatusCode::NOT_FOUND {
            eprintln!("{}", format!("Failed to fetch remote package info: HTTP {}", r.status()).red());
            return;
        }
    } else {
        eprintln!("{}", "Failed to query remote repository".red());
        return;
    }

    let files = collect_files(path, path);

    let pb = if !verbose {
        let pb = ProgressBar::new(files.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"));
        Some(pb)
    } else { None };

    for file in files.iter() {
        let remote_path = format!("{}/@{}/{}", lib_name, version, file.to_string_lossy());
        let content = fs::read(path.join(file)).unwrap_or_else(|_| {
            eprintln!("{}", format!("Failed to read file {}", file.display()).red());
            Vec::new()
        });
        let content_b64 = general_purpose::STANDARD.encode(&content);

        let body = serde_json::json!({
            "message": format!("Publish {}@{}", lib_name, version),
            "content": content_b64,
            "branch": "main"
        });

        let upload_url = format!("https://api.github.com/repos/{}/contents/{}", repo_slug, remote_path);
        let res = client.put(&upload_url)
            .header("User-Agent", "lym-publish")
            .basic_auth(&username, Some(&token))
            .json(&body)
            .send();

        match res {
            Ok(r) if r.status().is_success() => {
                if verbose {
                    println!("{}", format!("Uploaded {}", file.display()).bright_green());
                }
            }
            Ok(r) => {
                eprintln!("{}", format!("Failed to upload {}: HTTP {}", file.display(), r.status()).red());
                return;
            }
            Err(e) => {
                eprintln!("{}", format!("Failed to upload {}: {}", file.display(), e).red());
                return;
            }
        }

        if let Some(pb) = &pb {
            pb.inc(1);
        }
    }

    if let Some(pb) = &pb {
        pb.finish_with_message("Upload complete");
    }

    println!("{}", format!("Package {}@{} published successfully!", lib_name, version).bright_green());
    println!("{}", format!("View it here: https://github.com/{}/tree/main/{}/@{}", repo_slug, lib_name, version).bright_blue());
}

fn login(args: &[String]) {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        command_help("login");
        return;
    }

    println!("{}", "Welcome to Lym GitHub CLI login!".bright_blue());
    println!("{}", "This will guide you to create a GitHub Personal Access Token (PAT)".bright_blue());
    println!();
    println!("{}", "Step 1: Open the following page in your browser:".bright_blue());
    println!("https://github.com/settings/tokens/new?scopes=repo&description=LymCLI");
    println!("{}", "Step 2: Create a token with the 'repo' scope.".bright_blue());
    println!("{}", "Step 3: Copy the token and paste it below.".bright_blue());
    println!();

    print!("{}", "GitHub username: ".bright_yellow());
    stdout().flush().unwrap();
    let mut username = String::new();
    stdin().read_line(&mut username).unwrap();
    let username = username.trim();

    print!("{}", "Personal Access Token: ".bright_yellow());
    stdout().flush().unwrap();
    let mut token = String::new();
    stdin().read_line(&mut token).unwrap();
    let token = token.trim();

    if username.is_empty() || token.is_empty() {
        eprintln!("{}", "Username or token cannot be empty. Login failed.".red());
        return;
    }

    match update_lym_auth(username, token) {
        Ok(_) => println!("{}", "Login successful! Token saved to lym_auth.json".bright_green()),
        Err(e) => eprintln!("{}", format!("Failed to save auth: {}", e).red()),
    }

    println!();
    println!("{}", "You can now run `lym publish` or other commands requiring authentication.".bright_blue());
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
        "login" => login(command_args),
        "publish" => publish(command_args),
        "--help" => print_help(),
        _ => {
            eprintln!("{}", format!("Unknown command: '{}'\n", command).red());
            print_help();
            exit(1);
        }
    }
}
