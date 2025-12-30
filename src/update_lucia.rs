use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
};

use dialoguer::{Select, FuzzySelect, Confirm};
use flate2::read::GzDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde_json::Value;
use tar::Archive;
use tokio::{task, io::AsyncWriteExt};

use crate::update_config_with_lucia_info;

#[tokio::main]
pub async fn update_lucia(
    lucia_path: &Path,
    verbose: bool,
    no_confirm: bool,
    quiet: bool,
) -> Result<(), String> {
    let choices = [
        "Prebuilt (latest release)",
        "Build from source (latest commit)",
        "Build from source (latest release)",
        "Build from source (select commit)",
    ];

    let selection = Select::new()
        .with_prompt("How do you want to update Lucia?")
        .items(&choices)
        .default(0)
        .interact()
        .map_err(|e| e.to_string())?;

    if !no_confirm {
        let confirm = Confirm::new()
            .with_prompt("Are you sure you want to update Lucia?")
            .default(false)
            .interact()
            .unwrap_or(false);
        if !confirm {
            println!("Update cancelled.");
            return Ok(());
        }
    }

    let backup_path = lucia_path.with_extension("backup");
    if backup_path.exists() {
        task::spawn_blocking({
            let backup_path = backup_path.clone();
            move || fs::remove_dir_all(&backup_path)
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    }

    copy_dir_git_aware_with_spinner(lucia_path, &backup_path).await?;

    let result = (|| async {
        match selection {
            0 => update_prebuilt_async(lucia_path, verbose).await?,
            1 => build_from_source(lucia_path, SourceMode::LatestCommit, verbose)?,
            2 => build_from_source(lucia_path, SourceMode::LatestRelease, verbose)?,
            3 => {
                let commits = fetch_recent_commits_async().await?;
                let commit = select_commit_from_list(commits)?;
                build_from_source(lucia_path, SourceMode::Commit(commit), verbose)?
            }
            _ => unreachable!(),
        }

        init_lucia(lucia_path)?;
        let old_env = backup_path.join("src/env");
        let new_env = lucia_path.join("src/env");

        restore_env_files(&old_env, &new_env)?;

        if matches!(selection, 1 | 2 | 3) {
            run_cmd(lucia_path, "make", &["test"], verbose)?;
        }

        let version = get_lucia_version(lucia_path)?;
        if !quiet {
            println!("Lucia updated successfully to version {version}");
        }

        let config_path = new_env.join("config.json");
        update_config_with_lucia_info(&config_path)
            .map_err(|e| e.to_string())?;

        Ok::<(), String>(())
    })();

    if result.await.is_err() {
        let _ = fs::remove_dir_all(lucia_path);
        let _ = fs::rename(&backup_path, lucia_path);
        return Err("Update failed, restored backup".into());
    } else {
        let _ = fs::remove_dir_all(&backup_path);
    }

    Ok(())
}

enum SourceMode {
    LatestCommit,
    LatestRelease,
    Commit(String),
}

fn select_commit_from_list(commits: Vec<(String, String)>) -> Result<String, String> {
    let items: Vec<String> = commits.iter().map(|(h, m)| format!("{h}  {m}")).collect();
    let idx = FuzzySelect::new()
        .with_prompt("Select commit")
        .items(&items)
        .interact()
        .map_err(|e| e.to_string())?;
    Ok(commits[idx].0.clone())
}

async fn update_prebuilt_async(lucia_path: &Path, _verbose: bool) -> Result<(), String> {
    let tmp_dir = std::env::temp_dir().join("lucia-update");
    if tmp_dir.exists() {
        task::spawn_blocking({
            let tmp_dir = tmp_dir.clone();
            move || fs::remove_dir_all(&tmp_dir)
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    }
    task::spawn_blocking({
        let tmp_dir = tmp_dir.clone();
        move || fs::create_dir_all(&tmp_dir)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;

    let archive = tmp_dir.join("lucia.tar.gz");

    download_latest_release_async("SirPigari/lucia-rust", &archive).await?;

    task::spawn_blocking({
        let archive = archive.clone();
        let lucia_path = lucia_path.to_path_buf();
        move || extract_archive(&archive, &lucia_path)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;

    Ok(())
}

async fn download_latest_release_async(repo: &str, out: &Path) -> Result<(), String> {
    let client = Client::builder()
        .user_agent("lucia-updater")
        .build()
        .map_err(|e| e.to_string())?;

    let api_url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let resp = client.get(&api_url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("GitHub API request failed: {}", resp.status()));
    }
    let json: Value = resp.json().await.map_err(|e| e.to_string())?;
    let asset_url = json["assets"]
        .get(0)
        .and_then(|a| a["browser_download_url"].as_str())
        .ok_or("No release assets found")?;

    let mut resp = client.get(asset_url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Download failed: {}", resp.status()));
    }

    let total_size = resp.content_length().unwrap_or(0);
    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(ProgressStyle::with_template("{spinner:.green} Downloading...").unwrap().tick_chars("/|\\- "));
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    let mut out_file = tokio::fs::File::create(out).await.map_err(|e| e.to_string())?;
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        out_file.write_all(&chunk).await.map_err(|e| e.to_string())?;
        pb.inc(chunk.len() as u64);
    }

    spinner.finish_and_clear();
    pb.finish_with_message("Download complete");

    Ok(())
}

fn build_from_source(
    lucia_path: &Path,
    mode: SourceMode,
    verbose: bool,
) -> Result<(), String> {
    let tmp_dir = std::env::temp_dir().join("lucia-src");
    if tmp_dir.exists() {
        fs::remove_dir_all(&tmp_dir).map_err(|e| e.to_string())?;
    }
    fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;
    let repo_dir = tmp_dir.join("lucia");

    clone_repo("https://github.com/SirPigari/lucia-rust.git", &repo_dir)?;

    match mode {
        SourceMode::LatestCommit => {}
        SourceMode::LatestRelease => checkout_latest_release(&repo_dir)?,
        SourceMode::Commit(c) => checkout_commit(&repo_dir, &c)?,
    }

    run_cmd(&repo_dir, "make", &["release"], verbose)?;
    fs::remove_dir_all(lucia_path).map_err(|e| e.to_string())?;
    fs::rename(repo_dir, lucia_path).map_err(|e| e.to_string())
}

fn init_lucia(lucia_path: &Path) -> Result<(), String> {
    run_cmd(lucia_path, "lucia", &["-a", "-e"], false)
}

fn get_lucia_version(lucia_path: &Path) -> Result<String, String> {
    let output = Command::new("lucia")
        .arg("--build-info")
        .current_dir(lucia_path)
        .output()
        .map_err(|e| e.to_string())?;

    let json: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| e.to_string())?;

    json.get("version")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "Missing version field".to_string())
}

fn restore_env_files(old_env: &Path, new_env: &Path) -> Result<(), String> {
    fs::create_dir_all(new_env).map_err(|e| e.to_string())?;
    let paths = ["libs", "config.json", "libs.json"];

    for p in &paths {
        let src = old_env.join(p);
        let dst = new_env.join(p);

        if src.exists() {
            if dst.exists() {
                fs::remove_file(&dst).ok();
                fs::remove_dir_all(&dst).ok();
            }
            if src.is_dir() {
                copy_dir_recursive(&src, &dst).map_err(|e| e.to_string())?;
            } else {
                fs::copy(&src, &dst).map_err(|e| e.to_string())?;
            }
        }
    }

    Ok(())
}

fn clone_repo(url: &str, dest: &Path) -> Result<(), String> {
    let status = Command::new("git")
        .args(["clone", url])
        .arg(dest)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("git clone failed".into());
    }
    Ok(())
}

fn checkout_commit(repo: &Path, commit: &str) -> Result<(), String> {
    let status = Command::new("git")
        .args(["checkout", commit])
        .current_dir(repo)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("git checkout failed".into());
    }
    Ok(())
}

fn checkout_latest_release(repo: &Path) -> Result<(), String> {
    let tag = Command::new("git")
        .args(["describe", "--tags", "--abbrev=0"])
        .current_dir(repo)
        .output()
        .map_err(|e| e.to_string())?;
    let tag = String::from_utf8_lossy(&tag.stdout).trim().to_string();
    checkout_commit(repo, &tag)
}

fn run_cmd(cwd: &Path, bin: &str, args: &[&str], verbose: bool) -> Result<(), String> {
    let mut cmd = Command::new(bin);
    cmd.args(args).current_dir(cwd);
    if verbose {
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    }
    let status = cmd.status().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("{bin} {:?} failed", args));
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

async fn copy_dir_git_aware_with_spinner(src: &Path, dst: &Path) -> Result<(), String> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.green} Copying files...").unwrap()
            .tick_chars("/|\\- ")
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(80));

    let src = src.to_path_buf();
    let dst = dst.to_path_buf();

    task::spawn_blocking(move || -> Result<(), String> {
        copy_dir_git_aware(&src, &dst)
    })
    .await
    .map_err(|e| e.to_string())??;

    pb.finish_with_message("Backup complete");
    Ok(())
}

fn copy_dir_git_aware(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    for entry in fs::read_dir(src).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if is_git_ignored(&src_path) { continue; }
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            copy_dir_git_aware(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn is_git_ignored(path: &Path) -> bool {
    let output = Command::new("git")
        .args(["check-ignore", path.to_str().unwrap_or("")])
        .output()
        .unwrap_or_else(|_| std::process::Output {
            status: dummy_exit_status(),
            stdout: vec![],
            stderr: vec![],
        });
    output.status.success()
}

fn dummy_exit_status() -> std::process::ExitStatus {
    #[cfg(unix)]
    { std::os::unix::process::ExitStatusExt::from_raw(1) }
    #[cfg(windows)]
    { std::os::windows::process::ExitStatusExt::from_raw(1) }
}

async fn fetch_recent_commits_async() -> Result<Vec<(String,String)>, String> {
    let client = Client::builder().user_agent("lucia-updater").build().map_err(|e| e.to_string())?;
    let url = "https://api.github.com/repos/SirPigari/lucia-rust/commits?per_page=20";
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    let json: Value = resp.json().await.map_err(|e| e.to_string())?;

    let mut commits = Vec::new();
    for c in json.as_array().ok_or("Invalid JSON")? {
        let hash = c["sha"].as_str().unwrap_or("").chars().take(7).collect();
        let msg = c["commit"]["message"].as_str().unwrap_or("").lines().next().unwrap_or("").to_string();
        commits.push((hash, msg));
    }
    Ok(commits)
}

fn extract_archive(archive: &Path, dest: &Path) -> Result<(), String> {
    let tar_gz = fs::File::open(archive).map_err(|e| e.to_string())?;
    let tar = GzDecoder::new(tar_gz);
    let mut archive = Archive::new(tar);
    archive.unpack(dest).map_err(|e| e.to_string())?;
    Ok(())
}
