/*
 * Copyright (C) 2019-2022 TOS Labs. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};
use tl_codegen::Config;

fn get_value(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .and_then(|result| String::from_utf8(result.stdout).ok())
        .unwrap_or_else(|| "Unknown".to_string())
}

/// Build timestamp taken from the source, never from the wall clock, so that
/// two builds of one commit embed the same value: SOURCE_DATE_EPOCH when set,
/// otherwise the commit date of HEAD. Formatted in UTC so the host time zone
/// does not leak into the binary.
fn build_time() -> Result<String, String> {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let epoch = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(value) if !value.trim().is_empty() => value,
        Ok(_) | Err(std::env::VarError::NotPresent) => {
            match Command::new("git").args(["log", "-1", "--format=%ct"]).output() {
                Ok(out) if out.status.success() => String::from_utf8(out.stdout)
                    .map_err(|e| format!("commit date is not UTF-8: {e}"))?,
                _ => return Ok("Unknown".to_string()),
            }
        }
        Err(e) => return Err(format!("SOURCE_DATE_EPOCH is unreadable: {e}")),
    };
    let epoch: i64 = epoch
        .trim()
        .parse()
        .map_err(|e| format!("build epoch {:?} is not a Unix timestamp: {e}", epoch.trim()))?;
    let out = Command::new("date")
        .args(["-u", "-d", &format!("@{epoch}"), "+%Y-%m-%d %T %z"])
        .output()
        .map_err(|e| format!("cannot run date: {e}"))?;
    if !out.status.success() {
        return Err(format!("date rejected epoch {epoch}"));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("date output is not UTF-8: {e}"))
}

const OUTPUT_DIR: &str = "src/tos";
const TL_DIR: &str = "tl";
const TL_FILES: [&str; 3] = ["lite_api.tl", "tos_api.tl", "toslib_api.tl"];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // TODO: This line was commented because of different behavior of cargo in rust ver 1.50.
    //       We can revert it, when this behavior is fixed.
    // println!("cargo:rerun-if-changed={}", OUTPUT_DIR);
    println!("cargo:rerun-if-changed={}", TL_DIR);
    println!("cargo:rerun-if-changed=../codegen");

    let mut files: Vec<PathBuf> =
        TL_FILES.iter().map(|file| Path::new(TL_DIR).join(file)).collect();
    files.sort();

    let mut input = String::new();
    for file in files {
        if !input.is_empty() {
            input += "---types---\n";
        }
        fs::File::open(&file)?.read_to_string(&mut input)?;
        println!("cargo:rerun-if-changed={}", file.to_string_lossy());
    }

    let config_path = Path::new(TL_DIR).join("codegen.json");
    let config: Option<Config> = if config_path.exists() && config_path.is_file() {
        let mut config_string = String::new();
        fs::File::open(&config_path)?.read_to_string(&mut config_string)?;
        Some(serde_json::from_str(&config_string)?)
    } else {
        None
    };

    tl_codegen::generate_code_for(config, &input, Path::new(OUTPUT_DIR));

    let git_branch = get_value("git", &["rev-parse", "--abbrev-ref", "HEAD"]);
    let git_commit = get_value("git", &["rev-parse", "HEAD"]);
    let commit_date = get_value("git", &["log", "-1", "--date=iso", "--pretty=format:%cd"]);
    let build_time = build_time()?;
    let rust_version = get_value("rustc", &["--version"]);

    println!("cargo:rustc-env=BUILD_GIT_BRANCH={}", git_branch);
    println!("cargo:rustc-env=BUILD_GIT_COMMIT={}", git_commit);
    println!("cargo:rustc-env=BUILD_GIT_DATE={}", commit_date);
    println!("cargo:rustc-env=BUILD_TIME={}", build_time);
    println!("cargo:rustc-env=BUILD_RUST_VERSION={}", rust_version);
    Ok(())
}
