/*
 * Copyright 2018-2022 TON DEV SOLUTIONS LTD.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the Apache License, Version 2.0.
 * See the common/LICENSE file in this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use std::process::Command;

fn get_value(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .and_then(|result| String::from_utf8(result.stdout).ok())
        .unwrap_or_else(|| "Unknown".to_string())
}

fn get_env_or_command(env_var: &str, cmd: &str, args: &[&str]) -> String {
    std::env::var(env_var).unwrap_or_else(|_| get_value(cmd, args))
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

fn main() -> Result<(), String> {
    // Emitting a rerun directive disables the default "any package file"
    // trigger; keep it so the embedded git values stay current.
    println!("cargo:rerun-if-changed=.");
    let git_branch =
        get_env_or_command("GIT_BRANCH", "git", &["rev-parse", "--abbrev-ref", "HEAD"]);
    let git_commit = get_env_or_command("GIT_COMMIT", "git", &["rev-parse", "HEAD"]);
    let commit_date = get_env_or_command(
        "GIT_COMMIT_DATE",
        "git",
        &["log", "-1", "--date=iso", "--pretty=format:%cd"],
    );
    let build_time = build_time()?;
    let rust_version = get_value("rustc", &["--version"]);

    println!("cargo:rustc-env=BUILD_GIT_BRANCH={}", git_branch);
    println!("cargo:rustc-env=BUILD_GIT_COMMIT={}", git_commit);
    println!("cargo:rustc-env=BUILD_GIT_DATE={}", commit_date);
    println!("cargo:rustc-env=BUILD_TIME={}", build_time);
    println!("cargo:rustc-env=BUILD_RUST_VERSION={}", rust_version);
    Ok(())
}
