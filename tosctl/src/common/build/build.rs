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

#[path = "build_time.rs"]
mod build_time;
use build_time::build_time;

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
