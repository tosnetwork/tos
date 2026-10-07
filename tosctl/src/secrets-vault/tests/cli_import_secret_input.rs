/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Runs the vault CLI binary: `import` takes its secret only from a protected
//! file, an inherited descriptor, or a prompt, and refuses the retired
//! argument form without echoing the value.
#![cfg(feature = "secrets-vault-cli")]

use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output, Stdio},
};

const KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const MASTER_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn cli(vault: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_secrets-vault-cli"));
    command
        .args(args)
        .env("VAULT_URL", format!("file://{}?master_key={MASTER_KEY}", vault.display()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = command.spawn().expect("spawn vault CLI");
    if let Some(input) = stdin {
        child.stdin.take().expect("stdin").write_all(input.as_bytes()).expect("write stdin");
    }
    child.wait_with_output().expect("wait")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn import_reads_protected_channels_and_refuses_the_argument_form() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("tempdir");
    let vault = dir.path().join("vault.json");
    let init = cli(&vault, &["init"], None);
    assert!(init.status.success(), "{}", text(&init));

    // Retired form: a hard error that names the replacement and never
    // repeats the value, and imports nothing.
    let refused = cli(
        &vault,
        &["import", "--secret-id", "legacy", "--algorithm", "ed25519", "--data", KEY_HEX],
        None,
    );
    assert!(!refused.status.success());
    let message = text(&refused);
    assert!(message.contains("--data-file"), "{message}");
    assert!(!message.contains(KEY_HEX), "{message}");

    // A key file readable by others is refused before it is read.
    let key_file = dir.path().join("key.hex");
    std::fs::write(&key_file, format!("{KEY_HEX}\n")).expect("write key");
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let key_path = key_file.to_str().expect("utf8");
    let open = cli(
        &vault,
        &[
            "import",
            "--secret-id",
            "unprotected",
            "--algorithm",
            "ed25519",
            "--data-file",
            key_path,
        ],
        None,
    );
    assert!(!open.status.success());
    assert!(text(&open).contains("mode 0644"), "{}", text(&open));
    assert!(!text(&open).contains(KEY_HEX));

    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    let from_file = cli(
        &vault,
        &["import", "--secret-id", "from-file", "--algorithm", "ed25519", "--data-file", key_path],
        None,
    );
    assert!(from_file.status.success(), "{}", text(&from_file));

    let from_stdin = cli(
        &vault,
        &["import", "--secret-id", "from-stdin", "--algorithm", "ed25519", "--data-fd", "0"],
        Some(&format!("{KEY_HEX}\n")),
    );
    assert!(from_stdin.status.success(), "{}", text(&from_stdin));

    // Invalid hex is reported without the offending input.
    let bad = cli(
        &vault,
        &["import", "--secret-id", "badhex", "--algorithm", "ed25519", "--data-fd", "0"],
        Some("zz-not-hex-secret-tail"),
    );
    assert!(!bad.status.success());
    assert!(!text(&bad).contains("secret-tail"), "{}", text(&bad));

    let listed = text(&cli(&vault, &["list"], None));
    assert!(listed.contains("from-file") && listed.contains("from-stdin"), "{listed}");
    for refused_id in ["legacy", "unprotected", "badhex"] {
        assert!(!listed.contains(refused_id), "{listed}");
    }
}
