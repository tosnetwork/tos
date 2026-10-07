#!/usr/bin/env python3
"""Targeted sensitivity controls; restores each source even on test failure.

Run only in an isolated checkout with no other builds using these files.
A passing mutant is a failure: the regression must notice the removed control.
"""

import argparse
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CARGO = ["cargo", "test", "--locked", "--manifest-path", "tosctl/src/Cargo.toml"]
NATIVE = ["python3", "scripts/run-security-boundaries.py", "--filter"]

CASES = {
    "decrypt": (
        "adnl/decrypt-admission.h",
        "in_flight_ >= limit_ || !work_.take()",
        "false",
        NATIVE + ["DecryptAdmission"],
    ),
    "sources": (
        "adnl/decrypt-admission.h",
        "table.size() >= limit",
        "false",
        NATIVE + ["DecryptAdmission"],
    ),
    "multisig": (
        "crypto/smartcont/multisig-code.fc",
        "throw_unless(44, query_global_id == get_global_id());",
        "",
        CARGO
        + ["-p", "contracts", "--test", "multisig_code_sandbox", "signed_query_cannot_be_replayed"],
    ),
    "private-file": (
        "tosctl/src/secrets-vault/src/private_file.rs",
        "from_mode(0o600)",
        "from_mode(0o644)",
        CARGO + ["-p", "secrets-vault", "private_file::tests"],
    ),
    "api-key": (
        "tosctl/src/node-control/commands/src/commands/nodectl/config_chain_rpc_cmd.rs",
        "    url: String,",
        '    url: String,\n    #[arg(long = "api-key")]\n    insecure_api_key: Option<String>,',
        CARGO + ["-p", "commands", "secret_channel_tests"],
    ),
    "tool-call": (
        "assembly/appimage/create-appimages.sh",
        'python3 "$REPO_ROOT/scripts/verify-build-tool.py" "appimagetool-$ARCH" "appimagetool-$ARCH.AppImage"',
        "true",
        ["python3", "scripts/test-build-tool-pipelines.py"],
    ),
    "integrity": (
        "scripts/verify-build-tool.py",
        'digest.hexdigest() != pin["sha256"]',
        "False",
        ["python3", "scripts/test-build-tool-pins.py"],
    ),
    "http": (
        "http/http.cpp",
        'S != "chunked" || proto_version_ == "HTTP/1.0"',
        "false",
        NATIVE + ["HttpFraming"],
    ),
    "header-names": (
        "http/http.cpp",
        "TRY_STATUS(header.basic_check());",
        "",
        NATIVE + ["HttpFraming"],
    ),
    "response": (
        "http/http.cpp",
        'HttpHeader{"Transfer-Encoding", "chunked"}.store_http(output);',
        "",
        NATIVE + ["HttpFraming"],
    ),
    "legacy-key": (
        "crypto/smartcont/wallet-code.fc",
        "throw_if(34, weak_ed25519_key?(public_key));",
        "",
        CARGO + ["-p", "contracts", "--test", "legacy_wallet_key_sandbox"],
    ),
    "html": (
        "blockchain-explorer/blockchain-explorer-http.cpp",
        "escape_html(error_.to_string())",
        "error_.to_string()",
        NATIVE + ["HtmlErrorText"],
    ),
    "dispatch": (
        "validator/impl/dispatch-progress.h",
        "old_size <= hard_limit || post_cleanup_size <= soft_limit",
        "old_size <= hard_limit",
        NATIVE + ["DispatchCleanupAndRegrowth"],
    ),
}


def mutation(name, path, before, after, command, logdir):
    path = ROOT / path
    original = path.read_bytes()
    source = original.decode()
    if before not in source:
        raise RuntimeError(f"{name}: mutation target missing")
    try:
        path.write_text(source.replace(before, after))
        with (logdir / f"{name}-red.log").open("w") as log:
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode == 0:
            raise RuntimeError(f"{name}: removed control was not detected")
        red = (logdir / f"{name}-red.log").read_text()
        executed_failure = (
            (command[0] == "cargo" and "test result: FAILED" in red)
            or (command[0] == "pnpm" and "FAIL  packages/connect/src/bridge-trust.test.ts" in red)
            or (
                command[0] == "python3"
                and any("test-build-tool" in part for part in command)
                and "FAILED (failures=" in red
            )
            or ("--filter" in command and "Running test Test_SecurityBoundaries_" in red)
        )
        if not executed_failure:
            raise RuntimeError(f"{name}: failure did not reach the intended runtime test")
        print(f"{name}: red exit {result.returncode}", flush=True)
    finally:
        path.write_bytes(original)
    with (logdir / f"{name}-green.log").open("w") as log:
        result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"{name}: restored control fails (exit {result.returncode})")
    print(f"{name}: green exit 0", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", nargs="+", choices=list(CASES) + ["connect"])
    parser.add_argument("--logs", type=Path, required=True)
    args = parser.parse_args()
    os.environ.setdefault("TOS_ROOT", str(ROOT))
    args.logs.mkdir(parents=True, exist_ok=True)
    for name in args.cases:
        if name == "connect":
            # Both the transport and consumer gates are removed to restore the
            # original trust-on-first-envelope behavior. Restore both afterward.
            a = ROOT / "sdk/js/packages/connect/src/bridge.ts"
            b = ROOT / "sdk/js/packages/connect/src/TosConnect.ts"
            saved_a, saved_b = a.read_bytes(), b.read_bytes()
            try:
                a.write_text(
                    a.read_text().replace(
                        "!senderPk || !this.walletPublicKey ||\n            bytesToHex(senderPk) !== bytesToHex(this.walletPublicKey)",
                        "!senderPk",
                    )
                )
                before = "if (!this._walletPublicKey || fromHex.toLowerCase() !== bytesToHex(this._walletPublicKey)) return;"
                mutation(
                    name,
                    str(b.relative_to(ROOT)),
                    before,
                    "",
                    ["pnpm", "--dir", "sdk/js", "--filter", "@tos/connect", "test"],
                    args.logs.resolve(),
                )
            finally:
                a.write_bytes(saved_a)
                b.write_bytes(saved_b)
            # Re-run with both independent gates restored.
            subprocess.run(
                ["pnpm", "--dir", "sdk/js", "--filter", "@tos/connect", "test"],
                cwd=ROOT,
                check=True,
                stdout=subprocess.DEVNULL,
            )
        else:
            mutation(name, *CASES[name], args.logs.resolve())
