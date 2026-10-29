#!/usr/bin/env python3
"""Targeted sensitivity controls; restores each source even on test failure.

Run only in an isolated checkout with no other builds using these files.
A passing mutant is a failure: the regression must notice the removed control.
"""

import argparse
import os
import subprocess
import sys
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
        'sha256.hexdigest() != pin["sha256"]',
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

# str.replace mutates every copy of an anchor, so each anchor's occurrence count
# is pinned. These cases intentionally cover two parsers or renderers at once;
# every other anchor must occur exactly once. A new copy is a reviewed change.
ANCHOR_COUNTS = {"http": 2, "header-names": 2, "html": 2}

# The connect case removes both independent gates to restore the original
# trust-on-first-envelope behavior: the transport gate in the bridge and the
# consumer gate in the client. Both anchors are checked like every other case.
CONNECT_EDITS = [
    (
        "sdk/js/packages/connect/src/bridge.ts",
        "!senderPk || !this.walletPublicKey ||\n"
        "            bytesToHex(senderPk) !== bytesToHex(this.walletPublicKey)",
        "!senderPk",
    ),
    (
        "sdk/js/packages/connect/src/TosConnect.ts",
        "if (!this._walletPublicKey || fromHex.toLowerCase() !== "
        "bytesToHex(this._walletPublicKey)) return;",
        "",
    ),
]
CONNECT_COMMAND = ["pnpm", "--dir", "sdk/js", "--filter", "@tos/connect", "test"]


def anchor_table(cases=None, connect_edits=None):
    """Every (case, path, before, after, expected count) the runner may apply."""
    cases = CASES if cases is None else cases
    connect_edits = CONNECT_EDITS if connect_edits is None else connect_edits
    table = [
        (name, path, before, after, ANCHOR_COUNTS.get(name, 1))
        for name, (path, before, after, _command) in cases.items()
    ]
    table += [("connect", path, before, after, 1) for path, before, after in connect_edits]
    return table


def anchor_problems(root: Path, cases=None, connect_edits=None) -> list[str]:
    """Report every anchor that would not apply exactly as reviewed."""
    problems = []
    for name, path, before, after, expected in anchor_table(cases, connect_edits):
        if before == after:
            problems.append(f"{name}: {path}: mutation leaves the anchor unchanged")
            continue
        try:
            source = (root / path).read_bytes().decode("utf-8")
        except FileNotFoundError:
            problems.append(f"{name}: {path}: file is missing")
            continue
        except UnicodeDecodeError as error:
            problems.append(f"{name}: {path}: not UTF-8 ({error})")
            continue
        found = source.count(before)
        if found != expected:
            problems.append(f"{name}: {path}: anchor found {found} times, expected {expected}")
    return problems


def mutation(name, path, before, after, command, logdir):
    path = ROOT / path
    original = path.read_bytes()
    source = original.decode()
    # Second line of defence behind the load-time anchor check.
    if before not in source:
        raise RuntimeError(f"{name}: mutation target missing")
    try:
        path.write_text(source.replace(before, after))
        with (logdir / f"{name}-red.log").open("w") as log:
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode == 0:
            raise RuntimeError(f"{name}: removed control was not detected")
        # A crashing native test prints raw stack bytes; match on a lossy decode.
        red = (logdir / f"{name}-red.log").read_bytes().decode("utf-8", errors="replace")
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


def check_anchors_or_exit():
    """Refuse to start any mutation while any part of the table is stale."""
    problems = anchor_problems(ROOT)
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        raise SystemExit(2)
    table = anchor_table()
    cases = len({name for name, *_rest in table})
    return f"MUTATION_ANCHORS_OK: {len(table)} anchors in {cases} cases"


def run_connect(logdir):
    bridge_path, bridge_before, bridge_after = CONNECT_EDITS[0]
    client_path, client_before, client_after = CONNECT_EDITS[1]
    bridge = ROOT / bridge_path
    client = ROOT / client_path
    saved_bridge, saved_client = bridge.read_bytes(), client.read_bytes()
    try:
        source = saved_bridge.decode()
        if source.count(bridge_before) != 1:
            raise RuntimeError("connect: mutation target missing")
        bridge.write_text(source.replace(bridge_before, bridge_after))
        mutation("connect", client_path, client_before, client_after, CONNECT_COMMAND, logdir)
    finally:
        bridge.write_bytes(saved_bridge)
        client.write_bytes(saved_client)
    # Re-run with both independent gates restored.
    subprocess.run(CONNECT_COMMAND, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    known = list(CASES) + ["connect"]
    # Checked below rather than with choices=: older argparse rejects an empty
    # nargs="*" list against choices, which --check-anchors relies on.
    parser.add_argument("cases", nargs="*", metavar="case", help=f"one of {', '.join(known)}")
    parser.add_argument("--logs", type=Path)
    parser.add_argument(
        "--check-anchors",
        action="store_true",
        help="only check that every anchor in the table applies exactly as reviewed",
    )
    args = parser.parse_args()
    if not args.check_anchors and not args.cases:
        parser.error("name at least one case, or pass --check-anchors")
    unknown = [name for name in args.cases if name not in known]
    if unknown:
        parser.error(f"unknown case: {', '.join(unknown)}")
    if args.cases and args.logs is None:
        parser.error("--logs is required when running cases")
    # The whole table is checked, not only the selected cases, before any build starts.
    summary = check_anchors_or_exit()
    if args.check_anchors:
        print(summary)
        raise SystemExit(0)
    os.environ.setdefault("TOS_ROOT", str(ROOT))
    args.logs.mkdir(parents=True, exist_ok=True)
    for name in args.cases:
        if name == "connect":
            run_connect(args.logs.resolve())
        else:
            mutation(name, *CASES[name], args.logs.resolve())
