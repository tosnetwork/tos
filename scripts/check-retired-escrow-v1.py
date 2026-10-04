#!/usr/bin/env python3
"""Keeps stablecoin escrow v1 out of every supported deployment path.

Escrow v1 was retired rather than repaired: its source, frozen BOC, release
manifest, build/embed scripts, CMake wiring and the rehearsal that deployed it
were removed. Nothing in the remaining tree announces their return, so this
check does, in three ways:

1. No tracked file is named after escrow v1, and no tooling, build or contract
   file names it, its artifact, its protocol id, its code hash, or the opt-in
   flag that used to deploy it.
2. No frozen BOC anywhere in the tree is the v1 artifact under another name.
3. The deployment policy the escrow deploy script enforces refuses the v1 code
   hash (also on a non-production deployment), refuses unknown code, and
   refuses escrow v2 on a production deployment; and the deploy script still
   calls that policy before touching the network.

Historical evidence logs are exempt: they record what was built at the time.
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

RETIRED_CODE_HASH = "c9df2f743534978ad5b521aab8c09c081ff56769769c00ee9e68eac7c681a685"
RETIRED_BOC_SHA256 = "fdbb52a25b9e43f50cd27e03bbd2020245e2d8b31b76b5ff203454bfbc645048"

FORBIDDEN_TEXT = (
    "tos-service-stablecoin-escrow-v1",
    "tos_service_stablecoin_escrow_v1",
    "stablecoin-escrow-v1",
    "allow-deprecated-escrow-v1",
    "allow_deprecated_escrow_v1",
    RETIRED_CODE_HASH,
    RETIRED_BOC_SHA256,
)

# File kinds that build, test, deploy or are deployed. Prose is not scanned:
# documentation explaining the retirement may name what was retired.
SCANNED_SUFFIXES = {
    ".py",
    ".sh",
    ".rs",
    ".fc",
    ".fif",
    ".cpp",
    ".h",
    ".hpp",
    ".cmake",
    ".txt",
    ".yml",
    ".yaml",
    ".toml",
    ".json",
    ".base64",
    ".go",
    ".js",
    ".ts",
}

# Paths allowed to name the retired release, each for a stated reason.
EXEMPT_PREFIXES = (
    # Raw logs of past builds, kept as evidence of what ran at the time.
    "tools/node-health-monitor/evidence/",
)
EXEMPT_FILES = {
    # Holds the retired code hash so a copy restored from history is refused by name.
    "scripts/tos_service_escrow_deploy_policy.py",
    # This check and its test name what they look for.
    "scripts/check-retired-escrow-v1.py",
    "scripts/test_check_retired_escrow_v1.py",
}

DEPLOY_SCRIPT = "scripts/tos-service-stablecoin-escrow-deploy.py"


def tracked_files(root: Path) -> list[str]:
    if (root / ".git").exists():
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
        )
        return [name for name in result.stdout.decode().split("\0") if name]
    files = []
    for directory, _, names in os.walk(root):
        for name in names:
            files.append(str((Path(directory) / name).relative_to(root)))
    return files


def is_exempt(path: str) -> bool:
    return path in EXEMPT_FILES or any(path.startswith(prefix) for prefix in EXEMPT_PREFIXES)


def boc_sha256(path: Path) -> str | None:
    data = path.read_bytes()
    if path.name.endswith(".base64"):
        try:
            data = base64.b64decode(b"".join(data.split()), validate=True)
        except ValueError:
            return None
    return hashlib.sha256(data).hexdigest()


def scan_tree(root: Path) -> list[str]:
    failures = []
    for path in tracked_files(root):
        if is_exempt(path):
            continue
        full = root / path
        if not full.is_file():
            continue
        lowered = Path(path).name.lower()
        if "escrow-v1" in lowered or "escrow_v1" in lowered:
            failures.append(f"{path}: a file named after the retired escrow v1 is tracked")
        if lowered.endswith((".boc", ".boc.base64")) and boc_sha256(full) == RETIRED_BOC_SHA256:
            failures.append(f"{path}: this is the retired escrow v1 BOC under another name")
        suffix = full.suffix.lower()
        if suffix not in SCANNED_SUFFIXES and full.name != "CMakeLists.txt":
            continue
        try:
            text = full.read_text(errors="replace").lower()
        except OSError as error:
            failures.append(f"{path}: unreadable ({error})")
            continue
        for needle in FORBIDDEN_TEXT:
            if needle in text:
                failures.append(f"{path}: names the retired escrow v1 ({needle})")
    return failures


def check_policy(root: Path) -> list[str]:
    failures = []
    sys.path.insert(0, str(root / "scripts"))
    try:
        import tos_service_escrow_deploy_policy as policy
    finally:
        sys.path.pop(0)

    def refused(code_hash: str, non_production: bool) -> bool:
        try:
            policy.check_escrow_deployment(code_hash, non_production=non_production, repo=root)
        except policy.DeploymentRefused:
            return True
        return False

    for non_production in (False, True):
        if not refused(RETIRED_CODE_HASH, non_production):
            failures.append(
                f"policy accepts the retired escrow v1 code (non_production={non_production})"
            )
    if not refused("00" * 32, True):
        failures.append("policy accepts code that is not a supported escrow release")
    for manifest_path, entry in policy.SUPPORTED_ESCROW_RELEASES.items():
        manifest = json.loads((root / manifest_path).read_text())
        if manifest["protocol"] == "tos_service_stablecoin_escrow_v1":
            failures.append(f"{manifest_path}: the retired release is listed as supported")
        if not entry["production"] and not refused(manifest["code_hash"], False):
            failures.append(
                f"policy deploys non-production release {manifest['protocol']} in production"
            )
        if refused(manifest["code_hash"], True):
            failures.append(
                f"policy refuses supported release {manifest['protocol']} even for test use"
            )

    deploy = (root / DEPLOY_SCRIPT).read_text()
    applied = deploy.find("check_escrow_deployment(code_hash")
    sent = deploy.find("send_wallet_message(")
    if applied < 0:
        failures.append(f"{DEPLOY_SCRIPT} no longer applies the deployment policy")
    elif sent < 0 or applied > sent:
        failures.append(f"{DEPLOY_SCRIPT} does not apply the deployment policy before sending")
    return failures


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]).resolve()
    failures = scan_tree(root) + check_policy(root)
    for failure in failures:
        print(f"retired escrow v1 check failed: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("retired escrow v1: no supported tooling can deploy it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
