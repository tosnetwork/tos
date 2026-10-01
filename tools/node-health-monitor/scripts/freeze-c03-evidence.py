#!/usr/bin/env python3
"""Freeze C03 candidate source, raw and external executable/archive hashes."""

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence/c03-state-rules-notification"
BASE = "a884b0ca735736fd5a81306c26bdc65a5bd967df"


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_paths(command, *args):
    result = subprocess.run(["git", command, *args], cwd=ROOT, check=True, stdout=subprocess.PIPE)
    return [Path(value.decode()) for value in result.stdout.split(b"\0") if value]


sources = sorted(
    set(
        git_paths("diff", "--relative", "--name-only", "-z", BASE)
        + git_paths("ls-files", "-z", "--others", "--exclude-standard")
    )
)
sources = [
    path for path in sources if not str(path).startswith("evidence/c03-state-rules-notification/")
]
raw = sorted((EVIDENCE / "raw").rglob("*"))
raw = [path for path in raw if path.is_file()]
tools = Path.home() / "nhm-c03-tools"
build = Path.home() / "nhm-c03-build" / "debug"
binaries = [
    build / "health-state",
    build / "health-watchdog",
    tools / "prometheus-3.9.1.linux-amd64/prometheus",
    tools / "prometheus-3.9.1.linux-amd64/promtool",
    tools / "prometheus-3.9.1.linux-amd64.tar.gz",
    tools / "alertmanager-0.34.1.linux-amd64/alertmanager",
    tools / "alertmanager-0.34.1.linux-amd64/amtool",
    tools / "alertmanager-0.34.1.linux-amd64.tar.gz",
]
receipt_path = EVIDENCE / "raw/runtime-final/start-receipt.json"
receipt = json.loads(receipt_path.read_text())
for name, item in receipt["source_at_start"].items():
    original = Path(item["path"])
    materialized = (
        EVIDENCE / "raw/runtime-final" / f"frozen-{original.name}"
        if name.endswith("_config")
        else original
    )
    if sha(materialized) != item["sha256"]:
        raise RuntimeError(f"final runtime input differs from start receipt: {name}")


def freeze(name, paths):
    lines = [
        f"{sha(path)}  {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}"
        for path in paths
    ]
    destination = EVIDENCE / name
    destination.write_text("\n".join(lines) + "\n")
    return {"count": len(paths), "sha256": sha(destination)}


summary = {
    "source": freeze("SOURCE-SHA256SUMS", [ROOT / path for path in sources]),
    "raw": freeze("RAW-SHA256SUMS", raw),
    "binary": freeze("BINARY-SHA256SUMS", binaries),
    "runtime_start_receipt_sha256": sha(receipt_path),
}
report = EVIDENCE / "C03-STATE-RULES-NOTIFICATION-EVIDENCE.md"
if report.is_file():
    summary["report_sha256"] = sha(report)
(EVIDENCE / "INDEX-SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, sort_keys=True))
