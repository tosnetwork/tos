#!/usr/bin/env python3
"""Activation refusals with Param84 retained, at the real scoped resolver."""
import argparse
import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument("--repo", type=Path, required=True)
p.add_argument("--probe", type=Path, required=True)
p.add_argument("--mode", choices=["missing-capability", "old-version"], required=True)
p.add_argument("--evidence", type=Path)
a = p.parse_args()
out = a.evidence or Path(tempfile.mkdtemp(prefix="uno-genesis-activation-")) / "run"
out.mkdir(parents=True, exist_ok=False)
path = a.repo / "crypto/test/workchain-activation-rejection.py"
spec = importlib.util.spec_from_file_location("shared_activation", path)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
helper.check_activation_source(a.repo)
helper_commit = subprocess.check_output(["git", "log", "-1", "--format=%H", "--", str(path)], cwd=a.repo, text=True).strip()
helper_blob = subprocess.check_output(["git", "show", f"{helper_commit}:crypto/test/workchain-activation-rejection.py"], cwd=a.repo)
assert helper_blob == path.read_bytes(), "945: helper differs from committed source"
command = [str(a.probe)] + (["--old-version"] if a.mode == "old-version" else [])
result = subprocess.run(command, capture_output=True, timeout=30)
(out / "stdout.log").write_bytes(result.stdout)
(out / "stderr.log").write_bytes(result.stderr)
assert result.returncode == 0, "944: resolver probe did not complete"
helper.check_scoped_probe_output(result.stdout.decode())
facts = [line.split('\t') for line in result.stderr.decode().splitlines()
         if line.startswith('input_configuration\t')]
expected_disabled = ['14', '1', '1'] if a.mode == 'old-version' else ['16', '0', '1']
assert len(facts) == 4 and [row[1:] for row in facts] == [
    expected_disabled, ['16', '1', '1'], expected_disabled, ['16', '1', '1']], \
    "946: requested configuration experiment was not constructed"
(out / "report.json").write_text(json.dumps({"mode": a.mode, "command": command,
    "scope": "Real scoped resolver with Param84 retained in every configuration. These negative configurations are not legal genesis installations; no node startup, transaction or export observations are claimed.",
    "shared_helper": {"path": str(path), "commit": helper_commit, "sha256": hashlib.sha256(helper_blob).hexdigest()}}, indent=2) + "\n")
print(f"PASS: scoped activation refusal with Param84 retained; evidence={out}")
