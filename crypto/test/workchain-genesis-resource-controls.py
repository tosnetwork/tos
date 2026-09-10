#!/usr/bin/env python3
"""Calibrate the resource approval gate with one immutable-source copy."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument("--create-state", type=Path, required=True)
p.add_argument("--out", type=Path, required=True)
a = p.parse_args()
repo = Path(__file__).resolve().parents[2]
out = a.out.resolve()
out.mkdir(parents=True, exist_ok=False)
source = "crypto/smartcont/uno-genesis-config.fif"
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
original = subprocess.check_output(["git", "show", f"{commit}:{source}"], cwd=repo)
assert (repo / source).read_bytes() == original
before, after = b"{ drop false }", b"{ drop true }"
assert original.count(before) == 1
mutant = original.replace(before, after)
sha = lambda data: hashlib.sha256(data).hexdigest()
with tempfile.TemporaryDirectory(prefix="uno-resource-control-") as directory:
    copy = Path(directory) / "resource.fif"
    copy.write_bytes(original)
    assert sha(copy.read_bytes()) == sha(original)
    copy.write_bytes(mutant)
    command = ["python3", str(repo / "test/test-uno-genesis-operators.py"), "--repo", str(repo),
               "--create-state", str(a.create_state), "--resources", str(copy), "--evidence", str(out / "run")]
    result = subprocess.run(command, capture_output=True)
    (out / "stdout.log").write_bytes(result.stdout)
    (out / "stderr.log").write_bytes(result.stderr)
    assert result.returncode != 0 and b"AssertionError: 990:" in result.stderr
    assert (out / "run/resource-testnet.stdout.log").read_bytes().strip() == b"993"
    assert (out / "run/resource-mainnet.stdout.log").read_bytes().strip() == b"993"
    copy.write_bytes(original)
    restored = copy.read_bytes()
    assert restored == original and sha(restored.replace(before, after)) == sha(mutant)
    report = {"commit": commit, "source": source, "from": before.decode(), "to": after.decode(),
              "original_sha256": sha(original), "copy_before_sha256": sha(original),
              "mutant_sha256": sha(mutant), "restored_sha256": sha(restored),
              "restore_audit_sha256": sha(restored.replace(before, after)),
              "failure_identity": 990, "command": command,
              "interpretation_completed": "Both resource branches reached sentinel 993; not a load failure.",
              "source_unchanged": (repo / source).read_bytes() == original}
command = ["cmake", "--build", str(a.create_state.resolve().parent.parent), "--target", "create-state", "-j32"]
result = subprocess.run(command, capture_output=True)
(out / "restored-build.stdout.log").write_bytes(result.stdout)
(out / "restored-build.stderr.log").write_bytes(result.stderr)
assert result.returncode == 0
report["restored_build_command"] = command
(out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
