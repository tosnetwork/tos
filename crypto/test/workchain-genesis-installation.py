#!/usr/bin/env python3
"""Real genesis generation plus private production-method validation."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--repo", type=Path, required=True)
parser.add_argument("--create-state", type=Path, required=True)
parser.add_argument("--probe", type=Path, required=True)
parser.add_argument("--evidence", type=Path)
args = parser.parse_args()
out = args.evidence or Path(tempfile.mkdtemp(prefix="uno-genesis-evidence-")) / "run"
out.mkdir(parents=True, exist_ok=False)
assert args.create_state.is_file() and args.probe.is_file(), "940: missing executable"
source = (args.repo / "crypto/smartcont/gen-zerostate.fif").read_text()
assert source.count("1 setglobalid") == 1, "941: ambiguous network construction"
(out / "genesis.fif").write_text(source.replace("1 setglobalid", "-23901 setglobalid"))
# Public test validators from repeated-byte Ed25519 seeds 1, 2, 3, 4. Never
# imported into production: the generator copy has a distinct test global ID.
(out / "validator-keys.pub").write_bytes(bytes.fromhex(
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
    "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"
    "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1"
    "ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c"))
report = {"scope": "Real genesis and production check_mc_state_extra method, not complete block validation.", "runs": []}
def run(name, command):
    result = subprocess.run(command, cwd=out, env=dict(os.environ, SOURCE_DATE_EPOCH="1789434000"),
                            capture_output=True, timeout=90)
    (out / (name + ".stdout.log")).write_bytes(result.stdout)
    (out / (name + ".stderr.log")).write_bytes(result.stderr)
    report["runs"].append({"name": name, "command": list(map(str, command)), "exit": result.returncode})
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    assert result.returncode == 0, f"942: failed execution: {name}"
    return result.stdout
includes = ":".join(map(str, (args.repo / "crypto/fift/lib", args.create_state.parent / "smartcont",
                               args.repo / "crypto/smartcont")))
run("generate", [args.create_state, "-I", includes, out / "genesis.fif"])
(out / "zerostate.boc.fhash").write_bytes((out / "zerostate.fhash").read_bytes())
for mode, expected in [("genesis", 0), ("missing-instance", 1), ("wrong-descriptor", 1)]:
    diagnostics = out / (mode + "-diagnostics")
    diagnostics.mkdir()
    stdout = run(mode, [args.probe, out / "zerostate.boc", mode, diagnostics])
    assert stdout.strip() == f"final_typed_kind={expected}".encode(), f"943: wrong final typed result: {mode}"
print(f"PASS: genesis issued and three production method cases; evidence={out}")
