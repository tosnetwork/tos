#!/usr/bin/env python3
"""Compile single committed-source mutants without changing repository sources."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

p = argparse.ArgumentParser()
p.add_argument("--build", type=Path, required=True)
p.add_argument("--python", type=Path, required=True)
p.add_argument("--out", type=Path, required=True)
p.add_argument("--only", choices=["remove-genesis-issuance", "remove-destination-routing-guard", "remove-ledger-delta-guard"])
a = p.parse_args()
repo = Path(__file__).resolve().parents[2]
build, out = a.build.resolve(), a.out.resolve()
out.mkdir(parents=True, exist_ok=False)
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
sha = lambda data: hashlib.sha256(data).hexdigest()
commands = json.loads((build / "compile_commands.json").read_text())
report = {"commit": commit, "controls": [], "scope": "Single-source behavior controls; no milestone acceptance."}

def execute(name, command, cwd=build):
    result = subprocess.run(list(map(str, command)), cwd=cwd, capture_output=True)
    (out / (name + ".stdout.log")).write_bytes(result.stdout)
    (out / (name + ".stderr.log")).write_bytes(result.stderr)
    return result

def link_command(target):
    lines = subprocess.check_output(["ninja", "-C", str(build), "-t", "commands", target], text=True).splitlines()
    tokens = shlex.split(lines[-1])
    assert tokens[:2] == [":", "&&"] and tokens[-2:] == ["&&", ":"]
    return tokens[2:-2]

specs = [
    ("remove-genesis-issuance", "crypto/block/create-state.cpp", "create-state",
     "auto issued = block::reconstruct_configured_workchain_instances(\n      ledger_result.move_as_ok(), config_param_root, global_id);",
     "auto issued = std::move(ledger_result);"),
    ("remove-destination-routing-guard", "crypto/block/transaction.cpp", "test-tos-collator",
     "if (!it->second->accept_msgs) {", "if (false && !it->second->accept_msgs) {"),
    ("remove-ledger-delta-guard", "crypto/block/workchain-instance-identity.cpp", "test-workchain-instance-callsite",
     "if (expected->get_hash() != candidate->get_hash()) {", "if (false && expected->get_hash() != candidate->get_hash()) {"),
]
for name, source, target, before, after in specs:
    if a.only and name != a.only:
        continue
    original = subprocess.check_output(["git", "show", f"{commit}:{source}"], cwd=repo)
    assert (repo / source).read_bytes() == original and original.count(before.encode()) == 1
    mutant = original.replace(before.encode(), after.encode())
    with tempfile.TemporaryDirectory(prefix="uno-genesis-control-") as temporary:
        temp = Path(temporary)
        (temp / "smartcont").symlink_to(build / "crypto/smartcont", target_is_directory=True)
        copy = temp / Path(source).name
        copy.write_bytes(original)
        assert sha(copy.read_bytes()) == sha(original)
        copy.write_bytes(mutant)
        entry = next(e for e in commands if Path(e["file"]) == repo / source)
        compile_args = shlex.split(entry["command"])
        old_object = compile_args[compile_args.index("-o") + 1]
        obj = temp / Path(old_object).name
        compile_args[compile_args.index("-o") + 1] = str(obj)
        compile_args = [str(copy) if item == str(repo / source) else item for item in compile_args]
        compile_args += ["-I", str((repo / source).parent)]
        compiled = execute(name + "-compile", compile_args, Path(entry["directory"]))
        assert compiled.returncode == 0
        linked_args = link_command(target)
        executable = temp / target
        linked_args[linked_args.index("-o") + 1] = str(executable)
        archive_command = None
        if source == "crypto/block/create-state.cpp":
            assert old_object in linked_args
            linked_args = [str(obj) if item == old_object else item for item in linked_args]
        else:
            archive = temp / "libtos_block.a"
            shutil.copyfile(build / "crypto/libtos_block.a", archive)
            archive_command = ["ar", "r", str(archive), str(obj)]
            assert execute(name + "-archive", archive_command).returncode == 0
            assert "crypto/libtos_block.a" in linked_args
            linked_args = [str(archive) if item == "crypto/libtos_block.a" else item for item in linked_args]
        assert execute(name + "-link", linked_args).returncode == 0
        if target == "test-tos-collator":
            driver = repo / "crypto/test/workchain-genesis-routing.py"
            command = [a.python, driver, "--repo", repo, "--create-state", build / "crypto/create-state",
                       "--collator", executable, "--evidence", out / name]
            failed = execute(name, command)
            assert failed.returncode != 0 and b"AssertionError: 957" in failed.stderr
            matrix = json.loads((out / name / "report.json").read_text())
            assert len(matrix["cases"][0]["transactions"]) == 2
            assert matrix["cases"][1]["runs"][-1]["exit"] == 0
            failure_identity = 957
        else:
            command = [a.python, repo / "crypto/test/workchain-genesis-installation.py", "--repo", repo,
                       "--create-state", executable if target == "create-state" else build / "crypto/create-state",
                       "--probe", executable if target == "test-workchain-instance-callsite" else build / "crypto/test-workchain-instance-callsite",
                       "--evidence", out / name]
            failed = execute(name, command)
            assert failed.returncode != 0
            if target == "create-state":
                failure_identity = 936
                assert b"failure_identity=936" in (out / name / "genesis.stderr.log").read_bytes()
                assert json.loads((out / name / "report.json").read_text())["runs"][0]["exit"] == 0
            else:
                failure_identity = 931
                assert b"failure_identity=931" in (out / name / "missing-instance.stderr.log").read_bytes()
                assert (out / name / "genesis.stdout.log").read_bytes().strip() == b"final_typed_kind=0"
                # The driver stops on the first unexpected acceptance. Exercise
                # the distinct descriptor corruption explicitly as well.
                diagnostics = out / name / "wrong-descriptor-mutant-diagnostics"
                diagnostics.mkdir()
                extra = execute(name + "-wrong-descriptor", [executable, out / name / "zerostate.boc",
                                "wrong-descriptor", diagnostics])
                assert extra.returncode != 0 and b"failure_identity=931" in extra.stderr
        copy.write_bytes(original)
        restored = copy.read_bytes()
        assert restored == original and sha(restored.replace(before.encode(), after.encode())) == sha(mutant)
        report["controls"].append({"name": name, "source": source, "from": before, "to": after,
            "original_sha256": sha(original), "copy_before_sha256": sha(original), "mutant_sha256": sha(mutant),
            "restored_sha256": sha(restored), "restore_audit_sha256": sha(restored.replace(before.encode(), after.encode())),
            "compile_command": compile_args, "compile_exit": compiled.returncode, "archive_command": archive_command,
            "link_command": linked_args, "behavior_command": list(map(str, command)),
            "failure_identity": failure_identity, "source_unchanged": (repo / source).read_bytes() == original})
        (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")

restore = ["cmake", "--build", build, "--target", "create-state", "test-tos-collator",
           "test-workchain-instance-callsite", "-j32"]
assert execute("explicit-restored-targets", restore).returncode == 0
report["restored_targets"] = list(map(str, restore))
(out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
