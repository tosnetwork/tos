#!/usr/bin/env python3
"""One-source-at-a-time calibration in disposable measurement copies."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

repo = pathlib.Path(__file__).resolve().parents[1]
binary = pathlib.Path(sys.argv[1]).resolve()
out = pathlib.Path(sys.argv[2]).resolve()
out.mkdir(parents=True, exist_ok=False)
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
path = "crypto/smartcont/uno-genesis-operators.fif"
original = subprocess.check_output(["git", "show", f"{commit}:{path}"], cwd=repo)
assert (repo / path).read_bytes() == original
digest = lambda data: hashlib.sha256(data).hexdigest()
report = {"commit": commit, "source": path, "source_sha256": digest(original),
          "executable": str(binary), "executable_sha256": digest(binary.read_bytes()),
          "actual_executable_targets": ["create-state"],
          "scope": "Approval predicate and generator pre-artifact boundary only; not completed genesis or D40 acceptance.",
          "controls": []}
driver = repo / "test/test-uno-genesis-operators.py"

def run(name, operators, expected_code):
    command = [sys.executable, str(driver), "--repo", str(repo), "--create-state", str(binary),
               "--operators", str(operators), "--evidence", str(out / name)]
    result = subprocess.run(command, capture_output=True)
    (out / (name + ".stdout.log")).write_bytes(result.stdout)
    (out / (name + ".stderr.log")).write_bytes(result.stderr)
    assert (result.returncode == 0) == (expected_code == 0)
    if expected_code:
        assert f"AssertionError: {expected_code}:".encode() in result.stderr
    return {"command": command, "exit_code": result.returncode, "failure_identity": expected_code}

report["baseline"] = run("baseline", repo / path, 0)
for name, before, after, identity in [
    ("approve-unlisted-mainnet", "{ 2drop false }", "{ 2drop true }", 984),
    ("remove-enforcement", 'abort"mainnet coordinator/custody pair is not owner-approved"', "drop", 985),
]:
    before, after = before.encode(), after.encode()
    assert original.count(before) == 1
    mutant = original.replace(before, after)
    with tempfile.TemporaryDirectory(prefix="uno-operator-control-") as temporary:
        copy = pathlib.Path(temporary) / "operators.fif"
        copy.write_bytes(original)
        assert digest(copy.read_bytes()) == digest(original)
        copy.write_bytes(mutant)
        # Fift source is interpreted, not embedded in create-state. Load the
        # definition successfully before counting a subsequent behavioral red.
        syntax = pathlib.Path(temporary) / "syntax.fif"
        syntax.write_text(f'"{copy}" include\n')
        includes = ":".join(map(str, (repo / "crypto/fift/lib", binary.parent / "smartcont", repo / "crypto/smartcont")))
        loaded = subprocess.run([str(binary), "-I", includes, str(syntax)], capture_output=True)
        (out / (name + ".load.stdout.log")).write_bytes(loaded.stdout)
        (out / (name + ".load.stderr.log")).write_bytes(loaded.stderr)
        assert loaded.returncode == 0
        observed = run(name, copy, identity)
        copy.write_bytes(original)
        restored = copy.read_bytes()
        assert restored == original and digest(restored.replace(before, after)) == digest(mutant)
        report["controls"].append({"name": name, "from": before.decode(), "to": after.decode(),
            "copy_before_sha256": digest(original), "mutant_sha256": digest(mutant),
            "restored_sha256": digest(restored), "restore_audit_sha256": digest(restored.replace(before, after)),
            "load_exit_code": loaded.returncode, "observation": observed})

# Explicit rebuild after all measurement copies are discarded. The source
# mutation cannot persist in this binary, but the actual executable is named.
command = ["cmake", "--build", str(binary.parent.parent), "--target", "create-state", "-j32"]
rebuilt = subprocess.run(command, capture_output=True)
(out / "restored-build.stdout.log").write_bytes(rebuilt.stdout)
(out / "restored-build.stderr.log").write_bytes(rebuilt.stderr)
assert rebuilt.returncode == 0
report["restored_build"] = {"command": command, "exit_code": rebuilt.returncode}
report["restored"] = run("restored", repo / path, 0)
report["source_unchanged"] = (repo / path).read_bytes() == original
assert report["source_unchanged"]
(out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
