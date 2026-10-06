"""Reproduce a candidate bundle and prove changed identities/files are rejected.

All corruptions affect disposable public bundle copies, never the checkout or
compiler. A native compile failure does not count as a rejected mutation.
"""

import argparse
import contextlib
import importlib.util
import inspect
import io
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/build-wallet-v5r2-bundle.py"
spec = importlib.util.spec_from_file_location("v5r2_bundle", SCRIPT)
bundle_api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle_api)


def expect_refusal(check, changed, manifest, name, message):
    try:
        check(changed, manifest)
    except ValueError as error:
        if message not in str(error):
            raise AssertionError((name, "wrong failure", str(error))) from error
        return str(error)
    raise AssertionError("bundle corruption survived: " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--expected-manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    folder = args.output / "bundle"
    results = []

    def run(name, flags):
        command = [sys.executable, str(SCRIPT), *map(str, flags)]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=180)
        (args.output / (name + ".stdout")).write_text(result.stdout)
        (args.output / (name + ".stderr")).write_text(result.stderr)
        if result.returncode:
            raise RuntimeError(f"{name} failed before semantic controls: {result.stderr[-2000:]}")
        results.append({"name": name, "command": command, "exit": result.returncode})

    build_flags = ["--config", args.config.resolve(), "--output-dir", folder]
    if args.expected_manifest is not None:
        build_flags += ["--expected-manifest", args.expected_manifest.resolve()]
    run("build", build_flags)
    run("reproduce", ["--config", args.config.resolve(), "--check", folder])
    manifest = json.loads((folder / "manifest.json").read_text())
    # Exercise the CLI option, not only the comparison API. Native code must
    # exist before either expected-manifest refusal can count as semantic.
    wrong_namespace = None
    for label, message in (
        ("expected-namespace", "bundle differs from current sources: config"),
        ("expected-status", "unknown expected bundle format or acceptance status"),
    ):
        expected = json.loads((folder / "manifest.json").read_text())
        if label == "expected-namespace":
            expected["config"]["network"] = "ff" * 32
        else:
            expected["status"] = "approved"
        path = args.output / (label + ".json")
        path.write_text(json.dumps(expected))
        if label == "expected-namespace":
            wrong_namespace = path
        output = args.output / label
        command = [
            sys.executable,
            str(SCRIPT),
            "--config",
            str(args.config.resolve()),
            "--output-dir",
            str(output),
            "--expected-manifest",
            str(path),
        ]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=180)
        (args.output / (label + ".stdout")).write_text(result.stdout)
        (args.output / (label + ".stderr")).write_text(result.stderr)
        assert all(
            (output / "code" / (name + ".boc")).is_file() for name in ("wallet", "module", "vault")
        ), "expected-manifest control did not compile"
        assert result.returncode != 0 and message in result.stderr, (
            "expected manifest was not refused: " + label
        )
        results.append(
            {
                "name": label,
                "command": command,
                "exit": result.returncode,
                "semantic_refusal": message,
            }
        )

    # The same command-line assertion must detect deletion of the option's
    # actual call site. The mutation lives only in a function copy in memory.
    def invoke(entrypoint, output):
        argv = [
            str(SCRIPT),
            "--config",
            str(args.config.resolve()),
            "--output-dir",
            str(output),
            "--expected-manifest",
            str(wrong_namespace),
        ]
        with patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
            entrypoint()

    for label, entrypoint in (("original", bundle_api.main), ("deleted", None)):
        if entrypoint is None:
            source = inspect.getsource(bundle_api.main)
            guard = "if args.expected_manifest is not None:"
            assert source.count(guard) == 1, "expected-manifest CLI anchor changed"
            namespace = dict(bundle_api.__dict__)
            exec(compile(source.replace(guard, "if False:"), str(SCRIPT), "exec"), namespace)
            entrypoint = namespace["main"]

        def check(*_, routine=entrypoint, case=label):
            invoke(routine, args.output / (case + "-expected-option"))

        try:
            expect_refusal(
                check,
                None,
                None,
                "expected-manifest-option",
                "bundle differs from current sources: config",
            )
        except AssertionError as error:
            assert (
                label == "deleted"
                and str(error) == "bundle corruption survived: expected-manifest-option"
            )
            results.append(
                {"name": "deleted-expected-manifest-option", "red_assertion": str(error)}
            )
        else:
            assert label == "original", (
                "CLI negative test did not detect expected-manifest option deletion"
            )
    vector = "repository/test/rescue-fee-gate/suite-scenarios.tsv"
    guard_controls = {
        "wallet-bytecode": (
            "integrity",
            "if path.is_symlink() or digest(path.read_bytes()) != expected_digest:",
            "if False:",
        ),
        "unexpected-file": ("file-set", "if actual != expected:", "if False:"),
        "unreviewed-status": (
            "review-status",
            'if stored.get("format") != FORMAT or stored.get("status") != "unapproved-review-candidate":',
            "if False:",
        ),
        "wrong-namespace": (
            "configuration",
            "if stored.get(key) != fresh[key]:",
            'if key != "config" and stored.get(key) != fresh[key]:',
        ),
    }
    for name, target, message in (
        ("wallet-bytecode", "code/wallet.boc", "bundle file digest differs"),
        ("module-bytecode", "code/module.boc", "bundle file digest differs"),
        ("vault-bytecode", "code/vault.boc", "bundle file digest differs"),
        ("wire-vector", vector, "bundle file digest differs"),
        ("missing-code", "code/wallet.boc", "bundle file set differs"),
        ("unexpected-file", "untracked.boc", "bundle file set differs"),
        ("unreviewed-status", "manifest.json", "unknown bundle format or acceptance status"),
        ("wrong-namespace", "manifest.json", "bundle differs from current sources: config"),
    ):
        with tempfile.TemporaryDirectory(prefix="v5r2-bundle-negative-") as directory:
            changed = Path(directory) / "bundle"
            shutil.copytree(folder, changed)
            path = changed / target
            if name == "missing-code":
                path.unlink()
            elif name == "unexpected-file":
                path.write_bytes(b"unexpected public bundle content")
            elif name in ("unreviewed-status", "wrong-namespace"):
                record = json.loads(path.read_text())
                if name == "unreviewed-status":
                    record["status"] = "approved"
                else:
                    record["config"]["network"] = "ff" * 32
                path.write_text(json.dumps(record))
            else:
                raw = path.read_bytes()
                path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
            refusal = expect_refusal(bundle_api.check_bundle, changed, manifest, name, message)
            results.append({"name": name, "semantic_refusal": refusal})
            if name in guard_controls:
                # Delete only one guard in an in-memory function copy;
                # the same negative assertion must now fail, not the compiler.
                source = inspect.getsource(bundle_api.check_bundle)
                label, guard, replacement = guard_controls[name]
                if source.count(guard) != 1:
                    raise AssertionError("bundle guard anchor changed: " + label)
                namespace = dict(bundle_api.__dict__)
                exec(compile(source.replace(guard, replacement), str(SCRIPT), "exec"), namespace)
                mutated_check = namespace["check_bundle"]
                try:
                    expect_refusal(mutated_check, changed, manifest, name, message)
                except AssertionError as error:
                    if str(error) != "bundle corruption survived: " + name:
                        raise
                    results.append(
                        {"name": "deleted-" + label + "-guard", "red_assertion": str(error)}
                    )
                else:
                    raise AssertionError("bundle negative test did not detect guard deletion")
    # Exercise the command-line reproduction again after all disposable controls.
    restored_flags = ["--check", folder]
    if args.expected_manifest is not None:
        restored_flags += ["--expected-manifest", args.expected_manifest.resolve()]
    run("restored", restored_flags)
    report = {
        "passed": True,
        "scope": __doc__,
        "results": results,
        "config": manifest["config"],
        "code": manifest["code"],
        "manifest": bundle_api.digest((folder / "manifest.json").read_bytes()),
    }
    (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
