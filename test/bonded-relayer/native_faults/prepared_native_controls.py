"""Real native prepared-recovery guard controls using private retained local custody.

Run only in an isolated checkout with no other compiler/editor. All operations
against the retained custody are historical lookup/validation, never prepare/send.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--custody", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inactive-unit", required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    root = args.checkout.resolve()
    path = root / "tools/bonded-relayer/provider/src/prepared.rs"
    original = path.read_text()
    manifest = root / "tools/bonded-relayer/provider/Cargo.toml"
    target = Path(os.environ["CARGO_TARGET_DIR"])
    driver = root / "test/bonded-relayer/native_faults/check_prepared_recovery.py"
    rows = []

    def command(name, command):
        result = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            timeout=1800,
            env={**os.environ, "CARGO_TERM_COLOR": "never"},
        )
        raw = result.stdout + result.stderr
        (args.out / (name + ".log")).write_bytes(raw)
        return result, raw

    def build(name):
        result, _ = command(
            name + "-build",
            [
                "cargo",
                "+1.99.1",
                "build",
                "--manifest-path",
                str(manifest),
                "--release",
                "--locked",
                "--bin",
                "br1-native-provider",
            ],
        )
        if result.returncode:
            raise RuntimeError(name + ": compilation failed, not runtime evidence")
        binary = args.out / ("provider-" + name)
        shutil.copyfile(target / "release/br1-native-provider", binary)
        binary.chmod(0o500)
        return binary, hashlib.sha256(binary.read_bytes()).hexdigest()

    def historical(name, red=False):
        binary, digest = build(name)
        result, raw = command(
            name + "-runtime",
            [
                sys.executable,
                str(driver),
                "--provider",
                str(binary),
                "--sha256",
                digest,
                "--custody",
                str(args.custody),
                "--min-cases",
                "5",
                "--inactive-unit",
                args.inactive_unit,
                "--out",
                str(args.out / (name + "-result.json")),
            ],
        )
        if red:
            if result.returncode != 1 or b"AssertionError: changed slot recovered" not in raw:
                raise RuntimeError(name + ": intended native binding violation not detected")
        elif result.returncode:
            raise RuntimeError(name + ": historical baseline/restoration failed")
        rows.append(
            dict(
                name=name,
                exit=result.returncode,
                sha256=hashlib.sha256(raw).hexdigest(),
                bytes=len(raw),
                provider_sha256=digest,
            )
        )

    try:
        historical("baseline")
        start = original.index("pub fn recover(")
        end = original.index("\npub fn validate(", start)
        fragment = original[start:end]
        before = "    validate(config, identity, directory, &checked)?;"
        if fragment.count(before) != 1:
            raise RuntimeError("native validation anchor changed")
        path.write_text(
            original[:start] + fragment.replace(before, "    let _ = checked;") + original[end:]
        )
        historical("missing-native-validation", red=True)
        path.write_text(original)
        before = """    let bytes = lease
        .message
        .ok_or_else(|| anyhow::anyhow!("interrupted signing requires manual reconciliation"))?;"""
        after = """    let bytes = match lease.message {
        Some(bytes) => bytes,
        None => return Ok(Value::Null),
    };"""
        if fragment.count(before) != 1:
            raise RuntimeError("unsigned recovery anchor changed")
        path.write_text(original[:start] + fragment.replace(before, after) + original[end:])
        result, raw = command(
            "unsigned-cancellation-build",
            [
                "cargo",
                "+1.99.1",
                "test",
                "--manifest-path",
                str(manifest),
                "--release",
                "--locked",
                "--bin",
                "br1-native-provider",
                "--no-run",
                "--message-format=json",
            ],
        )
        if result.returncode:
            raise RuntimeError("unsigned control compilation failed, not evidence")
        binaries = [
            x["executable"]
            for line in result.stdout.splitlines()
            if (x := json.loads(line)).get("reason") == "compiler-artifact"
            and x.get("executable")
            and x["target"]["name"] == "br1-native-provider"
        ]
        if len(binaries) != 1:
            raise RuntimeError("exact native test artifact required")
        test = "prepared::recovery_tests::recovery_distinguishes_missing_lease_from_interrupted_unsigned_lease"
        result, raw = command("unsigned-cancellation-runtime", [binaries[0], test, "--exact"])
        if (
            result.returncode != 101
            or b"unsigned native lease must not authorize cancellation" not in raw
            or f"test {test} ... FAILED".encode() not in raw
        ):
            raise RuntimeError("unsigned cancellation control did not fail in intended test body")
        rows.append(
            dict(
                name="unsigned-cancellation",
                exit=result.returncode,
                sha256=hashlib.sha256(raw).hexdigest(),
                bytes=len(raw),
            )
        )
        path.write_text(original)
        historical("restored")
    finally:
        path.write_text(original)
    (args.out / "REPORT.json").write_text(
        json.dumps(
            dict(
                result="PASS",
                source_sha256=hashlib.sha256(original.encode()).hexdigest(),
                driver_sha256=hashlib.sha256(driver.read_bytes()).hexdigest(),
                rows=rows,
            ),
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
