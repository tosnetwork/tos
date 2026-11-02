"""Prepared-recovery sensitivity controls in a private Python-only copy."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CASES = [
    (
        "tick-recovery",
        "relay_service.py",
        "state = self.engine.recover_reserved(identity)",
        'state = "reserved"',
        "test_relay_service.ServiceTests.test_lost_prepare_reply_recovers_sealed_bytes_without_preparing_again",
    ),
    (
        "expired-dispatch",
        "relay_core.py",
        "if int(self.clock()) >= request.valid_until:",
        "if False:",
        "test_relay_service.ServiceTests.test_expired_sealed_recovery_keeps_bytes_and_never_broadcasts",
    ),
    (
        "operation-route",
        "native_process.py",
        '        "recover_prepared",\n',
        "",
        "test_native_boundary.ProcessTests.test_recovery_operation_reaches_the_sealed_process",
    ),
    (
        "uncertain-locks",
        "relay_service.py",
        """                except Exception:
                    failed += 1""",
        """                except Exception:
                    self.journal.cancel_unprepared(identity, int(self.engine.clock()))
                    failed += 1""",
        "test_relay_service.ServiceTests.test_uncertain_native_recovery_keeps_expired_reservations",
    ),
]

CASES.append(
    (
        "validation-before-journal",
        "relay_core.py",
        '        self.adapter.validate_prepared(\n            self.release, request, row["slot"], row["issued"], row["funding"], prepared\n        )\n        self.journal.store_prepared(identity, prepared)',
        "        self.journal.store_prepared(identity, prepared)",
        "test_relay_service.ServiceTests.test_recovered_bytes_require_validation_before_journaling_or_send",
    )
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[3]
    os.umask(0o077)
    rows = []
    with tempfile.TemporaryDirectory() as temporary:
        private = Path(temporary)
        tools = private / "tools/bonded-relayer"
        tests = private / "test/bonded-relayer"
        tools.mkdir(parents=True)
        tests.mkdir(parents=True)
        for source in (root / "tools/bonded-relayer").glob("*.py"):
            shutil.copyfile(source, tools / source.name)
        for name in (
            "test_engine.py",
            "test_journal_limits.py",
            "test_relay_service.py",
            "test_native_boundary.py",
            "_service_fixture.py",
        ):
            shutil.copyfile(root / "test/bonded-relayer" / name, tests / name)

        def run(name, selected=None):
            modules = (
                [selected]
                if selected
                else [
                    "test_engine",
                    "test_journal_limits",
                    "test_relay_service",
                    "test_native_boundary",
                ]
            )
            result = subprocess.run(
                [sys.executable, "-B", "-m", "unittest", *modules],
                cwd=tests,
                capture_output=True,
                timeout=60,
            )
            raw = result.stdout + result.stderr
            (args.out / (name + ".log")).write_bytes(raw)
            if selected:
                if (
                    result.returncode != 1
                    or b"AssertionError" not in raw
                    or not re.search(rb"FAILED \(failures=[1-9][0-9]*\)", raw)
                    or b"ERROR:" in raw
                ):
                    raise RuntimeError(name + ": intended runtime assertion did not fail")
            elif result.returncode:
                raise RuntimeError(name + ": baseline/restoration failed")
            rows.append(
                dict(
                    name=name,
                    test=selected,
                    exit=result.returncode,
                    sha256=hashlib.sha256(raw).hexdigest(),
                    bytes=len(raw),
                )
            )

        run("baseline")
        for name, file, before, after, test in CASES:
            path = tools / file
            original = path.read_text()
            if original.count(before) != 1:
                raise RuntimeError(name + ": anchor changed")
            path.write_text(original.replace(before, after))
            run(name, test)
            path.write_text(original)
        run("restored")
    files = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((root / "tools/bonded-relayer").glob("*.py"))
    }
    for name in (
        "test_engine.py",
        "test_journal_limits.py",
        "test_relay_service.py",
        "test_native_boundary.py",
        "_service_fixture.py",
    ):
        path = root / "test/bonded-relayer" / name
        files[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    files[str(Path(__file__).relative_to(root))] = hashlib.sha256(
        Path(__file__).read_bytes()
    ).hexdigest()
    (args.out / "REPORT.json").write_text(
        json.dumps(dict(result="PASS", files=files, rows=rows), indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
