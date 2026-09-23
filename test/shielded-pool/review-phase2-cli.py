#!/usr/bin/env python3
"""The three record-validation defects the 2026-09-22 review found, now refused.

Written as a reproducer: it asserted that a tampered record was *accepted*,
which was true and was the finding. The defects are fixed, so it asserts the
refusal instead -- and names the reason, because a refusal for the wrong
reason would keep this green while the check it is about was gone.

R1  the summary transcript was outside the final audit
R2  provenance and dimensions were printed as facts, never compared
R3  a malformed digest string panicked instead of naming a refusal

Findings and analysis: doc/shielded-pool-phase2-review-results.md
"""
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile


def main():
    script = Path(__file__).with_name("ceremony-cli.py")
    spec = importlib.util.spec_from_file_location("ceremony_cli", script)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    with tempfile.TemporaryDirectory(prefix="tos-phase2-REHEARSAL-") as temporary:
        work = Path(temporary)
        previous_args = sys.argv
        try:
            sys.argv = [str(script), "--work", str(work)]
            cli.main()
        finally:
            sys.argv = previous_args

        for name, changes, reason in (
            ("false-transcript", {"transcript": "00" * 32},
             "the record summarises it as"),
            ("false-provenance", {
                "phase1_transcript": "review-false-provenance",
                "constraints": 1,
                "instance_variables": 1,
            }, "the slice it was begun over is from"),
        ):
            directory = work / name
            shutil.copytree(work / "ceremony", directory)
            record_file = directory / "ceremony.json"
            record = json.loads(record_file.read_text())
            record.update(changes)
            record_file.write_text(json.dumps(record))
            result = cli.run(
                [str(cli.BINARIES / "phase2-verify"), str(directory)], expect_success=False
            )
            blob = result.stdout + result.stderr
            if "This ceremony is finished" in blob:
                raise RuntimeError(f"{name}: a tampered record was accepted")
            if reason not in blob:
                raise RuntimeError(
                    f"{name}: refused, but not for {reason!r} -- a refusal for another "
                    f"reason would hide the loss of this check\n{blob[-800:]}"
                )
            print(f"REFUSED for the right reason: {name}", flush=True)

        directory = work / "short-digest"
        shutil.copytree(work / "ceremony", directory)
        record_file = directory / "ceremony.json"
        record = json.loads(record_file.read_text())
        record["phase1_slice_sha256"] = "x"
        record_file.write_text(json.dumps(record))
        result = cli.run(
            [str(cli.BINARIES / "phase2-verify"), str(directory)], expect_success=False
        )
        blob = result.stdout + result.stderr
        if "panicked" in blob:
            raise RuntimeError(f"a malformed digest still panics\n{blob[-800:]}")
        if "is not a SHA-256 digest" not in blob:
            raise RuntimeError(f"refused, but not for the digest format\n{blob[-800:]}")
        print("REFUSED for the right reason: short-digest")
    if work.exists():
        raise RuntimeError("rehearsal cleanup failed")
    print("All rehearsal artifacts removed; no signing key was generated.")


if __name__ == "__main__":
    main()
