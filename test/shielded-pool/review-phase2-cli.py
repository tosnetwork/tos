#!/usr/bin/env python3
"""Reproduce the phase-2 review observations, using temporary rehearsal data.

This is a reproducer for the reviewed revision, not an acceptance gate:
successful reproduction of an erroneous acceptance is still a finding.
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

        for name, changes in (
            ("false-transcript", {"transcript": "00" * 32}),
            ("false-provenance", {
                "phase1_transcript": "review-false-provenance",
                "constraints": 1,
                "instance_variables": 1,
            }),
        ):
            directory = work / name
            shutil.copytree(work / "ceremony", directory)
            record_file = directory / "ceremony.json"
            record = json.loads(record_file.read_text())
            record.update(changes)
            record_file.write_text(json.dumps(record))
            result = cli.run([str(cli.BINARIES / "phase2-verify"), str(directory)])
            if "This ceremony is finished" not in result.stdout:
                raise RuntimeError("the expected erroneous acceptance was not reproduced")
            print(f"FINDING REPRODUCED: {name} was accepted", flush=True)

        directory = work / "short-digest"
        shutil.copytree(work / "ceremony", directory)
        record_file = directory / "ceremony.json"
        record = json.loads(record_file.read_text())
        record["phase1_slice_sha256"] = "x"
        record_file.write_text(json.dumps(record))
        result = cli.run(
            [str(cli.BINARIES / "phase2-verify"), str(directory)], expect_success=False
        )
        if "panicked" not in result.stderr or "out of bounds" not in result.stderr:
            raise RuntimeError("the expected parsing panic was not reproduced")
        print("FINDING REPRODUCED: a short digest panics instead of naming a refusal")
    if work.exists():
        raise RuntimeError("rehearsal cleanup failed")
    print("All rehearsal artifacts removed; no signing key was generated.")


if __name__ == "__main__":
    main()
