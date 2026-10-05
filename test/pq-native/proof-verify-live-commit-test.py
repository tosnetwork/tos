#!/usr/bin/env python3
"""tos-proof-verify's live-state commit path, through the installed CLI.

A test-only LD_PRELOAD shim records the commit's filesystem calls and can fail
the directory sync. Controls:
  * a successful live run commits in this order: sync the temporary record,
    close it, rename it over the record, sync the directory, close it;
  * a failed directory sync refuses the run;
  * a fresh process reopening the committed record refuses a target below the
    head (rollback) and another block at the head's height (conflict), and
    leaves the record unchanged.

usage: proof-verify-live-commit-test.py VERIFIER FIXTURE_WRITER SHIM
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def fail(message: str) -> None:
    print(f"PROOF_VERIFY_LIVE_COMMIT_FAILURE: {message}")
    sys.exit(1)


def run(verifier, fixture, request, material, state, shim, log, extra_env=None):
    env = {
        "LD_PRELOAD": str(shim),
        "PROOF_VERIFY_FS_DIR": str(state.parent),
        "PROOF_VERIFY_FS_LOG": str(log),
        **(extra_env or {}),
    }
    result = subprocess.run(
        [
            str(verifier),
            "verify",
            "--anchor",
            str(fixture / "anchor.json"),
            "--request",
            str(fixture / request),
            "--material",
            str(fixture / material),
            "--state",
            str(state),
        ],
        capture_output=True,
        env=env,
        timeout=120,
    )
    try:
        output = json.loads(result.stdout)
    except ValueError:
        fail(f"{request}: output is not JSON: {result.stdout[:200]!r}")
    return result.returncode, output


def main() -> int:
    verifier, writer, shim = (Path(arg).resolve() for arg in sys.argv[1:4])
    with tempfile.TemporaryDirectory() as work:
        work = Path(os.path.realpath(work))
        fixture = work / "fixture"
        fixture.mkdir()
        subprocess.run([str(writer), "--write-live-fixture", str(fixture)], check=True)

        # Successful commit and its ordering.
        state_dir = work / "state"
        state_dir.mkdir()
        state = state_dir / "live.json"
        log = work / "fs.log"
        code, output = run(verifier, fixture, "request-t.json", "material-t", state, shim, log)
        if code != 0 or output.get("status") != "verified":
            fail(f"live baseline refused: {output}")
        events = [line.split() for line in log.read_text().splitlines()]
        temporary = f"{state}.tmp"
        expected = [
            ["fsync", temporary],
            ["close", temporary],
            ["rename", temporary, str(state)],
            ["fsync-dir", str(state_dir)],
            ["close", str(state_dir)],
        ]
        commit = [
            event
            for event in events
            if event[0] in ("fsync", "fsync-dir", "rename")
            or (event[0] == "close" and event[1] in (temporary, str(state_dir)))
        ]
        if commit != expected:
            fail(f"commit order differs: {commit}")
        record = json.loads(state.read_text())
        if (
            record["head"]["seqno"] != 3
            or record["head"]["root_hash"] != output["target"]["root_hash"]
        ):
            fail(f"committed head differs from the verified target: {record}")
        print("PROOF_VERIFY_LIVE_COMMIT_CASE ordering PASS")

        # A fresh process reopens the committed record.
        committed = state.read_bytes()
        for request, material, reason, name in (
            ("request-k1.json", "material-k1", "rollback refused", "reopened-rollback"),
            (
                "request-t2.json",
                "material-t2",
                "conflicts with the verified head",
                "reopened-conflict",
            ),
        ):
            code, output = run(
                verifier, fixture, request, material, state, shim, work / "other.log"
            )
            if (
                code != 1
                or output.get("status") != "refused"
                or reason not in output.get("reason", "")
            ):
                fail(f"{name}: expected refusal '{reason}', got exit {code}: {output}")
            if state.read_bytes() != committed:
                fail(f"{name}: a refused run changed the committed record")
            print(f"PROOF_VERIFY_LIVE_COMMIT_CASE {name} PASS reason={output['reason']}")

        # Injected directory-sync failure.
        fresh_dir = work / "fresh"
        fresh_dir.mkdir()
        code, output = run(
            verifier,
            fixture,
            "request-t.json",
            "material-t",
            fresh_dir / "live.json",
            shim,
            work / "failing.log",
            {"PROOF_VERIFY_FAIL_DIR_FSYNC": "1"},
        )
        if code != 1 or "cannot sync live state directory" not in output.get("reason", ""):
            fail(f"directory sync failure was not refused: exit {code}: {output}")
        print(
            f"PROOF_VERIFY_LIVE_COMMIT_CASE directory-sync-failure PASS reason={output['reason']}"
        )
    print("PROOF_VERIFY_LIVE_COMMIT_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
