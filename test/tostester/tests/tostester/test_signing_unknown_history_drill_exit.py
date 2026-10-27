"""The unknown-history drill is a gate: its exit status follows the mode's verdict.

These run the drill's own analysis (--analyze-only) on small synthetic logs, without a
chain: a log run that holds the fence, a producer control that signs a candidate in a
fenced session, a main control that signs again in its old session, and empty logs.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[4]
RUNNER = ROOT / "test/integration/signing_unknown_history_drill.py"
MC = "(-1,8000000000000000)"
SESSION = "AB" * 32
STOPPED_AT = 1_800_000_100.0  # 2027-01-15 08:01:40 UTC


def at(seconds: int) -> str:
    """A log timestamp `seconds` after 2027-01-15 08:00:00 UTC."""
    minutes, secs = divmod(seconds, 60)
    return f"[2027-01-15 08:{minutes:02d}:{secs:02d}.000000]"


def created(t: int, cc: int) -> str:
    return f"[ 3]{at(t)}[manager.cpp:1][!manager]\tCreated validator group {MC}.{cc}:AAAA="


def started(t: int, cc: int) -> str:
    return f"[ 3]{at(t)}[manager.cpp:1][!manager]\tStarted validator group {MC}.{cc}:AAAA="


def index(t: int, cc: int, idx: int) -> str:
    return (
        f"[ 3]{at(t)}[bridge.cpp:1][!valgroup]\tconsensus: session {SESSION} of {MC} catchain {cc}: "
        f"local validator index {idx}"
    )


def admission(t: int, cc: int, verdict: str) -> str:
    reason = " (at or below the unknown-history fence)" if verdict == "fenced" else ""
    return (
        f"[ 2]{at(t)}[manager.cpp:1][!manager]\tsigning ledger: session {SESSION} of {MC} catchain {cc}: "
        f"{verdict}{reason}"
    )


def own(t: int, cc: int, kind: str) -> str:
    return (
        f"[ 3]{at(t)}[pool.cpp:1][!valgroup]\tconsensus: own signature: first {kind} signed in session "
        f"{SESSION} of {MC} catchain {cc}"
    )


def certificate(t: int, cc: int, votes: str) -> str:
    return (
        f"[ 3]{at(t)}[pool.cpp:1][!valgroup{MC}.{cc}.SimplexPool]\t"
        f"Obtained certificate for SkipVote{{slot=1}}: {votes}"
    )


FENCE = (
    f"[ 2]{at(200)}[signing-ledger.cpp:1][!SigningLedger]\tsigning ledger: unknown history fenced at "
    f"(-1,8000000000000000,17):AA:BB over 1 lineages; sessions more than 2 catchain counters above them "
    f"sign again; counters: {MC}=1"
)


def write_run(
    directory: Path, mode: str, target_before: list[str], target_after: list[str], peer: list[str]
) -> Path:
    directory.mkdir()
    for node in range(1, 5):
        (directory / f"node{node}").mkdir()
    (directory / "node4" / "log.before-restart").write_text("\n".join(target_before) + "\n")
    (directory / "node4" / "log").write_text("\n".join(target_after) + "\n")
    (directory / "node1" / "log").write_text("\n".join(peer) + "\n")
    summary = {"mode": mode, "stopped_at": STOPPED_AT, "mc_cc_at_stop": 0}
    (directory / "drill-summary.json").write_text(json.dumps(summary))
    return directory


def analyze(directory: Path, mode: str) -> tuple[int, dict[str, Any]]:
    done = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--mode",
            mode,
            "--build",
            str(directory),
            "--working-dir",
            str(directory),
            "--analyze-only",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    summary_file = directory / "drill-summary.json"
    return done.returncode, json.loads(summary_file.read_text())


BEFORE = [created(0, 0), started(0, 0), index(1, 0, 3)]
# Before the stop the target signed in masterchain session 0 (index 3).
PEER_BEFORE = [certificate(50, 0, "VVVV")]


def log_run(tmp: Path, fenced_candidate: bool) -> Path:
    after = [
        created(110, 0),
        started(110, 0),
        index(111, 0, 3),
        admission(111, 0, "fenced"),
        FENCE,
        created(300, 3),
        index(301, 3, 3),
        admission(301, 3, "fenced"),
        created(600, 4),
        started(600, 4),
        index(601, 4, 2),
        admission(601, 4, "admitted"),
        own(610, 4, "candidate"),
        own(611, 4, "notarize vote"),
    ]
    if fenced_candidate:
        after.append(own(320, 3, "candidate"))
    peer = PEER_BEFORE + [certificate(620, 4, "VVVV")]
    return write_run(tmp / ("producer" if fenced_candidate else "log"), "log", BEFORE, after, peer)


def test_log_run_that_holds_the_fence_exits_zero(tmp_path: Path) -> None:
    status, summary = analyze(log_run(tmp_path, fenced_candidate=False), "log")
    assert summary["verdict"]["passed"] is True
    assert status == 0


def test_signing_inside_the_fence_fails_a_log_run(tmp_path: Path) -> None:
    status, summary = analyze(log_run(tmp_path, fenced_candidate=True), "log")
    assert summary["verdict"]["passed"] is False
    assert status == 3


def test_producer_control_succeeds_when_it_signs_inside_the_fence(tmp_path: Path) -> None:
    status, summary = analyze(log_run(tmp_path, fenced_candidate=True), "producer-control")
    assert summary["expectation"]["met"] is True
    assert status == 0


def test_producer_control_that_stays_green_fails(tmp_path: Path) -> None:
    status, summary = analyze(log_run(tmp_path, fenced_candidate=False), "producer-control")
    assert summary["expectation"]["met"] is False
    assert status == 4


def main_control(tmp: Path, signs_again: bool) -> Path:
    after = [created(110, 0), started(110, 0), index(111, 0, 3)]
    peer = PEER_BEFORE + (
        [certificate(130, 0, "VVVV")] if signs_again else [certificate(130, 0, "VVV.")]
    )
    return write_run(tmp / ("red" if signs_again else "green"), "control", BEFORE, after, peer)


def test_main_control_succeeds_when_it_signs_in_the_old_session(tmp_path: Path) -> None:
    status, summary = analyze(main_control(tmp_path, signs_again=True), "control")
    assert summary["verdict"]["red"] is True
    assert status == 0


def test_main_control_that_does_not_sign_again_fails(tmp_path: Path) -> None:
    status, summary = analyze(main_control(tmp_path, signs_again=False), "control")
    assert summary["verdict"]["red"] is False
    assert status == 4


def test_empty_logs_fail_every_mode(tmp_path: Path) -> None:
    for mode, expected in (("log", 3), ("control", 4), ("producer-control", 4)):
        directory = write_run(
            tmp_path / mode, "log" if mode == "producer-control" else mode, [], [], []
        )
        status, _ = analyze(directory, mode)
        assert status == expected, mode


def test_missing_summary_fails(tmp_path: Path) -> None:
    done = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--mode",
            "log",
            "--build",
            str(tmp_path),
            "--working-dir",
            str(tmp_path / "absent"),
            "--analyze-only",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode != 0
