"""The fence drills are gates: each exit status follows its arm's verdict.

They run the drills' own analysis (--analyze-only) on small synthetic logs, without a
chain: D1 (restore from a file copy), D2 (genesis with and without the ceremony) and D5
(a handover that replaces half the weight), each arm passing and failing.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def _load(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The synthetic log lines of the unknown-history drill's exit tests, shared.
_lines: Any = _load(Path(__file__).resolve().parent / "test_signing_unknown_history_drill_exit.py")
BEFORE: list[str] = _lines.BEFORE
MC: str = _lines.MC
PEER_BEFORE: list[str] = _lines.PEER_BEFORE
STOPPED_AT: float = _lines.STOPPED_AT
admission = _lines.admission
at = _lines.at
certificate = _lines.certificate
created = _lines.created
index = _lines.index
own = _lines.own
started = _lines.started

ROOT = Path(__file__).resolve().parents[4]
RUNNER = ROOT / "test/integration/signing_fence_drills.py"
COPY_REASON = "the signing ledger directory is not the one it was created as: it was copied, restored or recreated"


def fence_line(t: int, counters: str) -> str:
    # As the ledger logs it now: the block, then when it was generated and the wait.
    return (
        f"[ 2]{at(t)}[signing-ledger.cpp:1][!SigningLedger]\tsigning ledger: unknown history fenced at "
        f"(-1,8000000000000000,17):AA:BB (generated 1800000200, waiting from 1800000050) over 1 lineages; "
        f"sessions more than 2 catchain counters above them sign again; counters: {counters}"
    )


def untrusted(t: int) -> str:
    return (
        f"[ 1]{at(t)}[signing-ledger.cpp:1][!SigningLedger]\tsigning ledger /db/consensus/signing-ledger: "
        f"{COPY_REASON}; a pending ledger for unknown history replaces it at the first admission"
    )


def hint(t: int) -> str:
    return f"[ 1]{at(t)}[manager.cpp:1][!manager]\tsigning ledger: no signing ledger at genesis: run ..."


def analyze(directory: Path, drill: str, mode: str) -> tuple[int, dict[str, Any]]:
    done = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--drill",
            drill,
            "--mode",
            mode,
            "--working-dir",
            str(directory),
            "--analyze-only",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return done.returncode, json.loads((directory / "drill-summary.json").read_text())


def write_nodes(
    directory: Path, logs: dict[int, dict[str, list[str]]], summary: dict[str, Any]
) -> Path:
    directory.mkdir()
    for node in range(1, int(summary.get("nodes", 4)) + 1):
        (directory / f"node{node}").mkdir()
        for name, lines in logs.get(node, {}).items():
            (directory / f"node{node}" / name).write_text("\n".join(lines) + "\n")
    (directory / "drill-summary.json").write_text(json.dumps(summary))
    return directory


# ===== D1: restore from a file copy =====


def restore_run(
    tmp: Path, mode: str, copy_detected: bool, signs_in_fence: bool, signs_again: bool
) -> Path:
    after = [created(110, 0), started(110, 0), index(111, 0, 3)]
    if copy_detected:
        after.append(untrusted(105))
    peer = list(PEER_BEFORE)
    if mode == "log":
        after += [
            admission(111, 0, "fenced"),
            fence_line(200, f"{MC}=1"),
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
        if signs_in_fence:
            after.append(own(320, 3, "skip vote"))
        peer.append(certificate(620, 4, "VVVV"))
    elif signs_again:
        peer.append(certificate(130, 0, "VVVV"))
    else:
        peer.append(certificate(130, 0, "VVV."))
    summary = {"drill": "restore-copy", "mode": mode, "stopped_at": STOPPED_AT, "mc_cc_at_stop": 0}
    name = f"{mode}-{copy_detected}-{signs_in_fence}-{signs_again}"
    return write_nodes(
        tmp / name, {4: {"log.before-restart": BEFORE, "log": after}, 1: {"log": peer}}, summary
    )


def test_restore_copy_log_arm_passes(tmp_path: Path) -> None:
    status, summary = analyze(
        restore_run(tmp_path, "log", True, False, False), "restore-copy", "log"
    )
    assert summary["verdict"]["ledger_untrusted_as_a_copy"] is True
    assert summary["verdict"]["passed"] is True
    assert status == 0


def test_restore_copy_log_arm_fails_without_the_copy_reason(tmp_path: Path) -> None:
    status, _ = analyze(restore_run(tmp_path, "log", False, False, False), "restore-copy", "log")
    assert status == 3


def test_restore_copy_log_arm_fails_on_a_signature_in_the_fence(tmp_path: Path) -> None:
    status, summary = analyze(
        restore_run(tmp_path, "log", True, True, False), "restore-copy", "log"
    )
    assert summary["verdict"]["no_signature_within_fence"] is False
    assert status == 3


def test_restore_copy_control_red_and_green(tmp_path: Path) -> None:
    status, _ = analyze(
        restore_run(tmp_path, "control", False, False, True), "restore-copy", "control"
    )
    assert status == 0
    status, _ = analyze(
        restore_run(tmp_path, "control", False, False, False), "restore-copy", "control"
    )
    assert status == 4


# ===== D2: genesis with and without the ceremony =====


def genesis_run(
    tmp: Path, mode: str, first: list[int], after: list[int], hinted: list[int]
) -> Path:
    summary = {
        "drill": "genesis",
        "mode": mode,
        "min_seqno": 10,
        "seqno_samples": {
            "first": [[float(i), float(s)] for i, s in enumerate(first)],
            "after-ceremony": [[float(i), float(s)] for i, s in enumerate(after)],
        },
    }
    logs = {node: {"log.without-ceremony": [hint(10)]} for node in hinted}
    return write_nodes(tmp / f"{mode}-{len(first)}-{len(after)}-{len(hinted)}", logs, summary)


def test_genesis_with_the_ceremony_passes(tmp_path: Path) -> None:
    status, _ = analyze(genesis_run(tmp_path, "log", [0, 3, 12], [], []), "genesis", "log")
    assert status == 0


def test_genesis_with_the_ceremony_fails_on_a_hint_or_no_blocks(tmp_path: Path) -> None:
    status, _ = analyze(genesis_run(tmp_path, "log", [0, 3, 12], [], [2]), "genesis", "log")
    assert status == 3
    status, _ = analyze(genesis_run(tmp_path, "log", [0, 0, 0], [], []), "genesis", "log")
    assert status == 3


def test_genesis_without_the_ceremony_control(tmp_path: Path) -> None:
    status, _ = analyze(
        genesis_run(tmp_path, "control", [0, 0], [0, 11], [1, 2, 3, 4]), "genesis", "control"
    )
    assert status == 0
    # A block without the ceremony, a node without the hint, or no recovery: the control fails.
    for first, after, hinted in (
        ([0, 1], [11], [1, 2, 3, 4]),
        ([0], [11], [1, 2, 3]),
        ([0], [0], [1, 2, 3, 4]),
    ):
        status, _ = analyze(
            genesis_run(tmp_path, "control", first, after, hinted), "genesis", "control"
        )
        assert status == 4, (first, after, hinted)


# ===== D5: a handover that replaces half the weight =====


def mc_cert(t: int, cc: int) -> str:
    return certificate(t, cc, "VVVV")


def handover_run(
    tmp: Path, mode: str, mc_counters: list[int], incoming_own: dict[int, list[int]]
) -> Path:
    """Incoming nodes 5 and 6 each fence at masterchain counter 10 (so 13 is the first above)."""
    logs: dict[int, dict[str, list[str]]] = {
        1: {"log": [mc_cert(100 + i, cc) for i, cc in enumerate(mc_counters)]}
    }
    for node in (5, 6):
        lines = [admission(50, 11, "fenced"), fence_line(60, f"{MC}=10 (0,8000000000000000)=4")]
        for cc in incoming_own.get(node, []):
            lines.append(own(200 + cc, cc, "notarize vote"))
        logs[node] = {"log": lines}
    summary = {"drill": "handover", "mode": mode, "nodes": 6, "incoming": [5, 6]}
    name = f"{mode}-{'-'.join(map(str, mc_counters))}-{json.dumps(incoming_own, sort_keys=True).__hash__() & 0xFFFF}"
    return write_nodes(tmp / name, logs, summary)


def test_handover_passes_on_counters_above_every_fence(tmp_path: Path) -> None:
    status, summary = analyze(
        handover_run(tmp_path, "log", [10, 11, 12, 13, 14], {5: [13], 6: [14]}), "handover", "log"
    )
    assert summary["verdict"]["passed"] is True
    assert status == 0


def test_handover_that_never_crosses_the_counters_fails(tmp_path: Path) -> None:
    # Up for a long time, but no certificate above cc(M) + 2: DRILL_FAILED, not a pass.
    status, summary = analyze(
        handover_run(tmp_path, "log", [10, 11, 12], {5: [], 6: []}), "handover", "log"
    )
    assert summary["verdict"]["passed"] is False
    assert status == 3


def test_handover_signature_at_or_below_the_fence_fails(tmp_path: Path) -> None:
    status, _ = analyze(
        handover_run(tmp_path, "log", [10, 13, 14], {5: [12, 13], 6: [14]}), "handover", "log"
    )
    assert status == 3


def test_handover_incoming_identity_that_never_signs_fails(tmp_path: Path) -> None:
    status, _ = analyze(
        handover_run(tmp_path, "log", [10, 13, 14], {5: [13], 6: []}), "handover", "log"
    )
    assert status == 3


def test_handover_control_shows_the_stall(tmp_path: Path) -> None:
    status, summary = analyze(
        handover_run(tmp_path, "control", [10, 11, 12], {}), "handover", "control"
    )
    assert summary["verdict"]["stalled_at_or_below_fence"] is True
    assert status == 0
    status, _ = analyze(handover_run(tmp_path, "control", [10, 13], {}), "handover", "control")
    assert status == 4


def test_a_summary_of_another_drill_is_refused(tmp_path: Path) -> None:
    directory = handover_run(tmp_path, "log", [13], {})
    done = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--drill",
            "genesis",
            "--mode",
            "log",
            "--working-dir",
            str(directory),
            "--analyze-only",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 1


def test_fence_lines_of_both_formats_are_read() -> None:
    FENCE = _load(ROOT / "test/integration/signing_unknown_history_drill.py").FENCE
    new = FENCE.search(fence_line(1, f"{MC}=7"))
    old = FENCE.search(
        f"signing ledger: unknown history fenced at (-1,8000000000000000,17):AA:BB over 1 lineages; "
        f"sessions more than 2 catchain counters above them sign again; counters: {MC}=7"
    )
    assert new is not None and new["n"] == "1"
    assert old is not None and old["n"] == "1"
