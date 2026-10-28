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

IDS = {i: f"{i:02X}" * 32 for i in range(1, 7)}
HANDOVER = 150  # seconds after 08:00:00, the new set's utime_since
HANDOVER_UTIME = 1_800_000_000 + HANDOVER


def config34(since: int, members: dict[int, int]) -> str:
    records = " ".join(
        f"validator_pq validator_id:x{IDS[i]} key_id:x{'AB' * 32} weight:{w} adnl_addr:x{'CD' * 32}"
        for i, w in members.items()
    )
    return f"ConfigParam(34) = ( validators_ext utime_since:{since} utime_until:{since + 600} total:4 main:4 total_weight:{sum(members.values())} list:( {records} ))"


def fence_block_of(t: int, node: int) -> str:
    return (
        f"[ 3]{at(t)}[manager.cpp:1][!manager]\tsigning ledger: fence block of validator {IDS[node]} is "
        f"(-1,8000000000000000,17):AA:BB (custody from 1800000000)"
    )


def handover_run(
    tmp: Path,
    name: str,
    mode: str,
    *,
    mc_certs: list[tuple[int, int]],
    own_by: dict[int, list[tuple[int, int]]],
    after_members: dict[int, int] | None = None,
    m_id_records: bool = True,
    identities: bool = True,
) -> Path:
    """Incoming nodes 5 and 6 fence at masterchain counter 10, so 13 is their first counter
    above it; in sessions 13 and 14 they hold indices 2 and 3. `mc_certs` are (time, counter)
    certificates signed by all four; `own_by` the incoming nodes' own signatures (time, counter)."""
    logs: dict[int, dict[str, list[str]]] = {
        1: {"log": [certificate(t, cc, "VVVV") for t, cc in mc_certs]}
    }
    for node, idx in ((5, 2), (6, 3)):
        lines = [admission(50, 11, "fenced"), fence_line(60, f"{MC}=10 (0,8000000000000000)=4")]
        if m_id_records:
            lines.append(fence_block_of(55, node))
        lines += [index(100, cc, idx) for cc in (11, 12, 13, 14)]
        lines += [own(t, cc, "notarize vote") for t, cc in own_by.get(node, [])]
        logs[node] = {"log": lines}
    summary: dict[str, Any] = {"drill": "handover", "mode": mode, "nodes": 6}
    if identities:
        summary["incoming_validators"] = {"5": IDS[5], "6": IDS[6]}
        summary["outgoing_validators"] = {"3": IDS[3], "4": IDS[4]}
    directory = write_nodes(tmp / name, logs, summary)
    (directory / "config34-before.txt").write_text(
        config34(1_800_000_000, {1: 100, 2: 100, 3: 100, 4: 100})
    )
    members = after_members if after_members is not None else {1: 100, 2: 100, 5: 100, 6: 100}
    (directory / "config34-after.txt").write_text(config34(HANDOVER_UTIME, members))
    return directory


GOOD_CERTS = [(200, 13), (230, 14)]
GOOD_OWN = {5: [(201, 13)], 6: [(231, 14)]}


def test_handover_passes_with_identities_roster_and_counters(tmp_path: Path) -> None:
    status, summary = analyze(
        handover_run(tmp_path, "pass", "log", mc_certs=GOOD_CERTS, own_by=GOOD_OWN),
        "handover",
        "log",
    )
    assert summary["verdict"]["roster"]["transition"] is True
    assert summary["verdict"]["passed"] is True
    assert status == 0


def test_handover_without_identities_fails(tmp_path: Path) -> None:
    run = handover_run(
        tmp_path, "no-ids", "log", mc_certs=GOOD_CERTS, own_by=GOOD_OWN, identities=False
    )
    status, summary = analyze(run, "handover", "log")
    assert summary["verdict"]["identities_and_fence_records"] is False
    assert status == 3


def test_handover_without_fence_block_records_fails(tmp_path: Path) -> None:
    run = handover_run(
        tmp_path, "no-m", "log", mc_certs=GOOD_CERTS, own_by=GOOD_OWN, m_id_records=False
    )
    status, summary = analyze(run, "handover", "log")
    assert summary["verdict"]["identities_and_fence_records"] is False
    assert status == 3


def test_handover_with_only_pre_handover_activity_fails(tmp_path: Path) -> None:
    # Certificates and own signatures above the fence, all before the new set took office.
    run = handover_run(
        tmp_path,
        "pre",
        "log",
        mc_certs=[(120, 13), (130, 14)],
        own_by={5: [(121, 13)], 6: [(131, 14)]},
    )
    status, _ = analyze(run, "handover", "log")
    assert status == 3


def test_handover_without_a_roster_change_fails(tmp_path: Path) -> None:
    run = handover_run(
        tmp_path,
        "same",
        "log",
        mc_certs=GOOD_CERTS,
        own_by=GOOD_OWN,
        after_members={1: 100, 2: 100, 3: 100, 4: 100},
    )
    status, summary = analyze(run, "handover", "log")
    assert summary["verdict"]["roster"]["transition"] is False
    assert status == 3


def test_handover_below_half_the_weight_fails(tmp_path: Path) -> None:
    run = handover_run(
        tmp_path,
        "light",
        "log",
        mc_certs=GOOD_CERTS,
        own_by=GOOD_OWN,
        after_members={1: 100, 2: 100, 5: 10, 6: 10},
    )
    status, summary = analyze(run, "handover", "log")
    assert summary["verdict"]["roster"]["incoming_weight_share"] < 0.5
    assert status == 3


def test_handover_that_never_crosses_the_counters_fails(tmp_path: Path) -> None:
    run = handover_run(tmp_path, "stuck", "log", mc_certs=[(200, 11), (230, 12)], own_by={})
    status, summary = analyze(run, "handover", "log")
    assert summary["verdict"]["passed"] is False
    assert status == 3


def test_handover_signature_at_or_below_the_fence_fails(tmp_path: Path) -> None:
    own_by = {5: [(180, 12), (201, 13)], 6: [(231, 14)]}
    status, _ = analyze(
        handover_run(tmp_path, "within", "log", mc_certs=GOOD_CERTS, own_by=own_by),
        "handover",
        "log",
    )
    assert status == 3


def test_handover_incoming_identity_that_never_signs_fails(tmp_path: Path) -> None:
    own_by = {5: [(201, 13)]}
    status, _ = analyze(
        handover_run(tmp_path, "silent", "log", mc_certs=[(200, 13)], own_by=own_by),
        "handover",
        "log",
    )
    assert status == 3


def test_handover_control_shows_the_stall(tmp_path: Path) -> None:
    run = handover_run(tmp_path, "stall", "control", mc_certs=[(200, 11), (230, 12)], own_by={})
    status, summary = analyze(run, "handover", "control")
    assert summary["verdict"]["stalled_at_or_below_fence"] is True
    assert status == 0
    run = handover_run(tmp_path, "moved-on", "control", mc_certs=[(200, 13)], own_by={})
    status, _ = analyze(run, "handover", "control")
    assert status == 4


def test_handover_control_needs_the_roster_change_and_records(tmp_path: Path) -> None:
    runs = [
        handover_run(
            tmp_path,
            "ctl-same",
            "control",
            mc_certs=[(200, 11)],
            own_by={},
            after_members={1: 100, 2: 100, 3: 100, 4: 100},
        ),
        handover_run(
            tmp_path, "ctl-no-m", "control", mc_certs=[(200, 11)], own_by={}, m_id_records=False
        ),
        handover_run(
            tmp_path, "ctl-no-ids", "control", mc_certs=[(200, 11)], own_by={}, identities=False
        ),
    ]
    for run in runs:
        status, _ = analyze(run, "handover", "control")
        assert status == 4, run.name


def test_a_summary_of_another_drill_is_refused(tmp_path: Path) -> None:
    directory = handover_run(tmp_path, "other-drill", "log", mc_certs=[], own_by={})
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
