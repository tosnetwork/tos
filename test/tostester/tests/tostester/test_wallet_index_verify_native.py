"""The native verification runner finds its sources and edits the snapshots it names."""

import importlib.util
import json
import struct
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[3] / "integration/wallet_index_verify_native.py"
SPEC = importlib.util.spec_from_file_location("wallet_index_verify_native", SOURCE)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
RECORDS = RUNNER.RECORDS


def block(seqno: int, salt: int = 0) -> bytes:
    return (
        struct.pack(">BiQI", 0, -1, 1 << 63, seqno)
        + bytes([seqno ^ salt]) * 32
        + bytes([seqno + 1]) * 32
    )


def snapshot():
    snapshot = RECORDS.Snapshot(4)
    snapshot.put(b"\0\1", struct.pack(">I", 4))
    snapshot.put(RECORDS.CHECKPOINT_KEY, block(1) + block(5))
    for account, lts in ((bytes([1]) * 32, (10, 20, 30)), (bytes([2]) * 32, (40,))):
        for lt in lts:
            snapshot.put(RECORDS.event_key(account, lt), bytes([lt]) * 4)
    return snapshot


def image(tmp_path: Path) -> Path:
    root = tmp_path / "init"
    for name in ("node0", "node1", "node2", "node5", "node6"):
        node = root / "network" / name
        for child in ("state", "celldb", "archive"):
            (node / child).mkdir(parents=True)
    (root / "network" / "node0" / "archive").rmdir()  # the DHT node holds no chain
    receipt = {
        "result": "NATIVE_INIT_BLOCK_JOIN_OK",
        "source": "node5",
        "target": "node6",
        "init_block": {"seqno": 7},
    }
    (root / "init-block-receipt.json").write_text(json.dumps(receipt))
    return root


def test_the_image_gives_a_full_and_the_joined_source(tmp_path):
    found = RUNNER.discover_image(image(tmp_path))
    assert found.full.name == "node1"
    assert found.joined.name == "node5"
    assert found.init_seqno == 7


def test_an_incomplete_image_is_refused(tmp_path):
    root = image(tmp_path)
    (root / "init-block-receipt.json").write_text(json.dumps({"result": "FAILED"}))
    with pytest.raises(RuntimeError):
        RUNNER.discover_image(root)


def test_each_edit_changes_what_its_control_names():
    honest = snapshot()
    a = bytes([1]) * 32
    tampered = snapshot()
    RUNNER.edit_tampered(tampered)
    changed = [k for (k, v), (_, w) in zip(honest.records, tampered.records) if v != w]
    assert changed == [RECORDS.event_key(a, 30)]
    omitted = snapshot()
    RUNNER.edit_omitted(omitted)
    assert [lt for _, lt, _ in omitted.events(a)] == [30, 10]
    truncated = snapshot()
    RUNNER.edit_truncated(truncated)
    assert [lt for _, lt, _ in truncated.events(a)] == [30, 20]
    wrong = snapshot()
    RUNNER.edit_wrong_checkpoint(wrong)
    point = RECORDS.checkpoint(wrong)
    assert point.anchor == block(1) and point.committed != block(5)
    assert point.committed[:17] == block(5)[:17]
    anchor = snapshot()
    RUNNER.edit_wrong_anchor(anchor)
    assert RECORDS.checkpoint(anchor).anchor != block(1)


def test_only_a_full_caught_up_index_ends_the_wait():
    assert RUNNER.until_full(200, {"verification": "full", "caught_up": True})
    assert not RUNNER.until_full(
        503, {"verification": "partial", "verification_phase": "ownership"}
    )
    assert not RUNNER.until_full(200, {"verification": "full", "caught_up": False})


def test_every_planned_scenario_is_present_and_none_is_skipped():
    planned = {
        "reference",
        "path-b",
        "path-a",
        "tampered",
        "omitted",
        "truncated",
        "injected",
        "wrong-checkpoint",
        "stale",
        "wrong-anchor",
        "forged-ownership",
        "destroyed-omitted",
        "recreated-omitted",
    }
    assert set(RUNNER.SCENARIOS) == planned
    for name in ("path-a", "injected", "stale", "forged-ownership"):
        with pytest.raises(RUNNER.Unavailable):
            RUNNER.SCENARIOS[name](None, None)


class ExitedAtOnce:
    """A service process that exits before it ever answers /readyz."""

    pid = 0
    returncode = 3

    def __init__(self, *args, **kwargs):
        pass

    def poll(self):
        return self.returncode

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass


def test_a_service_that_exits_early_never_counts_as_reaching_its_state(tmp_path, monkeypatch):
    monkeypatch.setattr(RUNNER.subprocess, "Popen", ExitedAtOnce)
    run = RUNNER.run_service(
        Path("/bin/true"),
        tmp_path,
        tmp_path / "data",
        [],
        lambda status, body: True,
        tmp_path / "log",
    )
    assert not run.reached and run.exit_code == 3
    with pytest.raises(RuntimeError, match="before the expected state"):
        RUNNER.require_reached(run, "reference")
    stopped = RUNNER.ServiceRun(exit_code=1, reached=True)
    with pytest.raises(RuntimeError, match="did not stop cleanly"):
        RUNNER.require_reached(stopped, "path-b")
    RUNNER.require_reached(RUNNER.ServiceRun(exit_code=0, reached=True), "path-b")


def fake_dumps(monkeypatch, bases):
    """Dumps that report each index's own base, or the base of the index
    named by --window-base-from; records every command."""
    calls = []

    def probe(*args, **kwargs):
        return RUNNER.subprocess.CompletedProcess(args, 0, "--canonical", "")

    def command(args, receipt):
        calls.append(args)
        index = args[args.index("--index-dir") + 1]
        if "--window-base-from" in args:
            index = args[args.index("--window-base-from") + 1]
        return f"head=30\nwindow_base={bases[index]}\nsha256={'ab' * 32}\n"

    monkeypatch.setattr(RUNNER.subprocess, "run", probe)
    monkeypatch.setattr(RUNNER.SNAPSHOT_RUNNER, "command", command)
    return calls


def test_the_reference_is_narrowed_to_the_import_s_stored_base(tmp_path, monkeypatch):
    # The import's base (14) is above the reference's (12): the reference is
    # dumped over the import's window.
    imported, reference = tmp_path / "import", tmp_path / "reference"
    calls = fake_dumps(monkeypatch, {str(imported): 14, str(reference): 12})
    own, other = RUNNER.common_window_digests(tmp_path, imported, reference, 30, tmp_path)
    assert "--window-base-from" not in calls[0] and "--window-base-from" not in calls[1]
    assert calls[2][calls[2].index("--index-dir") + 1] == str(reference)
    assert calls[2][calls[2].index("--window-base-from") + 1] == str(imported)
    assert own.window_base == other.window_base == 14
    assert own.head == other.head == 30
    assert all("--source-db" not in call for call in calls)


def test_a_reference_that_does_not_cover_the_import_s_window_is_refused(tmp_path, monkeypatch):
    # The import serves history from base 11; a reference from base 12 cannot
    # vouch for it, and the import's window is never narrowed to hide it.
    imported, reference = tmp_path / "import", tmp_path / "reference"
    calls = fake_dumps(monkeypatch, {str(imported): 11, str(reference): 12})
    with pytest.raises(RuntimeError, match="does not cover the import"):
        RUNNER.common_window_digests(tmp_path, imported, reference, 30, tmp_path)
    assert all("--window-base-from" not in call for call in calls)


def test_a_dump_at_another_head_is_refused(tmp_path, monkeypatch):
    def probe(*args, **kwargs):
        return RUNNER.subprocess.CompletedProcess(args, 0, "--canonical", "")

    monkeypatch.setattr(RUNNER.subprocess, "run", probe)
    monkeypatch.setattr(
        RUNNER.SNAPSHOT_RUNNER,
        "command",
        lambda args, receipt: f"head=29\nwindow_base=14\nsha256={'ab' * 32}\n",
    )
    with pytest.raises(RuntimeError, match="another window"):
        RUNNER.canonical_digest(tmp_path, tmp_path, 30, None, tmp_path / "log")
