"""Verify rotation identity and first-hop evidence refuses retired validators."""

import asyncio
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "local_elections", Path(__file__).with_name("local-pq-elections.py")
)
elections = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elections)


def test_replacement_keeps_four_unique_members():
    assert elections.roster(0) == (1, 2, 3, 7)
    assert elections.roster(1) == (1, 2, 3, 4)
    assert elections.roster(2) == elections.roster(0)
    assert set(elections.roster(0)) ^ set(elections.roster(1)) == {4, 7}


def test_exact_current_first_hops():
    elections.require_first_hops(1, [2, 3, 7], [1, 2, 3, 7])


@pytest.mark.parametrize("actual", [[2, 3, 4], [2, 3, 4, 7], [2, 3], [1, 2, 3, 7]])
def test_retired_missing_or_self_first_hop_refused(actual):
    with pytest.raises(ValueError):
        elections.require_first_hops(1, actual, [1, 2, 3, 7])


def test_retired_sender_refused():
    with pytest.raises(ValueError):
        elections.require_first_hops(4, [1, 2, 3, 7], [1, 2, 3, 7])


def trace_fixture(directory):
    import base64
    import datetime
    import json

    spec = importlib.util.spec_from_file_location(
        "relay_check", Path(__file__).with_name("check-local-pq-relays.py")
    )
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    candidates = {
        i: {"controller": f"-1:{i:064x}", "adnl_id": f"{i + 100:064x}"} for i in (1, 2, 3, 4, 7)
    }
    for i, c in candidates.items():
        (directory / f"candidate-{i}.json").write_text(json.dumps(c))
    for since, nodes in ((100, [1, 2, 3, 4]), (700, [1, 2, 3, 7])):
        (directory / f"activation-{since:04}.json").write_text(
            json.dumps(
                {
                    "observed_at": since,
                    "height": since,
                    "config34": {
                        "utime_since": since,
                        "utime_until": since + 600,
                        "validators": [{"controller_id_hex": f"{i:064x}"} for i in nodes],
                    },
                }
            )
        )
    timestamp = datetime.datetime.fromtimestamp(750, datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )
    prefix = f"[ 4][t 1][{timestamp}][!overlay.valgroup(-1,8000000000000000).0] "
    rows = []
    for sender in (1, 2, 3, 7):
        bid = f"{sender:064X}"
        rows.append(
            {
                "node": sender,
                "line": prefix + f"twostep START sender broadcast_id={bid} data_hash={bid}",
            }
        )
        for receiver in set((1, 2, 3, 7)) - {sender}:
            address = base64.b64encode(bytes.fromhex(candidates[receiver]["adnl_id"])).decode()
            rows.append(
                {
                    "node": sender,
                    "line": prefix + f"twostep FIRST_HOP sender broadcast_id={bid} to={address}",
                }
            )
            rows.append(
                {
                    "node": receiver,
                    "line": prefix
                    + f"twostep FINISH receiver broadcast_id={bid} data_hash={bid} decoded=true",
                }
            )
    path = directory / "relay-trace.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return checker, rows


def test_retained_trace_positive(tmp_path):
    checker, _ = trace_fixture(tmp_path)
    result = checker.check(tmp_path)
    assert result["retired_nodes"] == [4]
    assert result["new_nodes"] == [7]
    assert len(result["matched_broadcasts_by_sender"]) == 4


@pytest.mark.parametrize("mutation", ["retired_target", "missing_finish", "same_set", "period"])
def test_retained_trace_negative(tmp_path, mutation):
    import base64
    import json

    checker, rows = trace_fixture(tmp_path)
    if mutation == "retired_target":
        rows[1]["line"] = (
            rows[1]["line"].split(" to=")[0]
            + " to="
            + base64.b64encode(bytes.fromhex(f"{104:064x}")).decode()
        )
    if mutation == "missing_finish":
        rows = [r for r in rows if not ("FINISH" in r["line"] and r["node"] == 7)]
    if mutation in ("same_set", "period"):
        path = tmp_path / "activation-0700.json"
        obj = json.loads(path.read_text())
        if mutation == "period":
            obj["config34"]["utime_until"] += 1
        else:
            obj["config34"]["validators"][-1]["controller_id_hex"] = f"{4:064x}"
        path.write_text(json.dumps(obj))
    (tmp_path / "relay-trace.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    with pytest.raises(ValueError):
        checker.check(tmp_path)


def test_trace_follows_rotation_and_truncation(tmp_path, monkeypatch):
    import json

    monkeypatch.setattr(elections, "DATA", tmp_path)
    monkeypatch.setattr(elections, "OUT", tmp_path)
    directory = tmp_path / "testnet/node1"
    directory.mkdir(parents=True)
    path = directory / "log"
    path.write_bytes(b"twostep first\n")
    offsets = {}
    elections.trace_once(offsets)
    path.rename(directory / "log.old")
    path.write_bytes(b"twostep second\n")
    elections.trace_once(offsets)
    path.write_bytes(b"twostep third\n")
    elections.trace_once(offsets)
    rows = [
        json.loads(x)["line"] for x in (tmp_path / "relay-trace.jsonl").read_text().splitlines()
    ]
    assert rows == ["twostep first", "twostep second", "twostep third"]


def test_trace_partial_line_is_not_consumed(tmp_path, monkeypatch):
    monkeypatch.setattr(elections, "DATA", tmp_path)
    monkeypatch.setattr(elections, "OUT", tmp_path)
    directory = tmp_path / "testnet/node1"
    directory.mkdir(parents=True)
    path = directory / "log"
    path.write_bytes(b"twostep partial")
    offsets = {}
    elections.trace_once(offsets)
    assert (tmp_path / "relay-trace.jsonl").read_text() == ""
    with path.open("ab") as f:
        f.write(b" done\n")
    elections.trace_once(offsets)
    assert "partial done" in (tmp_path / "relay-trace.jsonl").read_text()


def test_a_missing_lite_client_is_refused_before_the_output_is_touched(monkeypatch, tmp_path):
    def untouched(*args, **kwargs):
        raise AssertionError("the output directory was touched before the lite-client check")

    monkeypatch.setattr(elections.local, "INSTALLED_LITE_CLIENT", tmp_path / "absent")
    monkeypatch.setattr(elections.local, "secure_output_dir", untouched)
    with pytest.raises(RuntimeError, match="does not exist"):
        asyncio.run(elections.main())


def test_lite_queries_run_the_installed_lite_client(monkeypatch, tmp_path):
    seen = []

    async def fake_exec(program, *args, **kwargs):
        seen.append(program)
        raise OSError("stop")

    monkeypatch.setattr(elections.local, "INSTALLED_LITE_CLIENT", tmp_path / "tos-lite-client")
    monkeypatch.setattr(elections.asyncio, "create_subprocess_exec", fake_exec)
    with pytest.raises(OSError, match="stop"):
        asyncio.run(elections.lite_int("active_election_id"))
    assert seen == [str(tmp_path / "tos-lite-client")]
