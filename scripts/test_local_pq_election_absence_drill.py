"""The absence drill must fail on a chain that holds an empty election, not only pass on one that recovers."""

import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "absence_drill", Path(__file__).with_name("local-pq-election-absence-drill.py")
)
drill = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drill)

EMPTY = {"elect_at": 400, "elect_close": 340, "total_stake": 0, "failed": False, "finished": False}
FRESH = {"elect_at": 700, "elect_close": 640, "total_stake": 0, "failed": False, "finished": False}


class Clock:
    def __init__(self):
        self.now = 0.0

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeChain:
    """An elector that opens an empty election at t=100, then either recovers or holds it."""

    def __init__(self, clock, recovers, staked=False):
        self.clock = clock
        self.recovers = recovers
        self.staked = staked
        self.driver_running = True

    def election(self):
        t = self.clock.now
        if t < 100:
            return None
        empty = dict(EMPTY, total_stake=10**13 if self.staked else 0)
        if t < EMPTY["elect_at"] or not self.recovers:
            return empty
        return dict(FRESH)

    def current_set_since(self):
        if self.recovers and self.driver_running and self.clock.now >= FRESH["elect_at"]:
            return FRESH["elect_at"]
        return 0

    def code_hash(self):
        return "00" * 32


def run(tmp_path, monkeypatch, recovers, staked=False):
    clock = Clock()
    chain = FakeChain(clock, recovers, staked)
    calls = []

    def systemctl(action):
        calls.append(action)
        chain.driver_running = action == "start"

    monkeypatch.setattr(drill.time, "time", clock.time)
    monkeypatch.setattr(drill.time, "sleep", clock.sleep)
    monkeypatch.setattr(drill, "Chain", lambda *_: chain)
    monkeypatch.setattr(drill, "systemctl", systemctl)
    monkeypatch.setattr(drill, "driver_active", lambda: True)
    network = tmp_path / "network.json"
    network.write_text(json.dumps({"zerostate_root": "ab" * 32}))
    out = tmp_path / "receipt.json"
    monkeypatch.setattr(
        drill.sys, "argv", ["drill", "--network", str(network), "--out", str(out), "--poll", "5"]
    )
    status = drill.main()
    return status, json.loads(out.read_text()), calls


def kinds(receipt):
    return [event["kind"] for event in receipt["events"]]


def test_a_recovering_chain_passes(tmp_path, monkeypatch):
    status, receipt, calls = run(tmp_path, monkeypatch, recovers=True)
    assert status == 0
    assert receipt["result"] == "pass"
    assert "fresh_election" in kinds(receipt) and "set_in_office" in kinds(receipt)
    assert calls == ["stop", "start"]


def test_a_chain_holding_the_empty_election_fails(tmp_path, monkeypatch):
    status, receipt, calls = run(tmp_path, monkeypatch, recovers=False)
    assert status == 1
    assert receipt["result"] == "fail"
    assert "deadlock" in kinds(receipt)
    assert calls == ["stop", "start"], "the driver must be restarted after a failed drill"


def test_an_election_that_received_stake_is_not_a_drill(tmp_path, monkeypatch):
    status, receipt, calls = run(tmp_path, monkeypatch, recovers=True, staked=True)
    assert status == 2
    assert receipt["result"] == "error"
    assert calls == ["stop", "start"]


@pytest.mark.parametrize("recovers", [True, False])
def test_the_receipt_records_its_exit_status(tmp_path, monkeypatch, recovers):
    status, receipt, _ = run(tmp_path, monkeypatch, recovers=recovers)
    assert receipt["exit_status"] == status
