#!/usr/bin/env python3
"""Offline tests of the startup catch-up loopback runner.

The evaluators are checked against fixed samples. The scenarios themselves (L1,
L4, L6) run against a simulated network and a simulated clock, so what the
runner samples, when, and against which baseline is checked too, not only how a
given set of samples is judged. stop() is checked against real processes.
Standard library only.
"""

from __future__ import annotations

import importlib.util
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "startup-catchup-loopback.py"
spec = importlib.util.spec_from_file_location("startup_catchup_loopback", SCRIPT)
assert spec is not None and spec.loader is not None
loop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loop)

NODE = 3
PEERS = [1, 2, 4]
PASS, FAIL, INCONCLUSIVE = loop.PASS, loop.FAIL, loop.INCONCLUSIVE


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def wall(self) -> float:
        return 1_700_000_000.0 + self.now

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            self.now += seconds


class Behaviour:
    """How the simulated restarted node behaves; each process starts its own story.

    `age` is the seconds since the process started; `index` counts the node's
    processes started by the scenario (0 for the first restart).
    """

    active_for = 300.0  # the mode ends Fresh this long after a start
    attempt_every = 100.0  # one settled import attempt per this many seconds
    sample_cost = 0.5  # seconds one actor read takes

    def read_cost(self, net: FakeNet, node: int) -> float:
        return self.sample_cost

    def bridges(self, index: int, age: float, active: bool) -> int:
        return 0 if active else 4

    def waiters(self, index: int, age: float) -> int:
        return 10

    def shard_client_ago(self, index: int, age: float) -> float:
        return max(5.0, 900.0 - age)

    def rss(self, node: int, now: float) -> float:
        return 1000.0

    def on_start(self, net: FakeNet, index: int) -> None:
        pass

    restart_latency = 0.0  # seconds restart() takes before the process is up
    snapshot_latency = 0.0  # seconds a rotation snapshot read takes

    def recorded_rss(self, node: int, now: float) -> float | None:
        """What the background recorder read for `node` at `now`; None is missing."""
        return self.rss(node, now)


class FakeNet:
    def __init__(self, clock: FakeClock, behaviour: Behaviour) -> None:
        self.clock = clock
        self.behaviour = behaviour
        self.dirs = {n: {"genesis-session"} for n in loop.NODES}
        self.down: set[int] = set()
        self.pids = {n: 100 + n for n in loop.NODES}
        self.starts: list[tuple[int, float]] = []  # the node's processes: (pid, start)
        self.events: list[tuple[str, float]] = []

    # The process of NODE that is running now, and its index and age.
    def _current(self) -> tuple[int, float] | None:
        if not self.starts or NODE in self.down:
            return None
        index = len(self.starts) - 1
        return index, self.clock.now - self.starts[index][1]

    def _active(self, index: int, age: float) -> bool:
        return age < self.behaviour.active_for

    def head(self, node: int) -> dict:
        return {"seqno": 1}

    def rotation_snapshot(self, node: int) -> None:
        return None

    def rotation_snapshot_from_peer(self, node: int) -> None:
        self.clock.sleep(self.behaviour.snapshot_latency)
        return None

    def peer_rss_rows(self, node: int, since: float, until: float) -> list[dict]:
        # The background recorder: one reading every SAMPLE_INTERVAL of simulated
        # time since the network started, whatever the main thread was doing.
        until = min(until, self.clock.now)
        step = loop.SAMPLE_INTERVAL
        rows = []
        k = max(0, int(-(-since // step)))
        while k * step <= until:
            now = k * step
            rows.append(
                {
                    "mono": now,
                    "rss": {
                        n: self.behaviour.recorded_rss(n, now) for n in loop.NODES if n != node
                    },
                }
            )
            k += 1
        return rows

    def rss_recorder_errors(self) -> list[str]:
        return []

    def stop(self, node: int, sig: int = signal.SIGTERM, timeout: float = 300.0) -> None:
        self.down.add(node)
        self.events.append(("stop", self.clock.now))

    def restart(self, node: int) -> dict:
        self.clock.sleep(self.behaviour.restart_latency)
        self.down.discard(node)
        self.pids[node] += 100
        self.starts.append((self.pids[node], self.clock.now))
        self.events.append(("restart", self.clock.now))
        self.behaviour.on_start(self, len(self.starts) - 1)
        return {"t": self.clock.wall(), "mono": self.clock.now, "pid": self.pids[node], "seq": 0}

    def consensus_dirs(self, node: int) -> set[str]:
        return set(self.dirs[node])

    def mode(self, node: int, mark: dict | None = None) -> dict:
        since = [
            (i, self.clock.now - start)
            for i, (pid, start) in enumerate(self.starts)
            if mark is None or pid >= mark["pid"]
        ]
        ended = [i for i, age in since if not self._active(i, age)]
        attempts = sum(int(age // self.behaviour.attempt_every) for _, age in since)
        return {
            "entered": len(since),
            "not_entered": 0,
            "refusals": [],
            "ended": ["Fresh" for _ in ended],
            "attempts": attempts,
            "archive_imports": 0,
            "failed_checks": 0,
        }

    def alive(self, node: int) -> bool:
        return node not in self.down

    def rss_mb(self, node: int) -> float | None:
        return self.behaviour.rss(node, self.clock.now) if self.alive(node) else None

    def actors(self, node: int) -> dict | None:
        self.clock.sleep(self.behaviour.read_cost(self, node))
        if not self.alive(node):
            return None
        if node != NODE:
            return {"WaitBlockState": 10, "BridgeImpl": 4}
        index, age = self._current()
        active = self._active(index, age)
        return {
            "WaitBlockState": self.behaviour.waiters(index, age),
            "BridgeImpl": self.behaviour.bridges(index, age, active),
        }

    def fresh_status(self, node: int, mark: dict) -> dict | None:
        current = self._current()
        if current is None or self.starts[current[0]][0] != mark["pid"]:
            return None
        return {"shard_client_ago": self.behaviour.shard_client_ago(*current)}

    def status_any(self, node: int) -> dict:
        return {"shard_client_ago": 1.0}


def run_scenario(name: str, behaviour: Behaviour) -> tuple[dict, FakeNet]:
    clock = FakeClock()
    saved = loop.CLOCK
    loop.CLOCK = clock
    try:
        net = FakeNet(clock, behaviour)
        report = loop.Report(name)
        loop.SCENARIOS[name](net, report)
    finally:
        loop.CLOCK = saved
    return report.data, net


def sample(t: float, **node_fields) -> dict:
    nodes = {
        n: {
            "alive": True,
            "rss_mb": 1000.0,
            "actors": {"WaitBlockState": 10, "BridgeImpl": 4},
            "status": None,
        }
        for n in loop.NODES
    }
    nodes[NODE]["status"] = {"shard_client_ago": 10.0}
    nodes[NODE]["status_t"] = float(t) + 1.0
    nodes[NODE].update(node_fields)
    return {
        "t": float(t),
        "t_end": float(t) + 2.0,
        "final_process": True,
        "mode_active": False,
        "new_dirs": [],
        "nodes": nodes,
    }


def dense(window: float = loop.L1_WINDOW) -> list[dict]:
    return [sample(t) for t in range(0, int(window), int(loop.SAMPLE_INTERVAL))]


def flat_history(rss: float = 1000.0, start: float = -loop.RSS_WINDOW) -> list[dict]:
    return [
        {"t": float(t), "rss": {p: rss for p in PEERS}}
        for t in range(int(start), 0, int(loop.SAMPLE_INTERVAL))
    ]


def at(samples: list[dict], t: float) -> dict:
    return next(s for s in samples if s["t"] == t)


class SelfTest(unittest.TestCase):
    def test_script_self_test(self) -> None:
        self.assertEqual(loop.self_test(), 0)


class CheckpointReading(unittest.TestCase):
    """The 10-minute reading is the sample started at 10 min, not a later one."""

    name = loop.checkpoint_name(loop.L1_CHECKPOINT)

    def judge(self, samples: list[dict]) -> str:
        return loop.evaluate_checkpoint(samples, NODE, PEERS, loop.L1_CHECKPOINT)["status"]

    def test_complete_reading_passes(self) -> None:
        self.assertEqual(self.judge(dense()), PASS)

    def test_waiter_violation_with_a_peer_missing_fails(self) -> None:
        # The reproduced case: 6,000 waiters at 600 s while a peer's count is
        # missing, and a complete, healthy sample afterwards.
        samples = dense()
        at(samples, 600)["nodes"][NODE]["actors"] = {"WaitBlockState": 6000, "BridgeImpl": 4}
        at(samples, 600)["nodes"][2]["actors"] = None
        self.assertEqual(self.judge(samples), FAIL)

    def test_peer_missing_at_the_deadline_with_later_recovery_is_inconclusive(self) -> None:
        samples = dense()
        at(samples, 600)["nodes"][2]["actors"] = None
        self.assertEqual(self.judge(samples), INCONCLUSIVE)

    def test_waiter_limit_boundary(self) -> None:
        samples = dense()
        at(samples, 600)["nodes"][NODE]["actors"] = {"WaitBlockState": 5000, "BridgeImpl": 4}
        self.assertEqual(self.judge(samples), FAIL)
        at(samples, 600)["nodes"][NODE]["actors"] = {"WaitBlockState": 4999, "BridgeImpl": 4}
        self.assertEqual(self.judge(samples), PASS)

    def test_reading_must_end_by_thirty_seconds_past(self) -> None:
        samples = [s for s in dense() if not 600 <= s["t"] < 630]
        late = sample(600)
        late["t_end"] = 630.0
        samples.append(late)
        samples.sort(key=lambda s: s["t"])
        self.assertEqual(self.judge(samples), PASS)
        late["t_end"] = 630.5
        self.assertEqual(self.judge(samples), INCONCLUSIVE)

    def test_first_sample_after_the_window_is_inconclusive(self) -> None:
        samples = [s for s in dense() if not 600 <= s["t"] <= 630]
        self.assertEqual(self.judge(samples), INCONCLUSIVE)

    def test_slow_peer_read_does_not_retag_a_later_sample(self) -> None:
        # The sample started at 600 s took 45 s because one peer answered slowly;
        # the complete sample at 650 s is not the 10-minute reading.
        samples = [s for s in dense() if not 600 < s["t"] < 650]
        at(samples, 600)["t_end"] = 645.0
        self.assertEqual(self.judge(samples), INCONCLUSIVE)

    def test_bridge_mismatch_fails(self) -> None:
        samples = dense()
        at(samples, 600)["nodes"][NODE]["actors"] = {"WaitBlockState": 10, "BridgeImpl": 0}
        self.assertEqual(self.judge(samples), FAIL)


class Coverage(unittest.TestCase):
    def judge(self, samples: list[dict]) -> str:
        return loop.evaluate_coverage(samples, loop.L1_WINDOW)["status"]

    def test_dense_window_passes(self) -> None:
        self.assertEqual(self.judge(dense()), PASS)

    def test_a_gap_is_inconclusive(self) -> None:
        samples = [s for s in dense() if not 400 < s["t"] < 445]
        self.assertEqual(self.judge(samples), INCONCLUSIVE)

    def test_a_short_window_is_inconclusive(self) -> None:
        samples = [s for s in dense() if s["t"] <= 660]
        self.assertEqual(self.judge(samples), INCONCLUSIVE)

    def test_late_first_sample_is_inconclusive_whatever_the_history(self) -> None:
        samples = [s for s in dense() if s["t"] >= 40]
        self.assertEqual(self.judge(samples), INCONCLUSIVE)
        full = loop.evaluate_restart(samples, NODE, PEERS, history=flat_history())
        self.assertEqual(full[loop.coverage_name(loop.L1_WINDOW)]["status"], INCONCLUSIVE)


class Rss(unittest.TestCase):
    """RSS against the peers' trailing-window peaks, not an instantaneous reading."""

    @staticmethod
    def sawtooth(t: float) -> float:
        return 2200.0 if (t % 240.0) < 120.0 else 1000.0

    def window(self, node_rss) -> tuple[list[dict], list[dict]]:
        samples = dense()
        for s in samples:
            for p in PEERS:
                s["nodes"][p]["rss_mb"] = self.sawtooth(s["t"])
            s["nodes"][NODE]["rss_mb"] = node_rss(s["t"])
        history = [
            {"t": float(t), "rss": {p: self.sawtooth(t) for p in PEERS}}
            for t in range(-int(loop.RSS_WINDOW), 0, int(loop.SAMPLE_INTERVAL))
        ]
        return samples, history

    def judge(self, samples, history) -> dict:
        return loop.evaluate_rss(samples, NODE, PEERS, history)

    def test_peer_trough_is_not_the_denominator(self) -> None:
        # 2,000 MB is above 1.5 x the peers' 1,000 MB trough but well below their peak.
        samples, history = self.window(lambda t: 2000.0)
        got = self.judge(samples, history)
        self.assertEqual(got["status"], PASS, got["detail"])

    def test_blowup_still_fails(self) -> None:
        samples, history = self.window(lambda t: 3500.0 if t >= 500 else 1500.0)
        got = self.judge(samples, history)
        self.assertEqual(got["status"], FAIL)
        self.assertEqual(got["detail"]["over"][0]["t"], 500.0)
        self.assertEqual(got["detail"]["over"][0]["reference_mb"], 2200.0)

    def test_peak_leaves_the_trailing_window(self) -> None:
        samples = dense()
        for s in samples:
            s["nodes"][NODE]["rss_mb"] = 2000.0 if s["t"] == 200 else 1000.0
        history = flat_history()
        for row in history:
            if row["t"] <= -250:
                row["rss"] = {p: 3000.0 for p in PEERS}
        got = self.judge(samples, history)
        self.assertEqual(got["status"], FAIL, got["detail"])
        self.assertEqual([e["t"] for e in got["detail"]["over"]], [200.0])

    def test_incomplete_history_is_inconclusive(self) -> None:
        self.assertEqual(self.judge(dense(), [])["status"], INCONCLUSIVE)
        self.assertEqual(self.judge(dense(), flat_history(start=-100.0))["status"], INCONCLUSIVE)
        gapped = [r for r in flat_history() if not -200 < r["t"] < -150]
        self.assertEqual(self.judge(dense(), gapped)["status"], INCONCLUSIVE)
        self.assertEqual(self.judge(dense(), flat_history())["status"], PASS)

    def test_known_violation_dominates_missing_rss(self) -> None:
        samples = dense()
        at(samples, 100)["nodes"][NODE]["rss_mb"] = 5000.0
        at(samples, 200)["nodes"][1]["rss_mb"] = None
        self.assertEqual(self.judge(samples, flat_history())["status"], FAIL)


class Scenarios(unittest.TestCase):
    def criteria(self, data: dict) -> dict:
        return {name: c["status"] for name, c in data["criteria"].items()}

    def test_l1_healthy_passes(self) -> None:
        data, _ = run_scenario("L1", Behaviour())
        statuses = self.criteria(data)
        self.assertEqual(loop.overall(data["criteria"]), PASS, statuses)

    def test_l1_directory_created_at_restart_is_new(self) -> None:
        class NewSessionAtStart(Behaviour):
            def on_start(self, net, index):
                net.dirs[NODE].add("session-of-the-restarted-process")

        data, _ = run_scenario("L1", NewSessionAtStart())
        got = data["criteria"]["no new consensus directory while the mode is active"]
        self.assertEqual(got["status"], FAIL)
        self.assertEqual(got["detail"], ["session-of-the-restarted-process"])

    def test_l1_samples_every_ten_seconds(self) -> None:
        data, _ = run_scenario("L1", Behaviour())
        times = [s["t"] for s in data["samples"]]
        self.assertEqual(times[0], 0.0)
        self.assertEqual({round(b - a, 1) for a, b in zip(times, times[1:])}, {10.0})

    def test_l1_samples_to_the_end_of_the_window(self) -> None:
        class CaughtUpAtOnce(Behaviour):
            def shard_client_ago(self, index, age):
                return 5.0

        data, _ = run_scenario("L1", CaughtUpAtOnce())
        times = [s["t"] for s in data["samples"]]
        self.assertGreaterEqual(times[-1], loop.L1_WINDOW - loop.SAMPLE_INTERVAL)
        self.assertLess(times[-1], loop.L1_WINDOW)

    def test_missed_slots_are_skipped_not_made_up(self) -> None:
        class SlowConsole(Behaviour):
            sample_cost = 9.0  # four actor reads: 36 s per sample

        data, _ = run_scenario("L1", SlowConsole())
        times = [s["t"] for s in data["samples"]]
        self.assertTrue(all(t % loop.SAMPLE_INTERVAL == 0 for t in times), times[:5])
        self.assertEqual({round(b - a, 1) for a, b in zip(times, times[1:])}, {40.0})
        name = loop.coverage_name(loop.L1_WINDOW)
        self.assertEqual(data["criteria"][name]["status"], INCONCLUSIVE)

    def test_status_read_after_the_deadline_does_not_count(self) -> None:
        # The last sample starts at 1,190 s, but slow console reads put the
        # STATUS read at 1,250 s, and the node caught up only after 1,200 s.
        class SlowAtTheEnd(Behaviour):
            def read_cost(self, net, node):
                age = net.clock.now - net.starts[-1][1]
                return 20.0 if age >= 1190 else 0.5

            def shard_client_ago(self, index, age):
                return 5.0 if age >= 1200 else 900.0

        data, _ = run_scenario("L1", SlowAtTheEnd())
        last = data["samples"][-1]
        self.assertEqual(last["t"], 1190.0)
        self.assertEqual(last["nodes"][NODE]["status_t"], 1250.0)
        name = loop.catchup_name(loop.L1_WINDOW)
        self.assertEqual(data["criteria"][name]["status"], FAIL, data["criteria"][name])

    def test_timely_status_survives_a_slow_peer_read(self) -> None:
        # The STATUS is read in time; a peer read after it makes the sample end
        # late, which does not make the timely evidence late.
        class SlowLastPeer(Behaviour):
            def read_cost(self, net, node):
                age = net.clock.now - net.starts[-1][1]
                return 60.0 if node == 4 and age >= 1190 else 0.5

            def shard_client_ago(self, index, age):
                return 5.0 if age >= 1190 else 900.0

        data, _ = run_scenario("L1", SlowLastPeer())
        last = data["samples"][-1]
        self.assertEqual(last["t"], 1190.0)
        self.assertGreater(last["t_end"], 1200.0)
        name = loop.catchup_name(loop.L1_WINDOW)
        self.assertEqual(data["criteria"][name]["status"], PASS, data["criteria"][name])
        self.assertLessEqual(data["criteria"][name]["detail"], 1200.0)

    def test_l1_rss_history_is_taken_before_the_restart(self) -> None:
        data, net = run_scenario("L1", Behaviour())
        history = data["rss_history"]
        times = [row["t"] for row in history]
        self.assertTrue(times, history)
        self.assertLessEqual(times[0], -loop.RSS_WINDOW)
        self.assertEqual(times[-1], 0.0)
        self.assertEqual({round(b - a, 1) for a, b in zip(times, times[1:])}, {10.0})
        self.assertTrue(all(NODE not in row["rss"] for row in history))
        self.assertTrue(all(s["t"] >= 0 for s in data["samples"]))

    def rss_status(self, data: dict) -> str:
        return data["criteria"][loop.RSS_NAME]["status"]

    def test_slow_start_keeps_the_peer_history_continuous(self) -> None:
        # The restarted process takes 25 s (then 60 s) to come up; the peers' RSS
        # keeps being recorded meanwhile, so the first windows are complete.
        for latency in (25.0, 60.0):

            class SlowStart(Behaviour):
                restart_latency = latency

            data, _ = run_scenario("L1", SlowStart())
            self.assertEqual(
                self.rss_status(data), PASS, (latency, data["criteria"][loop.RSS_NAME])
            )
            self.assertEqual(loop.overall(data["criteria"]), PASS, latency)

    def test_slow_l4_snapshot_keeps_the_peer_history_continuous(self) -> None:
        class SlowSnapshot(Behaviour):
            snapshot_latency = 45.0

        os.environ.pop("CATCHUP_L4_DOWNTIME", None)
        data, net = run_scenario("L4", SlowSnapshot())
        self.assertGreaterEqual(net.events[1][1] - net.events[0][1], 3645.0)
        self.assertEqual(self.rss_status(data), PASS, data["criteria"][loop.RSS_NAME])

    def test_missing_peer_readings_stay_inconclusive(self) -> None:
        # The recorder read nothing for peer 2 for 60 s shortly before the restart
        # (at 600 s + 1800 s of simulated time): the criterion is not loosened.
        class PeerUnreadable(Behaviour):
            def recorded_rss(self, node, now):
                if node == 2 and 2300.0 <= now < 2360.0:
                    return None
                return super().recorded_rss(node, now)

        data, _ = run_scenario("L1", PeerUnreadable())
        self.assertEqual(self.rss_status(data), INCONCLUSIVE, data["criteria"][loop.RSS_NAME])

    def test_l4_bounds_scale_with_the_downtime(self) -> None:
        # The bridges reach the peers' count once the mode ends at 15 min and the
        # node catches up at 25 min: both inside the 20/40-minute bounds of a
        # 60-minute downtime, both outside L1's 10/20 minutes.
        class LongImport(Behaviour):
            active_for = 900.0

            def shard_client_ago(self, index, age):
                return 5.0 if age >= 1500 else 900.0

        os.environ.pop("CATCHUP_L4_DOWNTIME", None)
        data, net = run_scenario("L4", LongImport())
        self.assertEqual(net.events[1][1] - net.events[0][1], 3600.0)
        statuses = self.criteria(data)
        checkpoint = loop.checkpoint_name(1200.0)
        catchup = loop.catchup_name(2400.0)
        self.assertIn(checkpoint, statuses)
        self.assertIn(catchup, statuses)
        self.assertEqual(statuses[checkpoint], PASS)
        self.assertEqual(statuses[catchup], PASS)
        self.assertEqual(data["samples"][-1]["t"], 2390.0)

    def test_scaled_bounds(self) -> None:
        self.assertEqual(loop.scaled_bounds(1800.0), (600.0, 1200.0))
        self.assertEqual(loop.scaled_bounds(900.0), (600.0, 1200.0))
        self.assertEqual(loop.scaled_bounds(3600.0), (1200.0, 2400.0))
        for bad in (0.0, -1.0, float("nan"), float("inf"), "3600"):
            with self.assertRaises(ValueError):
                loop.scaled_bounds(bad)

    def test_l6_samples_from_the_first_restart(self) -> None:
        # The first process briefly holds bridges while the mode is active; it is
        # killed after its second settled attempt, at 200 s.
        class BridgeInFirstProcess(Behaviour):
            def bridges(self, index, age, active):
                if index == 0 and 50 <= age < 80:
                    return 2
                return super().bridges(index, age, active)

        data, net = run_scenario("L6", BridgeInFirstProcess())
        self.assertEqual(data["samples"][0]["t"], 0.0)
        self.assertFalse(data["samples"][0]["final_process"])
        self.assertTrue(data["samples"][-1]["final_process"])
        got = data["criteria"]["no BridgeImpl while the mode is active"]
        self.assertEqual(got["status"], FAIL)
        self.assertEqual(got["detail"][0][0], 50.0)

    def test_l6_judges_what_it_saw_when_the_kill_never_happens(self) -> None:
        class NeverSettlesAndHoldsBridges(Behaviour):
            attempt_every = 10_000.0
            active_for = 10_000.0

            def bridges(self, index, age, active):
                return 2 if 50 <= age < 80 else 0

        data, net = run_scenario("L6", NeverSettlesAndHoldsBridges())
        statuses = self.criteria(data)
        self.assertEqual(
            statuses["killed after at least two import attempts settled"], INCONCLUSIVE
        )
        self.assertIn("no BridgeImpl while the mode is active", statuses)
        self.assertEqual(statuses["no BridgeImpl while the mode is active"], FAIL)
        self.assertEqual(loop.overall(data["criteria"]), FAIL)
        self.assertEqual([e for e, _ in net.events].count("restart"), 1)

    def test_l6_status_only_from_the_last_process(self) -> None:
        # The first process reports caught up; the last one never does.
        class OnlyFirstCatchesUp(Behaviour):
            def shard_client_ago(self, index, age):
                return 5.0 if index == 0 else 500.0

        data, _ = run_scenario("L6", OnlyFirstCatchesUp())
        name = loop.catchup_name(loop.L1_WINDOW)
        self.assertEqual(data["criteria"][name]["status"], FAIL)

    def test_l6_both_processes_share_the_original_baseline(self) -> None:
        class SessionInFirstProcess(Behaviour):
            active_for = 10_000.0

            def on_start(self, net, index):
                if index == 0:
                    net.dirs[NODE].add("first-process-session")

        data, net = run_scenario("L6", SessionInFirstProcess())
        final = [s for s in data["samples"] if s["final_process"]]
        self.assertTrue(final)
        self.assertTrue(all(s["new_dirs"] == ["first-process-session"] for s in final))
        self.assertEqual(
            data["criteria"]["no new consensus directory while the mode is active"]["status"], FAIL
        )

    def test_l6_kill_interval_is_not_a_death(self) -> None:
        data, _ = run_scenario("L6", Behaviour())
        self.assertEqual(data["criteria"]["engines alive throughout"]["status"], PASS)
        self.assertEqual(
            data["criteria"]["the last process was sampled inside the window"]["status"], PASS
        )


def wait_for_state(pid: int, state: str, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if loop.proc_state(pid) == state:
            return
        time.sleep(0.02)
    raise AssertionError(f"process {pid} never reached state {state}")


class Recorder(unittest.TestCase):
    def test_grid_skips_missed_slots_and_dates_by_completion(self) -> None:
        clock = FakeClock()
        reads = []

        def read():
            reads.append(clock.now)
            clock.sleep(25.0 if len(reads) == 3 else 1.0)  # the third read is slow
            return {n: 1000.0 for n in loop.NODES}

        def wait(seconds):
            clock.sleep(seconds)
            return len(reads) >= 6

        saved = loop.CLOCK
        loop.CLOCK = clock
        try:
            recorder = loop.RssRecorder(read, interval=10.0, keep=1000.0, wait=wait)
            recorder.run()
        finally:
            loop.CLOCK = saved
        # Each row is dated by when its reading completed, not by its slot.
        self.assertEqual(
            [r["mono"] for r in recorder.between(0.0, 1e9)], [1.0, 11.0, 45.0, 51.0, 61.0, 71.0]
        )
        # The slots at 30 s and 40 s, passed during the slow read, are skipped.
        self.assertEqual(reads, [0.0, 10.0, 20.0, 50.0, 60.0, 70.0])

    def test_failed_reading_is_missing_and_kept(self) -> None:
        clock = FakeClock()
        calls = []

        def read():
            calls.append(1)
            if len(calls) == 2:
                raise OSError("proc unreadable")
            return {n: 1000.0 for n in loop.NODES}

        saved = loop.CLOCK
        loop.CLOCK = clock
        try:
            recorder = loop.RssRecorder(
                read, interval=10.0, wait=lambda s: clock.sleep(s) or len(calls) >= 3
            )
            recorder.run()
        finally:
            loop.CLOCK = saved
        rows = recorder.between(0.0, 1e9)
        self.assertEqual([r["rss"][1] for r in rows], [1000.0, None, 1000.0])
        self.assertEqual(len(recorder.errors), 1)

    def test_old_rows_are_dropped(self) -> None:
        clock = FakeClock()
        saved = loop.CLOCK
        loop.CLOCK = clock
        try:
            recorder = loop.RssRecorder(
                lambda: {n: 1.0 for n in loop.NODES},
                interval=10.0,
                keep=100.0,
                wait=lambda s: clock.sleep(s) or clock.now > 1000,
            )
            recorder.run()
        finally:
            loop.CLOCK = saved
        rows = recorder.between(0.0, 1e9)
        self.assertLessEqual(len(rows), 11)
        self.assertGreaterEqual(rows[0]["mono"], rows[-1]["mono"] - 100.0)

    def test_records_while_the_main_thread_is_blocked(self) -> None:
        progressed = threading.Event()
        count = []

        def read():
            count.append(1)
            if len(count) >= 3:
                progressed.set()
            return {n: 1.0 for n in loop.NODES}

        recorder = loop.RssRecorder(read, interval=0.05)
        recorder.start()
        try:
            # The main thread does nothing but wait here, as it does inside a
            # restart or an RPC: the readings must come from the recorder's thread.
            self.assertTrue(progressed.wait(timeout=30.0), "no readings while blocked")
        finally:
            recorder.stop()
        self.assertIsNotNone(recorder.thread)
        self.assertFalse(recorder.thread.is_alive())


class Stop(unittest.TestCase):
    """stop() against real processes: a zombie has stopped."""

    def network(self, tmp: str, pid: int):
        net = object.__new__(loop.Network)
        net.net = Path(tmp)
        (Path(tmp) / f"node-{NODE}.pid").write_text(f"{pid}\n")
        return net

    def stops(self, net) -> None:
        try:
            net.stop(NODE, timeout=5.0)
        except RuntimeError as exc:
            self.fail(f"a zombie was taken for a running engine: {exc}")

    def test_own_child_zombie_is_reaped(self) -> None:
        child = subprocess.Popen(["sleep", "60"])
        try:
            os.kill(child.pid, signal.SIGKILL)
            wait_for_state(child.pid, "Z")
            with tempfile.TemporaryDirectory() as tmp:
                started = time.monotonic()
                self.stops(self.network(tmp, child.pid))
                self.assertLess(time.monotonic() - started, 5.0)
            with self.assertRaises(ChildProcessError):
                os.waitpid(child.pid, os.WNOHANG)
        finally:
            if child.returncode is None:
                try:
                    child.kill()
                except OSError:
                    pass

    def test_unreaped_grandchild_zombie_counts_as_stopped(self) -> None:
        holder = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import subprocess, sys, time\n"
                "p = subprocess.Popen(['sleep', '60'])\n"
                "print(p.pid, flush=True)\n"
                "time.sleep(60)\n",
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        grandchild = None
        try:
            assert holder.stdout is not None
            grandchild = int(holder.stdout.readline())
            os.kill(grandchild, signal.SIGKILL)
            wait_for_state(grandchild, "Z")
            with tempfile.TemporaryDirectory() as tmp:
                started = time.monotonic()
                self.stops(self.network(tmp, grandchild))
                self.assertLess(time.monotonic() - started, 5.0)
        finally:
            holder.kill()
            holder.wait()
            if holder.stdout is not None:
                holder.stdout.close()

    def test_running_process_is_not_stopped(self) -> None:
        child = subprocess.Popen(["sleep", "60"])
        try:
            self.assertFalse(loop.process_stopped(child.pid))
            # Not the runner's child, and not signalable or still running.
            self.assertFalse(loop.process_stopped(1))
        finally:
            child.kill()
            child.wait()
        self.assertTrue(loop.process_stopped(child.pid))

    def test_invalid_pid_is_refused(self) -> None:
        for bad in (0, -1, -(2**31)):
            with self.assertRaises(ValueError):
                loop.process_stopped(bad)


if __name__ == "__main__":
    unittest.main()
