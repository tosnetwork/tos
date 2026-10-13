#!/usr/bin/env python3
"""Loopback acceptance of startup archive catch-up for a stale validator.

Runs one acceptance scenario (L1-L7) on a four-validator loopback network
started by the network-settings repository's testnet/scripts/rehearse-loopback.sh
in hold mode, and prints a JSON report with every measurement and every
criterion. Each criterion is PASS, FAIL or INCONCLUSIVE; the overall result is
FAIL if any criterion failed, INCONCLUSIVE if any lacked evidence, and PASS only
when every criterion passed. Exit status: 0 PASS, 1 FAIL, 2 INCONCLUSIVE.

    startup-catchup-loopback.py --network-settings DIR --tos-root DIR \
        --tos-build DIR --work NEW_DIR --scenario L1 [--base-port N]

Evidence is accepted only when it is valid:
  * actor counts only from a console call that exited 0 and printed a
    structurally valid "All actors:" section (engine console get-actor-stats);
  * a STATUS line (shard_client_ago) only if the restarted process wrote it after
    its restart, and only while that same process is alive;
  * RSS only from a live process, for the restarted node and every peer in every
    sample;
  * the fence criteria only from actor samples taken while the mode was active.
Missing evidence makes a criterion INCONCLUSIVE, never PASS.

Scenarios:
  L1  four validators; one stopped 30 min, then restarted. Within 20 min of the
      restart shard_client_ago < 60 s; RSS < 1.5 x the peers' median throughout;
      at 10 min live WaitBlockState < 5000 and BridgeImpl equal to the peers';
      while the mode is active no BridgeImpl and no new consensus directory; the
      mode is entered and ends Fresh.
  L2  all four stopped 10 min with equal tips, then started. The stopped tips are
      established before the stop: production is halted by never letting more
      than one validator run (a lone validator has no quorum), each one's head is
      read while it runs alone, and the four full block ids must be equal. After
      the restart: a masterchain block beyond the highest stopped tip within 5 min
      of the last start; every node enters the mode and ends NoVerifiedSuccessor;
      no node imports an archive. A node that did not enter is a failure, unless
      its log names one of the evaluated entry refusals: then the scenario was not
      set up, which is INCONCLUSIVE.
  L3  one validator stopped, the others 2 min later; 10 min down; all started. The
      others' stopped tips are established as in L2 and must be equal and at
      least two blocks beyond the lagging node's last head. After the restart: a
      masterchain block beyond the highest stopped tip within 5 min; the lagging
      node enters the mode and ends Fresh or NoVerifiedSuccessor, never Abandoned;
      the others enter it and end NoVerifiedSuccessor. Not entering is judged as
      in L2.
  L4  L1 with a downtime that crosses a catchain rotation and a validator-set
      (key block) rotation. Needs a short-election configuration. The stopped
      validator's own last key block, ConfigParam 34 hash and catchain seqno are
      read immediately before the stop, and a peer's immediately before the
      restart; a key block generated between the stop and the restart, a changed
      validator set and a higher catchain seqno are all required. Otherwise
      INCONCLUSIVE ("rotation not established").
  L5  L1 on a validator whose database was initialized from a persistent state:
      its database is removed (keys and config kept) and it resynchronizes before
      the 30-minute stop. INCONCLUSIVE when the node did not start from a
      persistent state.
  L6  SIGKILL of the restarted node during import, after at least two import
      attempts settled, then a second restart: L1's bounds measured from the first
      restart, the STATUS from the last process, and no failed CHECK in any log.
  L7  a running validator frozen for 10 min (SIGSTOP; unprivileged stand-in for
      blocked traffic) and resumed: no catch-up mode entry and no archive import
      after the resume. The log mark is taken while the process is still stopped,
      so a line written at the first instant after the resume is counted.

`--self-test` checks the parsers and the evaluation against fixed samples, with an
independent red control for each kind of missing or invalid evidence, and exits.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

NODES = (1, 2, 3, 4)
SHARD_ALL = -(1 << 63)
PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"
STATUS_RE = re.compile(
    r"STATUS: last_masterchain_block_ago=(?P<mc>-?[0-9.]+)(?P<mcu>ns|us|ms|s|h|d) "
    r"last_known_key_block_ago=(?P<key>-?[0-9.]+)(?P<keyu>ns|us|ms|s|h|d) "
    r"shard_client_ago=(?P<sc>-?[0-9.]+)(?P<scu>ns|us|ms|s|h|d)"
)
UNITS = {"ns": 1e-9, "us": 1e-6, "ms": 1e-3, "s": 1.0, "h": 3600.0, "d": 86400.0}
ENTER = "startup catch-up: entering"
ENDED_RE = re.compile(r"startup catch-up ended: (?P<reason>\w+)")
NOT_ENTERED = "startup catch-up not entered"
REFUSAL_RE = re.compile(
    r"startup catch-up not entered: (?P<refusal>[^(]+?) \(sync reason: (?P<reason>[^)]*)\)"
)
# The refusals the entry decision evaluates, exactly as the engine logs them.
ENTRY_REFUSALS = frozenset(
    {
        "mandatory sync reason",
        "not stale",
        "no validator keys held",
        "validator or observer groups already exist",
        "operator import files present",
        "next block is a configured hardfork",
        "already decided in this process",
    }
)
ATTEMPT_RE = re.compile(r"startup catch-up attempt (?P<n>\d+):")
ARCHIVE_IMPORT = "Importing archive for masterchain seqno"
FAILED_CHECK = re.compile(r"Check `.*` failed")
ACTORS = ("WaitBlockState", "BridgeImpl")


def seconds(value: str, unit: str) -> float:
    return float(value) * UNITS[unit]


def parse_status(line: str) -> dict | None:
    m = STATUS_RE.search(line)
    if not m:
        return None
    return {
        "last_masterchain_block_ago": seconds(m["mc"], m["mcu"]),
        "last_known_key_block_ago": seconds(m["key"], m["keyu"]),
        "shard_client_ago": seconds(m["sc"], m["scu"]),
    }


def last_status(text: str) -> dict | None:
    last = None
    for line in text.splitlines():
        parsed = parse_status(line)
        if parsed is not None:
            last = parsed
    return last


def parse_actor_stats(text: str, names: tuple[str, ...] = ACTORS) -> dict[str, int] | None:
    """Live actors per class from get-actor-stats' "All actors:" section.

    Nothing unless the section is present and at least one class in it reports an
    alive count: an empty or truncated answer is not "zero actors".
    """
    alive = {name: 0 for name in names}
    in_all = False
    current = None
    classes = 0
    for line in text.splitlines():
        if line.startswith("All actors:"):
            in_all = True
            continue
        if not in_all:
            continue
        if line.startswith("\t") and not line.startswith("\t\t"):
            current = line.strip()
            continue
        m = re.search(r"alive: (\d+)", line)
        if m and current is not None:
            classes += 1
            for name in names:
                if current == name or current.endswith("::" + name):
                    alive[name] += int(m.group(1))
    if not in_all or classes == 0:
        return None
    return alive


def actors_from_console(returncode: int, stdout: bytes | str) -> dict[str, int] | None:
    if returncode != 0:
        return None
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    return parse_actor_stats(stdout)


# Only lines the runner reads are kept: the engine logs about 10 MB a minute.
KEPT_LINE = re.compile(
    r"STATUS: |startup catch-up|Importing archive for masterchain seqno|Check `.*` failed"
    r"|persistent state",
    re.IGNORECASE,
)


class LogFollower:
    """Follows a node's per-thread logs across rotation, in order, without losing lines.

    The engine writes one log per thread (node.log.threadN.log) and rotates each by
    renaming it to <name>.old and starting a new file. Each poll reads every log from
    where it stopped; a log whose inode changed is first finished from its .old copy,
    then read from the start. Every line read gets the next sequence number, so a
    mark taken at a restart separates what was written before it from what came
    after, whatever was rotated in between.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)
        self.streams: dict[str, dict] = {}
        self.seq = 0
        self.lines: list[tuple[int, str]] = []

    def _read(self, path: Path, stream: dict) -> None:
        try:
            with open(path, "rb") as f:
                f.seek(stream["pos"])
                data = f.read()
        except OSError:
            return
        stream["pos"] += len(data)
        text = stream["partial"] + data.decode("utf-8", errors="replace")
        parts = text.split("\n")
        stream["partial"] = parts.pop()
        for line in parts:
            self.seq += 1
            if KEPT_LINE.search(line):
                self.lines.append((self.seq, line))

    def poll(self) -> None:
        if not self.directory.is_dir():
            return
        for path in sorted(self.directory.glob("node.log*")):
            if path.name.endswith(".old"):
                continue
            try:
                st = path.stat()
            except OSError:
                continue
            stream = self.streams.get(str(path))
            if stream is None:
                stream = {"ino": st.st_ino, "pos": 0, "partial": ""}
                self.streams[str(path)] = stream
            elif stream["ino"] != st.st_ino:
                old = path.with_name(path.name + ".old")
                try:
                    if old.stat().st_ino == stream["ino"]:
                        self._read(old, stream)
                except OSError:
                    pass
                if stream["partial"]:
                    # The rotated file's last line is complete: it does not continue
                    # into the new file.
                    stream["partial"] += "\n"
                    self._read(Path(os.devnull), stream)
                stream.update(ino=st.st_ino, pos=0, partial="")
            elif st.st_size < stream["pos"]:
                stream["pos"] = 0
            self._read(path, stream)

    def mark(self) -> int:
        self.poll()
        return self.seq

    def text_since(self, mark: int | None) -> str:
        self.poll()
        return "\n".join(line for seq, line in self.lines if mark is None or seq > mark)


def criterion(status: str, detail) -> dict:
    return {"status": status, "detail": detail}


def overall(criteria: dict) -> str:
    if not criteria:
        return INCONCLUSIVE
    statuses = [c["status"] for c in criteria.values()]
    if FAIL in statuses:
        return FAIL
    if INCONCLUSIVE in statuses:
        return INCONCLUSIVE
    return PASS


def mode_from_text(text: str) -> dict:
    """What one node's log since a mark says about the mode."""
    return {
        "entered": text.count(ENTER),
        "not_entered": text.count(NOT_ENTERED),
        "refusals": [m["refusal"] for m in REFUSAL_RE.finditer(text)],
        "ended": [m["reason"] for m in ENDED_RE.finditer(text)],
        "attempts": len(ATTEMPT_RE.findall(text)),
        "archive_imports": text.count(ARCHIVE_IMPORT),
        "failed_checks": len(FAILED_CHECK.findall(text)),
    }


def stopped_network_entry(mode: dict, allowed_endings: tuple[str, ...]) -> dict:
    """A node restarted after the whole network stopped long enough to make it stale.

    It must enter the mode and end with one of `allowed_endings`. Not entering at all
    is a failure, unless the log names one of the evaluated entry refusals: then the
    run did not set up the scenario it meant to test, which is INCONCLUSIVE, never PASS.
    """
    if mode["entered"] >= 1:
        last = mode["ended"][-1:]
        ok = len(last) == 1 and last[0] in allowed_endings and "Abandoned" not in mode["ended"]
        return criterion(PASS if ok else FAIL, mode)
    refusals = [r for r in mode["refusals"] if r in ENTRY_REFUSALS]
    if refusals:
        return criterion(INCONCLUSIVE, {"entry refused": refusals, "mode": mode})
    return criterion(FAIL, mode)


def resume_observed(mark, resume):
    """Marks a stopped process's log, then resumes it.

    The mark is taken while the process cannot write, so every line it writes once
    resumed, including one written at the very first instant, comes after the mark.
    """
    taken = mark()
    resume()
    return taken


ROTATION_NOT_ESTABLISHED = "rotation not established"


def evaluate_rotation(
    before: dict | None, after: dict | None, node: int, stop_t: float, restart_t: float
) -> dict:
    """Whether the key block, validator set and catchain all changed during the downtime.

    A snapshot: {"node", "t" (wall clock when read), "key_block": {"seqno",
    "gen_utime"}, "catchain_seqno", "validator_set" (hash of ConfigParam 34)}.
    `before` must be the stopped validator's own view, read immediately before it was
    stopped at `stop_t`; `after` is read while it is down, at `restart_t` at the
    latest. A change that cannot be placed between the two is not counted: the
    result is then INCONCLUSIVE, never PASS.
    """
    if before is None or after is None:
        return criterion(INCONCLUSIVE, {ROTATION_NOT_ESTABLISHED: "a snapshot was not read"})
    detail = {"before": before, "after": after, "stop_t": stop_t, "restart_t": restart_t}
    missing = []
    if before["node"] != node:
        missing.append("baseline not read from the stopped validator")
    if before["t"] > stop_t:
        missing.append("baseline read after the stop")
    if not stop_t <= after["t"] <= restart_t:
        missing.append("after-state not read during the downtime")
    key = after["key_block"]
    if not (
        key["seqno"] > before["key_block"]["seqno"] and stop_t <= key["gen_utime"] <= restart_t
    ):
        missing.append("no key block produced during the downtime")
    if not after["catchain_seqno"] > before["catchain_seqno"]:
        missing.append("no catchain rotation")
    if after["validator_set"] == before["validator_set"]:
        missing.append("no validator-set change")
    if missing:
        detail[ROTATION_NOT_ESTABLISHED] = missing
        return criterion(INCONCLUSIVE, detail)
    return criterion(PASS, detail)


def evaluate_restart(samples: list[dict], node: int, peers: list[int], window: float) -> dict:
    """L1's criteria for `node` from samples taken after its restart.

    A sample: {"t": seconds since the restart, "mode_active": bool,
    "new_dirs": [new consensus directories], "nodes": {n: {"alive": bool,
    "rss_mb": float | None, "actors": dict | None, "status": dict | None}}}, where
    the restarted node's status is only one its new process wrote after the restart.
    """
    out: dict = {}
    if not samples:
        reason = "no samples"
        for name in (
            "engines alive throughout",
            "shard_client_ago < 60 s within 20 min",
            "RSS < 1.5 x peer median throughout",
            "at 10 min: WaitBlockState < 5000 and BridgeImpl equal to peers",
            "no BridgeImpl while the mode is active",
            "no new consensus directory while the mode is active",
        ):
            out[name] = criterion(INCONCLUSIVE, reason)
        return out

    dead = [(s["t"], n) for s in samples for n in [node, *peers] if not s["nodes"][n]["alive"]]
    out["engines alive throughout"] = criterion(FAIL if dead else PASS, dead[:10])

    fresh = [(s["t"], s["nodes"][node]["status"]) for s in samples if s["nodes"][node]["status"]]
    caught = [t for t, st in fresh if st["shard_client_ago"] < 60]
    if caught and caught[0] <= min(window, 1200):
        out["shard_client_ago < 60 s within 20 min"] = criterion(PASS, caught[0])
    elif fresh:
        out["shard_client_ago < 60 s within 20 min"] = criterion(FAIL, fresh[-1])
    else:
        out["shard_client_ago < 60 s within 20 min"] = criterion(
            INCONCLUSIVE, "no STATUS from the restarted process"
        )

    missing_rss = [
        s["t"] for s in samples if any(s["nodes"][n]["rss_mb"] is None for n in [node, *peers])
    ]
    if missing_rss:
        out["RSS < 1.5 x peer median throughout"] = criterion(
            INCONCLUSIVE, {"samples_missing_rss": len(missing_rss), "first": missing_rss[0]}
        )
    else:
        over = [
            s["t"]
            for s in samples
            if s["nodes"][node]["rss_mb"]
            >= 1.5 * statistics.median([s["nodes"][p]["rss_mb"] for p in peers])
        ]
        out["RSS < 1.5 x peer median throughout"] = criterion(FAIL if over else PASS, over[:10])

    at_10m = [
        s
        for s in samples
        if s["t"] >= 600 and all(s["nodes"][n]["actors"] is not None for n in [node, *peers])
    ]
    if not at_10m:
        out["at 10 min: WaitBlockState < 5000 and BridgeImpl equal to peers"] = criterion(
            INCONCLUSIVE, "no complete actor sample at or after 10 min"
        )
    else:
        s = at_10m[0]
        mine = s["nodes"][node]["actors"]
        peer_bridges = [s["nodes"][p]["actors"]["BridgeImpl"] for p in peers]
        ok = mine["WaitBlockState"] < 5000 and mine["BridgeImpl"] == statistics.median_low(
            peer_bridges
        )
        out["at 10 min: WaitBlockState < 5000 and BridgeImpl equal to peers"] = criterion(
            PASS if ok else FAIL, {"t": s["t"], "mine": mine, "peer_bridges": peer_bridges}
        )

    active = [s for s in samples if s["mode_active"]]
    if not active:
        out["no BridgeImpl while the mode is active"] = criterion(
            INCONCLUSIVE, "no sample taken while the mode was active"
        )
        out["no new consensus directory while the mode is active"] = criterion(
            INCONCLUSIVE, "no sample taken while the mode was active"
        )
    else:
        unobserved = [s["t"] for s in active if s["nodes"][node]["actors"] is None]
        if unobserved:
            out["no BridgeImpl while the mode is active"] = criterion(
                INCONCLUSIVE, {"active_samples_without_actors": unobserved}
            )
        else:
            bridges = max(s["nodes"][node]["actors"]["BridgeImpl"] for s in active)
            out["no BridgeImpl while the mode is active"] = criterion(
                PASS if bridges == 0 else FAIL, bridges
            )
        new_dirs = sorted({d for s in active for d in s["new_dirs"]})
        out["no new consensus directory while the mode is active"] = criterion(
            FAIL if new_dirs else PASS, new_dirs
        )
    return out


def self_test() -> int:
    status = parse_status(
        "[ 0][t 1][2026-10-12][manager.cpp:4570] STATUS: last_masterchain_block_ago=847.0s "
        "last_known_key_block_ago=1.2h shard_client_ago=1915.0s"
    )
    assert status is not None and status["shard_client_ago"] == 1915.0
    assert abs(status["last_known_key_block_ago"] - 4320.0) < 1e-6
    assert parse_status("no status here") is None
    stats = (
        "All actors:\n\ttos::validator::WaitBlockState\n\t\tload_per_second:\t0 0 0\n"
        "\t\talive: 57564 executing: 0 max_executing_for: 0s\n"
        "\ttos::validator::consensus::BridgeImpl\n\t\talive: 130 executing: 0 max_executing_for: 0s\n"
    )
    assert actors_from_console(0, stats) == {"WaitBlockState": 57564, "BridgeImpl": 130}
    assert ENDED_RE.search("startup catch-up ended: Fresh; masterchain ...")["reason"] == "Fresh"

    # Control: empty console output is no evidence.
    assert actors_from_console(0, "") is None
    # Control: a console that failed is no evidence, whatever it printed.
    assert actors_from_console(1, stats) is None
    # Control: a section header without any class is no evidence.
    assert actors_from_console(0, "All actors:\n\n") is None
    # Control: console output that is not UTF-8 is read, not a crash.
    assert actors_from_console(0, stats.encode() + b"\xff\xfe\n") == {
        "WaitBlockState": 57564,
        "BridgeImpl": 130,
    }
    assert actors_from_console(0, b"\xff\xfe\xfd") is None

    def status_line(ago: float) -> str:
        return (
            f"STATUS: last_masterchain_block_ago={ago}s last_known_key_block_ago=1.0s "
            f"shard_client_ago={ago}s\n"
        )

    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "node.log.thread1.log"

        def append(text: str) -> None:
            with open(log, "a") as f:
                f.write(text)

        def rotate() -> None:
            os.replace(log, log.with_name(log.name + ".old"))

        follower = LogFollower(Path(tmp))
        # Control: a STATUS written before the restart is stale, even after a rotation.
        append(status_line(2.0))
        restart = follower.mark()
        assert last_status(follower.text_since(restart)) is None
        rotate()
        append("startup catch-up: entering\n")
        assert last_status(follower.text_since(restart)) is None
        # Control: a rotation between two reads loses no line and keeps the order.
        append(status_line(30.0))
        follower.poll()
        append(status_line(31.0))
        append("startup catch-up attempt 1: one\n")
        rotate()  # unread lines are left in the .old file
        append(status_line(32.0))
        append("startup catch-up ended: Fresh\n")
        seen = follower.text_since(restart).splitlines()
        assert seen == [
            "startup catch-up: entering",
            status_line(30.0).strip(),
            status_line(31.0).strip(),
            "startup catch-up attempt 1: one",
            status_line(32.0).strip(),
            "startup catch-up ended: Fresh",
        ], seen
        assert last_status("\n".join(seen))["shard_client_ago"] == 32.0

    node, peers = 3, [1, 2, 4]
    good_actors = {"WaitBlockState": 10, "BridgeImpl": 4}

    def sample(t: float, active: bool, ago: float) -> dict:
        nodes = {
            n: {"alive": True, "rss_mb": 1000.0, "actors": dict(good_actors), "status": None}
            for n in NODES
        }
        nodes[node]["status"] = {"shard_client_ago": ago}
        if active:
            nodes[node]["actors"] = {"WaitBlockState": 10, "BridgeImpl": 0}
        return {"t": t, "mode_active": active, "new_dirs": [], "nodes": nodes}

    good = [sample(0, True, 900), sample(300, True, 200), sample(600, False, 10)]
    criteria = evaluate_restart(good, node, peers, 1200)
    assert overall(criteria) == PASS, criteria

    def red(mutate, name: str, expected: str) -> None:
        samples = copy.deepcopy(good)
        mutate(samples)
        got = evaluate_restart(samples, node, peers, 1200)
        assert got[name]["status"] == expected, (name, got[name])
        assert overall(got) != PASS, got

    def empty_output(samples):
        for s in samples:
            s["nodes"][node]["actors"] = actors_from_console(0, "")

    def console_error(samples):
        for s in samples:
            for n in NODES:
                s["nodes"][n]["actors"] = actors_from_console(1, stats)

    def dead_process(samples):
        samples[1]["nodes"][2]["alive"] = False
        samples[1]["nodes"][2]["rss_mb"] = None

    def stale_status(samples):
        for s in samples:
            s["nodes"][node]["status"] = None

    def no_active_samples(samples):
        for s in samples:
            s["mode_active"] = False

    def missing_rss(samples):
        samples[2]["nodes"][1]["rss_mb"] = None

    red(empty_output, "no BridgeImpl while the mode is active", INCONCLUSIVE)
    red(
        console_error,
        "at 10 min: WaitBlockState < 5000 and BridgeImpl equal to peers",
        INCONCLUSIVE,
    )
    red(dead_process, "engines alive throughout", FAIL)
    red(stale_status, "shard_client_ago < 60 s within 20 min", INCONCLUSIVE)
    red(no_active_samples, "no BridgeImpl while the mode is active", INCONCLUSIVE)
    red(missing_rss, "RSS < 1.5 x peer median throughout", INCONCLUSIVE)

    # Everything missing at once: dead engines, no RSS, empty actors, stale STATUS.
    def nothing(samples):
        for s in samples:
            for n in NODES:
                s["nodes"][n] = {"alive": False, "rss_mb": None, "actors": None, "status": None}

    red(nothing, "engines alive throughout", FAIL)
    assert overall({}) == INCONCLUSIVE

    # Sustained production: one new block, or a node left behind, is not enough.
    assert sustained({1: 120, 2: 121, 3: 125, 4: 120}, 100)
    assert not sustained({1: 101, 2: 101, 3: 101, 4: 101}, 100)
    assert not sustained({1: 130, 2: 130, 3: 100, 4: 130}, 100)
    assert not sustained({1: 130, 2: 130, 3: None, 4: 130}, 100)

    # Entry after a stop of the whole network (L2, L3), from the engine's own lines.
    nvs = ("NoVerifiedSuccessor",)
    entered = mode_from_text(
        "startup catch-up: entering for a stale validator; ...\n"
        "startup catch-up ended: NoVerifiedSuccessor; ...\n"
    )
    assert stopped_network_entry(entered, nvs)["status"] == PASS
    refused = mode_from_text("startup catch-up not entered: not stale (sync reason: fresh)\n")
    assert refused["refusals"] == ["not stale"], refused
    assert stopped_network_entry(refused, nvs)["status"] == INCONCLUSIVE
    for name in sorted(ENTRY_REFUSALS):
        line = f"startup catch-up not entered: {name} (sync reason: stale validator)\n"
        assert stopped_network_entry(mode_from_text(line), nvs)["status"] == INCONCLUSIVE, name
    # Control: not entering with no validated refusal is not a pass.
    assert stopped_network_entry(mode_from_text(""), nvs)["status"] == FAIL
    assert stopped_network_entry(mode_from_text("STATUS: unrelated\n"), nvs)["status"] == FAIL
    # Control: a refusal the entry decision does not evaluate is not validated.
    unknown = mode_from_text("startup catch-up not entered: unknown (sync reason: fresh)\n")
    assert stopped_network_entry(unknown, nvs)["status"] == FAIL
    # Control: entered, but the wrong ending, no ending, or Abandoned.
    fresh = mode_from_text("startup catch-up: entering\nstartup catch-up ended: Fresh\n")
    assert stopped_network_entry(fresh, nvs)["status"] == FAIL
    assert stopped_network_entry(fresh, ("Fresh", "NoVerifiedSuccessor"))["status"] == PASS
    assert (
        stopped_network_entry(mode_from_text("startup catch-up: entering\n"), nvs)["status"] == FAIL
    )
    abandoned = mode_from_text("startup catch-up: entering\nstartup catch-up ended: Abandoned\n")
    assert stopped_network_entry(abandoned, ("Fresh", "NoVerifiedSuccessor"))["status"] == FAIL

    # L4: the rotations must fall between the stop (t=1000) and the restart (t=4600).
    def snap(node: int, t: float, key: int, key_utime: int, cc: int, vset: str) -> dict:
        return {
            "node": node,
            "t": t,
            "key_block": {"seqno": key, "gen_utime": key_utime},
            "catchain_seqno": cc,
            "validator_set": vset,
        }

    before = snap(3, 999.0, 50, 400, 7, "set-a")
    after = snap(1, 4590.0, 80, 2500, 9, "set-b")
    assert evaluate_rotation(before, after, 3, 1000.0, 4600.0)["status"] == PASS

    def not_established(b, a) -> list[str]:
        result = evaluate_rotation(b, a, 3, 1000.0, 4600.0)
        assert result["status"] == INCONCLUSIVE, result
        if ROTATION_NOT_ESTABLISHED in result["detail"]:
            return result["detail"][ROTATION_NOT_ESTABLISHED]
        return []

    # Control: a key block produced before the stop (during the warm-up) is not counted,
    # even though it is newer than a baseline read at the start of the warm-up.
    warmup = snap(3, 10.0, 50, 400, 7, "set-a")
    assert "no key block produced during the downtime" in not_established(
        warmup, snap(1, 4590.0, 60, 600, 9, "set-b")
    )
    assert "baseline read after the stop" not in not_established(
        warmup, snap(1, 4590.0, 60, 600, 9, "set-b")
    )
    assert "no key block produced during the downtime" in not_established(
        before, snap(1, 4590.0, 60, 900, 9, "set-b")
    )
    # Control: a key block after the restart is not counted either.
    assert "no key block produced during the downtime" in not_established(
        before, snap(1, 4590.0, 80, 4700, 9, "set-b")
    )
    # Control: a different node's baseline is not counted.
    assert "baseline not read from the stopped validator" in not_established(
        snap(1, 999.0, 50, 400, 7, "set-a"), after
    )
    # Control: a missing validator-set change gives INCONCLUSIVE.
    assert not_established(before, snap(1, 4590.0, 80, 2500, 9, "set-a")) == [
        "no validator-set change"
    ]
    # Control: a missing catchain rotation gives INCONCLUSIVE.
    assert not_established(before, snap(1, 4590.0, 80, 2500, 7, "set-b")) == [
        "no catchain rotation"
    ]
    # Control: an after-state read outside the downtime, or not read at all.
    assert "after-state not read during the downtime" in not_established(
        before, snap(1, 5000.0, 80, 2500, 9, "set-b")
    )
    assert "baseline read after the stop" in not_established(
        snap(3, 1001.0, 50, 400, 7, "set-a"), after
    )
    assert evaluate_rotation(None, after, 3, 1000.0, 4600.0)["status"] == INCONCLUSIVE
    assert evaluate_rotation(before, None, 3, 1000.0, 4600.0)["status"] == INCONCLUSIVE

    # The snapshot reader, against a fake JSON-RPC: the key block is the head's
    # previous key block, read by its own header; the validator set is ConfigParam 34
    # at the head.
    def fake_network(headers: dict, p34: bytes, answering: set[int]):
        calls = []

        def rpc(node, method, params=None):
            calls.append((node, method, params))
            if node not in answering:
                return None
            if method == "getMasterchainInfo":
                return {"last": {"seqno": max(headers)}}
            if method == "getBlockHeader":
                return headers.get(params["seqno"])
            if method == "getConfigParam" and params == {"param": 34, "seqno": max(headers)}:
                return {"config": {"bytes": base64.b64encode(p34).decode()}}
            return None

        net = object.__new__(Network)
        net.rpc = rpc
        return net, calls

    def header(seqno: int, key: bool, prev_key: int, cc: int, utime: int) -> dict:
        return {
            "id": {"seqno": seqno},
            "is_key_block": key,
            "prev_key_block_seqno": prev_key,
            "catchain_seqno": cc,
            "gen_utime": utime,
        }

    headers = {40: header(40, True, 30, 5, 1234), 90: header(90, False, 40, 6, 2000)}
    net, calls = fake_network(headers, b"vset", {3})
    got = net.rotation_snapshot(3)
    assert got is not None and got["node"] == 3, got
    assert got["key_block"] == {"seqno": 40, "gen_utime": 1234}, got
    assert got["catchain_seqno"] == 6 and got["head_seqno"] == 90, got
    assert got["validator_set"] == hashlib.sha256(b"vset").hexdigest(), got
    assert {c[0] for c in calls} == {3}, calls
    # A head that is itself a key block is the last key block.
    net, _ = fake_network({90: header(90, True, 40, 6, 2000)}, b"vset", {3})
    assert net.rotation_snapshot(3)["key_block"] == {"seqno": 90, "gen_utime": 2000}
    # Control: a header for another seqno, or an unreadable key block, is no snapshot.
    wrong = {40: header(40, True, 30, 5, 1234), 90: header(91, False, 40, 6, 2000)}
    net, _ = fake_network(wrong, b"vset", {3})
    assert net.rotation_snapshot(3) is None
    net, _ = fake_network({90: header(90, False, 40, 6, 2000)}, b"vset", {3})
    assert net.rotation_snapshot(3) is None
    # No key block since the zero state: the zero state has no header to read.
    net, _ = fake_network({90: header(90, False, 0, 6, 2000)}, b"vset", {3})
    assert net.rotation_snapshot(3)["key_block"] == {"seqno": 0, "gen_utime": 0}
    # Control: such a baseline still needs a key block inside the downtime.
    zero = snap(3, 999.0, 0, 0, 7, "set-a")
    assert evaluate_rotation(zero, after, 3, 1000.0, 4600.0)["status"] == PASS
    assert "no key block produced during the downtime" in not_established(
        zero, snap(1, 4590.0, 0, 0, 9, "set-b")
    )
    # The after-state comes from a peer, never the stopped validator, even if it answers.
    net, calls = fake_network(headers, b"vset", set(NODES))
    assert net.rotation_snapshot_from_peer(1)["node"] == 2
    assert all(c[0] != 1 for c in calls), calls
    net, _ = fake_network(headers, b"vset", {3})
    assert net.rotation_snapshot_from_peer(1)["node"] == 3
    assert net.rotation_snapshot_from_peer(3) is None

    # Control: a line the process writes at the first instant of its resume is counted.
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "node.log.thread1.log"
        log.write_text(status_line(1.0))
        follower = LogFollower(Path(tmp))

        def resume() -> None:
            with open(log, "a") as f:
                f.write("startup catch-up: entering\nImporting archive for masterchain seqno 7\n")

        mark = resume_observed(follower.mark, resume)
        after = mode_from_text(follower.text_since(mark))
        assert after["entered"] == 1 and after["archive_imports"] == 1, after
    print("startup-catchup-loopback self-test: OK")
    return 0


class Network:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.work = Path(args.work).resolve()
        self.net = self.work / "net"
        self.base = args.base_port
        self.process: subprocess.Popen | None = None
        # The logs rotate about once a minute: they are followed continuously, so no
        # rotation happens twice between two reads of the same log.
        self.followers = {n: LogFollower(self.net / f"log{n}") for n in NODES}
        self.follow_lock = threading.Lock()
        self.follow_stop = threading.Event()
        self.follow_thread = threading.Thread(target=self._follow, daemon=True)

    def _follow(self) -> None:
        while not self.follow_stop.wait(1.0):
            with self.follow_lock:
                for follower in self.followers.values():
                    follower.poll()

    def port(self, node: int, slot: int) -> int:
        return self.base + 10 * node + slot

    def start(self) -> None:
        self.work.mkdir(mode=0o700, parents=True, exist_ok=False)
        env = dict(os.environ)
        env.update(
            REHEARSAL_HOLD_SECONDS=str(self.args.hold_seconds),
            REHEARSAL_BASE_PORT=str(self.base),
            TOS_ROOT=str(Path(self.args.tos_root).resolve()),
            TOS_BUILD=str(Path(self.args.tos_build).resolve()),
        )
        script = Path(self.args.network_settings) / "testnet/scripts/rehearse-loopback.sh"
        log = open(self.work / "rehearsal.log", "w")
        self.process = subprocess.Popen(
            ["bash", str(script), str(self.net), "600"],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        self.follow_thread.start()
        deadline = time.time() + 1200
        while time.time() < deadline:
            text = (self.work / "rehearsal.log").read_text(errors="replace")
            if "holding the network" in text:
                return
            if self.process.poll() is not None:
                raise RuntimeError(
                    "the loopback rehearsal ended before holding the network; see rehearsal.log"
                )
            time.sleep(5)
        raise RuntimeError("the loopback rehearsal did not reach its hold within 20 minutes")

    def close(self) -> None:
        self.follow_stop.set()
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                self.process.kill()

    def pid(self, node: int) -> int | None:
        try:
            return int((self.net / f"node-{node}.pid").read_text().strip())
        except (OSError, ValueError):
            return None

    def alive(self, node: int) -> bool:
        pid = self.pid(node)
        if pid is None:
            return False
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        try:
            state = Path(f"/proc/{pid}/stat").read_text().split(")")[-1].split()[0]
        except (OSError, IndexError):
            return False
        return state != "Z"

    def send_signal(self, node: int, sig: int) -> None:
        pid = self.pid(node)
        if pid is None:
            raise RuntimeError(f"node {node} has no pid")
        os.kill(pid, sig)

    def stop(self, node: int, sig: int = signal.SIGTERM) -> None:
        pid = self.pid(node)
        if pid is None:
            raise RuntimeError(f"node {node} has no pid")
        os.kill(pid, sig)
        try:
            os.kill(pid, signal.SIGCONT)  # a frozen engine handles SIGTERM only once resumed
        except OSError:
            pass
        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except OSError:
                return
            time.sleep(1)
        raise RuntimeError(f"node {node} did not stop")

    def mark(self, node: int) -> dict:
        with self.follow_lock:
            seq = self.followers[node].mark()
        return {"t": time.time(), "pid": self.pid(node), "seq": seq}

    def restart(self, node: int) -> dict:
        before = self.mark(node)
        subprocess.Popen(
            ["bash", str(self.net / f"node-{node}.start")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.time() + 60
        while time.time() < deadline:
            pid = self.pid(node)
            if pid is not None and pid != before["pid"] and self.alive(node):
                break
            time.sleep(0.5)
        else:
            raise RuntimeError(f"node {node} did not start")
        before["t"] = time.time()
        before["pid"] = self.pid(node)
        return before

    def text_since(self, node: int, mark: dict | None) -> str:
        """The kept log lines written after `mark` (all of them without one), in order."""
        with self.follow_lock:
            return self.followers[node].text_since(None if mark is None else mark["seq"])

    def fresh_status(self, node: int, mark: dict) -> dict | None:
        """The last STATUS the process started at `mark` wrote, while it is alive."""
        if self.pid(node) != mark["pid"] or not self.alive(node):
            return None
        return last_status(self.text_since(node, mark))

    def status_any(self, node: int) -> dict | None:
        return last_status(self.text_since(node, None))

    def rss_mb(self, node: int) -> float | None:
        if not self.alive(node):
            return None
        try:
            for line in Path(f"/proc/{self.pid(node)}/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
        except (OSError, ValueError):
            return None
        return None

    def rpc(self, node: int, method: str, params: dict | None = None) -> dict | None:
        """One JSON-RPC call to `node`; its result, or nothing on any failure."""
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        ).encode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port(node, 4)}",
            body,
            {"Content-Type": "application/json"},
            method="POST",
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=10) as response:
                answer = json.load(response)
            result = answer["result"]
            return result if isinstance(result, dict) else None
        except Exception:  # noqa: BLE001 - a node that does not answer gives no result
            return None

    def head(self, node: int) -> dict | None:
        result = self.rpc(node, "getMasterchainInfo")
        try:
            last = result["last"]
            int(last["seqno"])
            return last
        except (TypeError, KeyError, ValueError):
            return None

    def header(self, node: int, seqno: int) -> dict | None:
        result = self.rpc(
            node,
            "getBlockHeader",
            {"workchain": -1, "shard": str(SHARD_ALL), "seqno": seqno},
        )
        try:
            if int(result["id"]["seqno"]) != seqno:
                return None
            int(result["catchain_seqno"]), int(result["prev_key_block_seqno"])
            int(result["gen_utime"]), bool(result["is_key_block"])
            return result
        except (TypeError, KeyError, ValueError):
            return None

    def rotation_snapshot(self, node: int) -> dict | None:
        """`node`'s own last key block, catchain seqno and validator set, at its head."""
        t = time.time()
        head = self.head(node)
        if head is None:
            return None
        seqno = int(head["seqno"])
        top = self.header(node, seqno)
        if top is None:
            return None
        key_seqno = seqno if top["is_key_block"] else int(top["prev_key_block_seqno"])
        if key_seqno == seqno:
            key = top
        elif key_seqno == 0:
            # No key block since the zero state, which has no block header; time 0
            # never falls inside a downtime.
            key = {"gen_utime": 0}
        else:
            key = self.header(node, key_seqno)
        p34 = self.rpc(node, "getConfigParam", {"param": 34, "seqno": seqno})
        try:
            validator_set = hashlib.sha256(base64.b64decode(p34["config"]["bytes"])).hexdigest()
        except (TypeError, KeyError, ValueError):
            return None
        if key is None:
            return None
        return {
            "node": node,
            "t": t,
            "head_seqno": seqno,
            "key_block": {"seqno": key_seqno, "gen_utime": int(key["gen_utime"])},
            "catchain_seqno": int(top["catchain_seqno"]),
            "validator_set": validator_set,
        }

    def rotation_snapshot_from_peer(self, node: int) -> dict | None:
        """The first running peer's snapshot, while `node` is down."""
        for peer in NODES:
            if peer != node:
                snapshot = self.rotation_snapshot(peer)
                if snapshot is not None:
                    return snapshot
        return None

    def actors(self, node: int) -> dict[str, int] | None:
        if not self.alive(node):
            return None
        console = Path(self.args.tos_build) / "validator-engine-console/validator-engine-console"
        client = self.net / f"console-{node}"
        try:
            out = subprocess.run(
                [
                    str(console),
                    "-a",
                    f"127.0.0.1:{self.port(node, 2)}",
                    "-k",
                    str(client / "client"),
                    "-p",
                    str(client / "server.pub"),
                    "-c",
                    "get-actor-stats",
                    "-c",
                    "quit",
                ],
                capture_output=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        # Raw bytes, decoded with replacement: output that is not UTF-8 is an invalid
        # or partial sample at worst, never a crash.
        return actors_from_console(out.returncode, out.stdout)

    def consensus_dirs(self, node: int) -> set[str]:
        root = self.net / f"node{node}" / "consensus"
        return {p.name for p in root.iterdir()} if root.is_dir() else set()

    def mode(self, node: int, mark: dict | None = None) -> dict:
        return mode_from_text(self.text_since(node, mark))

    def freeze_and_read_tips(self, nodes: list[int]) -> dict[int, dict] | None:
        """Each node's head with production halted: all frozen, then each run alone.

        A lone validator of four has no quorum, so no block can be produced while the
        heads are read. Nothing when a head cannot be read or changes while read.
        """
        for n in nodes:
            self.send_signal(n, signal.SIGSTOP)
        tips = {}
        for n in nodes:
            self.send_signal(n, signal.SIGCONT)
            time.sleep(20)
            first = self.head(n)
            time.sleep(10)
            second = self.head(n)
            self.send_signal(n, signal.SIGSTOP)
            if first is None or second is None or first != second:
                return None
            tips[n] = first
        return tips


class Report:
    def __init__(self, scenario: str) -> None:
        self.data: dict = {"scenario": scenario, "criteria": {}, "samples": [], "notes": []}

    def set(self, name: str, status: str, detail=None) -> None:
        self.data["criteria"][name] = criterion(status, detail)

    def check(self, name: str, ok: bool, detail=None) -> None:
        self.set(name, PASS if ok else FAIL, detail)

    def merge(self, criteria: dict) -> None:
        self.data["criteria"].update(criteria)

    def result(self) -> str:
        return overall(self.data["criteria"])


def take_sample(net: Network, node: int, mark: dict, dirs_before: set[str], t0: float) -> dict:
    mode = net.mode(node, mark)
    active = mode["entered"] > len(mode["ended"])
    nodes = {}
    for n in NODES:
        nodes[n] = {
            "alive": net.alive(n),
            "rss_mb": net.rss_mb(n),
            "actors": net.actors(n),
            "status": net.fresh_status(n, mark) if n == node else net.status_any(n),
            "head": net.head(n),
        }
    return {
        "t": round(time.time() - t0, 1),
        "mode_active": active,
        "new_dirs": sorted(net.consensus_dirs(node) - dirs_before) if active else [],
        "nodes": nodes,
    }


def measure_restart(
    net: Network, report: Report, node: int, mark: dict, t0: float, window: float = 1200.0
) -> None:
    """L1's numbers for `node`, sampled every 30 s from `t0`; STATUS from `mark`'s process."""
    peers = [n for n in NODES if n != node]
    dirs_before = net.consensus_dirs(node)
    samples = []
    while time.time() < t0 + window:
        row = take_sample(net, node, mark, dirs_before, t0)
        samples.append(row)
        report.data["samples"].append(row)
        st = row["nodes"][node]["status"]
        if st is not None and st["shard_client_ago"] < 60 and row["t"] >= 660:
            break
        time.sleep(30)
    report.merge(evaluate_restart(samples, node, peers, window))
    mode = net.mode(node, mark)
    report.check("no failed CHECK", mode["failed_checks"] == 0, mode["failed_checks"])
    report.data["mode"] = mode


def scenario_l1(
    net: Network,
    report: Report,
    downtime: float = 1800.0,
    node: int = 3,
    boundary: dict | None = None,
) -> None:
    """L1; with `boundary`, also the stopped validator's rotation state around the
    downtime: its own snapshot immediately before the stop, and a peer's immediately
    before the restart."""
    time.sleep(600)
    report.data["notes"].append({"head_before_stop": net.head(node)})
    if boundary is not None:
        boundary["before"] = net.rotation_snapshot(node)
        boundary["stop_t"] = time.time()
    net.stop(node)
    time.sleep(downtime)
    if boundary is not None:
        boundary["after"] = net.rotation_snapshot_from_peer(node)
        boundary["restart_t"] = time.time()
    mark = net.restart(node)
    measure_restart(net, report, node, mark, mark["t"])
    mode = net.mode(node, mark)
    report.check(
        "mode entered and ended Fresh",
        mode["entered"] >= 1 and mode["ended"][-1:] == ["Fresh"],
        mode,
    )


def production_beyond(net: Network, seqno: int, deadline: float) -> dict | None:
    while time.time() < deadline:
        for n in NODES:
            h = net.head(n)
            if h is not None and int(h["seqno"]) > seqno:
                return h
        time.sleep(10)
    return None


SUSTAINED_BLOCKS = 20
SUSTAINED_SECONDS = 900


def sustained(heads: dict[int, int | None], top: int, blocks: int = SUSTAINED_BLOCKS) -> bool:
    """Every node's head is at least `blocks` masterchain blocks beyond `top`."""
    return all(h is not None and h >= top + blocks for h in heads.values())


def sustained_production(net: Network, top: int, deadline: float) -> dict:
    heads: dict[int, int | None] = {n: None for n in NODES}
    while time.time() < deadline:
        for n in NODES:
            h = net.head(n)
            if h is not None:
                heads[n] = max(heads[n] or 0, int(h["seqno"]))
        if sustained(heads, top):
            break
        time.sleep(10)
    return heads


def check_resumed(net: Network, report: Report, top: int, last_start: float) -> None:
    produced = production_beyond(net, top, last_start + 300)
    report.check(
        "a masterchain block beyond the stopped tip within 5 min of the last start",
        produced is not None,
        {"stopped_tip": top, "first_beyond": produced},
    )
    heads = sustained_production(net, top, last_start + SUSTAINED_SECONDS)
    report.check(
        f"sustained production: every node at least {SUSTAINED_BLOCKS} blocks beyond the "
        f"stopped tip within {SUSTAINED_SECONDS} s of the last start",
        sustained(heads, top),
        {"stopped_tip": top, "heads": heads},
    )


def scenario_l2(net: Network, report: Report) -> None:
    time.sleep(300)
    tips = net.freeze_and_read_tips(list(NODES))
    report.data["notes"].append({"stopped_tips": tips})
    if tips is None:
        report.set("equal full block ids at the stopped boundary", INCONCLUSIVE, "not read")
        return
    equal = len({json.dumps(t, sort_keys=True) for t in tips.values()}) == 1
    if not equal:
        report.set("equal full block ids at the stopped boundary", INCONCLUSIVE, tips)
        return
    report.set("equal full block ids at the stopped boundary", PASS, tips[1])
    top = max(int(t["seqno"]) for t in tips.values())
    for n in NODES:
        net.stop(n)
    time.sleep(600)
    marks = {n: net.restart(n) for n in NODES}
    last_start = max(m["t"] for m in marks.values())
    check_resumed(net, report, top, last_start)
    for n in NODES:
        mode = net.mode(n, marks[n])
        report.merge(
            {
                f"node {n} enters the mode and ends NoVerifiedSuccessor": stopped_network_entry(
                    mode, ("NoVerifiedSuccessor",)
                )
            }
        )
        report.check(
            f"node {n} imports no archive after the restart", mode["archive_imports"] == 0, mode
        )


def scenario_l3(net: Network, report: Report) -> None:
    time.sleep(300)
    lagging = net.head(1)
    net.stop(1)
    time.sleep(120)
    tips = net.freeze_and_read_tips([2, 3, 4])
    report.data["notes"].append({"lagging_head": lagging, "stopped_tips": tips})
    if lagging is None or tips is None:
        report.set("distinct stopped tips", INCONCLUSIVE, "not read")
        return
    others = {json.dumps(t, sort_keys=True) for t in tips.values()}
    top = max(int(t["seqno"]) for t in tips.values())
    distinct = len(others) == 1 and top >= int(lagging["seqno"]) + 2
    if not distinct:
        report.set("distinct stopped tips", INCONCLUSIVE, {"lagging": lagging, "others": tips})
        return
    report.set("distinct stopped tips", PASS, {"lagging": lagging["seqno"], "others": top})
    for n in (2, 3, 4):
        net.stop(n)
    time.sleep(600)
    marks = {n: net.restart(n) for n in NODES}
    last_start = max(m["t"] for m in marks.values())
    check_resumed(net, report, top, last_start)
    report.merge(
        {
            "the lagging node enters the mode and ends Fresh or NoVerifiedSuccessor, never "
            "Abandoned": stopped_network_entry(
                net.mode(1, marks[1]), ("Fresh", "NoVerifiedSuccessor")
            )
        }
    )
    for n in (2, 3, 4):
        report.merge(
            {
                f"node {n}, stopped at the higher tip, enters the mode and ends "
                "NoVerifiedSuccessor": stopped_network_entry(
                    net.mode(n, marks[n]), ("NoVerifiedSuccessor",)
                )
            }
        )


def scenario_l4(net: Network, report: Report) -> None:
    node = 3
    boundary: dict = {}
    scenario_l1(
        net,
        report,
        downtime=float(os.environ.get("CATCHUP_L4_DOWNTIME", "3600")),
        node=node,
        boundary=boundary,
    )
    report.merge(
        {
            "a key block, a validator-set change and a catchain rotation during the "
            "downtime": evaluate_rotation(
                boundary.get("before"),
                boundary.get("after"),
                node,
                boundary.get("stop_t", 0.0),
                boundary.get("restart_t", 0.0),
            )
        }
    )


def scenario_l5(net: Network, report: Report) -> None:
    node = 3
    time.sleep(600)
    net.stop(node)
    db = net.net / f"node{node}"
    for entry in db.iterdir():
        if entry.name in ("config.json", "keyring", "keys", "static"):
            continue
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()
    mark = net.restart(node)
    deadline = time.time() + 3600
    while time.time() < deadline:
        st = net.fresh_status(node, mark)
        if st is not None and st["shard_client_ago"] < 60:
            break
        time.sleep(30)
    from_persistent = "persistent state" in net.text_since(node, mark).lower()
    report.set(
        "the node started from a persistent state",
        PASS if from_persistent else INCONCLUSIVE,
        None,
    )
    scenario_l1(net, report, node=node)


def scenario_l6(net: Network, report: Report) -> None:
    node = 3
    time.sleep(600)
    net.stop(node)
    time.sleep(1800)
    first = net.restart(node)
    deadline = time.time() + 1200
    while time.time() < deadline and net.mode(node, first)["attempts"] < 2:
        time.sleep(5)
    attempts = net.mode(node, first)["attempts"]
    if attempts < 2:
        report.set("killed after at least two import attempts settled", INCONCLUSIVE, attempts)
        return
    report.set("killed after at least two import attempts settled", PASS, attempts)
    net.stop(node, signal.SIGKILL)
    second = net.restart(node)
    measure_restart(net, report, node, second, first["t"])
    report.check(
        "the mode was entered again in the new process",
        net.mode(node, second)["entered"] >= 1,
        net.mode(node, second),
    )


def scenario_l7(net: Network, report: Report) -> None:
    node = 3
    time.sleep(600)
    if not net.alive(node):
        report.set("the validator runs before the freeze", INCONCLUSIVE, None)
        return
    net.send_signal(node, signal.SIGSTOP)
    time.sleep(600)
    mark = resume_observed(lambda: net.mark(node), lambda: net.send_signal(node, signal.SIGCONT))
    time.sleep(600)
    if not net.alive(node) or net.pid(node) != mark["pid"]:
        report.set("the same process ran through the freeze", FAIL, None)
        return
    after = net.mode(node, mark)
    report.check("no catch-up mode entry after the resume", after["entered"] == 0, after)
    report.check("no archive import after the resume", after["archive_imports"] == 0, after)


SCENARIOS = {
    "L1": scenario_l1,
    "L2": scenario_l2,
    "L3": scenario_l3,
    "L4": scenario_l4,
    "L5": scenario_l5,
    "L6": scenario_l6,
    "L7": scenario_l7,
}
EXIT = {PASS: 0, FAIL: 1, INCONCLUSIVE: 2}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--network-settings")
    parser.add_argument("--tos-root")
    parser.add_argument("--tos-build")
    parser.add_argument("--work")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS))
    parser.add_argument("--base-port", type=int, default=42000)
    parser.add_argument("--hold-seconds", type=int, default=6 * 3600)
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    for name in ("network_settings", "tos_root", "tos_build", "work", "scenario"):
        if getattr(args, name) is None:
            parser.error(f"--{name.replace('_', '-')} is required")
    net = Network(args)
    report = Report(args.scenario)
    try:
        net.start()
        SCENARIOS[args.scenario](net, report)
    except Exception as exc:  # noqa: BLE001 - the report records why the scenario did not finish
        report.set("scenario ran to the end", INCONCLUSIVE, repr(exc))
    finally:
        net.close()
    for node in NODES:
        try:
            report.data.setdefault("final_mode", {})[node] = net.mode(node)
        except OSError:
            pass
    result = report.result()
    report.data["result"] = result
    out = json.dumps(report.data, indent=2, default=str)
    (Path(args.work) / f"report-{args.scenario}.json").write_text(out + "\n")
    print(out)
    return EXIT[result]


if __name__ == "__main__":
    sys.exit(main())
