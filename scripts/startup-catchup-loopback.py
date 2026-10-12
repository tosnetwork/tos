#!/usr/bin/env python3
"""Loopback acceptance of startup archive catch-up for a stale validator.

Runs one acceptance scenario (L1-L7) on a four-validator loopback network
started by the network-settings repository's testnet/scripts/rehearse-loopback.sh
in hold mode, and prints a JSON report with every measurement and every
criterion. The exit status is 0 only when every criterion of the scenario holds.

    startup-catchup-loopback.py --network-settings DIR --tos-root DIR \
        --tos-build DIR --work NEW_DIR --scenario L1 [--base-port N]

Measurements, per node and sample:
  * the STATUS line of the node log (last_masterchain_block_ago, shard_client_ago);
  * RSS of the engine process (/proc/<pid>/status);
  * live WaitBlockState and BridgeImpl actors (engine console get-actor-stats);
  * the masterchain head over JSON-RPC (getMasterchainInfo);
  * the catch-up mode's log lines ("startup catch-up: entering", "... ended: R",
    "... not entered") and the consensus directory listing.

Scenarios:
  L1  four validators; one stopped 30 min, then restarted. Within 20 min of the
      restart shard_client_ago < 60 s; RSS < 1.5 x the peers' median throughout;
      within 10 min live WaitBlockState < 5000 and BridgeImpl equal to the peers';
      while the mode is active no BridgeImpl and no new consensus directory; the
      mode is entered and ends Fresh.
  L2  all four stopped 10 min with equal tips, then started: a new masterchain
      block within 5 min of the last start; every node's mode ends
      NoVerifiedSuccessor or is never entered; no node imports archives.
  L3  one validator stopped, the others 2 min later; 10 min down; all started: a
      new masterchain block within 5 min; the lagging node ends Fresh or
      NoVerifiedSuccessor, never Abandoned.
  L4  L1 with a downtime that crosses a catchain rotation and a validator-set
      (key block) rotation. Needs a short-election configuration; the scenario is
      refused as not established when no key block was produced while the node
      was down.
  L5  L1 on a validator whose database was initialized from a persistent state:
      its database is removed (keys and config kept) and it resynchronizes before
      the 30-minute stop. Refused as not established when the node did not start
      from a persistent state.
  L6  SIGKILL of the restarted node during import, after at least two import
      attempts settled, then a second restart: L1's bounds measured from the first
      restart, and no failed CHECK in any log.
  L7  a running validator frozen for 10 min (SIGSTOP; unprivileged stand-in for
      blocked traffic) and resumed: no catch-up mode entry and no archive import
      after the resume.

`--self-test` checks the parsers against fixed samples and exits.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

NODES = (1, 2, 3, 4)
STATUS_RE = re.compile(
    r"STATUS: last_masterchain_block_ago=(?P<mc>-?[0-9.]+)(?P<mcu>ns|us|ms|s|h|d) "
    r"last_known_key_block_ago=(?P<key>-?[0-9.]+)(?P<keyu>ns|us|ms|s|h|d) "
    r"shard_client_ago=(?P<sc>-?[0-9.]+)(?P<scu>ns|us|ms|s|h|d)"
)
UNITS = {"ns": 1e-9, "us": 1e-6, "ms": 1e-3, "s": 1.0, "h": 3600.0, "d": 86400.0}
ENTER = "startup catch-up: entering"
ENDED_RE = re.compile(r"startup catch-up ended: (?P<reason>\w+)")
NOT_ENTERED = "startup catch-up not entered"
ATTEMPT_RE = re.compile(r"startup catch-up attempt (?P<n>\d+):")
ARCHIVE_IMPORT = "Importing archive for masterchain seqno"
FAILED_CHECK = re.compile(r"Check `.*` failed")


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


def parse_actor_stats(text: str, names: tuple[str, ...]) -> dict[str, int]:
    """Live actors per class from get-actor-stats' "All actors:" section."""
    alive = {name: 0 for name in names}
    in_all = False
    current = None
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
            for name in names:
                if current == name or current.endswith("::" + name):
                    alive[name] += int(m.group(1))
    return alive


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
    alive = parse_actor_stats(stats, ("WaitBlockState", "BridgeImpl"))
    assert alive == {"WaitBlockState": 57564, "BridgeImpl": 130}, alive
    assert ENDED_RE.search("startup catch-up ended: Fresh; masterchain ...")["reason"] == "Fresh"
    print("startup-catchup-loopback self-test: OK")
    return 0


class Network:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.work = Path(args.work).resolve()
        self.net = self.work / "net"
        self.base = args.base_port
        self.process: subprocess.Popen | None = None

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
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                self.process.kill()

    def pid(self, node: int) -> int:
        return int((self.net / f"node-{node}.pid").read_text().strip())

    def alive(self, node: int) -> bool:
        try:
            os.kill(self.pid(node), 0)
            return True
        except (OSError, ValueError):
            return False

    def stop(self, node: int, sig: int = signal.SIGTERM) -> None:
        pid = self.pid(node)
        os.kill(pid, sig)
        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except OSError:
                return
            time.sleep(1)
        raise RuntimeError(f"node {node} did not stop")

    def restart(self, node: int) -> float:
        subprocess.Popen(
            ["bash", str(self.net / f"node-{node}.start")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(2)
        return time.time()

    def logs(self, node: int) -> list[Path]:
        return sorted((self.net / f"log{node}").glob("node.log*"), key=lambda p: p.stat().st_mtime)

    def log_text(self, node: int) -> str:
        return "".join(p.read_text(errors="replace") for p in self.logs(node))

    def status(self, node: int) -> dict | None:
        last = None
        for line in self.log_text(node).splitlines():
            parsed = parse_status(line)
            if parsed is not None:
                last = parsed
        return last

    def rss_mb(self, node: int) -> float | None:
        try:
            for line in Path(f"/proc/{self.pid(node)}/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
        except (OSError, ValueError):
            return None
        return None

    def head(self, node: int) -> int | None:
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "getMasterchainInfo", "params": {}}
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
            return int(answer["result"]["last"]["seqno"])
        except Exception:  # noqa: BLE001 - a node that does not answer has no head
            return None

    def actors(self, node: int) -> dict[str, int] | None:
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
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return parse_actor_stats(out.stdout, ("WaitBlockState", "BridgeImpl"))

    def consensus_dirs(self, node: int) -> set[str]:
        root = self.net / f"node{node}" / "consensus"
        return {p.name for p in root.iterdir()} if root.is_dir() else set()

    def mode(self, node: int) -> dict:
        text = self.log_text(node)
        ended = [m["reason"] for m in ENDED_RE.finditer(text)]
        return {
            "entered": text.count(ENTER),
            "not_entered": text.count(NOT_ENTERED),
            "ended": ended,
            "attempts": len(ATTEMPT_RE.findall(text)),
            "archive_imports": text.count(ARCHIVE_IMPORT),
            "failed_checks": len(FAILED_CHECK.findall(text)),
        }


class Report:
    def __init__(self, scenario: str) -> None:
        self.data: dict = {"scenario": scenario, "criteria": {}, "samples": [], "notes": []}

    def criterion(self, name: str, ok: bool, detail) -> None:
        self.data["criteria"][name] = {"ok": bool(ok), "detail": detail}

    def ok(self) -> bool:
        return bool(self.data["criteria"]) and all(c["ok"] for c in self.data["criteria"].values())


def sample(net: Network, t0: float) -> dict:
    row = {"t": round(time.time() - t0, 1), "nodes": {}}
    for node in NODES:
        row["nodes"][node] = {
            "alive": net.alive(node),
            "status": net.status(node),
            "rss_mb": net.rss_mb(node),
            "head": net.head(node),
            "actors": net.actors(node),
        }
    return row


def measure_restart(
    net: Network, report: Report, node: int, restarted_at: float, window: float
) -> None:
    """L1's numbers for `node` restarted at `restarted_at`, sampled every 30 s."""
    peers = [n for n in NODES if n != node]
    caught_up_at = None
    rss_ok = True
    actors_ok_10m = None
    bridges_while_active = 0
    dirs_before = net.consensus_dirs(node)
    new_dirs_while_active: set[str] = set()
    while time.time() < restarted_at + window:
        row = sample(net, restarted_at)
        report.data["samples"].append(row)
        mine = row["nodes"][node]
        status = mine["status"]
        if caught_up_at is None and status is not None and status["shard_client_ago"] < 60:
            caught_up_at = row["t"]
        peer_rss = [row["nodes"][p]["rss_mb"] for p in peers if row["nodes"][p]["rss_mb"]]
        if mine["rss_mb"] and peer_rss and mine["rss_mb"] >= 1.5 * statistics.median(peer_rss):
            rss_ok = False
        mode = net.mode(node)
        active = mode["entered"] > len(mode["ended"])
        if active:
            if mine["actors"]:
                bridges_while_active = max(bridges_while_active, mine["actors"]["BridgeImpl"])
            new_dirs_while_active |= net.consensus_dirs(node) - dirs_before
        if row["t"] >= 600 and actors_ok_10m is None and mine["actors"]:
            peer_bridges = [
                row["nodes"][p]["actors"]["BridgeImpl"] for p in peers if row["nodes"][p]["actors"]
            ]
            actors_ok_10m = mine["actors"]["WaitBlockState"] < 5000 and (
                bool(peer_bridges)
                and mine["actors"]["BridgeImpl"] == statistics.median_low(peer_bridges)
            )
            report.data["notes"].append(
                {"actors_at_10m": mine["actors"], "peer_bridges": peer_bridges}
            )
        if caught_up_at is not None and row["t"] >= 660:
            break
        time.sleep(30)
    mode = net.mode(node)
    report.criterion(
        "shard_client_ago < 60 s within 20 min",
        caught_up_at is not None and caught_up_at <= 1200,
        caught_up_at,
    )
    report.criterion("RSS < 1.5 x peer median throughout", rss_ok, None)
    report.criterion(
        "at 10 min: WaitBlockState < 5000 and BridgeImpl equal to peers", bool(actors_ok_10m), None
    )
    report.criterion(
        "no BridgeImpl while the mode is active", bridges_while_active == 0, bridges_while_active
    )
    report.criterion(
        "no new consensus directory while the mode is active",
        not new_dirs_while_active,
        sorted(new_dirs_while_active),
    )
    report.criterion("no failed CHECK", mode["failed_checks"] == 0, mode["failed_checks"])
    report.data["mode"] = mode


def scenario_l1(net: Network, report: Report, downtime: float = 1800.0, node: int = 3) -> None:
    time.sleep(600)
    heads_before = net.head(1)
    net.stop(node)
    time.sleep(downtime)
    report.data["notes"].append({"head_before_stop": heads_before, "head_at_restart": net.head(1)})
    restarted = net.restart(node)
    measure_restart(net, report, node, restarted, 1200.0)
    mode = net.mode(node)
    report.criterion(
        "mode entered and ended Fresh",
        mode["entered"] >= 1 and mode["ended"][-1:] == ["Fresh"],
        mode,
    )


def new_block_after(net: Network, since_head: int | None, deadline: float) -> bool:
    while time.time() < deadline:
        heads = [h for h in (net.head(n) for n in NODES) if h is not None]
        if heads and since_head is not None and max(heads) > since_head:
            return True
        time.sleep(10)
    return False


def scenario_l2(net: Network, report: Report) -> None:
    time.sleep(300)
    report.data["notes"].append({"heads_before_stop": [net.head(n) for n in NODES]})
    for node in NODES:
        net.stop(node)
    time.sleep(600)
    starts = [net.restart(node) for node in NODES]
    heads = [h for h in (net.head(n) for n in NODES) if h is not None]
    top = max(heads) if heads else None
    report.criterion(
        "a new masterchain block within 5 min of the last start",
        new_block_after(net, top, starts[-1] + 300),
        top,
    )
    for node in NODES:
        mode = net.mode(node)
        ok = mode["entered"] == 0 or (mode["ended"][-1:] == ["NoVerifiedSuccessor"])
        report.criterion(f"node {node} mode ends NoVerifiedSuccessor or is not entered", ok, mode)


def scenario_l3(net: Network, report: Report) -> None:
    time.sleep(300)
    net.stop(1)
    time.sleep(120)
    for node in (2, 3, 4):
        net.stop(node)
    time.sleep(600)
    starts = [net.restart(node) for node in NODES]
    time.sleep(30)
    heads = [h for h in (net.head(n) for n in NODES) if h is not None]
    top = max(heads) if heads else None
    report.criterion(
        "a new masterchain block within 5 min of the last start",
        new_block_after(net, top, starts[-1] + 300),
        top,
    )
    mode = net.mode(1)
    report.criterion(
        "the lagging node ends Fresh or NoVerifiedSuccessor, never Abandoned",
        "Abandoned" not in mode["ended"]
        and (mode["entered"] == 0 or mode["ended"][-1:] in (["Fresh"], ["NoVerifiedSuccessor"])),
        mode,
    )


def scenario_l4(net: Network, report: Report) -> None:
    status_before = net.status(1)
    scenario_l1(net, report, downtime=float(os.environ.get("CATCHUP_L4_DOWNTIME", "3600")))
    status_after = net.status(1)
    rotated = (
        status_before is not None
        and status_after is not None
        and status_after["last_known_key_block_ago"] < status_before["last_known_key_block_ago"]
    )
    report.criterion(
        "a key block was produced while the node was down (scenario established)",
        rotated,
        {"before": status_before, "after": status_after},
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
    net.restart(node)
    deadline = time.time() + 3600
    while time.time() < deadline and (net.status(node) or {}).get("shard_client_ago", 1e9) > 60:
        time.sleep(30)
    from_persistent = "persistent state" in net.log_text(node).lower()
    report.criterion(
        "the node started from a persistent state (scenario established)", from_persistent, None
    )
    scenario_l1(net, report, node=node)


def scenario_l6(net: Network, report: Report) -> None:
    node = 3
    time.sleep(600)
    net.stop(node)
    time.sleep(1800)
    restarted = net.restart(node)
    deadline = time.time() + 1200
    while time.time() < deadline and net.mode(node)["attempts"] < 2:
        time.sleep(5)
    attempts = net.mode(node)["attempts"]
    report.criterion("killed after at least two import attempts settled", attempts >= 2, attempts)
    net.stop(node, signal.SIGKILL)
    net.restart(node)
    measure_restart(net, report, node, restarted, 1200.0)
    report.criterion(
        "the mode was entered again in the new process",
        net.mode(node)["entered"] >= 2,
        net.mode(node),
    )


def scenario_l7(net: Network, report: Report) -> None:
    node = 3
    time.sleep(600)
    before = net.mode(node)
    os.kill(net.pid(node), signal.SIGSTOP)
    time.sleep(600)
    os.kill(net.pid(node), signal.SIGCONT)
    time.sleep(600)
    after = net.mode(node)
    report.criterion(
        "no catch-up mode entry after the resume",
        after["entered"] == before["entered"],
        {"before": before, "after": after},
    )
    report.criterion(
        "no archive import after the resume",
        after["archive_imports"] == before["archive_imports"],
        {"before": before, "after": after},
    )


SCENARIOS = {
    "L1": scenario_l1,
    "L2": scenario_l2,
    "L3": scenario_l3,
    "L4": scenario_l4,
    "L5": scenario_l5,
    "L6": scenario_l6,
    "L7": scenario_l7,
}


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
        report.criterion("scenario ran to the end", False, repr(exc))
    finally:
        net.close()
    for node in NODES:
        try:
            report.data.setdefault("final_mode", {})[node] = net.mode(node)
        except OSError:
            pass
    report.data["ok"] = report.ok()
    out = json.dumps(report.data, indent=2, default=str)
    (Path(args.work) / f"report-{args.scenario}.json").write_text(out + "\n")
    print(out)
    return 0 if report.ok() else 1


if __name__ == "__main__":
    sys.exit(main())
