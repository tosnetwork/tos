#!/usr/bin/env python3
"""Local-chain drill: a validator loses consensus/ while a shard split is pending.

LOCAL ONLY. It boots a DHT node and four PQ validators of a disposable local chain
(global id 3) in a new working directory, on ports away from any other local network on
the host. Nothing here touches a shared network, /data or a service.

The basechain starts with min_split 1, so it splits shortly after genesis. While the
split is pending (the target, node 3, has built a tentative group for a child shard and
no current one), the target is stopped, its consensus/ directory is moved aside (the node
sees it deleted; the drill keeps it as evidence), and the target is restarted at once,
within the same masterchain session.

  --mode log      the build under test: the target runs with --signing-decision-log and,
                  before its first start, a ledger from the genesis ceremony. Expected:
                  after the restart, every session at or below cc(M) + 2 of its lineage
                  is fenced and the target signs in none of them; from cc(M) + 3 it signs
                  again. M is the fence block the target logs.
  --mode control  a build without the log (main): the red control. Expected: the target
                  signs again at once, in the masterchain session it signed in before.
  --mode producer-control
                  a build whose block producer skips its admission checks, set up as in
                  --mode log: the red control for the signing boundary. Expected: the
                  target signs a candidate in a fenced session.

Exit status. The drill is a gate: it exits 0 only when the run shows what its mode
expects, and the summary (drill-summary.json) is written either way for diagnosis.
  0  the expectation of the mode is met: for --mode log the fence held and signing
     resumed at cc(M) + 3; for a control mode the control detected what it exists to
     detect (main signed in the old session; the producer control signed a candidate in
     a fenced session). A control that stays green is a failure of the drill.
  1  the drill could not run or read its input (a DRILL_FAILED message says why).
  3  --mode log: the fence did not hold, signing did not resume as expected, or no
     fence was recorded.
  4  a control mode: the control did not show the violation it is meant to show.
The same codes apply to --analyze-only, which recomputes the verdict from the logs.

Signing is observed two ways.
- At the signing boundary: the target logs, once per session, the first candidate and
  the first vote of each kind (notarize, finalize, skip) it signs ("own signature: first
  ..."). This sees a signature whether or not it is ever published or certified.
- On every node: a certificate lists the indices of the validators whose signatures it
  carries ("Obtained certificate ...: V.VV", logged by the actor valgroup<shard>.<cc>),
  and the target logs its own index in each session. A certificate carrying the target's
  index, obtained after the restart, proves the target signed then.

Usage:
  uv run python test/integration/signing_unknown_history_drill.py --mode log \\
      --build BUILD_DIR --working-dir NEW_DIR [--mc-lifetime 300] [--shard-lifetime 60] [--observe 1200]

The masterchain session outlives the restart (300 s), so a node that signs at once
signs in the session it signed in before; the shard sessions rotate faster (60 s).
"""

from __future__ import annotations

import argparse
import asyncio
import calendar
import hashlib
import json
import logging
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from tostester.install import Install
from tostester.network import FullNode, Network, StartOptions

TARGET = 3
MC = "(-1,8000000000000000)"

STAMP = re.compile(r"\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\.(\d+)\]")
ADMISSION = re.compile(
    r"signing ledger: session (?P<session>[0-9A-Fa-f]{64}) of (?P<shard>\(\S+\)) catchain "
    r"(?P<cc>\d+): (?P<verdict>admitted|fenced)(?: \((?P<reason>.*)\))?"
)
INDEX = re.compile(
    r"of (?P<shard>\(\S+\)) catchain (?P<cc>\d+): local validator index (?P<idx>\d+)"
)
FENCE = re.compile(
    r"signing ledger: unknown history fenced at (?P<block>\S+) over (?P<n>\d+) lineages.*counters:(?P<counters>.*)$"
)
COUNTER = re.compile(r"(\(\S+\))=(\d+)")
CREATED = re.compile(r"Created validator group (?P<shard>\(\S+\))\.(?P<cc>\d+):")
STARTED = re.compile(r"Started validator group (?P<shard>\(\S+\))\.(?P<cc>\d+):")
CERT = re.compile(
    r"\[!valgroup(?P<shard>\(\S+\))\.(?P<cc>\d+)\.SimplexPool\]\s*Obtained certificate for (?P<vote>.*?): (?P<votes>[.V]+)"
)
OWN = re.compile(
    r"consensus: own signature: first (?P<kind>candidate|notarize vote|finalize vote|skip vote) "
    r"signed in session [0-9A-Fa-f]{64} of (?P<shard>\(\S+\)) catchain (?P<cc>\d+)"
)
NOT_SIGNING = re.compile(
    r"the decision log admits no signing in this session|decision log stopped before"
)


def strip(line: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", line)


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [strip(x) for x in path.read_text(errors="replace").splitlines()]


def stamp(line: str) -> float | None:
    m = STAMP.search(line)
    if not m:
        return None
    return calendar.timegm(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")) + float(
        "0." + m.group(2)
    )


def keys(pattern: re.Pattern[str], lines: list[str]) -> set[tuple[str, int]]:
    return {(m["shard"], int(m["cc"])) for line in lines if (m := pattern.search(line))}


def split_pending(lines: list[str]) -> tuple[str, int] | None:
    """A basechain child shard with a tentative group and no current one."""
    started = keys(STARTED, lines)
    for shard, cc in sorted(keys(CREATED, lines)):
        child = shard.startswith("(0,") and not shard.endswith(",8000000000000000)")
        if child and not any(s == shard for s, _ in started):
            return shard, cc
    return None


def current_mc_cc(lines: list[str]) -> int | None:
    started = [cc for shard, cc in keys(STARTED, lines) if shard == MC]
    return max(started) if started else None


async def wait_for(predicate, timeout: float, what: str, step: float = 0.2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        await asyncio.sleep(step)
    raise SystemExit(f"DRILL_FAILED timed out waiting for {what}")


def certificates(node_dirs: list[Path]) -> list[dict[str, Any]]:
    out = []
    for index, directory in enumerate(node_dirs):
        for path in sorted(directory.glob("log*")):
            for line in read_lines(path):
                if m := CERT.search(line):
                    out.append(
                        {
                            "node": index,
                            "file": path.name,
                            "at": stamp(line),
                            "shard": m["shard"],
                            "cc": int(m["cc"]),
                            "votes": m["votes"],
                        }
                    )
    return out


def analyze(working_dir: Path, summary: dict[str, Any]) -> None:
    """Reads the nodes' logs in `working_dir` and adds the verdict to `summary`.

    A signature counts as made after the restart only in a certificate obtained after the
    restarted target built its group for that session: a restarted process signs in a
    session only through its group, and a certificate obtained earlier can carry votes the
    target cast before the stop that were still in flight.
    """
    node_dirs = [working_dir / f"node{i + 1}" for i in range(4)]
    target_dir = node_dirs[TARGET]
    mode = summary["mode"]
    stopped_at = summary["stopped_at"]
    mc_cc = summary["mc_cc_at_stop"]
    after = read_lines(target_dir / "log")
    before = read_lines(target_dir / "log.before-restart")
    index = {}
    for line in before + after:
        if m := INDEX.search(line):
            index[(m["shard"], int(m["cc"]))] = int(m["idx"])
    built_after = {}
    for line in after:
        if (m := CREATED.search(line)) and (m["shard"], int(m["cc"])) not in built_after:
            built_after[(m["shard"], int(m["cc"]))] = stamp(line)
    admissions = {}
    for line in after:
        if m := ADMISSION.search(line):
            admissions[(m["shard"], int(m["cc"]))] = {
                "verdict": m["verdict"],
                "reason": m["reason"],
            }
    fences = []
    for line in after:
        if m := FENCE.search(line):
            fences.append(
                {
                    "block": m["block"],
                    "lineages": int(m["n"]),
                    "counters": {s: int(c) for s, c in COUNTER.findall(m["counters"])},
                    "at": stamp(line),
                }
            )
    certs = certificates(node_dirs)
    own: dict[tuple[str, int], list[str]] = {}
    for line in after:
        if m := OWN.search(line):
            own.setdefault((m["shard"], int(m["cc"])), []).append(m["kind"])
    mc_after = sorted(cc for shard, cc in keys(STARTED, after) if shard == MC)

    def target_signatures(shard: str, cc: int, since: float | None, until: float | None) -> int:
        idx = index.get((shard, cc))
        if idx is None or since is None:
            return 0
        return sum(
            1
            for c in certs
            if c["shard"] == shard
            and c["cc"] == cc
            and c["at"] is not None
            and c["at"] >= since
            and (until is None or c["at"] < until)
            and idx < len(c["votes"])
            and c["votes"][idx] == "V"
        )

    def counter_at_m(shard: str) -> int | None:
        if not fences:
            return None
        counters = fences[0]["counters"]
        if shard in counters:
            return counters[shard]
        # A related lineage: here, any basechain entry for a basechain shard.
        related = [c for s, c in counters.items() if s.split(",")[0] == shard.split(",")[0]]
        return max(related) if related else None

    sessions = []
    for (shard, cc), built in sorted(built_after.items()):
        at_m = counter_at_m(shard)
        sessions.append(
            {
                "shard": shard,
                "cc": cc,
                "local_index": index.get((shard, cc)),
                "admission": admissions.get((shard, cc), {}).get("verdict"),
                "reason": admissions.get((shard, cc), {}).get("reason"),
                "counter_at_fence": at_m,
                "within_fence": at_m is not None and cc <= at_m + 2,
                "group_built_after_restart_at": built,
                "target_signatures_after_restart": target_signatures(shard, cc, built, None),
                "target_signatures_before_stop": target_signatures(shard, cc, 0, stopped_at),
                "own_signatures_after_restart": sorted(own.get((shard, cc), [])),
            }
        )
    summary["fence"] = fences
    summary["mc_cc_started_after_restart"] = mc_after
    summary["restarted_within_mc_session"] = bool(mc_after) and mc_after[0] == mc_cc
    summary["sessions_after_restart"] = sessions
    summary["not_signing_lines_after_restart"] = sum(
        1 for line in after if NOT_SIGNING.search(line)
    )
    old = next((s for s in sessions if s["shard"] == MC and s["cc"] == mc_cc), None)
    if mode in ("log", "producer-control"):
        violations = [
            s
            for s in sessions
            if s["within_fence"]
            and (s["target_signatures_after_restart"] > 0 or s["own_signatures_after_restart"])
        ]
        above = [s for s in sessions if s["counter_at_fence"] is not None and not s["within_fence"]]
        boundary_kinds_above = sorted({k for s in above for k in s["own_signatures_after_restart"]})
        own_first_mc = min(
            (s["cc"] for s in sessions if s["shard"] == MC and s["own_signatures_after_restart"]),
            default=None,
        )
        fenced_ok = all(s["admission"] == "fenced" for s in sessions if s["within_fence"])
        resumed = [
            s for s in sessions if s["shard"] == MC and s["target_signatures_after_restart"] > 0
        ]
        first_resumed = min((s["cc"] for s in resumed), default=None)
        at_m = counter_at_m(MC)
        summary["verdict"] = {
            "fence_recorded": bool(fences),
            "signed_in_the_old_masterchain_session_before_stop": bool(old)
            and old["target_signatures_before_stop"] > 0,
            "no_signature_within_fence": not violations,
            "signatures_within_fence": [
                {
                    "shard": s["shard"],
                    "cc": s["cc"],
                    "certificates": s["target_signatures_after_restart"],
                    "own": s["own_signatures_after_restart"],
                }
                for s in violations
            ],
            "own_signature_kinds_above_fence": boundary_kinds_above,
            "masterchain_first_own_signature_cc": own_first_mc,
            "every_session_within_fence_fenced": fenced_ok,
            "masterchain_first_signed_cc": first_resumed,
            "masterchain_expected_first_cc": None if at_m is None else at_m + 3,
            "passed": bool(fences)
            and bool(old)
            and old["target_signatures_before_stop"] > 0
            and not violations
            and fenced_ok
            and first_resumed is not None
            and at_m is not None
            and first_resumed == at_m + 3
            and own_first_mc == at_m + 3
            and "candidate" in boundary_kinds_above
            and any(k.endswith("vote") for k in boundary_kinds_above),
        }
    else:
        summary["verdict"] = {
            "signed_in_the_old_masterchain_session_before_stop": bool(old)
            and old["target_signatures_before_stop"] > 0,
            "signatures_in_the_old_masterchain_session_after_restart": old[
                "target_signatures_after_restart"
            ]
            if old
            else 0,
            "red": bool(old) and old["target_signatures_after_restart"] > 0,
        }


EXIT_EXPECTED = 0
EXIT_LOG_FAILED = 3
EXIT_CONTROL_UNDETECTED = 4


def judge(mode: str, summary: dict[str, Any]) -> int:
    """The exit status for `mode` from the verdict, recorded in `summary` as well."""
    verdict = summary["verdict"]
    if mode == "log":
        met = verdict.get("passed") is True
        expected = "the fence held and signing resumed at cc(M) + 3"
        failure = EXIT_LOG_FAILED
    elif mode == "control":
        met = (
            verdict.get("red") is True
            and verdict.get("signed_in_the_old_masterchain_session_before_stop") is True
        )
        expected = "the target signed again in the masterchain session it signed in before"
        failure = EXIT_CONTROL_UNDETECTED
    else:
        met = any(
            "candidate" in violation["own"]
            for violation in verdict.get("signatures_within_fence", [])
        )
        expected = "the target signed a candidate in a fenced session"
        failure = EXIT_CONTROL_UNDETECTED
    status = EXIT_EXPECTED if met else failure
    summary["expectation"] = {"mode": mode, "expected": expected, "met": met, "exit_status": status}
    return status


async def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--mode", choices=["log", "control", "producer-control"], required=True)
    parser.add_argument(
        "--analyze-only",
        action="store_true",
        help="recompute the verdict of an earlier run in --working-dir from its logs",
    )
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--working-dir", type=Path, required=True)
    parser.add_argument("--base-port", type=int, default=34000)
    parser.add_argument(
        "--mc-lifetime", type=int, default=300, help="masterchain catchain lifetime, seconds"
    )
    parser.add_argument(
        "--shard-lifetime", type=int, default=60, help="shard catchain lifetime, seconds"
    )
    parser.add_argument(
        "--observe", type=int, default=600, help="seconds to observe after the restart"
    )
    args = parser.parse_args()

    working_dir = args.working_dir.resolve()
    if args.analyze_only:
        summary = json.loads((working_dir / "drill-summary.json").read_text())
        # A producer control is set up as a log run; earlier runs recorded it as one.
        compatible = {args.mode} | ({"log"} if args.mode == "producer-control" else set())
        if summary["mode"] not in compatible:
            raise SystemExit("DRILL_FAILED --mode differs from the run's")
        analyze(working_dir, summary)
        status = judge(args.mode, summary)
        write_summary(working_dir, summary)
        return status
    working_dir.mkdir(parents=True, exist_ok=False)
    install = Install(args.build.resolve(), args.source.resolve())
    install.toslibjson.client_set_verbosity_level(1)
    logging.basicConfig(
        level=logging.INFO, format="[%(levelname)s][%(asctime)s][%(name)s] %(message)s"
    )
    log = logging.getLogger("drill")
    summary: dict[str, Any] = {
        "mode": args.mode,
        "mc_lifetime": args.mc_lifetime,
        "shard_lifetime": args.shard_lifetime,
        "observe": args.observe,
        "working_dir": str(working_dir),
        "build": str(args.build.resolve()),
        "source": str(args.source.resolve()),
    }

    # Away from the ports of any other local network on the host.
    async with Network(install, working_dir, base_port=args.base_port) as network:
        config = network.config
        # A fresh AUTH network tag per drill chain, as the local tooling derives one.
        config.auth_network_tag = hashlib.sha256(
            f"TOS-AUTH-NETWORK-TAG-v1;network=signing-drill;global_id=3;epoch={int(time.time())}".encode()
        ).digest()
        config.shard_validators = 4
        config.split = 1
        config.mc_valgroup_lifetime = args.mc_lifetime
        config.shard_valgroup_lifetime = args.shard_lifetime
        dht = network.create_dht_node()
        nodes: list[FullNode] = []
        ids = []
        for index in range(4):
            node = network.create_full_node()
            validator_id = hashlib.sha256(f"drill-validator-id-{index}".encode()).digest()
            node.make_initial_pq_validator(
                validator_id, hashlib.sha256(f"drill-validator-seed-{index}".encode()).digest()
            )
            node.announce_to(dht)
            nodes.append(node)
            ids.append(validator_id)
        target = nodes[TARGET]
        # Generated now, before any node starts, so the ceremony can name it.
        zerostate = network._get_or_generate_zerostate()  # pyright: ignore[reportPrivateUsage]
        summary["zerostate"] = {
            "root_hash": zerostate.masterchain.root_hash.hex(),
            "file_hash": zerostate.masterchain.file_hash.hex(),
        }
        target_args: list[str] = []
        if args.mode in ("log", "producer-control"):
            ceremony = subprocess.run(
                [
                    str(install.pq_consensus_key_exe),
                    "init-signing-ledger",
                    "--genesis-ceremony",
                    str(target.directory),
                    ids[TARGET].hex(),
                    zerostate.masterchain.root_hash.hex(),
                    zerostate.masterchain.file_hash.hex(),
                ],
                capture_output=True,
                text=True,
            )
            summary["ceremony"] = {
                "rc": ceremony.returncode,
                "out": ceremony.stdout.strip(),
                "err": ceremony.stderr.strip(),
            }
            if ceremony.returncode != 0:
                raise SystemExit(f"DRILL_FAILED genesis ceremony: {ceremony.stderr}")
            target_args = ["--signing-decision-log"]

        async with asyncio.TaskGroup() as group:
            group.create_task(dht.run())
            for index, node in enumerate(nodes):
                group.create_task(
                    node.run(StartOptions(args=target_args if index == TARGET else ()))
                )
        log.info("nodes started")

        # The target must have signed (its index in a masterchain certificate) and the
        # split must be pending.
        await wait_for(lambda: split_pending(read_lines(target.log_path)), 600, "a pending split")
        before = read_lines(target.log_path)
        pending = split_pending(before)
        mc_cc = current_mc_cc(before)
        summary["pending_split"] = {"shard": pending[0], "cc": pending[1]} if pending else None
        summary["mc_cc_at_stop"] = mc_cc
        summary["started_before_stop"] = sorted(keys(STARTED, before))
        log.info(f"split pending: {pending}; masterchain catchain {mc_cc}")

        stopped_at = time.time()
        await target.stop()
        target.log_path.rename(target.directory / "log.before-restart")
        moved = target.directory / f"consensus.removed-{int(stopped_at)}"
        (target.directory / "consensus").rename(moved)
        summary["consensus_moved_to"] = moved.name
        await target.run(StartOptions(args=target_args))
        restarted_at = time.time()
        summary["stopped_at"] = stopped_at
        summary["restarted_at"] = restarted_at
        log.info(f"target restarted {restarted_at - stopped_at:.1f}s after the stop")

        await asyncio.sleep(args.observe)
        for node in nodes:
            await node.stop()
        await dht.stop()

    analyze(working_dir, summary)
    status = judge(args.mode, summary)
    write_summary(working_dir, summary)
    return status


def write_summary(working_dir: Path, summary: dict[str, Any]) -> None:
    out = working_dir / "drill-summary.json"
    out.write_text(json.dumps(summary, indent=2, sort_keys=True))
    print(f"DRILL_SUMMARY {out} {json.dumps(summary['verdict'], sort_keys=True)}")
    print(f"DRILL_EXPECTATION {json.dumps(summary['expectation'], sort_keys=True)}")


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
