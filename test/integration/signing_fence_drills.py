#!/usr/bin/env python3
"""Local-chain drills for the mandatory own-decision log: restore, genesis, handover.

LOCAL ONLY. Each live drill boots a DHT node and four PQ validators of a disposable local
chain (global id 3) in a new working directory, on ports away from any other local
network on the host (--base-port). Nothing here touches a shared network, /data or a
service. The handover drill only reads logs it is pointed at.

Drills (--drill) and their arms (--mode):

  restore-copy  --mode log | control
      D1. The target (node 4) signs; it is stopped and its whole database is copied while
      stopped (the snapshot); it runs and signs for --signing-after-snapshot seconds; it is
      stopped, its database is moved aside, the snapshot is copied over it, and it starts
      again within 90 s.
        log      (this build) the copied ledger is untrusted ("copied, restored or
                 recreated"), no own vote or candidate in any session at or below
                 cc(M) + 2, signing resumes at cc(M) + 3.
        control  (a build without the log, main) the target signs again at once in the
                 masterchain session it signed in before: the red control.

  genesis       --mode log | control
      D2. log      every genesis validator runs the genesis ceremony: the masterchain
                   reaches --min-seqno and no node logs the genesis hint.
          control  no validator runs it: no masterchain block in --observe seconds and the
                   genesis hint on all four; then every node is stopped, its consensus/
                   moved aside, the ceremony run and the node started: the chain starts.

  handover      --mode log | control   (analysis of a run made elsewhere: --collect-from)
      D5. Half the weight is replaced at an election by two fresh identities with no
      ledger and no ceremony. The verdict is read from counters, never from elapsed time:
        log      for every incoming identity, its fence counters cc(M) are recorded; a
                 masterchain certificate exists in a session above cc(M) + 2; it made an
                 own vote or candidate in a session above its fence and none at or below.
        control  (main with the log on) the masterchain makes no certificate above any
                 incoming identity's cc(M) + 2: the handover stall.
      The election run itself (rosters, staking) is driven by the local network tooling;
      --collect-from copies the nodes' logs into --working-dir and analyses them.

Exit status (also for --analyze-only, which recomputes the verdict from the logs):
  0  the arm's expectation is met (for a control arm: the control showed the violation)
  1  the drill could not run or read its input (DRILL_FAILED says why)
  3  a log arm's expectation is not met
  4  a control arm did not show what it exists to show
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import logging
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any


def _load_sibling(name: str) -> Any:
    """A script beside this one, loaded by path: the drills share its log analysis."""
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_restart: Any = _load_sibling("signing_unknown_history_drill")
ADMISSION = _restart.ADMISSION
COUNTER = _restart.COUNTER
FENCE = _restart.FENCE
MC: str = _restart.MC
OWN = _restart.OWN
STARTED = _restart.STARTED
certificates = _restart.certificates
current_mc_cc = _restart.current_mc_cc
keys = _restart.keys
read_lines = _restart.read_lines
stamp = _restart.stamp
wait_for = _restart.wait_for
analyze_restart = _restart.analyze

TARGET = 3
UNTRUSTED_COPY = "the signing ledger directory is not the one it was created as: it was copied, restored or recreated"
GENESIS_HINT = "no signing ledger at genesis"
FENCE_BLOCK_OF = re.compile(
    r"signing ledger: fence block of validator (?P<validator>[0-9a-fA-F]{64}) is (?P<block>\S+)"
)

EXIT_EXPECTED = 0
EXIT_FAILED = 1
EXIT_LOG_FAILED = 3
EXIT_CONTROL_UNDETECTED = 4


def write_summary(working_dir: Path, summary: dict[str, Any]) -> None:
    (working_dir / "drill-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )


def node_dirs(working_dir: Path, count: int) -> list[Path]:
    return [working_dir / f"node{i + 1}" for i in range(count)]


# ===== D1: restore from a file copy =====


def analyze_restore_copy(working_dir: Path, summary: dict[str, Any]) -> None:
    """The restart analysis of the unknown-history drill, plus the reason the ledger is not trusted."""
    analyze_restart(working_dir, summary)
    after = read_lines(working_dir / f"node{TARGET + 1}" / "log")
    summary["verdict"]["ledger_untrusted_as_a_copy"] = any(UNTRUSTED_COPY in line for line in after)


def judge_restore_copy(mode: str, summary: dict[str, Any]) -> int:
    verdict = summary["verdict"]
    if mode == "log":
        met = verdict.get("passed") is True and verdict.get("ledger_untrusted_as_a_copy") is True
        expected = "the copy was untrusted, the fence held and signing resumed at cc(M) + 3"
        failure = EXIT_LOG_FAILED
    else:
        met = (
            verdict.get("red") is True
            and verdict.get("signed_in_the_old_masterchain_session_before_stop") is True
        )
        expected = "the restored target signed again in the masterchain session it signed in before"
        failure = EXIT_CONTROL_UNDETECTED
    status = EXIT_EXPECTED if met else failure
    summary["expectation"] = {"mode": mode, "expected": expected, "met": met, "exit_status": status}
    return status


# ===== D2: genesis with and without the ceremony =====


def analyze_genesis(working_dir: Path, summary: dict[str, Any]) -> None:
    """Masterchain progress from the recorded samples; the genesis hint from each node's logs."""
    phases: dict[str, list[list[float]]] = summary.get("seqno_samples", {})
    hinted = {}
    for index, directory in enumerate(node_dirs(working_dir, 4)):
        lines = [x for path in sorted(directory.glob("log*")) for x in read_lines(path)]
        hinted[index + 1] = sum(1 for x in lines if GENESIS_HINT in x)

    def top(phase: str) -> int:
        return int(max((seqno for _, seqno in phases.get(phase, [])), default=0))

    summary["verdict"] = {
        "max_seqno_first_start": top("first"),
        "max_seqno_after_ceremony": top("after-ceremony"),
        "genesis_hint_lines": hinted,
        "genesis_hint_on_every_node": all(n >= 1 for n in hinted.values()),
        "genesis_hint_on_no_node": all(n == 0 for n in hinted.values()),
    }


def judge_genesis(mode: str, summary: dict[str, Any]) -> int:
    verdict = summary["verdict"]
    need = int(summary.get("min_seqno", 10))
    if mode == "log":
        met = verdict["max_seqno_first_start"] >= need and verdict["genesis_hint_on_no_node"]
        expected = f"with the ceremony the masterchain reached seqno {need} and no node logged the genesis hint"
        failure = EXIT_LOG_FAILED
    else:
        met = (
            verdict["max_seqno_first_start"] == 0
            and verdict["genesis_hint_on_every_node"]
            and verdict["max_seqno_after_ceremony"] >= need
        )
        expected = (
            "without the ceremony no block and the hint on all four; after the ceremony the chain "
            f"reached seqno {need}"
        )
        failure = EXIT_CONTROL_UNDETECTED
    status = EXIT_EXPECTED if met else failure
    summary["expectation"] = {"mode": mode, "expected": expected, "met": met, "exit_status": status}
    return status


# ===== D5: a handover that replaces half the weight =====


def analyze_handover(working_dir: Path, summary: dict[str, Any]) -> None:
    """Counter-based: per incoming node, its fence, its admissions and its own signatures; the
    masterchain counters certificates were obtained in, on every node."""
    count = int(summary["nodes"])
    dirs = node_dirs(working_dir, count)
    certs = certificates(dirs)
    mc_cert_counters = sorted({c["cc"] for c in certs if c["shard"] == MC})
    incoming = []
    for node in summary["incoming"]:
        lines = [x for path in sorted(dirs[node - 1].glob("log*")) for x in read_lines(path)]
        fences = []
        for line in lines:
            if m := FENCE.search(line):
                fences.append({s: int(c) for s, c in COUNTER.findall(m["counters"])})
        fence_mc = fences[0].get(MC) if fences else None
        admissions = {}
        for line in lines:
            if m := ADMISSION.search(line):
                admissions.setdefault(f"{m['shard']}.{m['cc']}", m["verdict"])
        own_within, own_above = [], []
        for line in lines:
            if not (m := OWN.search(line)):
                continue
            shard, cc = m["shard"], int(m["cc"])
            # The fence counter of this lineage: the shard's own entry, or any entry of its workchain.
            counters = fences[0] if fences else {}
            entry = counters.get(shard)
            if entry is None:
                related = [c for s, c in counters.items() if s.split(",")[0] == shard.split(",")[0]]
                entry = max(related) if related else None
            item = {"shard": shard, "cc": cc, "kind": m["kind"], "at": stamp(line)}
            if entry is None or cc <= entry + 2:
                own_within.append(item)
            else:
                own_above.append(item)
        recorded = [m["validator"] for line in lines if (m := FENCE_BLOCK_OF.search(line))]
        incoming.append(
            {
                "node": node,
                "fence_block_recorded_for": recorded,
                "fence_counters": fences[0] if fences else None,
                "fence_mc": fence_mc,
                "admissions": admissions,
                "own_signatures_at_or_below_fence": own_within,
                "own_signatures_above_fence": own_above,
                "mc_certificate_above_fence": fence_mc is not None
                and any(cc > fence_mc + 2 for cc in mc_cert_counters),
            }
        )
    started_mc = sorted(
        {
            cc
            for d in dirs
            for path in d.glob("log*")
            for shard, cc in keys(STARTED, read_lines(path))
            if shard == MC
        }
    )
    lowest_fence = min((i["fence_mc"] for i in incoming if i["fence_mc"] is not None), default=None)
    summary["verdict"] = {
        "masterchain_certificate_counters": mc_cert_counters,
        "masterchain_started_counters": started_mc,
        "incoming": incoming,
        "every_fence_recorded": all(i["fence_mc"] is not None for i in incoming),
        "passed": bool(incoming)
        and all(
            i["fence_mc"] is not None
            and i["mc_certificate_above_fence"]
            and i["own_signatures_above_fence"]
            and not i["own_signatures_at_or_below_fence"]
            for i in incoming
        ),
        "stalled_at_or_below_fence": lowest_fence is not None
        and not any(cc > lowest_fence + 2 for cc in mc_cert_counters),
    }


def judge_handover(mode: str, summary: dict[str, Any]) -> int:
    verdict = summary["verdict"]
    if mode == "log":
        met = verdict["passed"] is True
        expected = (
            "every incoming identity: masterchain certificates above cc(M) + 2, own signatures above "
            "its fence and none at or below"
        )
        failure = EXIT_LOG_FAILED
    else:
        met = verdict["every_fence_recorded"] and verdict["stalled_at_or_below_fence"] is True
        expected = (
            "the masterchain made no certificate above the incoming set's fence: the handover stall"
        )
        failure = EXIT_CONTROL_UNDETECTED
    status = EXIT_EXPECTED if met else failure
    summary["expectation"] = {"mode": mode, "expected": expected, "met": met, "exit_status": status}
    return status


ANALYZE = {
    "restore-copy": analyze_restore_copy,
    "genesis": analyze_genesis,
    "handover": analyze_handover,
}
JUDGE = {"restore-copy": judge_restore_copy, "genesis": judge_genesis, "handover": judge_handover}


# ===== Live runs =====


def tostester_network(args: argparse.Namespace, working_dir: Path):
    from tostester.install import Install
    from tostester.network import Network

    install = Install(args.build.resolve(), args.source.resolve())
    install.toslibjson.client_set_verbosity_level(1)
    network = Network(install, working_dir, base_port=args.base_port)
    config = network.config
    config.auth_network_tag = hashlib.sha256(
        f"TOS-AUTH-NETWORK-TAG-v1;network=signing-fence-drill;global_id=3;epoch={int(time.time())}".encode()
    ).digest()
    config.shard_validators = 4
    config.mc_valgroup_lifetime = args.mc_lifetime
    config.shard_valgroup_lifetime = args.shard_lifetime
    return network


def make_validators(network: Any) -> tuple[Any, list[Any]]:
    dht = network.create_dht_node()
    nodes = []
    for index in range(4):
        node = network.create_full_node()
        node.make_initial_pq_validator(
            hashlib.sha256(f"fence-drill-validator-id-{index}".encode()).digest(),
            hashlib.sha256(f"fence-drill-validator-seed-{index}".encode()).digest(),
        )
        node.announce_to(dht)
        nodes.append(node)
    return dht, nodes


def target_signed_in_masterchain(target_dir: Path, dirs: list[Path]) -> bool:
    lines = read_lines(target_dir / "log")
    mc_cc = current_mc_cc(lines)
    if mc_cc is None:
        return False
    idx = None
    for line in lines:
        if (m := re.search(r"of (\(\S+\)) catchain (\d+): local validator index (\d+)", line)) and (
            m[1] == MC and int(m[2]) == mc_cc
        ):
            idx = int(m[3])
    if idx is None:
        return False
    return any(
        c["shard"] == MC and c["cc"] == mc_cc and c["votes"][idx : idx + 1] == "V"
        for c in certificates(dirs)
    )


async def run_restore_copy(
    args: argparse.Namespace, working_dir: Path, summary: dict[str, Any]
) -> None:
    log = logging.getLogger("drill")
    async with tostester_network(args, working_dir) as network:
        dht, nodes = make_validators(network)
        target = nodes[TARGET]
        dirs = [n.directory for n in nodes]
        async with asyncio.TaskGroup() as group:
            group.create_task(dht.run())
            for node in nodes:
                group.create_task(node.run())
        await wait_for(
            lambda: target_signed_in_masterchain(target.directory, dirs), 900, "the target to sign"
        )
        # The snapshot: the whole database copied while the target is stopped.
        await target.stop()
        snapshot = working_dir / "node4.snapshot"
        shutil.copytree(target.directory, snapshot, symlinks=True)
        summary["snapshot_at"] = time.time()
        await target.run()
        await asyncio.sleep(args.signing_after_snapshot)
        await wait_for(
            lambda: target_signed_in_masterchain(target.directory, dirs),
            600,
            "the target to sign again",
        )
        before = read_lines(target.directory / "log")
        summary["mc_cc_at_stop"] = current_mc_cc(before)
        stopped_at = time.time()
        await target.stop()
        moved = working_dir / f"node4.moved-{int(stopped_at)}"
        target.directory.rename(moved)
        shutil.copytree(snapshot, target.directory, symlinks=True)
        (target.directory / "log").rename(target.directory / "log.snapshot")
        shutil.copy2(moved / "log", target.directory / "log.before-restart")
        await target.run()
        restarted_at = time.time()
        summary.update(stopped_at=stopped_at, restarted_at=restarted_at, moved_to=moved.name)
        log.info(
            f"target restored from the copy and restarted {restarted_at - stopped_at:.1f}s after the stop"
        )
        if restarted_at - stopped_at > 90:
            raise SystemExit("DRILL_FAILED the target did not restart within 90 s")
        await asyncio.sleep(args.observe)


async def mc_seqno(node: Any) -> int:
    from toslib import ToslibError

    try:
        client = await node.toslib_client()
        info = await asyncio.wait_for(client.get_masterchain_info(), 10)
        return int(info.last.seqno) if info.last is not None else 0
    except (ToslibError, TimeoutError, OSError):
        return 0


async def sample(node: Any, seconds: float, stop_at: int, out: list[list[float]]) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        seqno = await mc_seqno(node)
        out.append([time.time(), seqno])
        if seqno >= stop_at:
            return
        await asyncio.sleep(5)


async def run_genesis(args: argparse.Namespace, working_dir: Path, summary: dict[str, Any]) -> None:
    samples: dict[str, list[list[float]]] = {"first": [], "after-ceremony": []}
    summary["seqno_samples"] = samples
    async with tostester_network(args, working_dir) as network:
        dht, nodes = make_validators(network)
        if args.mode == "control":
            for node in nodes:
                node.without_genesis_ceremony()
        async with asyncio.TaskGroup() as group:
            group.create_task(dht.run())
            for node in nodes:
                group.create_task(node.run())
        await sample(
            nodes[0],
            args.observe,
            args.min_seqno if args.mode == "log" else 1 << 31,
            samples["first"],
        )
        if args.mode == "log":
            return
        # Recovery: stop, set the never-trusted state aside (nothing is deleted), run the
        # ceremony, start.
        for node in nodes:
            await node.stop()
        moved = int(time.time())
        for node in nodes:
            (node.directory / "consensus").rename(node.directory / f"consensus.removed-{moved}")
            (node.directory / "log").rename(node.directory / "log.without-ceremony")
            node.run_genesis_ceremony()
        async with asyncio.TaskGroup() as group:
            for node in nodes:
                group.create_task(node.run())
        await sample(nodes[0], args.observe, args.min_seqno, samples["after-ceremony"])


def collect_handover(source: Path, working_dir: Path, count: int) -> None:
    for index in range(1, count + 1):
        node = source / f"node{index}"
        if not node.is_dir():
            raise SystemExit(f"DRILL_FAILED no node directory {node}")
        dest = working_dir / f"node{index}"
        dest.mkdir()
        for path in sorted(node.glob("log*")):
            if path.is_file():
                shutil.copy2(path, dest / path.name)


async def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--drill", choices=sorted(ANALYZE), required=True)
    parser.add_argument("--mode", choices=["log", "control"], required=True)
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument("--working-dir", type=Path, required=True)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--base-port", type=int, default=34200)
    parser.add_argument(
        "--mc-lifetime", type=int, default=120, help="masterchain catchain lifetime, seconds"
    )
    parser.add_argument(
        "--shard-lifetime", type=int, default=60, help="shard catchain lifetime, seconds"
    )
    parser.add_argument("--observe", type=int, default=900, help="seconds to observe")
    parser.add_argument("--signing-after-snapshot", type=int, default=60)
    parser.add_argument("--min-seqno", type=int, default=10)
    parser.add_argument(
        "--collect-from", type=Path, help="handover: the run's directory holding node1..nodeN"
    )
    parser.add_argument("--nodes", type=int, default=6, help="handover: how many node directories")
    parser.add_argument(
        "--incoming", default="5,6", help="handover: the incoming nodes, comma-separated"
    )
    args = parser.parse_args()
    working_dir = args.working_dir.resolve()

    if args.analyze_only:
        try:
            summary = json.loads((working_dir / "drill-summary.json").read_text())
        except (OSError, ValueError) as error:
            print(f"DRILL_FAILED cannot read the run's summary: {error}", file=sys.stderr)
            return EXIT_FAILED
        if summary.get("drill") != args.drill or summary.get("mode") != args.mode:
            print("DRILL_FAILED --drill or --mode differs from the run's", file=sys.stderr)
            return EXIT_FAILED
        ANALYZE[args.drill](working_dir, summary)
        status = JUDGE[args.drill](args.mode, summary)
        write_summary(working_dir, summary)
        return status

    working_dir.mkdir(parents=True, exist_ok=False)
    logging.basicConfig(
        level=logging.INFO, format="[%(levelname)s][%(asctime)s][%(name)s] %(message)s"
    )
    summary: dict[str, Any] = {
        "drill": args.drill,
        "mode": args.mode,
        "mc_lifetime": args.mc_lifetime,
        "shard_lifetime": args.shard_lifetime,
        "observe": args.observe,
        "min_seqno": args.min_seqno,
        "working_dir": str(working_dir),
    }
    try:
        if args.drill == "handover":
            if args.collect_from is None:
                raise SystemExit("DRILL_FAILED handover needs --collect-from")
            summary["nodes"] = args.nodes
            summary["incoming"] = [int(x) for x in args.incoming.split(",")]
            summary["collected_from"] = str(args.collect_from.resolve())
            collect_handover(args.collect_from.resolve(), working_dir, args.nodes)
        else:
            if args.build is None:
                raise SystemExit("DRILL_FAILED --build is required for a live drill")
            summary["build"] = str(args.build.resolve())
            await (run_restore_copy if args.drill == "restore-copy" else run_genesis)(
                args, working_dir, summary
            )
    except SystemExit as stop:
        summary["failure"] = str(stop.code)
        write_summary(working_dir, summary)
        print(stop.code, file=sys.stderr)
        return EXIT_FAILED
    ANALYZE[args.drill](working_dir, summary)
    status = JUDGE[args.drill](args.mode, summary)
    write_summary(working_dir, summary)
    print(json.dumps(summary["expectation"]))
    return status


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
