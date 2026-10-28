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
import subprocess
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


JOURNAL_EVIDENCE = "journal-evidence.json"
SESSION_DIR_NAME = re.compile(r"^consensus\.(-?\d+)\.(\d+)\.(\d+)\.[0-9A-Fa-f]{64}$")
CERT_LINE = re.compile(
    r"\[!valgroup(?P<shard>\(\S+\))\.(?P<cc>\d+)\.SimplexPool\]\s*Obtained certificate for (?P<vote>.*?): (?P<votes>[.V]+)"
)
TARGET_INDEX = re.compile(
    r"of (?P<shard>\(\S+\)) catchain (?P<cc>\d+): local validator index (?P<idx>\d+)"
)


def session_of_dir(name: str) -> tuple[str, int] | None:
    """(shard as the logs print it, catchain counter) of a consensus.<wc>.<shard>.<cc>.<id> directory."""
    m = SESSION_DIR_NAME.match(name)
    if m is None:
        return None
    return f"({m[1]},{int(m[2]):016x})", int(m[3])


def extract_journals(working_dir: Path, tool: Path, nodes: int = 4) -> dict[str, Any]:
    """Dumps the vote records of every session journal of the target's snapshot and of every
    node's database as it is now, from copies (opening RocksDB writes into its directory, so
    the evidence itself is never opened). Writes journal-evidence.json."""
    copies = working_dir / "journal-copies"
    copies.mkdir()
    sources = {"snapshot": working_dir / f"node{TARGET + 1}.snapshot"}
    sources.update({str(i): working_dir / f"node{i}" for i in range(1, nodes + 1)})
    evidence: dict[str, Any] = {"tool": str(tool), "journals": {}}
    for label, root in sources.items():
        records: list[dict[str, Any]] = []
        for session_dir in sorted((root / "consensus").glob("consensus.*")):
            session = session_of_dir(session_dir.name)
            if session is None or not (session_dir / "db").is_dir():
                continue
            copy = copies / label / session_dir.name
            shutil.copytree(session_dir / "db", copy, symlinks=True)
            done = subprocess.run(
                [str(tool), str(copy)], capture_output=True, text=True, timeout=600, check=False
            )
            if done.returncode != 0:
                raise SystemExit(
                    f"DRILL_FAILED cannot read the journal {session_dir}: {done.stderr[-500:]}"
                )
            for line in done.stdout.splitlines():
                record = json.loads(line)
                record["shard"], record["cc"] = session
                records.append(record)
        evidence["journals"][label] = records
    (working_dir / JOURNAL_EVIDENCE).write_text(json.dumps(evidence, sort_keys=True) + "\n")
    return evidence


def analyze_restore_copy(working_dir: Path, summary: dict[str, Any]) -> None:
    """The restart analysis of the unknown-history drill, with one rule changed after the first
    D1 run (see RESULTS.md): a certificate obtained after the restart that carries the target's
    signature is not counted as a new signature only when that signature is provably replayed
    history, i.e. the certificate as the node that logged it stored it holds a target signature
    byte-identical (same unsigned vote bytes, same signature bytes) to one in the target's
    snapshot journal of that session. Anything else counts: a certificate with no stored record,
    one whose target signature is not in the snapshot, and every own signature the target logs
    inside the fence."""
    analyze_restart(working_dir, summary)
    inherited = summary.pop("verdict")
    summary["inherited_verdict"] = inherited
    target_dir = working_dir / f"node{TARGET + 1}"
    after = read_lines(target_dir / "log")
    before = read_lines(target_dir / "log.before-restart")
    index = {
        (m["shard"], int(m["cc"])): int(m["idx"])
        for line in before + after
        if (m := TARGET_INDEX.search(line))
    }
    evidence_path = working_dir / JOURNAL_EVIDENCE
    journals = json.loads(evidence_path.read_text())["journals"] if evidence_path.is_file() else {}

    def target_signatures(
        records: list[dict[str, Any]], shard: str, cc: int, vote: str | None
    ) -> set[tuple[str, str]]:
        """(vote bytes hash, signature bytes hash) of the target's signatures in these records."""
        idx = index.get((shard, cc))
        out = set()
        for r in records:
            if r["shard"] != shard or r["cc"] != cc or (vote is not None and r["vote"] != vote):
                continue
            for sig in r["signatures"]:
                if (r["kind"] == "own_signed" and sig["who"] == -1) or (
                    r["kind"] == "cert" and sig["who"] == idx
                ):
                    out.add((r["vote_sha256"], sig["sha256"]))
        return out

    snapshot = journals.get("snapshot", [])
    sessions = {(x["shard"], x["cc"]): x for x in summary["sessions_after_restart"]}
    candidates = []
    for node in range(1, 5):
        for path in sorted((working_dir / f"node{node}").glob("log*")):
            if path.name in ("log.before-restart", "log.snapshot"):
                continue
            for line in read_lines(path):
                m = CERT_LINE.search(line)
                if not m:
                    continue
                shard, cc = m["shard"], int(m["cc"])
                session = sessions.get((shard, cc))
                idx = index.get((shard, cc))
                at = stamp(line)
                if (
                    session is None
                    or idx is None
                    or at is None
                    or at < session["group_built_after_restart_at"]
                ):
                    continue
                if m["votes"][idx : idx + 1] != "V":
                    continue
                stored = target_signatures(journals.get(str(node), []), shard, cc, m["vote"])
                replayed = target_signatures(snapshot, shard, cc, m["vote"])
                excluded = bool(stored) and stored <= replayed
                candidates.append(
                    {
                        "node": node,
                        "shard": shard,
                        "cc": cc,
                        "vote": m["vote"],
                        "at": at,
                        "stored_target_signatures": len(stored),
                        "replayed_from_snapshot": excluded,
                    }
                )
    new_signatures: dict[tuple[str, int], int] = {}
    for c in candidates:
        if not c["replayed_from_snapshot"]:
            new_signatures[(c["shard"], c["cc"])] = new_signatures.get((c["shard"], c["cc"]), 0) + 1
    violations = [
        {
            "shard": x["shard"],
            "cc": x["cc"],
            "new_certificate_signatures": new_signatures.get((x["shard"], x["cc"]), 0),
            "own": x["own_signatures_after_restart"],
        }
        for x in summary["sessions_after_restart"]
        if x["within_fence"]
        and (new_signatures.get((x["shard"], x["cc"]), 0) > 0 or x["own_signatures_after_restart"])
    ]
    fences = summary.get("fence") or []
    at_m = fences[0]["counters"].get(MC) if fences else None
    mc_cc = int(summary.get("mc_cc_at_stop") or 0)
    kinds: list[str] = list(inherited.get("own_signature_kinds_above_fence", []))
    new_in_old_session = new_signatures.get((MC, mc_cc), 0)
    first_resumed = min(
        (cc for (shard, cc), n in new_signatures.items() if shard == MC and n > 0), default=None
    )
    verdict: dict[str, Any] = {
        "rule": "replayed only if byte-identical to the target's snapshot journal",
        "journal_evidence": bool(journals),
        "candidates": candidates,
        "replayed_excluded": sum(1 for c in candidates if c["replayed_from_snapshot"]),
        "fence_recorded": inherited.get("fence_recorded", False),
        "signed_in_the_old_masterchain_session_before_stop": inherited.get(
            "signed_in_the_old_masterchain_session_before_stop", False
        ),
        "ledger_untrusted_as_a_copy": any(UNTRUSTED_COPY in line for line in after),
        "signatures_within_fence": violations,
        "no_new_signature_within_fence": not violations,
        "every_session_within_fence_fenced": inherited.get(
            "every_session_within_fence_fenced", False
        ),
        "masterchain_first_new_signature_cc": first_resumed,
        "masterchain_first_own_signature_cc": inherited.get("masterchain_first_own_signature_cc"),
        "masterchain_expected_first_cc": None if at_m is None else at_m + 3,
        "own_signature_kinds_above_fence": kinds,
        "new_signatures_in_the_old_masterchain_session_after_restart": new_in_old_session,
    }
    verdict["passed"] = (
        verdict["fence_recorded"]
        and verdict["signed_in_the_old_masterchain_session_before_stop"]
        and verdict["no_new_signature_within_fence"]
        and verdict["every_session_within_fence_fenced"]
        and at_m is not None
        and first_resumed == at_m + 3
        and verdict["masterchain_first_own_signature_cc"] == at_m + 3
        and "candidate" in kinds
        and any(k.endswith("vote") for k in kinds)
    )
    verdict["red"] = new_in_old_session > 0
    summary["verdict"] = verdict


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


CONFIG34_BEFORE = "config34-before.txt"
CONFIG34_AFTER = "config34-after.txt"
INDEX_LINE = re.compile(
    r"of (?P<shard>\(\S+\)) catchain (?P<cc>\d+): local validator index (?P<idx>\d+)"
)


def parse_config34(text: str) -> dict[str, Any] | None:
    """utime_since and {validator id: weight} from lite-client `getconfig 34` output."""
    since = re.search(r"utime_since:(\d+)", text)
    records = re.split(r"\bvalidator_pq\b", text)[1:]
    weights: dict[str, int] = {}
    for record in records:
        vid = re.search(r"validator_id:x([0-9A-Fa-f]{64})", record)
        weight = re.search(r"\bweight:(\d+)", record)
        if vid is None or weight is None:
            return None
        weights[vid.group(1).upper()] = int(weight.group(1))
    if since is None or not weights:
        return None
    return {"utime_since": int(since.group(1)), "weights": weights}


def analyze_handover(working_dir: Path, summary: dict[str, Any]) -> None:
    """Counter-based and bound to identities. A pass needs, for the run's named incoming
    and outgoing validator ids:
      - each incoming identity's own fence-block record (M_id) and its fence counters;
      - the roster transition in ConfigParam 34: before, every outgoing id and no incoming one;
        after, every incoming id and no outgoing one, with the incoming ids holding at least
        half the weight; its utime_since is the handover time;
      - after the handover, a masterchain certificate in a session above each incoming
        identity's cc(M) + 2 carrying that identity's own signature;
      - own signatures by each incoming identity above its fence and none at or below.
    """
    count = int(summary.get("nodes", 6))
    dirs = node_dirs(working_dir, count)
    incoming_ids: dict[str, str] = {
        str(k): v.upper() for k, v in (summary.get("incoming_validators") or {}).items()
    }
    outgoing_ids: dict[str, str] = {
        str(k): v.upper() for k, v in (summary.get("outgoing_validators") or {}).items()
    }

    def read(name: str) -> dict[str, Any] | None:
        path = working_dir / name
        return parse_config34(path.read_text()) if path.is_file() else None

    before, after = read(CONFIG34_BEFORE), read(CONFIG34_AFTER)
    roster: dict[str, Any] = {"before": before, "after": after, "transition": False}
    handover_at = None
    if before and after and incoming_ids and outgoing_ids:
        total_after = sum(after["weights"].values())
        incoming_weight = sum(after["weights"].get(v, 0) for v in incoming_ids.values())
        roster.update(
            incoming_weight_share=incoming_weight / total_after if total_after else 0.0,
            outgoing_in_before=all(v in before["weights"] for v in outgoing_ids.values()),
            incoming_absent_before=all(v not in before["weights"] for v in incoming_ids.values()),
            incoming_in_after=all(v in after["weights"] for v in incoming_ids.values()),
            outgoing_absent_after=all(v not in after["weights"] for v in outgoing_ids.values()),
        )
        roster["transition"] = (
            after["utime_since"] > before["utime_since"]
            and roster["outgoing_in_before"]
            and roster["incoming_absent_before"]
            and roster["incoming_in_after"]
            and roster["outgoing_absent_after"]
            and roster["incoming_weight_share"] >= 0.5
        )
        if roster["transition"]:
            handover_at = float(after["utime_since"])
    certs = certificates(dirs)
    incoming = []
    for node, vid in sorted(incoming_ids.items()):
        lines = [x for path in sorted(dirs[int(node) - 1].glob("log*")) for x in read_lines(path)]
        m_id = [
            m["block"]
            for line in lines
            if (m := FENCE_BLOCK_OF.search(line)) and m["validator"].upper() == vid
        ]
        fences = [
            {s: int(c) for s, c in COUNTER.findall(m["counters"])}
            for line in lines
            if (m := FENCE.search(line))
        ]
        counters = fences[0] if fences else {}
        fence_mc = counters.get(MC)
        index = {
            (m["shard"], int(m["cc"])): int(m["idx"])
            for line in lines
            if (m := INDEX_LINE.search(line))
        }
        own_within, own_above = [], []
        for line in lines:
            if not (m := OWN.search(line)):
                continue
            shard, cc = m["shard"], int(m["cc"])
            entry = counters.get(shard)
            if entry is None:
                related = [c for s, c in counters.items() if s.split(",")[0] == shard.split(",")[0]]
                entry = max(related) if related else None
            item = {"shard": shard, "cc": cc, "kind": m["kind"], "at": stamp(line)}
            (own_within if entry is None or cc <= entry + 2 else own_above).append(item)
        signed_after_handover = sorted(
            {
                c["cc"]
                for c in certs
                if c["shard"] == MC
                and fence_mc is not None
                and c["cc"] > fence_mc + 2
                and handover_at is not None
                and c["at"] is not None
                and c["at"] >= handover_at
                and (idx := index.get((MC, c["cc"]))) is not None
                and c["votes"][idx : idx + 1] == "V"
            }
        )
        own_above_after = [
            o
            for o in own_above
            if handover_at is not None and o["at"] is not None and o["at"] >= handover_at
        ]
        incoming.append(
            {
                "node": int(node),
                "validator": vid,
                "fence_block_record": m_id,
                "fence_counters": counters or None,
                "fence_mc": fence_mc,
                "masterchain_sessions_signed_above_fence_after_handover": signed_after_handover,
                "own_signatures_at_or_below_fence": own_within,
                "own_signatures_above_fence_after_handover": own_above_after,
            }
        )
    identities_ok = (
        bool(incoming)
        and len(incoming) == len(incoming_ids)
        and all(i["fence_block_record"] and i["fence_mc"] is not None for i in incoming)
    )
    lowest_fence = min((i["fence_mc"] for i in incoming if i["fence_mc"] is not None), default=None)
    mc_after_handover = sorted(
        {
            c["cc"]
            for c in certs
            if c["shard"] == MC
            and handover_at is not None
            and c["at"] is not None
            and c["at"] >= handover_at
        }
    )
    summary["verdict"] = {
        "roster": roster,
        "handover_at": handover_at,
        "incoming": incoming,
        "identities_and_fence_records": identities_ok,
        "masterchain_certificate_counters_after_handover": mc_after_handover,
        "passed": identities_ok
        and roster["transition"] is True
        and all(
            i["masterchain_sessions_signed_above_fence_after_handover"]
            and i["own_signatures_above_fence_after_handover"]
            and not i["own_signatures_at_or_below_fence"]
            for i in incoming
        ),
        "stalled_at_or_below_fence": identities_ok
        and roster["transition"] is True
        and lowest_fence is not None
        and not any(cc > lowest_fence + 2 for cc in mc_after_handover),
    }


def judge_handover(mode: str, summary: dict[str, Any]) -> int:
    verdict = summary["verdict"]
    if mode == "log":
        met = verdict["passed"] is True
        expected = (
            "named incoming identities with fence records, a >= 50% weight roster transition in "
            "ConfigParam 34, and after it masterchain certificates above each cc(M) + 2 signed by "
            "the incoming identities, own signatures above the fence and none at or below"
        )
        failure = EXIT_LOG_FAILED
    else:
        met = verdict["stalled_at_or_below_fence"] is True
        expected = (
            "named incoming identities with fence records and the roster transition, then no "
            "masterchain certificate above the incoming set's fence: the handover stall"
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
    # Every node is stopped now: the journals are read from copies.
    extract_journals(working_dir, args.dump_tool.resolve())


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


# The stake each staker sends, as the local election driver stakes; the fee covers the
# elector's processing, and the wallet keeps a reserve for its own fees.
STAKE = 11_000 * 10**9
STAKE_FEE = 1_200_000_000
WALLET_FUNDS = STAKE + STAKE_FEE + 10 * 10**9


async def lite_command(lite: list[str], config: Path, command: str) -> str:
    def run() -> str:
        argv = [*lite, "-C", str(config), "-v", "0", "-c", "time", "-c", command, "-c", "quit"]
        done = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
        return done.stdout + done.stderr

    return await asyncio.to_thread(run)


async def lite_runmethod_int(lite: list[str], config: Path, address: str, method: str) -> int:
    output = await lite_command(lite, config, f"runmethod {address} {method}")
    match = re.search(r"result:\s*\[\s*(-?(?:0x[0-9a-fA-F]+|\d+))", output)
    if match is None:
        raise RuntimeError(f"cannot parse {method}: {output[-500:]}")
    return int(match.group(1), 0)


async def send_and_wait(wallet: Any, message: Any, what: str, timeout: float = 180) -> None:
    """Sends one wallet message and waits until the wallet's seqno moves past it."""
    seqno = (await wallet.current).seqno
    await wallet.send(message, seqno)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        await asyncio.sleep(2)
        try:
            if (await wallet.current).seqno > seqno:
                return
        except Exception:  # an account between blocks
            continue
    raise SystemExit(f"DRILL_FAILED {what}: the wallet's message was not processed")


async def run_handover(
    args: argparse.Namespace, working_dir: Path, summary: dict[str, Any]
) -> None:
    """D5 live: four genesis validators V1..V4 and two fresh identities N5, N6 (no ledger, no
    ceremony) on a disposable chain with short elections. At the first election V1, V2, N5
    and N6 stake and V3, V4 do not, so the incoming set replaces half the weight."""
    import nacl.signing
    from contract import WalletV1Blueprint
    from pytosiq_core import Cell, CurrencyCollection, InternalMsgInfo, MessageAny, WalletMessage
    from tosapi import tos_api
    from tostester.network import StartOptions
    from tostester.pq_election_fixture import (
        ELECTOR,
        build_production_pool_stake_order,
        elector_body_from_pool_order,
    )
    from tostester.pq_initial_validator import deterministic_pq_initial_validator_seed

    log = logging.getLogger("drill")
    builder = args.stake_order_builder.resolve()
    if not builder.is_file():
        raise SystemExit(f"DRILL_FAILED no stake order builder at {builder}")
    stakers = [1, 2, 5, 6]
    summary.update(nodes=6, incoming=[5, 6], stakers=stakers, elected_for=args.elected_for)
    async with tostester_network(args, working_dir) as network:
        config = network.config
        config.validator_economics_profile = True
        config.validator_election_stage_a_profile = True
        config.validator_election_stage_a_elected_for = args.elected_for
        config.validator_election_stage_a_start_before = args.elected_for // 2
        config.validator_election_experiment_faucet_balance_nanotos = 1_000_000_000 * 10**9
        config.bootstrap_validator_set_valid_for = args.elected_for
        dht = network.create_dht_node()
        wallets = {
            i: WalletV1Blueprint(
                workchain=-1,
                private_key=nacl.signing.SigningKey(
                    hashlib.sha256(f"handover-wallet-{i}".encode()).digest()
                ),
            )
            for i in range(1, 7)
        }
        nodes = []
        for i in range(1, 7):
            node = network.create_full_node()
            if i <= 4:
                node.make_initial_pq_validator(
                    wallets[i].address.hash_part, deterministic_pq_initial_validator_seed(i)
                )
            else:
                # A fresh identity: no ledger and no ceremony.
                node.make_noninitial_pq_validator(
                    wallets[i].address.hash_part, deterministic_pq_initial_validator_seed(i)
                )
            node.announce_to(dht)
            nodes.append(node)
        engine_args = tuple(args.engine_arg)
        async with asyncio.TaskGroup() as group:
            group.create_task(dht.run())
            for node in nodes:
                group.create_task(node.run(StartOptions(args=engine_args)))
        summary["started_at"] = time.time()
        lite_config = working_dir / "lite-client.json"
        lite_config.write_text(nodes[0].liteserver_config.to_json())
        lite = [str(args.build.resolve() / "lite-client/lite-client")]
        client = await nodes[0].toslib_client()
        await network.wait_mc_block(3)
        summary["incoming_validators"] = {
            str(i): wallets[i].address.hash_part.hex().upper() for i in (5, 6)
        }
        summary["outgoing_validators"] = {
            str(i): wallets[i].address.hash_part.hex().upper() for i in (3, 4)
        }
        config34_before = await lite_command(lite, lite_config, "getconfig 34")
        (working_dir / CONFIG34_BEFORE).write_text(config34_before)
        since_before = (parse_config34(config34_before) or {}).get("utime_since")
        if since_before is None:
            raise SystemExit("DRILL_FAILED cannot read ConfigParam 34 before the election")
        faucet = network.zerostate.main_wallet(client)
        for i in stakers:
            await send_and_wait(
                faucet,
                WalletMessage(
                    send_mode=3,
                    message=MessageAny(
                        info=InternalMsgInfo(
                            ihr_disabled=True,
                            bounce=False,
                            bounced=False,
                            src=faucet.address,
                            dest=wallets[i].address,
                            value=CurrencyCollection(WALLET_FUNDS),
                            ihr_fee=0,
                            fwd_fee=0,
                            created_lt=0,
                            created_at=0,
                        ),
                        init=wallets[i].state_init,
                        body=Cell.empty(),
                    ),
                ),
                f"funding the wallet of node {i}",
            )
        log.info("staker wallets deployed and funded")
        election = 0
        deadline = time.monotonic() + 3 * args.elected_for
        while time.monotonic() < deadline and not election:
            try:
                election = await lite_runmethod_int(
                    lite, lite_config, f"-1:{'33' * 32}", "active_election_id"
                )
            except RuntimeError:
                election = 0
            if not election:
                await asyncio.sleep(5)
        if not election:
            raise SystemExit("DRILL_FAILED no election opened")
        summary["election"] = election
        submitted = []
        for i in stakers:
            node = nodes[i - 1]
            request = tos_api.Engine_validator_createPqStakeAuthorizationRequest(
                election_date=election,
                max_factor=1 << 16,
                adnl_addr=node.adnl_identity,
                src_addr=wallets[i].address.hash_part,
            )
            response, _, _ = await node.engine_console.request_with_raw(request)
            auth = request.parse_result(response)
            order = await asyncio.to_thread(
                build_production_pool_stake_order,
                builder,
                query_id=(election << 8) | i,
                stake_amount=STAKE,
                stake_at=election,
                max_factor=1 << 16,
                adnl_addr=node.adnl_identity,
                algorithm_id=1,
                public_key=auth.public_key,
                signature=auth.signature,
            )
            wallet = wallets[i].materialize(client)
            await send_and_wait(
                wallet,
                WalletMessage(
                    send_mode=3,
                    message=MessageAny(
                        info=InternalMsgInfo(
                            ihr_disabled=True,
                            bounce=True,
                            bounced=False,
                            src=wallet.address,
                            dest=ELECTOR,
                            value=CurrencyCollection(STAKE + STAKE_FEE),
                            ihr_fee=0,
                            fwd_fee=0,
                            created_lt=0,
                            created_at=0,
                        ),
                        init=None,
                        body=elector_body_from_pool_order(order),
                    ),
                ),
                f"the stake of node {i}",
            )
            submitted.append(i)
        summary["stakes_submitted"] = submitted
        summary["stakes_submitted_at"] = time.time()
        log.info(f"stakes of nodes {submitted} sent in election {election}")
        # The roster transition, as ConfigParam 34 records it once the new set takes office.
        deadline = time.monotonic() + 3 * args.elected_for
        while True:
            text = await lite_command(lite, lite_config, "getconfig 34")
            parsed = parse_config34(text)
            if parsed and parsed["utime_since"] > since_before:
                (working_dir / CONFIG34_AFTER).write_text(text)
                break
            if time.monotonic() > deadline:
                raise SystemExit("DRILL_FAILED the elected set never took office")
            await asyncio.sleep(10)
        # Counters, not time, decide the verdict; the observation only bounds the run. A log
        # run stops early once the analysis passes.
        deadline = time.monotonic() + args.observe
        while time.monotonic() < deadline:
            await asyncio.sleep(30)
            probe = dict(summary)
            analyze_handover(working_dir, probe)
            if args.mode == "log" and probe["verdict"]["passed"]:
                break
        summary["observed_until"] = time.time()


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
    parser.add_argument(
        "--extract-journals",
        action="store_true",
        help="restore-copy: dump the session journals of an earlier run (from copies), then analyse",
    )
    parser.add_argument(
        "--dump-tool",
        type=Path,
        default=Path("/tos/build/fix-322/build/test/validator/consensus/dump-consensus-journal"),
    )
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
    parser.add_argument(
        "--elected-for", type=int, default=600, help="handover: validator set lifetime, seconds"
    )
    parser.add_argument(
        "--stake-order-builder",
        type=Path,
        default=Path("/tos/build/fix-322/cargo-target/release/examples/pq_pool_stake_order"),
        help="handover: the tosctl pq_pool_stake_order example binary",
    )
    parser.add_argument(
        "--engine-arg",
        action="append",
        default=[],
        help="handover: an extra validator-engine argument for every node (repeatable)",
    )
    args = parser.parse_args()
    working_dir = args.working_dir.resolve()

    if args.extract_journals:
        if args.drill != "restore-copy":
            print("DRILL_FAILED --extract-journals is for --drill restore-copy", file=sys.stderr)
            return EXIT_FAILED
        try:
            extract_journals(working_dir, args.dump_tool.resolve())
        except SystemExit as stop:
            print(stop.code, file=sys.stderr)
            return EXIT_FAILED
        args.analyze_only = True
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
        if args.drill == "handover" and args.collect_from is None:
            if args.build is None:
                raise SystemExit("DRILL_FAILED --build is required for a live drill")
            summary["build"] = str(args.build.resolve())
            await run_handover(args, working_dir, summary)
        elif args.drill == "handover":
            source = args.collect_from.resolve()
            identities = json.loads((source / "handover-identities.json").read_text())
            summary["incoming_validators"] = identities["incoming"]
            summary["outgoing_validators"] = identities["outgoing"]
            for name in (CONFIG34_BEFORE, CONFIG34_AFTER):
                if (source / name).is_file():
                    shutil.copy2(source / name, working_dir / name)
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
