#!/usr/bin/env python3
"""Full four-validator StageA fault coordinator inside one private service.

The run's committed binding selects one scenario: P, deterministic partial loss through
NFQUEUE, or D, 100% directed isolation through tc. Both share one lifecycle: readiness,
live identity, raw full IDs, the same-block Config34 proof, natural StageA settlement and
owned cleanup. No live action at import. Entry is the existing hash-verified ordinary driver.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import ipaddress
import json
import os
import re
import resource
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import types
import urllib.parse
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INPUT_PATH = REPO / "scripts/x02_four_node_inputs.json"
RUN_ID = "2026092600040001"
SETUP_SECONDS = 900
# After the settlement tail: StageA's final capture plus the coordinator's witnesses. P's
# reviewed 2400 s service is exactly SETUP + 420 + 600 + this; D keeps the same margin.
STAGE_FINAL_SECONDS = 480
# Reserved after the service budget for the finally block (StageA terminate 15+5 s, thread
# joins, owned nft/tc removal). The unit's RuntimeMaxSec must be at least service + this.
CLEANUP_SECONDS = 60
# collect() samples the 2/4 halt three times, 25 s apart, after the drain; its 3/4 and
# recovery loops check their window, then sleep one 10 s poll before the next sample.
DIRECTED_HALT_SAMPLING_SECONDS = 3 * 25
DIRECTED_POLL_SECONDS = 10
TC_PATH = "/usr/sbin/tc"
CHILD_BOOTSTRAP = """import ctypes,hashlib,os,sys,types
libc=ctypes.CDLL(None,use_errno=True)
assert os.getresuid()==(1000,1000,1000) and os.getresgid()==(1000,1000,1000) and not os.getgroups(), 'child IDs/groups differ'
assert libc.prctl(47,4,0,0,0)==0, 'child ambient clear failed'
class H(ctypes.Structure):
 _fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class D(ctypes.Structure):
 _fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
h=H(0x20080522,0);d=(D*2)()
assert libc.capset(ctypes.byref(h),ctypes.byref(d))==0, 'child caps clear failed'
s=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line)
assert all(int(s[k],16)==0 for k in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd')) and int(s['NoNewPrivs'])==1, 'child final privilege state differs'
p,ph,q,qh=sys.argv[1:5];b=open(p,'rb').read();c=open(q,'rb').read()
assert hashlib.sha256(b).hexdigest()==ph and hashlib.sha256(c).hexdigest()==qh, 'child/helper execution bytes differ'
m=types.ModuleType('x02_four_node_binding');m.__file__=q;m.__executed_sha256__=qh;sys.modules[m.__name__]=m
exec(compile(c,q,'exec'),m.__dict__)
sys.argv=[p]+sys.argv[5:]
exec(compile(b,p,'exec'),{'__name__':'__main__','__file__':p,'__x02_child_sha256__':ph})
"""


def require(value, reason):
    if not value:
        raise ValueError(reason)


def clear_stage_launcher_caps():
    """Give bwrap no network capabilities; the coordinator keeps its own."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)

    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    header, empty = Header(0x20080522, 0), (Data * 2)()
    if (
        libc.prctl(47, 4, 0, 0, 0) != 0
        or libc.capset(ctypes.byref(header), ctypes.byref(empty)) != 0
    ):
        raise OSError(ctypes.get_errno(), "cannot clear StageA launcher capabilities")


def service_seconds(windows):
    """Coordinator budget from invocation to StageA's natural exit and its witnesses."""
    return SETUP_SECONDS + windows["duration"] + windows["settlement_tail"] + STAGE_FINAL_SECONDS


def unit_bounds(windows):
    """Outer limits a one-use executor must give the service unit and its own wait."""
    runtime = service_seconds(windows) + CLEANUP_SECONDS
    return {
        "service_seconds": service_seconds(windows),
        "unit_runtime_max_seconds": runtime,
        "executor_wait_seconds": runtime + 20,
    }


def directed_fault_seconds(thresholds):
    """Upper bound of collect()'s waits: 3/4 window and one poll, drain, 2/4 samples,
    recovery window and one poll. RPC sampling time is checked after the fact."""
    return (
        thresholds["three_max_seconds"]
        + DIRECTED_POLL_SECONDS
        + thresholds["two_drain_seconds"]
        + DIRECTED_HALT_SAMPLING_SECONDS
        + thresholds["recovery_max_seconds"]
        + DIRECTED_POLL_SECONDS
    )


def recovery_target_met(anchor, current, deadline_ns, min_delta):
    return (
        current["full_id"][2] >= anchor["full_id"][2] + min_delta
        and current["completed_ns"] <= deadline_ns
    )


def fresh_observer_epoch(state, epoch):
    return (
        state["completed_epoch"] == epoch
        and state["requested_epoch"] == epoch
        and state["idle_started_ns"] >= state["requested_ns"]
        and state["last_packet_ns"] <= state["idle_started_ns"]
        and state["idle_completed_ns"] > state["idle_started_ns"]
    )


def distinct_db_inodes(nodes):
    """Four path labels must identify four real, different DB directories."""
    if len(nodes) != 4:
        return False
    identities = [(node.get("db_dev"), node.get("db_ino")) for node in nodes]
    return (
        all(
            type(dev) is int and dev > 0 and type(ino) is int and ino > 0 for dev, ino in identities
        )
        and len(set(identities)) == 4
    )


def declared_node_mapping(nodes, readiness):
    """Bind pre-election declared public identities to live PID/DB rows."""
    rows = readiness["validators"]
    require(len(rows) == len(nodes) == 4, "four declared/live identity rows absent")
    mapped = []
    fields = (
        "validator_index",
        "node_name",
        "controller_id_hex",
        "consensus_key_id_hex",
        "adnl_id_hex",
    )
    for index, (row, node) in enumerate(zip(rows, nodes), 1):
        require(
            type(row.get("validator_index")) is int
            and row["validator_index"] == index
            and row.get("node_name") == f"node-{index}"
            and node["name"] == f"node{index}"
            and node["validator_index"] == index
            and all(re.fullmatch("[0-9a-fA-F]{64}", row.get(key, "")) for key in fields[2:])
            and node["controller_id"].lower() == row["controller_id_hex"].lower()
            and node["consensus_key_id"].lower() == row["consensus_key_id_hex"].lower()
            and node["adnl_id"].lower() == row["adnl_id_hex"].lower(),
            "declared controller/key/ADNL row differs from live validator",
        )
        mapped.append({key: row[key] for key in fields})
    for field in fields[2:]:
        require(
            len({row[field].lower() for row in mapped}) == 4,
            "declared public identity aliases another validator: " + field,
        )
    return mapped


def config34_pairs(raw):
    """Decode PQ controller/key/ADNL fields from lite TEXT, not a BOC proof."""
    markers = list(re.finditer(r"\bvalidator_pq\b", raw))
    identities = list(re.finditer(r"\bvalidator_pq\s+validator_id:x([0-9A-Fa-f]{64})", raw))
    require(len(markers) == len(identities), "Config34 PQ validator ID record malformed")
    pairs = []
    for index, match in enumerate(identities):
        end = identities[index + 1].start() if index + 1 < len(identities) else len(raw)
        section = raw[match.end() : end]
        keys = re.findall(r"\bkey_id:x([0-9A-Fa-f]{64})", section)
        adnl = re.findall(r"\badnl_addr:x([0-9A-Fa-f]{64})", section)
        require(len(keys) == len(adnl) == 1, "Config34 PQ validator key/ADNL text record malformed")
        pairs.append((match.group(1).lower(), keys[0].lower(), adnl[0].lower()))
    require(
        len({controller for controller, _, _ in pairs}) == len(pairs)
        and len({key for _, key, _ in pairs}) == len(pairs)
        and len({adnl for _, _, adnl in pairs}) == len(pairs),
        "Config34 PQ identities alias",
    )
    return pairs


def verify_elected_identity(report, readiness_parent, declared, ledger, proof_check):
    """Accept an elected set only through its same-block Config34 proof.

    The decoded lite TEXT and report rows are still checked, as diagnostics that must
    agree; the acceptance check is proof_check, which re-verifies Stage A's retained
    proof bundle from block root to Config34 cell and compares it with the frozen rows.
    """
    allocation_path = Path(report["experiment"]["allocation_evidence"])
    require(
        allocation_path == readiness_parent / "reward-election-allocation-evidence-v4.json",
        "StageA allocation path differs from readiness run",
    )
    allocation_raw = allocation_path.read_bytes()
    require(len(allocation_raw) <= 16 * 1024 * 1024, "allocation original exceeds bound")
    allocation = json.loads(allocation_raw)
    require(
        allocation["schema"] == "tos.validator-reward-election-allocation-evidence.v4"
        and allocation["status"] == "complete"
        and allocation["mode"] == "experiment"
        and allocation["provenance"]["source_commit"] == report["source_commit"],
        "final allocation source/status differs",
    )
    expected = {
        row["controller_id_hex"].lower(): (
            row["consensus_key_id_hex"].lower(),
            row["adnl_id_hex"].lower(),
        )
        for row in declared
    }
    activated = 0
    for election in allocation["elections"]:
        if "config34_artifact" not in election:
            continue
        activated += 1
        election_id = election["election_id"]
        require(
            type(election_id) is int
            and election_id > 0
            and set(election["validators"]) == {"1", "2", "3", "4"}
            and type(election["config34_cell_hash"]) is int
            and election["config34_cell_hash"] > 0,
            "activated election attribution/cell hash incomplete",
        )
        artifact = election["config34_artifact"]
        path = Path(artifact["path"])
        require(
            path == readiness_parent / "artifacts" / f"election-{election_id}-config34.txt"
            and path.is_file()
            and not path.is_symlink()
            and type(artifact["size"]) is int
            and 0 < artifact["size"] <= 1024 * 1024,
            "raw Config34 artifact path/type/size differs",
        )
        raw_bytes = path.read_bytes()
        digest = hashlib.sha256(raw_bytes).hexdigest()
        require(
            len(raw_bytes) == artifact["size"]
            and digest == artifact["sha256"]
            and digest == election["config34"]["raw_sha256"]
            and election["config34"]["utime_since"] == election_id
            and election["config34"]["total"] == election["config34"]["main"] == 4,
            "raw Config34/cell election provenance differs",
        )
        pairs = config34_pairs(raw_bytes.decode("utf-8"))
        require(
            len(pairs) == 4
            and {controller: (key, adnl) for controller, key, adnl in pairs} == expected,
            "elected Config34 decoded text controller/key/ADNL mapping differs",
        )
        for index, row in enumerate(declared, 1):
            candidate = election["validators"][str(index)]
            require(
                candidate["validator_index"] == index
                and candidate["controller_id_hex"].lower() == row["controller_id_hex"].lower()
                and candidate["consensus_key_id_hex"].lower() == row["consensus_key_id_hex"].lower()
                and candidate["adnl_id_hex"].lower() == row["adnl_id_hex"].lower()
                and candidate["selection_status"] == "selected",
                "elected candidate differs from frozen pre-fault public row",
            )
        ledger.append(
            {
                "event": "elected_config34_decoded_text_identity_verified",
                "role": "diagnostic; acceptance is the same-block proof below",
                "election_id": election_id,
                "raw_hex": raw_bytes.hex(),
                "raw_sha256": digest,
                "reported_cell_hash_unverified": election["config34_cell_hash"],
                "controller_key_adnl_text_rows": pairs,
                "boc_cell_pq_key_proof": False,
            }
        )
        require(
            isinstance(election.get("config34_proof"), dict),
            "activated election has no same-block Config34 proof",
        )
        verdict = proof_check(election, readiness_parent, declared)
        require(
            verdict.get("verdict") == "X02_CONFIG34_SAME_BLOCK_PROOF_OK"
            and verdict.get("election_id") == election_id
            and int(verdict["config34_cell_hash"], 16) == election["config34_cell_hash"],
            "same-block Config34 proof does not accept this election",
        )
        ledger.append(
            {
                "event": "elected_config34_same_block_proof_verified",
                "election_id": election_id,
                "verdict": verdict,
            }
        )
    require(activated > 0, "no activated elected Config34 allocation")
    ledger.append(
        {
            "event": "allocation_original",
            "raw_hex": allocation_raw.hex(),
            "sha256": hashlib.sha256(allocation_raw).hexdigest(),
            "activated_elections": activated,
        }
    )


VERIFIER_TIMEOUT_SECONDS = 120
VERIFIER_STREAM_MAX_BYTES = 1 << 20


ANCHORED_VERIFIER = "lite-client/proof-verify/tos-proof-verify"


def zerostate_anchor(manifest):
    """The network's masterchain zerostate identity, from the frozen readiness manifest."""
    zero = manifest["network"]["zero_state"]["masterchain"]
    require(
        zero.get("workchain") == -1
        and all(
            isinstance(zero.get(key), str) and re.fullmatch("[0-9a-fA-F]{64}", zero[key])
            for key in ("root_hash_hex", "file_hash_hex")
        ),
        "readiness manifest has no full masterchain zerostate identity",
    )
    return {
        "kind": "zerostate",
        "workchain": -1,
        "shard": "8000000000000000",
        "seqno": 0,
        "root_hash": zero["root_hash_hex"].lower(),
        "file_hash": zero["file_hash_hex"].lower(),
    }


def verifier_sandbox_argv(binding, output, command, binds=()):
    """The pinned U24 rootfs and loader, read-only and without network, for one verifier process.

    Same mounts as Stage A's own sandbox (U24 root, source, runtime and dependency roots),
    plus every namespace unshared; the run output is bound read-only for the request and
    retained artifacts. Only `command` differs between the real verifier and its controls.
    """
    argv = [
        binding["bwrap_path"],
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        binding["rootfs_root"],
        "/",
        "--tmpfs",
        "/datax",
        "--tmpfs",
        "/home",
        "--ro-bind",
        binding["source_root"],
        binding["source_root"],
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
    ]
    for root in [*binding["runtime_roots"], *binding["dependency_roots"]]:
        argv += ["--ro-bind", root, root]
    argv += ["--ro-bind", binding["interpreter"], binding["interpreter"]]
    for path in binds:
        argv += ["--ro-bind", str(path), str(path)]
    argv += [
        "--ro-bind",
        str(output),
        str(output),
        "--chdir",
        "/",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "PYTHONDONTWRITEBYTECODE",
        "1",
        "--",
        *command,
    ]
    return argv


def run_bounded(
    argv, output, name, timeout=VERIFIER_TIMEOUT_SECONDS, max_bytes=VERIFIER_STREAM_MAX_BYTES
):
    """Run once into fresh regular files bounded by RLIMIT_FSIZE; kill the group on timeout."""

    def exclusive(suffix):
        return os.open(
            output / f"{name}.{suffix}",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o644,
        )

    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_bytes, max_bytes))

    out_fd, err_fd = exclusive("stdout.raw"), exclusive("stderr.raw")
    started, timed_out = time.monotonic_ns(), False
    try:
        child = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=out_fd,
            stderr=err_fd,
            preexec_fn=limits,
            start_new_session=True,
        )
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGKILL)
            code = child.wait()
    finally:
        os.close(out_fd)
        os.close(err_fd)
    sizes = {
        stream: os.stat(output / f"{name}.{stream}.raw", follow_symlinks=False).st_size
        for stream in ("stdout", "stderr")
    }
    with open(output / f"{name}.stderr.raw", "rb") as stream:
        sandbox_failed = stream.read(len(b"bwrap: ")) == b"bwrap: "
    fd = os.open(
        output / f"{name}.exit.raw", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644
    )
    with os.fdopen(fd, "w") as stream:
        stream.write(f"{code}\n")
    return {
        "argv": argv,
        "pid": child.pid,
        "natural_exit": code,
        "timed_out": timed_out,
        "capture_limit_reached": any(size >= max_bytes for size in sizes.values())
        or code in (-signal.SIGXFSZ, 128 + signal.SIGXFSZ),
        "signalled": code < 0,
        "sandbox_setup_failed": sandbox_failed,
        "stream_bytes": sizes,
        "started_ns": started,
        "completed_ns": time.monotonic_ns(),
    }


def config34_proof_check(
    binding,
    context,
    output,
    anchor,
    launcher=verifier_sandbox_argv,
    deadline=None,
    clock=time.monotonic,
):
    """Re-verify Stage A's retained bundle in the pinned U24 rootfs, as a separate bounded process.

    The block is authenticated by the compiled anchored verifier from `anchor`, the network's
    masterchain zerostate identity frozen in the readiness manifest -- never from the bundle.
    The verifier executable is the one indexed by digest in the binding's frozen closure.

    With a service deadline, a verifier that could not finish its full bound before it, with
    the cleanup reserve still left, is refused before it starts instead of overrunning the unit.
    """
    script = REPO / "scripts/x02_config34_proof.py"

    def check(election, readiness_parent, declared):
        require(
            deadline is None or clock() + VERIFIER_TIMEOUT_SECONDS + CLEANUP_SECONDS <= deadline,
            "no service budget left for a bounded Config34 verifier",
        )
        raw = script.read_bytes()
        frozen = subprocess.check_output(
            ["git", "-C", str(REPO), "show", context["source_sha"] + ":scripts/" + script.name]
        )
        require(raw == frozen, "Config34 proof verifier differs from fixed source")
        verifier = Path(binding["build_root"]) / ANCHORED_VERIFIER
        receipt = binding["files"].get(str(verifier))
        require(
            isinstance(receipt, dict)
            and hashlib.sha256(verifier.read_bytes()).hexdigest() == receipt.get("sha256"),
            "anchored proof verifier is not the binary indexed in the frozen closure",
        )
        name = f"config34-proof-{election['election_id']}"
        request = output / f"{name}.request.json"
        write_once(
            request,
            {
                "base": str(readiness_parent / "artifacts"),
                "election_id": election["election_id"],
                "anchor": anchor,
                "bundle": election["config34_proof"],
                "frozen_rows": declared,
            },
        )
        command = [
            binding["interpreter"],
            "-I",
            "-B",
            str(script),
            "--source-root",
            str(REPO),
            "--request",
            str(request),
            "--verifier",
            str(verifier),
        ]
        for root in binding["dependency_roots"]:
            command += ["--dependency-root", root]
        record = run_bounded(launcher(binding, output, command, [verifier]), output, name)
        write_once(output / f"{name}.terminal.json", record)
        require(
            not (
                record["timed_out"]
                or record["capture_limit_reached"]
                or record["signalled"]
                or record["sandbox_setup_failed"]
            ),
            "Config34 proof verifier did not reach a natural bounded exit",
        )
        stdout = (output / f"{name}.stdout.raw").read_bytes()
        require(
            record["natural_exit"] == 0,
            "Config34 proof verifier refused: " + stdout.decode(errors="replace")[:400],
        )
        return json.loads(stdout)

    return check


def primary_deadline_epoch(manifest):
    """StageA's own primary-window deadline, as its readiness manifest states it."""
    raw = manifest["window"]["deadline_at"]
    require(
        isinstance(raw, str) and raw.endswith("+00:00"), "readiness primary deadline is not UTC"
    )
    return datetime.datetime.fromisoformat(raw).timestamp()


def directed_phase(
    output,
    binding,
    context,
    evidence,
    prepare,
    directed,
    readiness_raw,
    manifest,
    nodes,
    stage,
    ledger,
    frozen_out,
    now=time.time,
    which=shutil.which,
):
    """D: freeze the 100% directed policy from this readiness, then run it once.

    Nothing from any other run is consumed: the policy is built from this run's readiness
    bytes and live nodes, and collect() writes only into the exclusive <output>/directed.
    The whole fault must fit inside StageA's primary window, before and after.
    The frozen policy is appended to frozen_out as soon as it exists, so the caller can
    prove tc cleanup even when this phase fails later.
    """
    expected = binding["host_files"][TC_PATH]["sha256"]
    found = which("tc")
    actual = (
        hashlib.sha256(Path(TC_PATH).read_bytes()).hexdigest() if Path(TC_PATH).is_file() else None
    )
    ledger.append(
        {
            "event": "directed_tc_pin",
            "which": found,
            "realpath": os.path.realpath(found) if found else None,
            "sha256": actual,
            "expected_sha256": expected,
        }
    )
    require(
        found == TC_PATH and os.path.realpath(found) == TC_PATH and actual == expected,
        "tc on the worker PATH differs from the binding pin",
    )
    head, files = prepare.fixed_source()
    require(head == context["source_sha"], "directed policy source commit differs from the run")
    policy = prepare.build_policy(readiness_raw, head, files, nodes)
    encoded = (json.dumps(policy, sort_keys=True, indent=2) + "\n").encode()
    policy_path = output / "directed-policy.json"
    with policy_path.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    policy_sha = hashlib.sha256(encoded).hexdigest()
    frozen = evidence.read_policy(policy_path, policy_sha)
    frozen_out.append(frozen)
    deadline = primary_deadline_epoch(manifest)
    bound = directed_fault_seconds(frozen["thresholds"])
    started = now()
    ledger.append(
        {
            "event": "directed_policy_frozen",
            "path": str(policy_path),
            "sha256": policy_sha,
            "rules": len(frozen["rules"]),
            "fault_bound_seconds": bound,
            "started_epoch": started,
            "primary_deadline_epoch": deadline,
        }
    )
    require(
        started + bound <= deadline, "directed fault cannot finish inside the StageA primary window"
    )
    require(stage.poll() is None, "StageA exited before the directed fault")
    result = directed.collect(frozen, policy_sha, output / "directed", context["host_netns"])
    finished = now()
    ledger.append({"event": "directed_result", "result": result, "finished_epoch": finished})
    require(
        result.get("status") == "passed" and result.get("policy_sha256") == policy_sha,
        "directed 100% fault did not pass: " + str(result.get("error")),
    )
    verdict_raw = (output / "directed" / "verdict.json").read_bytes()
    require(
        json.loads(verdict_raw).get("passed") is True, "directed verdict is not an explicit pass"
    )
    require(finished <= deadline, "directed fault overran the StageA primary window")
    require(stage.poll() is None, "StageA exited during the directed fault")
    ledger.append(
        {
            "event": "directed_and_recovery_verified",
            "policy_sha256": policy_sha,
            "verdict_sha256": hashlib.sha256(verdict_raw).hexdigest(),
            "started_epoch": started,
            "finished_epoch": finished,
        }
    )


def directed_tc_cleanup(evidence, policy, ledger):
    """Owned tc cleanup witness for D: lo must end with no egress filter and no clsact.

    collect() already removes what it installed; this re-reads the raw tc state and, only if
    anything remains, runs the policy's own remove argv once, keeping every raw command.
    """
    iface = policy["clsact"]["interface"]

    def clean(snapshot):
        filters = evidence.command_json(
            snapshot[iface]["filters"], ["tc", "-j", "-s", "filter", "show", "dev", iface, "egress"]
        )
        return filters == [] and not evidence.has_clsact({"tc": snapshot}, iface)

    before = evidence.capture_tc(policy)
    if clean(before):
        ledger.append({"event": "directed_tc_clean", "tc": before})
        return
    commands = [evidence.run_raw(rule["remove_argv"]) for rule in reversed(policy["rules"])]
    commands.append(evidence.run_raw(policy["clsact"]["cleanup_argv"]))
    after = evidence.capture_tc(policy)
    ledger.append(
        {
            "event": "directed_tc_fallback_cleanup",
            "before": before,
            "commands": commands,
            "after": after,
        }
    )
    require(clean(after), "directed tc state remains after fallback cleanup")


def verify_live_pid_identity(live_identity, before, after, readiness_parent, declared):
    """Bind the four PIDs to their nodes' own authorizations for the active elected set."""
    allocation_path = readiness_parent / "reward-election-allocation-evidence-v4.json"
    allocation = json.loads(live_identity.read_bounded(allocation_path, 16 << 20))
    selected = [
        e
        for e in allocation["elections"]
        if e.get("selection_status") == "selected" and e.get("pq_authorizations")
    ]
    require(selected, "no selected election carries node authorizations")
    election = max(selected, key=lambda item: item["election_id"])
    records = []
    for index in range(1, 5):
        provenances = election["pq_authorizations"].get(str(index)) or []
        require(provenances, f"validator {index} has no retained node authorization")
        records.append(
            live_identity.authorization_record(
                readiness_parent / "artifacts", provenances[-1], election["election_id"], index
            )
        )
    return live_identity.verify_live_identity(before, after, records, declared)


def rpc_endpoint(node):
    """host:port of a frozen node's JSON-RPC URL, as Stage A addresses it."""
    parsed = urllib.parse.urlsplit(node["rpc_url"])
    require(
        parsed.scheme == "http" and parsed.path == "/jsonRPC" and parsed.port,
        "node RPC URL malformed",
    )
    return f"{parsed.hostname}:{parsed.port}"


def write_once(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


def fixed_module(name, context):
    path = REPO / "scripts" / (name + ".py")
    raw = path.read_bytes()
    frozen = subprocess.check_output(
        ["git", "-C", str(REPO), "show", context["source_sha"] + ":scripts/" + path.name]
    )
    require(raw == frozen and name not in sys.modules, "coordinator source changed/already loaded")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def socket_and_namespace(node, context):
    proc = Path("/proc") / str(node["pid"])
    require(
        os.readlink(proc / "ns/net") == context["netns"]
        and (proc / "cgroup").read_text() == context["cgroup"],
        "validator outside private namespace/cgroup",
    )
    status = dict(
        line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line
    )
    require(
        all(int(status[key], 16) == 0 for key in ("CapEff", "CapPrm", "CapInh", "CapAmb"))
        and int(status["CapBnd"], 16) == 0
        and int(status["NoNewPrivs"]) == 1
        and status["Uid"].split() == ["1000"] * 4
        and status["Gid"].split() == ["1000"] * 4
        and not status["Groups"].split(),
        "validator IDs/groups/capabilities/NNP differ",
    )
    inodes = set()
    for fd in (proc / "fd").iterdir():
        try:
            link = os.readlink(fd)
        except OSError:
            continue
        if link.startswith("socket:["):
            inodes.add(int(link[8:-1]))
    table = Path("/proc/net/tcp").read_text()
    port = int(node["rpc_url"].split(":")[2].split("/")[0])
    matches = []
    for line in table.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 10:
            addr, encoded_port = fields[1].split(":")
            if int(encoded_port, 16) == port and int(fields[9]) in inodes and fields[3] == "0A":
                require(
                    str(ipaddress.IPv4Address(bytes.fromhex(addr)[::-1])) == "127.0.0.1",
                    "RPC listener is not frozen loopback address",
                )
                matches.append(int(fields[9]))
    require(len(matches) == 1, "RPC socket is absent or ambiguous for validator PID")
    return {
        "tcp_table": table,
        "rpc_inode": matches[0],
        "socket_inodes": sorted(inodes),
        "status": (proc / "status").read_text(),
        "netns": os.readlink(proc / "ns/net"),
        "cgroup": (proc / "cgroup").read_text(),
    }


class ChainCapture:
    def __init__(self, evidence, nodes, zerostate, ledger, context):
        self.e, self.nodes, self.zero, self.ledger, self.context = (
            evidence,
            nodes,
            zerostate,
            ledger,
            context,
        )
        self.previous = {}
        self.native = {node["name"]: {} for node in nodes}
        self.global_ids = {}
        self.tips = {node["name"]: 0 for node in nodes}
        self.samples = []

    def sample(self, phase, anchor=None, deadline=None, event_start=None):
        e = self.e
        row = {
            "event": "chain_sample",
            "phase": phase,
            "started_ns": time.monotonic_ns(),
            "anchor": anchor,
            "nodes": {},
            "headers": {},
        }
        self.ledger.append(
            {"event": "chain_capture_started", "phase": phase, "started_ns": row["started_ns"]}
        )
        for node in self.nodes:
            name = node["name"]
            process = e.capture_process(node)
            e.process_identity(process, node)
            socket_receipt = socket_and_namespace(node, self.context)
            prior = self.previous.get(name)
            native = e.capture_native_log(node, prior)
            self.ledger.append(
                {
                    "event": "node_original",
                    "phase": phase,
                    "node": name,
                    "process": process,
                    "socket_namespace": socket_receipt,
                    "native": native,
                }
            )
            parsed = e.native_log_ids(native, node, prior)
            self.previous[name] = native
            for height, value in parsed.items():
                old = self.native[name].get(height)
                require(old is None or old[:2] == value[:2], "same-height native fullID conflict")
                self.native[name][height] = value if old is None else old
            tip = e.rpc(
                node["rpc_url"],
                "getMasterchainInfo",
                None,
                len(self.samples) * 100 + len(row["nodes"]),
            )
            # Raw request, status/body/timing survives even if parse fails.
            self.ledger.append({"event": "rpc_original", "phase": phase, "node": name, "raw": tip})
            block = e.parse_rpc(tip, node, "getMasterchainInfo", expected_init=self.zero)
            self.global_ids.setdefault(block[2], block)
            require(self.global_ids[block[2]] == block, "first-tip same-height RPC fullID conflict")
            require(block[2] >= self.tips[name], "validator masterchain tip regressed")
            self.tips[name] = block[2]
            row["nodes"][name] = {
                "process": process,
                "socket_namespace": socket_receipt,
                "native": native,
                "tip_rpc": tip,
                "tip_full_id": block,
            }
        common = min(value["tip_full_id"][2] for value in row["nodes"].values())
        require(
            anchor is None or common >= anchor["full_id"][2], "common height below frozen anchor"
        )
        first = common if anchor is None else anchor["full_id"][2]
        require(common - first <= 512, "chain range exceeded fixed capture bound")
        for height in range(first, common + 1):
            by_node = {}
            for node in self.nodes:
                name = node["name"]
                params = {"workchain": -1, "shard": str(-(1 << 63)), "seqno": height}
                raw = e.rpc(node["rpc_url"], "getBlockHeader", params, height)
                self.ledger.append(
                    {"event": "rpc_original", "phase": phase, "node": name, "raw": raw}
                )
                block = e.parse_rpc(raw, node, "getBlockHeader", expected_seq=height)
                require(block[2] == height, "returned header height differs from requested height")
                self.global_ids.setdefault(height, block)
                require(self.global_ids[height] == block, "same-height RPC fullID conflict")
                by_node[name] = {"raw": raw, "full_id": block}
            row["headers"][str(height)] = by_node
        # Post-RPC native reads prove full-ID joins and preserve complete byte cursors.
        row["post_native"] = {}
        for node in self.nodes:
            name, prior = node["name"], self.previous[node["name"]]
            native = e.capture_native_log(node, prior)
            self.ledger.append(
                {"event": "post_native_original", "phase": phase, "node": name, "native": native}
            )
            parsed = e.native_log_ids(native, node, prior)
            self.previous[name] = native
            row["post_native"][name] = native
            for height, value in parsed.items():
                old = self.native[name].get(height)
                require(old is None or old[:2] == value[:2], "post-RPC native conflict")
                self.native[name][height] = value if old is None else old
            for height in range(first, common + 1):
                block = row["headers"][str(height)][name]["full_id"]
                value = self.native[name].get(height)
                require(
                    value is not None and value[:2] == block[3:5],
                    "common fullID absent or differs in native finalized log",
                )
        row["full_id"] = row["headers"][str(common)][self.nodes[0]["name"]]["full_id"]
        row["completed_ns"] = time.monotonic_ns()
        row["rpc_completed_ns"] = max(
            item["raw"]["completed_ns"]
            for group in row["headers"].values()
            for item in group.values()
        )
        row["native_join_completed_ns"] = max(
            item["completed_ns"] for item in row["post_native"].values()
        )
        self.ledger.append(row)
        require(
            deadline is None
            or max(row["rpc_completed_ns"], row["native_join_completed_ns"]) <= deadline,
            "chain evidence completed after fixed phase deadline",
        )
        self.samples.append(row)
        return {
            "full_id": row["full_id"],
            "sample_sha256": hashlib.sha256(
                json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "completed_ns": row["completed_ns"],
        }

    def progress_after(self, anchor, current, event_start, min_delta):
        """Require min_delta consecutive joined full IDs actually finalized after install.

        Preserve all earlier joined heights too; an in-flight pre-install block
        cannot be one of the progress IDs, even if it exceeds baseline.
        """
        require(
            type(min_delta) is int and min_delta >= 1, "progress delta is not a positive integer"
        )
        height = current["full_id"][2]
        return height >= anchor["full_id"][2] + min_delta and all(
            self.native[node["name"]][seq][2] >= event_start
            for node in self.nodes
            for seq in range(height - min_delta + 1, height + 1)
        )


def freeze_senders(nodes, ledger, stopped):
    for node in nodes:
        pid = node["pid"]
        fields = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()
        require(
            int(fields[19]) == node["pid_start_ticks"], "sender PID generation changed before stop"
        )
        os.kill(pid, signal.SIGSTOP)
        stopped.add(pid)
    deadline = time.monotonic() + 5
    for node in nodes:
        while True:
            states = {
                task.name: (task / "stat").read_bytes().rsplit(b") ", 1)[1].split()[0].decode()
                for task in Path(f"/proc/{node['pid']}/task").iterdir()
            }
            if all(state in ("T", "t") for state in states.values()):
                ledger.append(
                    {
                        "event": "owned_sender_stopped",
                        "node": node["name"],
                        "pid": node["pid"],
                        "start_ticks": node["pid_start_ticks"],
                        "task_states": states,
                        "monotonic_ns": time.monotonic_ns(),
                    }
                )
                break
            require(time.monotonic() < deadline, "owned sender did not quiesce")
            time.sleep(0.02)


def simple_partial_phase(output, binding, context, nodes, zerostate, stage, ledger, chain_ledger):
    """Kernel counted ordinal 1-in-4 loss on the 24 selected UDP directions."""
    require(
        os.readlink("/proc/self/ns/net") == context["netns"] != context["host_netns"],
        "partial fault is outside its private network namespace",
    )
    table = "x02partial"
    nft = "/usr/sbin/nft"
    require(
        hashlib.sha256(Path(nft).read_bytes()).hexdigest() == binding["host_files"][nft]["sha256"],
        "partial fault nft executable differs",
    )
    by_name = {node["name"]: node for node in nodes}
    require(set(by_name) == {f"node{i}" for i in range(1, 5)}, "partial node set differs")
    from x02_partial_sequence import DIRECTIONS

    def command(argv, data=None):
        result = subprocess.run(argv, input=data, capture_output=True, timeout=10, check=False)
        require(
            len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 1024 * 1024,
            "partial nft output cap exceeded",
        )
        ledger.append(
            {
                "event": "partial_nft_command",
                "argv": argv,
                "stdin_sha256": hashlib.sha256(data).hexdigest() if data else None,
                "stdout_hex": result.stdout.hex(),
                "stderr_hex": result.stderr.hex(),
                "exit": result.returncode,
                "monotonic_ns": time.monotonic_ns(),
            }
        )
        return result

    baseline_chain = ChainCapture(
        __import__("x02_fault_evidence"), nodes, zerostate, chain_ledger, context
    )
    baseline = baseline_chain.sample("baseline")
    absent = command([nft, "-j", "list", "table", "ip", table])
    require(absent.returncode != 0, "partial fault table already exists")
    lines = [f"add table ip {table}"]
    for ordinal in range(len(DIRECTIONS)):
        for label in ("entry", "drop", "pass"):
            lines.append(f"add counter ip {table} {label}{ordinal}")
    lines.append(
        f"add chain ip {table} output {{ type filter hook output priority 0; policy accept; }}"
    )
    endpoints = {}
    for ordinal, direction in enumerate(DIRECTIONS):
        pair, transport = direction.split("/")
        source, destination = pair.split(">")
        field = "peer_port" if transport == "adnl" else "quic_port"
        a, b = by_name[source], by_name[destination]
        src_ip, dst_ip = (
            str(ipaddress.IPv4Address(a["peer_ip"])),
            str(ipaddress.IPv4Address(b["peer_ip"])),
        )
        src_port, dst_port = a[field], b[field]
        require(
            all(type(port) is int and 0 < port < 65536 for port in (src_port, dst_port)),
            "partial UDP port differs",
        )
        endpoints[direction] = [src_ip, src_port, dst_ip, dst_port]
        match = f"ip saddr {src_ip} ip daddr {dst_ip} udp sport {src_port} udp dport {dst_port}"
        lines.append(
            f"add rule ip {table} output {match} counter name entry{ordinal} "
            f"numgen inc mod 4 == 0 counter name drop{ordinal} drop"
        )
        lines.append(f"add rule ip {table} output {match} counter name pass{ordinal} accept")
    script = ("\n".join(lines) + "\n").encode()
    write_once(
        output / "partial-fault-policy.json",
        {
            "schema": "tos.x02.partial-nft-ordinal.v1",
            "source_commit": context["source_sha"],
            "binding_scenario": binding["scenario"],
            "seed": 0,
            "modulus": 4,
            "drop_ordinal": 0,
            "directions": endpoints,
            "nft_script_sha256": hashlib.sha256(script).hexdigest(),
            "window_seconds": 120,
            "recovery_seconds": 180,
        },
    )
    with (output / "partial-fault.nft").open("xb") as stream:
        stream.write(script)
        stream.flush()
        os.fsync(stream.fileno())
    installed = False
    try:
        require(command([nft, "-f", "-"], script).returncode == 0, "partial nft install failed")
        installed = True
        fault_start = time.monotonic_ns()
        deadline = fault_start + 120 * 1_000_000_000
        progress = False
        last = baseline
        while time.monotonic_ns() + 30_000_000_000 < deadline and not progress:
            require(stage.poll() is None, "StageA failed during partial loss")
            last = baseline_chain.sample("partial_four_live", baseline, deadline, fault_start)
            progress |= baseline_chain.progress_after(baseline, last, fault_start, 2)
            time.sleep(min(10, max(0, (deadline - time.monotonic_ns()) / 1e9 - 30)))
        require(progress, "partial loss lacks two new native common full IDs")
        remaining = (deadline - time.monotonic_ns()) / 1e9
        if remaining > 0:
            time.sleep(remaining)
        # The fault remains installed through this last capture. It freezes the
        # actual pre-removal tip without counting post-window heights as progress.
        last = baseline_chain.sample("partial_end", baseline, None, fault_start)
        raw = command([nft, "-j", "list", "table", "ip", table])
        require(raw.returncode == 0, "partial nft counters absent")
        objects = json.loads(raw.stdout)["nftables"]
        counters = {row["counter"]["name"]: row["counter"] for row in objects if "counter" in row}
        require(len(counters) == 3 * len(DIRECTIONS), "partial counters missing or extra")
        counts = {}
        for ordinal, direction in enumerate(DIRECTIONS):
            seen, dropped, passed = (
                counters[f"{name}{ordinal}"]["packets"] for name in ("entry", "drop", "pass")
            )
            require(
                seen >= 8
                and dropped > 0
                and passed > 0
                and seen == dropped + passed
                and abs(4 * dropped - seen) <= 3,
                "partial kernel hit/drop/pass counts or deterministic ratio differ: " + direction,
            )
            counts[direction] = {"seen": seen, "drop": dropped, "pass": passed}
        anchor = last
        remove_started = time.monotonic_ns()
        require(
            command([nft, "delete", "table", "ip", table]).returncode == 0,
            "partial nft removal failed",
        )
        installed = False
        require(
            command([nft, "-j", "list", "table", "ip", table]).returncode != 0,
            "partial nft table survived removal",
        )
        recovery_deadline = remove_started + 180 * 1_000_000_000
        recovery = None
        while recovery is None:
            require(
                time.monotonic_ns() < recovery_deadline and stage.poll() is None,
                "partial recovery deadline or StageA failed",
            )
            current = baseline_chain.sample("recovery", anchor, recovery_deadline)
            if recovery_target_met(
                anchor, current, recovery_deadline, 2
            ) and baseline_chain.progress_after(anchor, current, remove_started, 2):
                recovery = current
            else:
                time.sleep(5)
        ledger.append(
            {
                "event": "simple_partial_and_recovery_verified",
                "counts": counts,
                "baseline": baseline,
                "anchor": anchor,
                "recovery": recovery,
                "fault_start_ns": fault_start,
                "remove_started_ns": remove_started,
                "recovery_deadline_ns": recovery_deadline,
            }
        )
    finally:
        if installed:
            require(
                command([nft, "delete", "table", "ip", table]).returncode == 0,
                "partial nft cleanup failed",
            )


def run(args, context):
    require(
        args.case == "positive" and args.run_id == RUN_ID,
        "full-chain entry is not the fixed preset",
    )
    # Missing full runtime closure stops BEFORE any socket, loopback, node or helper reuse.
    require(INPUT_PATH.is_file(), "full StageA executable/dependency closure is not frozen")
    raw = INPUT_PATH.read_bytes()
    frozen = subprocess.check_output(
        ["git", "-C", str(REPO), "show", context["source_sha"] + ":scripts/" + INPUT_PATH.name]
    )
    require(raw == frozen, "four-node runtime input binding differs from fixed source")
    binding = json.loads(raw)
    closure = fixed_module("x02_four_node_binding", context)
    closure.verify_binding(binding, host=True)
    require(
        binding["source_root"] == str(REPO), "full StageA source must be the reviewed driver tree"
    )
    windows = closure.scenario_windows(binding)
    service = service_seconds(windows)
    args.output.mkdir(exist_ok=False)
    # Driver calls this after verified module load; imports below refer to those bytes.
    from x02_nfqueue_backend import QueueBackend
    from x02_nft_rules import RuleManager
    from x02_packet_identity import ingress_identity
    from x02_partial_adapter import DecisionAdapter, DurableLedger
    from x02_partial_sequence import DIRECTIONS, candidate_policy, verify_selection_trace
    from x02_queue_stats_fd import QueueStatsFD

    evidence = fixed_module("x02_fault_evidence", context)
    prepare = fixed_module("x02_prepare_policy", context)
    live_identity = fixed_module("x02_live_identity", context)
    # D only: its runner imports the fault-evidence module already loaded from fixed bytes above.
    directed = fixed_module("x02_directed_run", context) if binding["scenario"] == "D" else None
    directed_frozen = []
    ledger = DurableLedger(args.output / "kernel.jsonl")
    chain_ledger = DurableLedger(args.output / "chain.jsonl")
    delivered = DurableLedger(args.output / "delivered.jsonl")
    stats = QueueStatsFD(args.queue_stats_fd, args.queue_receipt_fd, args.host_netns)
    stop, errors, stopped = threading.Event(), [], set()
    observer_condition = threading.Condition()
    observer_state = {
        "requested_epoch": 0,
        "completed_epoch": 0,
        "requested_ns": 0,
        "last_packet_ns": 0,
        "idle_started_ns": 0,
        "idle_completed_ns": 0,
    }
    stage, backend, manager, worker, observer, observer_worker = (None,) * 6
    nodes, cleanup_ok, checks_passed, stage_natural = [], False, False, False
    received = Counter()
    invocation = time.monotonic()
    try:
        ledger.append({"event": "context", **context})
        stats.inverse_controls(ledger)
        setup = subprocess.run(
            ["/usr/sbin/ip", "link", "set", "dev", "lo", "up"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        ledger.append(
            {
                "event": "private_loopback_setup",
                "exit": setup.returncode,
                "stdout_hex": setup.stdout.hex(),
                "stderr_hex": setup.stderr.hex(),
            }
        )
        require(setup.returncode == 0, "private loopback configuration failed")
        binding.update(
            private_netns=context["netns"],
            host_netns=context["host_netns"],
            cgroup=context["cgroup"],
        )
        require(
            binding["stage_output"] == str(args.output / "stage-a"),
            "StageA output is not exclusive run leaf",
        )
        binding_path = args.output / "binding.json"
        binding_sha = write_once(binding_path, binding)
        child = REPO / "scripts/x02_stage_a_child.py"
        helper = REPO / "scripts/x02_four_node_binding.py"
        inner_argv = [
            binding["interpreter"],
            "-I",
            "-S",
            "-B",
            "-c",
            CHILD_BOOTSTRAP,
            str(child),
            binding["files"][str(child)]["sha256"],
            str(helper),
            binding["files"][str(helper)]["sha256"],
            "--binding",
            str(binding_path),
            "--binding-sha256",
            binding_sha,
            "--output",
            str(args.output),
        ]
        env = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "HOME": str(args.output / "home"),
            "TMPDIR": str(args.output / "tmp"),
            "PYTHONHASHSEED": "0",
            "UV_OFFLINE": "1",
        }
        Path(env["HOME"]).mkdir()
        Path(env["TMPDIR"]).mkdir()
        # Mount-only ordinary sandbox: NO PID or network namespace unshare.
        # All native PIDs remain host-visible in the driver's existing private
        # network namespace, while U24 supplies the actual ELF loader/libc.
        argv = [
            binding["bwrap_path"],
            "--unshare-user",
            "--uid",
            "1000",
            "--gid",
            "1000",
            "--cap-drop",
            "ALL",
            "--die-with-parent",
            "--ro-bind",
            binding["rootfs_root"],
            "/",
            "--tmpfs",
            "/datax",
            "--tmpfs",
            "/home",
            "--ro-bind",
            binding["rootfs_root"],
            binding["rootfs_root"],
            "--ro-bind",
            binding["source_root"],
            binding["source_root"],
            "--ro-bind",
            binding["git_common_root"],
            binding["git_common_root"],
            "--ro-bind",
            binding["build_root"],
            binding["build_root"],
            "--ro-bind",
            "/proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
        ]
        for root in binding["runtime_roots"]:
            argv += ["--ro-bind", root, root]
        for root in binding["dependency_roots"]:
            argv += ["--ro-bind", root, root]
        # The interpreter's own directory holds symlinks and is not a closure root, so the
        # indexed interpreter file itself is bound; its prefix still resolves to the stdlib root.
        argv += ["--ro-bind", binding["interpreter"], binding["interpreter"]]
        argv += ["--bind", str(args.output), str(args.output), "--chdir", str(REPO), "--clearenv"]
        for name, value in env.items():
            argv += ["--setenv", name, value]
        argv += ["--", *inner_argv]
        with (
            (args.output / "stage.stdout.raw").open("xb") as stdout,
            (args.output / "stage.stderr.raw").open("xb") as stderr,
        ):
            stage = subprocess.Popen(
                argv,
                stdout=stdout,
                stderr=stderr,
                cwd=REPO,
                env=env,
                close_fds=True,
                start_new_session=True,
                preexec_fn=clear_stage_launcher_caps,
            )
        ledger.append(
            {
                "event": "stage_started",
                "argv": argv,
                "env": env,
                "pid": stage.pid,
                "monotonic_ns": time.monotonic_ns(),
            }
        )
        readiness = None
        setup_deadline = invocation + SETUP_SECONDS
        while readiness is None:
            require(stage.poll() is None, "StageA exited before readiness")
            require(time.monotonic() < setup_deadline, "full StageA setup deadline exceeded")
            candidates = list(Path(binding["stage_output"]).glob("*/readiness-manifest.json"))
            require(len(candidates) <= 1, "multiple StageA readiness runs")
            if candidates:
                readiness = candidates[0]
                break
            time.sleep(0.25)
        readiness_raw = readiness.read_bytes()
        child_receipt = json.loads((args.output / "child-bootstrap.json").read_text())
        harness_pid = child_receipt["pid"]
        harness_stat = Path(f"/proc/{harness_pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()
        require(
            int(harness_stat[2]) == stage.pid
            and child_receipt["netns"] == context["netns"]
            and child_receipt["cgroup"] == context["cgroup"],
            "StageA sandbox harness escaped owning group/namespace",
        )
        manifest = json.loads(readiness_raw)
        require(
            manifest["schema"] == "tos.validator-election-experiment-readiness.v2"
            and manifest["status"] == "ready"
            and manifest["mode"] == "experiment"
            and manifest["election"]["mapping_status"] == "declared-before-first-election"
            and manifest["network"]["validator_count"] == 4
            and manifest["network"]["internal_base_port"] == 32600
            and manifest["provenance"]["source_commit"] == context["source_sha"],
            "StageA readiness source/schema/preset differs",
        )
        require(
            manifest["window"]["duration_seconds"] == windows["duration"]
            and manifest["window"]["settlement_tail_seconds"] == windows["settlement_tail"],
            "StageA readiness window differs from the scenario preset",
        )
        nodes = [prepare.live_node(item) for item in manifest["validators"]]
        require(
            len(nodes) == 4
            and {node["name"] for node in nodes} == {f"node{i}" for i in range(1, 5)}
            and len({node["pid"] for node in nodes}) == 4
            and len({node["data_dir"] for node in nodes}) == 4
            and distinct_db_inodes(nodes)
            and len({(node["log_dev"], node["log_ino"]) for node in nodes}) == 4,
            "four distinct native identities/DB/logs absent",
        )
        for key in ("consensus_key_id", "adnl_id"):
            require(
                len({evidence.hex64(node[key], key) for node in nodes}) == 4,
                "four validator keys alias",
            )
        declared = declared_node_mapping(nodes, manifest)
        # The readiness rows above are what the live identity is compared against, never its source.
        validator_bytes = os.stat(
            Path(binding["build_root"]) / "validator-engine/validator-engine"
        ).st_size

        def capture_identity(node):
            return live_identity.capture_node(
                node["pid"],
                Path(node["data_dir"]),
                binding["native_binary_sha256"],
                validator_bytes,
                urllib.parse.urlsplit(node["rpc_url"]).port,
            )

        identity_before = [capture_identity(node) for node in nodes]
        chain_ledger.append(
            {
                "event": "live_identity_before",
                "captures": identity_before,
                "monotonic_ns": time.monotonic_ns(),
            }
        )
        for i, node in enumerate(nodes):
            require(
                node["name"] == f"node{i + 1}"
                and node["peer_port"] == 32602 + i * 3
                and node["quic_port"] == 33602 + i * 3
                and node["rpc_url"] == f"http://127.0.0.1:{34600 + i}/jsonRPC"
                and node["exe_sha256"] == binding["native_binary_sha256"]
                and node["harness_pid"] == harness_pid,
                "native node preset/provenance differs",
            )
            socket_and_namespace(node, context)
        if binding["scenario"] == "D":
            directed_phase(
                args.output,
                binding,
                context,
                evidence,
                prepare,
                directed,
                readiness_raw,
                manifest,
                nodes,
                stage,
                ledger,
                directed_frozen,
            )
        elif binding.get("partial_engine") == "nft-ordinal-v1":
            zero = manifest["network"]["zero_state"]["masterchain"]
            simple_partial_phase(
                args.output,
                binding,
                context,
                nodes,
                {"root_hash": zero["root_hash_hex"], "file_hash": zero["file_hash_hex"]},
                stage,
                ledger,
                chain_ledger,
            )
        else:
            zero = manifest["network"]["zero_state"]["masterchain"]
            zerostate = {"root_hash": zero["root_hash_hex"], "file_hash": zero["file_hash_hex"]}
            by_name = {node["name"]: node for node in nodes}
            endpoints = {}
            for direction in DIRECTIONS:
                pair, transport = direction.split("/")
                source, destination = pair.split(">")
                field = "peer_port" if transport == "adnl" else "quic_port"
                endpoints[direction] = (
                    by_name[source]["peer_ip"],
                    by_name[source][field],
                    by_name[destination]["peer_ip"],
                    by_name[destination][field],
                )
            policy = candidate_policy(context["source_sha"])
            # Every window, delta and traffic floor below is read from the frozen selection
            # policy, so the record and the enforced behaviour cannot drift apart.
            thresholds = policy["chain_thresholds"]
            policy_record = {
                "schema": "tos.x02.four-node-live-policy.v1",
                "selection": policy,
                "nodes": nodes,
                "endpoints": endpoints,
                "zerostate": zerostate,
                "declared_public_identity_rows": declared,
                "identity_mapping_status": manifest["election"]["mapping_status"],
                "readiness_sha256": hashlib.sha256(readiness_raw).hexdigest(),
                "readiness_b64": base64.b64encode(readiness_raw).decode(),
                "native_source_sha": binding["native_source_sha"],
                "binding_sha256": binding_sha,
                "network_namespace": context["netns"],
                "original_config34": manifest["network"]["initial_config34"],
                "partial_seconds": thresholds["progress_max_seconds"],
                "recovery_seconds": thresholds["recovery_max_seconds"],
                "halt_claim": policy["halt_claim"],
            }
            policy_sha = write_once(args.output / "policy.json", policy_record)
            chain = ChainCapture(evidence, nodes, zerostate, chain_ledger, context)
            baseline = chain.sample("baseline")
            ledger.append(
                {
                    "event": "policy_and_baseline_frozen",
                    "policy_sha256": policy_sha,
                    "baseline": baseline,
                    "monotonic_ns": time.monotonic_ns(),
                }
            )
            engine = DecisionAdapter(policy, endpoints, ledger)
            # Stop every native sender before queue bind/rule install/observer start.
            freeze_senders(nodes, ledger, stopped)
            backend = QueueBackend(ledger, stats)
            backend.bind()
            manager = RuleManager(args.run_id, engine, backend, ledger)
            manager.preflight()
            # Receive-only raw observer proves input delivery bytes separately from ACKs/counters.
            observer = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
            observer.bind(("lo", 0x0800))
            observer.setsockopt(263, 8, 1)  # SOL_PACKET/PACKET_AUXDATA, exact20-byte native struct.
            observer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
            observer.settimeout(0.2)
            tuples = set(endpoints.values())

            def receive_delivered():
                try:
                    while not stop.is_set():
                        read_started = time.monotonic_ns()
                        try:
                            packet, ancillary, flags, peer = observer.recvmsg(65535, 256)
                        except socket.timeout:
                            with observer_condition:
                                if (
                                    observer_state["requested_epoch"]
                                    > observer_state["completed_epoch"]
                                    and read_started >= observer_state["requested_ns"]
                                ):
                                    observer_state.update(
                                        completed_epoch=observer_state["requested_epoch"],
                                        idle_started_ns=read_started,
                                        idle_completed_ns=time.monotonic_ns(),
                                    )
                                    delivered.append(
                                        {"event": "fresh_observer_idle", **observer_state}
                                    )
                                    observer_condition.notify_all()
                            continue
                        require(
                            not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and peer[0] == "lo",
                            "truncated or foreign ingress observer frame",
                        )
                        # PACKET_OUTGOING duplicates and unrelated DHT/TCP traffic
                        # are outside the selected24 UDP four-tuples, not loss hits.
                        if peer[2] != 0 or len(packet) < 28 or packet[9] != 17:
                            continue
                        ihl = (packet[0] & 15) * 4
                        if len(packet) < ihl + 8:
                            continue
                        ports = struct.unpack_from("!HH", packet, ihl)
                        endpoint = (
                            socket.inet_ntoa(packet[12:16]),
                            ports[0],
                            socket.inet_ntoa(packet[16:20]),
                            ports[1],
                        )
                        if endpoint in tuples:
                            aux = [
                                raw for level, kind, raw in ancillary if (level, kind) == (263, 8)
                            ]
                            require(
                                len(aux) == 1 and len(aux[0]) == 20 and len(ancillary) == 1,
                                "ingress checksum auxiliary metadata missing or ambiguous",
                            )
                            status, wire_len, snap_len, mac, net, vlan, vlan_type = struct.unpack(
                                "=IIIHHHH", aux[0]
                            )
                            require(vlan == vlan_type == 0, "unexpected loopback VLAN metadata")
                            identity = ingress_identity(packet, status, wire_len, snap_len)
                            digest = identity["identity_sha256"]
                            received[digest] += 1
                            received_ns = time.monotonic_ns()
                            with observer_condition:
                                observer_state["last_packet_ns"] = received_ns
                            delivered.append(
                                {
                                    "event": "raw_ingress",
                                    "packet_hex": packet.hex(),
                                    "identity": identity,
                                    "aux_hex": aux[0].hex(),
                                    "peer": list(peer[:-1]) + [peer[-1].hex()],
                                    "monotonic_ns": received_ns,
                                }
                            )
                except Exception as error:
                    errors.append("observer: " + repr(error))

            def process_queues():
                try:
                    while not stop.is_set():
                        require(
                            time.monotonic() - invocation < service, "callback service deadline"
                        )
                        try:
                            backend.process_one(engine)
                        except socket.timeout:
                            require(not engine.failed, "verdict ACK timeout poisoned adapter")
                            continue
                except Exception as error:
                    errors.append("queue: " + repr(error))

            observer_worker = threading.Thread(target=receive_delivered, name="x02-delivery")
            worker = threading.Thread(target=process_queues, name="x02-nfqueue")
            observer_worker.start()
            worker.start()
            manager.install()
            partial_start = time.monotonic_ns()
            partial_deadline = partial_start + thresholds["progress_max_seconds"] * 1_000_000_000
            ledger.append(
                {
                    "event": "partial_started",
                    "started_ns": partial_start,
                    "deadline_ns": partial_deadline,
                    "baseline": baseline,
                }
            )
            for pid in list(stopped):
                os.kill(pid, signal.SIGCONT)
                stopped.remove(pid)
            last_partial, progress_proved = baseline, False
            while time.monotonic_ns() + 2_000_000_000 < partial_deadline:
                require(
                    not errors and not engine.failed and stage.poll() is None,
                    "callback or full StageA failed during partial",
                )
                last_partial = chain.sample(
                    "partial_four_live", baseline, partial_deadline, partial_start
                )
                progress_proved |= chain.progress_after(
                    baseline, last_partial, partial_start, thresholds["progress_min_delta"]
                )
                time.sleep(min(5, max(0, (partial_deadline - time.monotonic_ns()) / 1e9 - 2)))
            require(
                progress_proved
                and all(
                    count["seen"] >= policy["minimum_packets_per_direction"]
                    for count in engine.counts.values()
                ),
                "partial lacks two new common IDs or actual traffic in all24 directions",
            )
            # Freeze LAST complete partial fullID BEFORE sender stop, drain or removal.
            anchor = last_partial
            ledger.append(
                {
                    "event": "recovery_anchor_frozen",
                    "anchor": anchor,
                    "monotonic_ns": time.monotonic_ns(),
                }
            )
            freeze_senders(nodes, ledger, stopped)
            drain_deadline = time.monotonic() + 10
            while True:
                require(not errors and not engine.failed, "callback failed while draining")
                try:
                    backend.health(require_empty=True)
                    require(engine.pending is None, "queue is not drained")
                    break
                except ValueError as error:
                    require(
                        str(error) == "queue is not drained" and time.monotonic() < drain_deadline,
                        "queue drain failed: " + str(error),
                    )
                    time.sleep(0.05)
            with observer_condition:
                epoch = observer_state["requested_epoch"] + 1
                observer_state.update(requested_epoch=epoch, requested_ns=time.monotonic_ns())
                request = dict(observer_state)
                delivered.append({"event": "observer_drain_requested", **request})
                fresh = observer_condition.wait_for(
                    lambda: observer_state["completed_epoch"] == epoch, timeout=5
                )
                require(
                    fresh and fresh_observer_epoch(observer_state, epoch),
                    "raw ingress observer has no fresh post-drain idle epoch",
                )
            # Thread consumes only receives now; request/unbind is exclusively main after join.
            counts = manager.counters_quiescent()
            ledger.append(
                {
                    "event": "partial_quiescent_counters",
                    "counts": counts,
                    "adapter_counts": engine.counts,
                    "monotonic_ns": time.monotonic_ns(),
                }
            )
            removal_start = time.monotonic_ns()
            manager.remove_owned_table()
            removal_complete = time.monotonic_ns()
            stop.set()
            worker.join(5)
            observer_worker.join(5)
            require(
                not worker.is_alive() and not observer_worker.is_alive() and not errors,
                "callback/observer did not stop cleanly",
            )
            packet_stats = observer.getsockopt(263, 6, 8)
            packets_seen, packets_dropped = struct.unpack("=II", packet_stats)
            delivered.append(
                {
                    "event": "packet_socket_statistics",
                    "raw_hex": packet_stats.hex(),
                    "packets_seen": packets_seen,
                    "packets_dropped": packets_dropped,
                    "monotonic_ns": time.monotonic_ns(),
                }
            )
            require(packets_dropped == 0, "ingress observer dropped packets")
            observer.close()
            backend.close_drained()
            # Stable counters and exact raw delivery multiset are checked independently.
            records = [
                json.loads(line) for line in (args.output / "kernel.jsonl").read_text().splitlines()
            ]
            intents = [row for row in records if row.get("event") == "intent"]
            submitted = [row for row in records if row.get("event") == "verdict_submitted"]
            require(
                len(intents) == len(submitted) and engine.pending is None and not engine.failed,
                "verdict receipt missing or adapter poisoned",
            )
            fields = ("direction", "index", "queue_packet_id", "dropped")
            require(
                [tuple(row[key] for key in fields) for row in intents]
                == [tuple(row[key] for key in fields) for row in submitted]
                and all(
                    hashlib.sha256(bytes.fromhex(row["packet_hex"])).hexdigest()
                    == row["packet_sha256"]
                    for row in intents
                ),
                "intent/ACK identity or captured datagram digest differs",
            )
            selection = verify_selection_trace(
                policy,
                [
                    {key: row[key] for key in ("direction", "index", "packet_sha256", "dropped")}
                    for row in intents
                ],
            )
            metadata_rows = [row for row in records if row.get("event") == "kernel_packet_identity"]
            metadata = {
                (row["direction"], row["queue_packet_id"]): row["identity"] for row in metadata_rows
            }
            require(
                len(metadata) == len(metadata_rows) == len(intents)
                and all(
                    metadata[(row["direction"], row["queue_packet_id"])]["raw_sha256"]
                    == row["packet_sha256"]
                    for row in intents
                ),
                "checksum metadata does not bind every queued datagram",
            )
            accepted = Counter(
                metadata[(row["direction"], row["queue_packet_id"])]["identity_sha256"]
                for row in intents
                if not row["dropped"]
            )
            require(received == accepted, "native ingress identities differ from selected accepts")
            for ordinal, direction in enumerate(DIRECTIONS):
                actual = engine.counts[direction]
                require(
                    counts[f"entry{ordinal}"]["packets"] == actual["seen"]
                    and counts[f"post{ordinal}"]["packets"] == actual["submitted_accept"]
                    and counts[f"entry{ordinal}"]["bytes"]
                    == sum(
                        len(bytes.fromhex(row["packet_hex"]))
                        for row in intents
                        if row["direction"] == direction
                    )
                    and counts[f"post{ordinal}"]["bytes"]
                    == sum(
                        len(bytes.fromhex(row["packet_hex"]))
                        for row in intents
                        if row["direction"] == direction and not row["dropped"]
                    ),
                    "actual native nft counter does not match serialized verdicts",
                )
            ledger.append(
                {
                    "event": "owned_partial_removed",
                    "started_ns": removal_start,
                    "completed_ns": removal_complete,
                    "selection": selection,
                    "raw_ingress_verified": True,
                    "canonical_rule": "udp-checksum-field-only-after-mode-validation.v1",
                }
            )
            for pid in list(stopped):
                os.kill(pid, signal.SIGCONT)
                stopped.remove(pid)
            # Conservative recovery clock starts at removal START, never at drain or first tip.
            recovery_deadline = removal_start + thresholds["recovery_max_seconds"] * 1_000_000_000
            recovery = None
            while recovery is None:
                require(
                    time.monotonic_ns() < recovery_deadline and stage.poll() is None,
                    "recovery deadline/StageA failed",
                )
                current = chain.sample("recovery", anchor, recovery_deadline)
                if recovery_target_met(
                    anchor, current, recovery_deadline, thresholds["recovery_min_delta"]
                ) and chain.progress_after(
                    anchor, current, removal_start, thresholds["recovery_min_delta"]
                ):
                    recovery = current
                else:
                    time.sleep(5)
            ledger.append(
                {
                    "event": "partial_and_recovery_verified",
                    "anchor": anchor,
                    "recovery": recovery,
                    "deadline_ns": recovery_deadline,
                }
            )
        # Capture again while the validators still run: same PIDs, generations and sources.
        identity_after = [capture_identity(node) for node in nodes]
        live_bindings = verify_live_pid_identity(
            live_identity, identity_before, identity_after, readiness.parent, declared
        )
        chain_ledger.append(
            {
                "event": "live_pid_identity_verified",
                "after": identity_after,
                "bindings": live_bindings,
                "monotonic_ns": time.monotonic_ns(),
            }
        )
        remaining = service - (time.monotonic() - invocation)
        require(remaining > 0, "no budget for natural StageA settlement")
        code = stage.wait(timeout=remaining)
        stage_natural = True
        write_once(
            args.output / "stage-exit.json",
            {"natural": True, "exit": code, "observed_ns": time.monotonic_ns(), "pid": stage.pid},
        )
        require(code == 0, "full StageA experiment/settlement naturally failed")
        report_path = readiness.parent / "report.json"
        report_raw = report_path.read_bytes()
        report = json.loads(report_raw)
        ledger.append(
            {
                "event": "stage_report_original",
                "path": str(report_path),
                "raw_hex": report_raw.hex(),
                "sha256": hashlib.sha256(report_raw).hexdigest(),
            }
        )
        require(
            report["status"] == "pass"
            and report["mode"] == "experiment"
            and report["experiment"]["final_status"] == "complete"
            and report["source_commit"] == context["source_sha"]
            and report["source_commit_at_report"] == context["source_sha"]
            and not report["git_status"],
            "natural StageA report/settlement/source differs",
        )
        verify_elected_identity(
            report,
            readiness.parent,
            declared,
            chain_ledger,
            config34_proof_check(
                binding,
                context,
                args.output,
                zerostate_anchor(manifest),
                deadline=invocation + service,
            ),
        )
        closure.verify_binding(binding, host=True)
        cgroup_path = Path("/sys/fs/cgroup") / context["cgroup"].split(":", 2)[-1].strip().lstrip(
            "/"
        )
        remaining_pids = (cgroup_path / "cgroup.procs").read_text()
        ledger.append(
            {
                "event": "post_stage_cgroup",
                "raw": remaining_pids,
                "path": str(cgroup_path),
                "monotonic_ns": time.monotonic_ns(),
            }
        )
        require(
            set(map(int, remaining_pids.split())) == {os.getpid()},
            "StageA tools/DHT or descendants remain in service cgroup",
        )
        require(
            all(not Path(f"/proc/{node['pid']}").exists() for node in nodes),
            "validator child remains after natural StageA exit",
        )
        checks_passed = True
    finally:
        cleanup_errors = []

        def attempt(label, action):
            try:
                action()
            except Exception as error:
                cleanup_errors.append(label + ": " + repr(error))
                ledger.append({"event": "cleanup_failed", "action": label, "error": repr(error)})

        # Each owned cleanup is attempted independently; an unknown nft owner
        # must never suppress child termination or turn a failed delete green.
        if manager is not None and not manager.removed:
            attempt("owned_table", manager.remove_owned_table)
        if directed_frozen:
            attempt(
                "directed_tc", lambda: directed_tc_cleanup(evidence, directed_frozen[0], ledger)
            )
        for pid in list(stopped):

            def resume(pid=pid):
                node = next(node for node in nodes if node["pid"] == pid)
                current = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()
                require(
                    int(current[19]) == node["pid_start_ticks"], "cleanup sender generation changed"
                )
                os.kill(pid, signal.SIGCONT)
                stopped.remove(pid)

            attempt("resume_owned_sender", resume)
        stop.set()
        for thread in (worker, observer_worker):
            if thread is not None:

                def join(thread=thread):
                    thread.join(5)
                    require(not thread.is_alive(), "cleanup thread remains")

                attempt("join_" + thread.name, join)
        if observer is not None:
            attempt("close_observer", observer.close)
        if backend is not None and backend.bound:

            def close_backend():
                require(worker is None or not worker.is_alive(), "worker owns queue socket")
                backend.close_drained()

            attempt("queue_empty_unbind", close_backend)
        if stage is not None:

            def terminate_stage():
                if stage.poll() is None:
                    os.killpg(stage.pid, signal.SIGTERM)
                    try:
                        code = stage.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        os.killpg(stage.pid, signal.SIGKILL)
                        code = stage.wait(timeout=5)
                    write_once(
                        args.output / "stage-abort.json",
                        {
                            "natural": False,
                            "exit": code,
                            "pid": stage.pid,
                            "observed_ns": time.monotonic_ns(),
                        },
                    )
                elif not stage_natural:
                    write_once(
                        args.output / "stage-exit.json",
                        {
                            "natural": True,
                            "exit": stage.returncode,
                            "pid": stage.pid,
                            "observed_ns": time.monotonic_ns(),
                        },
                    )

            attempt("StageA_terminal", terminate_stage)

        def verify_children_gone():
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if all(not Path(f"/proc/{node['pid']}").exists() for node in nodes):
                    return
                time.sleep(0.1)
            require(
                all(not Path(f"/proc/{node['pid']}").exists() for node in nodes),
                "validator remains after internal cleanup",
            )

        attempt("owned_children_gone", verify_children_gone)
        cleanup_ok = not cleanup_errors and not errors
        ledger.append(
            {
                "event": "final",
                "scenario": binding["scenario"],
                "checks_passed": checks_passed,
                "cleanup_ok": cleanup_ok,
                "stage_natural": stage_natural,
                "worker_alive": bool(worker and worker.is_alive()),
                "observer_alive": bool(observer_worker and observer_worker.is_alive()),
                "errors": errors,
                "monotonic_ns": time.monotonic_ns(),
            }
        )
        for stream in (ledger, chain_ledger, delivered):
            stream.close()
    require(checks_passed and cleanup_ok, "full four-node run or owned cleanup incomplete")
