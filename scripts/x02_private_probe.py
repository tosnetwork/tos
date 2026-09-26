#!/usr/bin/env python3
"""Finite real UDP/NFQUEUE probe, only in a supervisor-created private netns.

No validator, host nft operation or dependency installation. Requires a separate
reviewed resource scheme; the standard runner does not grant these capabilities.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import struct
import subprocess
import threading
import time
import sys
import types
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_fixed_sources(context):
    """Compile verified source bytes directly; never trust ignored __pycache__."""
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            "requires python -I -S -B")
    modules = {}
    for name in ("x02_partial_sequence", "x02_partial_adapter", "x02_nfqueue_backend", "x02_nft_rules"):
        path = REPO / "scripts" / (name + ".py")
        raw = path.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == context["sources"][name + ".py"]
                and name not in sys.modules, "source changed or module already loaded")
        module = types.ModuleType(name)
        module.__file__ = str(path)
        sys.modules[name] = module
        exec(compile(raw, str(path), "exec"), module.__dict__)
        modules[name] = module
    globals().update(DIRECTIONS=modules["x02_partial_sequence"].DIRECTIONS,
                     candidate_policy=modules["x02_partial_sequence"].candidate_policy,
                     DecisionAdapter=modules["x02_partial_adapter"].DecisionAdapter,
                     DurableLedger=modules["x02_partial_adapter"].DurableLedger,
                     QueueBackend=modules["x02_nfqueue_backend"].QueueBackend,
                     attribute=modules["x02_nfqueue_backend"].attribute,
                     RuleManager=modules["x02_nft_rules"].RuleManager)


class NegativeControl(RuntimeError):
    pass


def negative_control(case: str, manager, backend, ledger) -> None:
    if case == "install-race":
        marker = "foreign-fixture-" + manager.marker
        manager.command(["/usr/sbin/nft", "-f", "-"],
                        f'create table ip {manager.table} {{ comment "{marker}"; }}\n'.encode())
        raw = manager.snapshot()
        tables = [item["table"] for item in json.loads(raw)["nftables"] if "table" in item]
        require(len(tables) == 1 and tables[0].get("comment") == marker,
                "foreign fixture identity missing")
        handle = tables[0]["handle"]
        try:
            manager.install()
        except ValueError as error:
            require(str(error) == "nft command failed; cleanup required", "unexpected install failure")
        else:
            raise ValueError("same-name install did not reject")
        try:
            manager.remove_owned_table()
        except ValueError as error:
            require("do not delete same-name table" in str(error), "unexpected refusal reason")
        else:
            raise ValueError("cleanup deleted foreign table")
        after = [item["table"] for item in json.loads(manager.snapshot())["nftables"] if "table" in item]
        require(after == tables, "foreign fixture changed or disappeared")
        ledger.append({"event": "negative_control_triggered", "case": case,
                       "foreign_handle": handle, "reason": "install conflict; foreign table retained"})
        # Only the fixture's creator removes its proved foreign table.
        manager.command(["/usr/sbin/nft", "delete", "table", "ip", "handle", str(handle)])
        ruleset = json.loads(manager.command(["/usr/sbin/nft", "-j", "list", "ruleset"]))
        require(not any(item.get("table", {}).get("name") == manager.table
                        for item in ruleset["nftables"]), "foreign fixture cleanup failed")
        manager.removed = True  # Independent fixture removal was verified; no own table was installed.
    elif case == "wrong-flow":
        manager.install()
        handle = manager.ownership["rules"]["entry0"]
        queue = min(backend.queues)
        def replacement(port):
            return (f'replace rule ip {manager.table} enqueue handle {handle} ip saddr 127.0.0.1 '
                    f'ip daddr 127.0.0.2 udp sport {port} udp dport 33000 counter queue to {queue} '
                    f'comment "{manager.marker}:entry0"\n').encode()
        manager.command(["/usr/sbin/nft", "-f", "-"], replacement(32199))
        try:
            manager.validate_snapshot(manager.snapshot())
        except ValueError as error:
            require(str(error) == "counter four-tuple or expression differs", "unexpected flow rejection")
        else:
            raise ValueError("wrong actual flow accepted by counter validator")
        manager.command(["/usr/sbin/nft", "-f", "-"], replacement(32000))
        manager.validate_snapshot(manager.snapshot())
        ledger.append({"event": "negative_control_triggered", "case": case,
                       "reason": "actual wrong-flow rule rejected and fixture restored"})
    elif case == "late-ack":
        receive = backend.receive
        def delayed_receive():
            messages = receive()  # Real config ACK; delay only acceptance, not kernel behavior.
            time.sleep(2.05)
            return messages
        backend.receive = delayed_receive
        try:
            backend.request(2, min(backend.queues), attribute(3, struct.pack("!I", 256)))
        except ValueError as error:
            require(str(error) == "late kernel ACK or packet batch", "unexpected deadline rejection")
        else:
            raise ValueError("late ACK accepted")
        finally:
            backend.receive = receive
        ledger.append({"event": "negative_control_triggered", "case": case,
                       "reason": "real ACK acceptance delayed beyond absolute deadline and rejected"})
    else:
        raise ValueError("unknown negative control")
    raise NegativeControl(case)


def checksum(raw: bytes) -> int:
    padded = raw + bytes(len(raw) % 2)
    total = sum(struct.unpack(f"!{len(padded) // 2}H", padded))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(ordinal: int, index: int, run_id: str) -> bytes:
    payload = f"X02/{run_id}/{ordinal:02d}/{index:02d}".encode("ascii")
    src, dst = socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.2")
    udp = struct.pack("!HHHH", 32000 + ordinal, 33000 + ordinal, len(payload) + 8, 0) + payload
    pseudo = src + dst + struct.pack("!BBH", 0, 17, len(udp))
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 65535) + udp[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp),
                     1 + ordinal * 8 + index, 0x4000, 64, 17, 0, src, dst)
    return ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:] + udp


def environment(source_sha: str, host_netns: str, unit: str) -> dict:
    require(os.getuid() != 0 and os.geteuid() == os.getuid(), "probe must run as ordinary user")
    namespace = os.readlink("/proc/self/ns/net")
    require(host_netns.startswith("net:[") and namespace != host_netns,
            "refusing host network namespace")
    require(unit.startswith("n6-heavy-") and unit.endswith(".service"), "invalid resource unit")
    cgroup = Path("/proc/self/cgroup").read_text()
    require(any(line.split(":", 2)[-1].rstrip().endswith("/" + unit)
                for line in cgroup.splitlines()), "outside assigned resource cgroup")
    status = Path("/proc/self/status").read_text()
    capabilities = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                    for line in status.splitlines() if line.startswith("Cap")}
    for key in ("CapEff", "CapPrm", "CapAmb"):
        require(int(capabilities[key], 16) == (1 << 12 | 1 << 13),
                "requires only NET_ADMIN and NET_RAW capabilities")
    head = subprocess.check_output(["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip()
    clean = subprocess.check_output(["git", "-C", str(REPO), "status", "--porcelain", "--untracked-files=no"])
    require(head == source_sha and not clean, "source HEAD or tracked cleanliness differs")
    sources = {}
    for name in ("x02_partial_sequence.py", "x02_partial_adapter.py", "x02_nfqueue_backend.py",
                 "x02_nft_rules.py", "x02_private_probe.py"):
        raw = (REPO / "scripts" / name).read_bytes()
        frozen = subprocess.check_output(["git", "-C", str(REPO), "show", f"HEAD:scripts/{name}"])
        require(raw == frozen, "runtime source bytes differ")
        sources[name] = hashlib.sha256(raw).hexdigest()
    return {"source_sha": head, "sources": sources, "uid": os.getuid(), "pid": os.getpid(),
            "proc_stat": Path("/proc/self/stat").read_text(), "netns": namespace,
            "host_netns": host_netns, "cgroup": cgroup, "capabilities": capabilities,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "interpreter_sha256": hashlib.sha256(Path("/proc/self/exe").read_bytes()).hexdigest()}


def run(args) -> None:
    context = environment(args.source_sha, args.host_netns, args.unit)
    load_fixed_sources(context)
    args.output.mkdir(exist_ok=False)
    ledger = DurableLedger(args.output / "kernel.jsonl")
    sent = DurableLedger(args.output / "sender.jsonl")
    received = DurableLedger(args.output / "receiver.jsonl")
    backend, manager, worker = None, None, None
    sockets, errors = [], []
    stop = threading.Event()
    success, cleanup_ok = False, False
    deadline = time.monotonic() + 30
    try:
        ledger.append({"event": "context", **context})
        # Only this private namespace's loopback is configured.
        argv = ["/usr/sbin/ip", "link", "set", "dev", "lo", "up"]
        result = subprocess.run(argv, capture_output=True, timeout=5, check=False)
        ledger.append({"event": "loopback_setup", "argv": argv, "exit": result.returncode,
                       "stdout_hex": result.stdout.hex(), "stderr_hex": result.stderr.hex()})
        require(result.returncode == 0, "private loopback setup failed")
        endpoints = {direction: ("127.0.0.1", 32000 + ordinal, "127.0.0.2", 33000 + ordinal)
                     for ordinal, direction in enumerate(DIRECTIONS)}
        policy = candidate_policy(args.source_sha)
        ledger.append({"event": "frozen_probe_policy", "policy": policy, "run_id": args.run_id,
                       "endpoints": endpoints, "monotonic_ns": time.monotonic_ns()})
        engine = DecisionAdapter(policy, endpoints, ledger)
        backend = QueueBackend(ledger)
        backend.bind()
        manager = RuleManager(args.run_id, engine, backend, ledger)
        manager.preflight()
        if args.case != "positive":
            negative_control(args.case, manager, backend, ledger)
        sink = []
        for ordinal in range(24):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sockets.append(sock)
            sock.bind(("127.0.0.2", 33000 + ordinal))
            sock.setblocking(False)
            sink.append(sock)
        observer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sockets.append(observer)
        observer.bind(("127.0.0.2", 0))
        observer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
        sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sockets.append(sender)
        sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        def consume():
            try:
                while not stop.is_set() and sum(row["seen"] for row in engine.counts.values()) < 192:
                    require(time.monotonic() < deadline, "probe processing deadline exceeded")
                    try:
                        backend.process_one(engine)
                    except socket.timeout:
                        continue
            except Exception as error:
                errors.append(repr(error))
        worker = threading.Thread(target=consume)
        worker.start()
        manager.install()
        expected = {}
        for ordinal, direction in enumerate(DIRECTIONS):
            # Independent receiver oracle: literal cycle offsets, no selected_drop call.
            for index in range(8):
                raw = packet(ordinal, index, args.run_id)
                sent.append({"event": "send_intent", "direction": direction, "index": index,
                             "packet_hex": raw.hex(), "monotonic_ns": time.monotonic_ns()})
                require(sender.sendto(raw, ("127.0.0.2", 0)) == len(raw), "short raw send")
                if index % 4 != (3, 2, 1, 0)[ordinal % 4]:
                    expected[raw] = (direction, index)
        sent.append({"event": "sender_finished", "packets": 192,
                     "monotonic_ns": time.monotonic_ns()})
        worker.join(max(0, deadline - time.monotonic()))
        require(not worker.is_alive() and not errors and not engine.failed,
                f"backend failed or timed out: {errors}")
        raw_seen = set()
        while len(raw_seen) < len(expected):
            require(time.monotonic() < deadline, "raw receiver deadline exceeded")
            observer.settimeout(deadline - time.monotonic())
            raw = observer.recv(65535)
            received.append({"event": "raw_receiver", "packet_hex": raw.hex(),
                             "monotonic_ns": time.monotonic_ns()})
            require(raw in expected and raw not in raw_seen, "unexpected or duplicate raw delivery")
            raw_seen.add(raw)
        require(raw_seen == set(expected), "raw receiver bytes differ from fixed accepted set")
        observer.setblocking(False)
        try:
            extra = observer.recv(65535)
        except BlockingIOError:
            pass
        else:
            received.append({"event": "unexpected_extra_raw", "packet_hex": extra.hex()})
            raise ValueError("extra raw receiver packet")
        for ordinal, sock in enumerate(sink):
            actual = []
            while len(actual) < 6:
                require(time.monotonic() < deadline, "UDP receiver deadline exceeded")
                sock.settimeout(deadline - time.monotonic())
                payload, peer = sock.recvfrom(65535)
                received.append({"event": "udp_receiver", "direction": DIRECTIONS[ordinal],
                                 "peer": list(peer), "payload_hex": payload.hex()})
                require(peer == ("127.0.0.1", 32000 + ordinal), "receiver endpoint differs")
                actual.append(payload)
            wanted = [raw[28:] for raw, pair in expected.items() if pair[0] == DIRECTIONS[ordinal]]
            require(sorted(actual) == sorted(wanted) and len(actual) == 6,
                    "actual UDP socket receipt differs")
            sock.setblocking(False)
            try:
                extra, peer = sock.recvfrom(65535)
            except BlockingIOError:
                pass
            else:
                received.append({"event": "unexpected_extra_udp", "direction": DIRECTIONS[ordinal],
                                 "payload_hex": extra.hex(), "peer": list(peer)})
                raise ValueError("extra UDP receiver payload")
        counters = manager.counters_quiescent()
        for ordinal, direction in enumerate(DIRECTIONS):
            require(counters[f"entry{ordinal}"]["packets"] == 8
                    and counters[f"post{ordinal}"]["packets"] == 6
                    and engine.counts[direction] == {"seen": 8, "submitted_drop": 2, "submitted_accept": 6},
                    "entry/posthook/selection counts differ")
        # Authenticate every selected input, including the two unreceived drops.
        records = [json.loads(line) for line in (args.output / "kernel.jsonl").read_text().splitlines()]
        intents = {}
        completions = set()
        for row in records:
            if row["event"] == "intent":
                key = (row["direction"], row["index"])
                require(key not in intents, "duplicate selection input")
                ordinal = DIRECTIONS.index(row["direction"])
                raw = packet(ordinal, row["index"], args.run_id)
                require(row["packet_hex"] == raw.hex()
                        and row["packet_sha256"] == hashlib.sha256(raw).hexdigest()
                        and row["dropped"] == (row["index"] % 4 == (3, 2, 1, 0)[ordinal % 4]),
                        "selected input bytes or decision differ from sender")
                intents[key] = row["queue_packet_id"]
            elif row["event"] == "verdict_submitted":
                key = (row["direction"], row["index"])
                require(key in intents and key not in completions
                        and row["queue_packet_id"] == intents[key], "verdict packet ID join differs")
                completions.add(key)
        require(set(intents) == completions == {(direction, index) for direction in DIRECTIONS
                                              for index in range(8)}, "missing intent/verdict join")
        ledger.append({"event": "probe_checks_passed", "scope": "private-UDP-probe-only"})
        success = True
    finally:
        stop.set()
        if worker is not None:
            worker.join(3)
        try:
            if manager is not None and manager.preflight_done:
                # Best-effort detach proven-owned rules even if the worker cannot drain.
                manager.remove_owned_table()
                require(worker is None or not worker.is_alive(), "worker still alive; unbind blocked")
                backend.close_drained()
            elif backend is not None:
                require(worker is None or not worker.is_alive(), "worker still alive; close blocked")
                backend.sock.close()
            cleanup_ok = True
        except Exception as error:
            ledger.append({"event": "cleanup_failed", "error": repr(error)})
            if backend is not None:
                backend.sock.close()
            raise
        finally:
            for sock in sockets:
                sock.close()
            ledger.append({"event": "final", "checks_passed": success, "cleanup_ok": cleanup_ok,
                           "worker_alive": worker is not None and worker.is_alive(),
                           "monotonic_ns": time.monotonic_ns()})
            for log in (sent, received, ledger):
                log.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--host-netns", required=True)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--case", choices=("positive", "install-race", "wrong-flow", "late-ack"), default="positive")
    parser.add_argument("--output", required=True, type=Path)
    run(parser.parse_args())
