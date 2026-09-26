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
from pathlib import Path

from x02_partial_adapter import DecisionAdapter, DurableLedger
from x02_partial_sequence import DIRECTIONS, candidate_policy, require
from x02_nfqueue_backend import QueueBackend
from x02_nft_rules import RuleManager

REPO = Path(__file__).resolve().parents[1]


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
        observer.setblocking(False)
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
        while True:
            try:
                raw = observer.recv(65535)
            except BlockingIOError:
                break
            received.append({"event": "raw_receiver", "packet_hex": raw.hex(),
                             "monotonic_ns": time.monotonic_ns()})
            require(raw in expected and raw not in raw_seen, "unexpected or duplicate raw delivery")
            raw_seen.add(raw)
        require(raw_seen == set(expected), "raw receiver bytes differ from fixed accepted set")
        for ordinal, sock in enumerate(sink):
            actual = []
            while True:
                try:
                    payload, peer = sock.recvfrom(65535)
                except BlockingIOError:
                    break
                received.append({"event": "udp_receiver", "direction": DIRECTIONS[ordinal],
                                 "peer": list(peer), "payload_hex": payload.hex()})
                require(peer == ("127.0.0.1", 32000 + ordinal), "receiver endpoint differs")
                actual.append(payload)
            wanted = [raw[28:] for raw, pair in expected.items() if pair[0] == DIRECTIONS[ordinal]]
            require(sorted(actual) == sorted(wanted) and len(actual) == 6,
                    "actual UDP socket receipt differs")
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
    parser.add_argument("--output", required=True, type=Path)
    run(parser.parse_args())
