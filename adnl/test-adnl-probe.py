#!/usr/bin/env python3
"""Smoke test for tos-adnl-probe (protocol tos-adnl-probe/1).

Launches two probe instances on loopback and drives the full flow:
listen both -> dial/await -> hold -> reconnect -> echo 1024 -> echo 65536
-> close, asserting every completion event. Runs the flow on 127.0.0.1 and
then attempts ::1, recording (not hiding) the ::1 outcome.

Usage: test-adnl-probe.py [path-to-tos-adnl-probe]
"""

import hashlib
import json
import subprocess
import sys
import threading
import queue
import time

DEFAULT_BINARY = "build/adnl/tos-adnl-probe"


class Probe:
    def __init__(self, binary, name):
        self.name = name
        self.proc = subprocess.Popen(
            [binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self.events = queue.Queue()
        self.next_id = 0
        self.reader = threading.Thread(target=self._read_loop, daemon=True)
        self.reader.start()
        hello = self.wait_event(lambda e: e.get("event") == "hello", 10)
        assert hello["protocol"] == "tos-adnl-probe/1", hello
        assert hello["implementation"], hello
        assert len(hello.get("implementation_commit", "")) == 40, hello
        log(f"{self.name}: hello {hello['implementation']} "
            f"commit={hello['implementation_commit'][:12]} "
            f"toolchain={hello.get('toolchain')} target={hello.get('target')}")

    def _read_loop(self):
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self.events.put(json.loads(line))
            except json.JSONDecodeError:
                self.events.put({"event": "_unparseable", "raw": line})

    def send(self, cmd, **kwargs):
        self.next_id += 1
        msg = {"id": self.next_id, "cmd": cmd}
        msg.update(kwargs)
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        return self.next_id

    def wait_event(self, predicate, timeout):
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"{self.name}: timed out waiting for event")
            try:
                event = self.events.get(timeout=remaining)
            except queue.Empty:
                continue
            if predicate(event):
                return event

    def wait_completion(self, cmd_id, timeout):
        return self.wait_event(lambda e: e.get("id") == cmd_id, timeout)

    def request(self, cmd, timeout=15, **kwargs):
        cmd_id = self.send(cmd, **kwargs)
        return self.wait_completion(cmd_id, timeout)

    def close(self):
        try:
            event = self.request("close", timeout=5)
            assert event.get("event") == "closed", event
        finally:
            self.proc.stdin.close()
            rc = self.proc.wait(timeout=10)
            assert rc == 0, f"{self.name}: exit code {rc}"
            log(f"{self.name}: closed, exit code {rc}")

    def kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()


def log(message):
    print(f"[smoke] {message}", flush=True)


def run_flow(binary, host, wrap_host):
    """Full flow between two probes on the given loopback host.

    Returns normally on success; raises AssertionError on failure.
    """
    a = Probe(binary, f"A({host})")
    b = Probe(binary, f"B({host})")
    try:
        listen_a = a.request("listen", bind=f"{wrap_host}:0")
        if listen_a.get("event") == "error":
            raise AssertionError(f"listen error: {listen_a['message']}")
        assert listen_a["event"] == "listening", listen_a
        listen_b = b.request("listen", bind=f"{wrap_host}:0")
        assert listen_b["event"] == "listening", listen_b
        port_a = int(listen_a["addr"].rsplit(":", 1)[1])
        port_b = int(listen_b["addr"].rsplit(":", 1)[1])
        log(f"A listening on {listen_a['addr']} id={listen_a['adnl_id_hex'][:12]}")
        log(f"B listening on {listen_b['addr']} id={listen_b['adnl_id_hex'][:12]}")

        # punch both directions (loopback: mostly a no-op, but must complete)
        punched = a.request("punch", targets=[f"{host}:{port_b}"], rounds=3, interval_ms=50)
        assert punched["event"] == "punched", punched
        punched = b.request("punch", targets=[f"{host}:{port_a}"], rounds=3, interval_ms=50)
        assert punched["event"] == "punched", punched
        log("punch: both directions punched")

        # dial from A, await on B
        await_id = b.send("await", peer_pubkey_hex=listen_a["adnl_pubkey_hex"], timeout_ms=10000)
        dial_id = a.send(
            "dial",
            peer_pubkey_hex=listen_b["adnl_pubkey_hex"],
            candidates=[f"{host}:{port_b}"],
            timeout_ms=10000,
        )
        dialed = a.wait_completion(dial_id, 15)
        awaited = b.wait_completion(await_id, 15)
        if dialed["event"] != "established" or awaited["event"] != "established":
            raise AssertionError(f"dial={dialed} await={awaited}")
        log(f"dial: established in {dialed['millis']} ms (peer_addr={dialed['peer_addr']})")
        log(f"await: established in {awaited['millis']} ms (peer_addr={awaited['peer_addr']})")

        # hold 3s / 300ms keepalives on both sides
        hold_a = a.send("hold", window_ms=3000, keepalive_ms=300)
        hold_b = b.send("hold", window_ms=3000, keepalive_ms=300)
        held_a = a.wait_completion(hold_a, 15)
        held_b = b.wait_completion(hold_b, 15)
        assert held_a["event"] == "held" and held_a["completed"] is True, held_a
        assert held_b["event"] == "held" and held_b["completed"] is True, held_b
        assert held_a["survival_seconds"] == 3, held_a
        log(f"hold: A survival={held_a['survival_seconds']}s completed={held_a['completed']}, "
            f"B survival={held_b['survival_seconds']}s completed={held_b['completed']}")

        # reconnect from A
        reconnected = a.request("reconnect", timeout_ms=10000)
        assert reconnected["event"] == "reconnected" and reconnected["succeeded"] is True, reconnected
        log(f"reconnect: succeeded in {reconnected['millis']} ms")

        # echo 1024 (must round trip, hash-verified on both ends)
        echoed = a.request("echo", bytes=1024, timeout_ms=10000)
        assert echoed["event"] == "echoed" and echoed["ok"] is True, echoed
        assert len(echoed["sha256_hex"]) == 64, echoed
        log(f"echo 1024: ok in {echoed['millis']} ms sha256={echoed['sha256_hex'][:16]}…")

        # echo 65536: the native stack caps query payloads at 8 KiB; an honest
        # ok=false with an error naming the cap is the expected outcome
        echoed64 = a.request("echo", bytes=65536, timeout_ms=10000)
        assert echoed64["event"] == "echoed", echoed64
        if echoed64["ok"]:
            log(f"echo 65536: ok in {echoed64['millis']} ms")
        else:
            assert "error" in echoed64, echoed64
            log(f"echo 65536: ok=false (expected on native stack): {echoed64['error']}")

        a.close()
        b.close()
    except Exception:
        a.kill()
        b.kill()
        raise


def run_identity_handoff(binary):
    """Rendezvous handoff: identity first (no socket), then listen on a port
    the driver just used for its own UDP socket, keypair reused exactly."""
    import socket

    a = Probe(binary, "A(handoff)")
    b = Probe(binary, "B(handoff)")
    try:
        # (a) identity before any listen: keypair without a socket
        ident = a.request("identity")
        assert ident["event"] == "identity", ident
        assert len(ident["adnl_pubkey_hex"]) == 64, ident
        assert len(ident["adnl_id_hex"]) == 64, ident
        log(f"identity: pubkey={ident['adnl_pubkey_hex'][:16]}… id={ident['adnl_id_hex'][:12]}")

        # calling identity again must return the same keypair
        ident2 = a.request("identity")
        assert ident2["adnl_pubkey_hex"] == ident["adnl_pubkey_hex"], (ident, ident2)

        # (b) the driver plays orchestrator: rendezvous on its own UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        rendezvous_port = sock.getsockname()[1]
        sock.close()
        log(f"handoff: rendezvous socket used and closed port {rendezvous_port}")

        # (c) immediately hand the same port to the sidecar
        listen_a = a.request("listen", bind=f"127.0.0.1:{rendezvous_port}")
        assert listen_a["event"] == "listening", listen_a
        listened_port = int(listen_a["addr"].rsplit(":", 1)[1])
        assert listened_port == rendezvous_port, listen_a
        assert listen_a["adnl_pubkey_hex"] == ident["adnl_pubkey_hex"], (ident, listen_a)
        assert listen_a["adnl_id_hex"] == ident["adnl_id_hex"], (ident, listen_a)
        log(f"handoff: listening on port {listened_port} with the identity keypair reused")

        # end-to-end establishment over the handed-off port
        listen_b = b.request("listen", bind="127.0.0.1:0")
        assert listen_b["event"] == "listening", listen_b
        port_b = int(listen_b["addr"].rsplit(":", 1)[1])
        await_id = a.send("await", peer_pubkey_hex=listen_b["adnl_pubkey_hex"], timeout_ms=10000)
        dial_id = b.send(
            "dial",
            peer_pubkey_hex=listen_a["adnl_pubkey_hex"],
            candidates=[f"127.0.0.1:{rendezvous_port}"],
            timeout_ms=10000,
        )
        dialed = b.wait_completion(dial_id, 15)
        awaited = a.wait_completion(await_id, 15)
        assert dialed["event"] == "established", dialed
        assert awaited["event"] == "established", awaited
        log(f"handoff: dial established in {dialed['millis']} ms over the handed-off port, "
            f"await in {awaited['millis']} ms")
        _ = port_b

        a.close()
        b.close()
    except Exception:
        a.kill()
        b.kill()
        raise


def run_port0_candidate_case(binary):
    """A malformed candidate advertising port 0 must be filtered, not crash
    the native stack (its send-error path aborts on sendmmsg EINVAL)."""
    a = Probe(binary, "A(port0-dial)")
    b = Probe(binary, "B(port0-dial)")
    try:
        la = a.request("listen", bind="0.0.0.0:0")
        lb = b.request("listen", bind="0.0.0.0:0")
        assert la["event"] == "listening" and lb["event"] == "listening", (la, lb)
        dialed = a.request(
            "dial",
            peer_pubkey_hex=lb["adnl_pubkey_hex"],
            candidates=["127.0.0.1:0"],
            timeout_ms=4000,
            timeout=15,
        )
        assert dialed["event"] == "failed", dialed
        assert dialed["class"] == "no-candidate", dialed
        log(f"dial with 127.0.0.1:0 candidate: failed class={dialed['class']} (no crash, honest failure)")
        a.close()
        b.close()
    except Exception:
        a.kill()
        b.kill()
        raise


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BINARY

    log("=== flow on 127.0.0.1 ===")
    run_flow(binary, "127.0.0.1", "127.0.0.1")
    log("=== 127.0.0.1 flow PASSED ===")

    log("=== identity + port handoff on 127.0.0.1 ===")
    run_identity_handoff(binary)
    log("=== identity handoff PASSED ===")

    log("=== port-0 candidate filtering ===")
    run_port0_candidate_case(binary)
    log("=== port-0 candidate case PASSED ===")

    log("=== flow on ::1 (recording the outcome, pass or fail) ===")
    try:
        run_flow(binary, "::1", "::1")
        log("=== ::1 flow PASSED (native stack supports IPv6 loopback) ===")
    except AssertionError as e:
        log(f"::1 outcome: {e}")
        log("=== ::1 flow NOT SUPPORTED by the native stack (see PROTOCOL.md IPv6 section) ===")
        # also verify the dial-with-::1-candidate path fails honestly instead of crashing
        a = Probe(binary, "A(::1-dial)")
        b = Probe(binary, "B(::1-dial)")
        try:
            la = a.request("listen", bind="0.0.0.0:0")
            lb = b.request("listen", bind="0.0.0.0:0")
            assert la["event"] == "listening" and lb["event"] == "listening", (la, lb)
            port_b = int(lb["addr"].rsplit(":", 1)[1])
            dialed = a.request(
                "dial",
                peer_pubkey_hex=lb["adnl_pubkey_hex"],
                candidates=[f"::1:{port_b}"],
                timeout_ms=4000,
                timeout=15,
            )
            assert dialed["event"] == "failed", dialed
            assert dialed["class"] == "no-candidate", dialed
            log(f"dial with ::1 candidate: failed class={dialed['class']} (no crash, honest failure)")
            a.close()
            b.close()
        except Exception:
            a.kill()
            b.kill()
            raise

    log("smoke test finished")


if __name__ == "__main__":
    main()
