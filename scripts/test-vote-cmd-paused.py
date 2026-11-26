#!/usr/bin/env python3
"""Run the vote controls with a measured SIGSTOP while their futures are pending.

Build the commands test binary separately under the build/thermal guard, then pass
its path. This script never builds or signals any process it did not start.
"""

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import time
from pathlib import Path

CASES = (
    "elector_control_tests::stake_confirmation_uses_one_snapshot_per_poll_and_propagates_upgrade",
    "elector_control_tests::confirmation_refuses_another_election_or_a_partial_invalid_response",
    "proposal_control_tests::offer_upgrade_errors_never_fall_back_to_public_proposals",
)
LIMIT = 4 * 1024 * 1024


def process_state(pid):
    fields = Path(f"/proc/{pid}/stat").read_text()
    return fields[fields.rfind(")") + 2 :].split()[0]


def receive(process, output, marker, deadline):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while marker not in output:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("test control timed out")
            if not selector.select(min(remaining, 1)):
                continue
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                raise RuntimeError("test exited before the required rendezvous")
            output.extend(chunk)
            if len(output) > LIMIT:
                raise RuntimeError("test output limit exceeded")


def run(binary, name, seconds, out):
    env = dict(os.environ, VOTE_CMD_PAUSE_GATE="1")
    output = bytearray()
    process = subprocess.Popen(
        [str(binary), "--exact", name, "--nocapture", "--test-threads=1"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        bufsize=0,
    )
    deadline = time.monotonic() + 120
    try:
        receive(process, output, b"VOTE_CMD_PAUSE_READY", deadline)
        os.kill(process.pid, signal.SIGSTOP)
        stop_deadline = time.monotonic() + 2
        while process_state(process.pid) != "T":
            if time.monotonic() >= stop_deadline:
                raise RuntimeError("test did not stop")
            time.sleep(0.01)
        stopped = time.monotonic()
        while time.monotonic() - stopped < seconds:
            if process_state(process.pid) != "T":
                raise RuntimeError("test resumed before the control released it")
            time.sleep(0.05)
        elapsed = time.monotonic() - stopped
        os.kill(process.pid, signal.SIGCONT)
        process.stdin.write(b"g")
        process.stdin.close()
        receive(process, output, b"test result:", deadline)
        # Drain bounded output through EOF, then require the named test to pass.
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("test output drain timed out")
                if not selector.select(min(remaining, 1)):
                    continue
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > LIMIT:
                    raise RuntimeError("test output limit exceeded")
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if code or not re.search(rb"test result: ok\. 1 passed; 0 failed;", output):
            raise RuntimeError(f"named test did not pass: {name}")
        log = out / (name.rsplit("::", 1)[-1] + ".log")
        log.write_bytes(output)
        return dict(
            test=name,
            stopped_seconds=elapsed,
            exit_code=code,
            log=log.name,
            sha256=hashlib.sha256(output).hexdigest(),
        )
    finally:
        (out / (name.rsplit("::", 1)[-1] + ".log")).write_bytes(output)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        if not process.stdin.closed:
            process.stdin.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--stop-seconds", type=float, default=10)
    parser.add_argument("--case", choices=CASES)
    args = parser.parse_args()
    if not 10 <= args.stop_seconds <= 60:
        parser.error("--stop-seconds must be in [10, 60]")
    binary = args.test_binary.resolve(strict=True)
    listing = subprocess.run(
        [str(binary), "--list"], check=True, capture_output=True, text=True, timeout=30
    ).stdout
    names = [
        line.removesuffix(": test") for line in listing.splitlines() if line.endswith(": test")
    ]
    selected = []
    for case in [args.case] if args.case else CASES:
        matches = [name for name in names if name.endswith(case)]
        if len(matches) != 1:
            raise RuntimeError(f"expected exactly one test matching {case}")
        selected.append(matches[0])
    args.out.mkdir(parents=True, exist_ok=False)
    results = [run(binary, name, args.stop_seconds, args.out) for name in selected]
    receipt = dict(
        status="PASS",
        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        results=results,
    )
    (args.out / "RESULTS.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
