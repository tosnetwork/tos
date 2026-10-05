#!/usr/bin/env python3
"""Startup refusals of the full-node master and slave, on the real engine binary.

The full-node master service is allowlist-only, and a slave must sign in to its
masters with its full-node key. The engine checks both before it starts any
service, so these cases are decided on a node that has no chain yet:

  - a node configured with a full-node master and no --full-node-master-trusted
    id exits with code 2 and names the missing option;
  - the same node with a trusted id gets past the check;
  - a node configured as a slave without a full-node ADNL id exits with code 2;
  - a slave whose full-node ADNL key is missing from its keyring exits with
    code 2 and never starts;
  - a slave with its full-node key gets past the check.

"Gets past the check" means the engine is still running, with no refusal in
its output, after the refusal cases have all exited well within the same time.

Usage: full-node-master-startup-test.py <validator-engine>
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

MASTER_REFUSAL = "refusing to start the full-node master"
SLAVE_REFUSAL = "refusing to start the full-node slave"
REFUSAL_TIMEOUT_S = 30.0
SURVIVAL_S = 6.0


def fail(message: str) -> None:
    print(f"FULL_NODE_MASTER_STARTUP_FAILURE: {message}", file=sys.stderr)
    sys.exit(1)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def write_global_config(path: str) -> None:
    block = {
        "@type": "tosNode.blockIdExt",
        "workchain": -1,
        "shard": -9223372036854775808,
        "seqno": 0,
        "root_hash": b64(b"\x01" * 32),
        "file_hash": b64(b"\x02" * 32),
    }
    config = {
        "@type": "config.global",
        "dht": {
            "@type": "dht.config.global",
            "k": 6,
            "a": 3,
            "static_nodes": {"@type": "dht.nodes", "nodes": []},
        },
        "validator": {
            "@type": "validator.config.global",
            "zero_state": block,
            "init_block": block,
            "hardforks": [],
        },
    }
    with open(path, "w") as f:
        json.dump(config, f)


class Node:
    def __init__(self, engine: str, root: str) -> None:
        self.engine = engine
        self.root = root
        self.global_config = os.path.join(root, "global.json")
        self.db = os.path.join(root, "db")
        write_global_config(self.global_config)

    def command(self, extra: list[str]) -> list[str]:
        port = free_port()
        return [
            self.engine,
            "-C",
            self.global_config,
            "-D",
            self.db,
            "-I",
            f"127.0.0.1:{port}",
            "-t",
            "1",
            *extra,
        ]

    def create_config(self) -> dict:
        # With no config in the database the engine writes a fresh one, with a
        # full-node ADNL key in its keyring, and exits.
        result = subprocess.run(self.command([]), capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            fail(f"creating the local config exited {result.returncode}: {result.stderr[-2000:]}")
        return self.read_config()

    def read_config(self) -> dict:
        with open(os.path.join(self.db, "config.json")) as f:
            return json.load(f)

    def write_config(self, config: dict) -> None:
        with open(os.path.join(self.db, "config.json"), "w") as f:
            json.dump(config, f, indent=2)

    def expect_refusal(self, extra: list[str], refusal: str, case: str) -> None:
        start = time.monotonic()
        try:
            result = subprocess.run(self.command(extra), capture_output=True, text=True, timeout=REFUSAL_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            fail(f"{case}: the engine did not refuse to start within {REFUSAL_TIMEOUT_S} s")
        elapsed = time.monotonic() - start
        output = result.stdout + result.stderr
        if result.returncode != 2:
            fail(f"{case}: expected exit code 2, got {result.returncode}: {output[-2000:]}")
        if refusal not in output:
            fail(f"{case}: exit code 2 without the expected refusal '{refusal}': {output[-2000:]}")
        print(f"FULL_NODE_MASTER_STARTUP {case}=refused exit=2 seconds={elapsed:.1f}")

    def expect_survival(self, extra: list[str], case: str) -> None:
        log_path = os.path.join(self.root, f"{case}.log")
        with open(log_path, "w") as log:
            process = subprocess.Popen(self.command(extra), stdout=log, stderr=subprocess.STDOUT)
            try:
                time.sleep(SURVIVAL_S)
                code = process.poll()
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
        with open(log_path, errors="replace") as f:
            output = f.read()
        if MASTER_REFUSAL in output or SLAVE_REFUSAL in output:
            fail(f"{case}: a valid configuration was refused: {output[-2000:]}")
        if code is not None:
            fail(f"{case}: the engine exited {code} within {SURVIVAL_S} s: {output[-2000:]}")
        print(f"FULL_NODE_MASTER_STARTUP {case}=started")


def adnl_hex(base64_id: str) -> str:
    return base64.b64decode(base64_id).hex()


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: full-node-master-startup-test.py <validator-engine>")
    engine = os.path.abspath(sys.argv[1])
    if not os.access(engine, os.X_OK):
        fail(f"not an executable: {engine}")
    root = tempfile.mkdtemp(prefix="tos-full-node-master-startup-")
    try:
        node = Node(engine, root)
        base = node.create_config()
        full_node_id = base.get("fullnode")
        if not full_node_id or base64.b64decode(full_node_id) == b"\x00" * 32:
            fail("the generated config has no full-node ADNL id")

        # Master with no trusted slave: refused. With one: past the check.
        master = dict(base)
        master["fullnodemasters"] = [
            {"@type": "engine.validator.fullNodeMaster", "port": free_port(), "adnl": full_node_id}
        ]
        node.write_config(master)
        node.expect_refusal([], MASTER_REFUSAL, "master_without_trusted")
        trusted = os.urandom(32).hex()
        node.expect_survival(["--full-node-master-trusted", trusted], "master_with_trusted")

        # Slave entries point at a master that does not need to exist: the
        # checks run before any connection is attempted.
        slave_entry = {
            "@type": "engine.validator.fullNodeSlave",
            "ip": 0x7F000001,
            "port": free_port(),
            "adnl": {"@type": "pub.ed25519", "key": b64(os.urandom(32))},
        }

        # Slave without a full-node ADNL id: refused.
        no_id = dict(base)
        no_id["fullnode"] = b64(b"\x00" * 32)
        no_id["fullnodeslaves"] = [slave_entry]
        node.write_config(no_id)
        node.expect_refusal([], SLAVE_REFUSAL, "slave_without_full_node_id")

        # Slave whose full-node ADNL key is not in its keyring: refused before
        # it starts. The config loader already needs every configured key, so
        # this exits there; what matters is that it never starts anonymously.
        keyring = os.path.join(node.db, "keyring")
        key_file = os.path.join(keyring, adnl_hex(full_node_id).upper())
        if not os.path.exists(key_file):
            candidates = [n for n in os.listdir(keyring) if n.lower() == adnl_hex(full_node_id)]
            if len(candidates) != 1:
                fail(f"cannot find the full-node key in {keyring}: {sorted(os.listdir(keyring))}")
            key_file = os.path.join(keyring, candidates[0])
        hidden = key_file + ".hidden"
        with_slave = dict(base)
        with_slave["fullnodeslaves"] = [slave_entry]
        node.write_config(with_slave)
        os.rename(key_file, hidden)
        try:
            start = time.monotonic()
            try:
                result = subprocess.run(node.command([]), capture_output=True, text=True, timeout=REFUSAL_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                fail("slave_missing_key: the engine did not refuse to start")
            if result.returncode != 2:
                fail(f"slave_missing_key: expected exit code 2, got {result.returncode}: {result.stderr[-2000:]}")
            reason = (result.stdout + result.stderr).strip().splitlines()[-1:] or [""]
            print(f"FULL_NODE_MASTER_STARTUP slave_missing_key=refused exit=2 "
                  f"seconds={time.monotonic() - start:.1f} reason={reason[0][-200:]!r}")
        finally:
            os.rename(hidden, key_file)

        # Slave with its key: past the check.
        node.write_config(with_slave)
        node.expect_survival([], "slave_with_key")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print("FULL_NODE_MASTER_STARTUP_OK")


if __name__ == "__main__":
    main()
