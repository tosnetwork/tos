#!/usr/bin/env python3
"""Before forwarding one prepared write, finalize a competing spend; then replay its body."""

from __future__ import annotations

import argparse
import base64
import fcntl
import json
import os
import sqlite3
import subprocess
import time
import urllib.request
from pathlib import Path

from control import configuration
from proxy import Gate

ROOT = Path(__file__).resolve().parents[3]


class Race(Gate):
    def before_send(self, value):
        scenario = json.loads(self.args.scenario.read_bytes())
        config = configuration(self.args.config)
        if config["release"].global_id != 3:
            raise RuntimeError("local network required")
        with sqlite3.connect(
            f"file:{Path(config['state_dir']) / 'leases.db'}?mode=ro", uri=True
        ) as db:
            row = db.execute(
                "SELECT message FROM leases WHERE request=?", (scenario["request_id"],)
            ).fetchone()
        if row is None or bytes(row[0]) != base64.b64decode(value["params"]["boc"], validate=True):
            raise RuntimeError("gate received another prepared message")
        self.save(
            self.args.out / "race-started.json",
            json.dumps({"request_id": scenario["request_id"]}).encode(),
        )
        self.send_faucet(scenario["winner_body"], "winner")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.commitments(config["release"].pool) == scenario["commitments_after_winner"]:
                self.winner_head_lt = self.pool_head(config["release"].pool)
                return
            time.sleep(0.1)
        raise RuntimeError("competing transaction not observed; original not forwarded")

    def commitments(self, pool):
        query = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "runGetMethod",
            "params": {"address": pool, "method": "commitment_next_index", "stack": []},
        }
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.args.upstream_port}/jsonRPC",
            json.dumps(query).encode(),
            {"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            value = json.load(response)["result"]
        if value["exit_code"] != 0:
            raise RuntimeError("pool diagnostic getter")
        return int(value["stack"][0][1], 0)

    def pool_head(self, pool):
        query = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransactions",
            "params": {"address": pool, "limit": 1},
        }
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.args.upstream_port}/jsonRPC",
            json.dumps(query).encode(),
            {"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            rows = json.load(response)["result"]
        return int(rows[0]["transaction_id"]["lt"])

    def wait_new_head(self, previous):
        pool = configuration(self.args.config)["release"].pool
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            head = self.pool_head(pool)
            if head > previous:
                return head
            time.sleep(0.1)
        raise RuntimeError("expected pool transaction not observed; never retry")

    def send_faucet(self, body, label):
        command = [
            str(self.args.client_python),
            str(Path(__file__).with_name("faucet_send.py")),
            "--root",
            str(self.args.root),
            "--body",
            body,
            "--marker",
            str(self.args.out / (label + "-send-started")),
            "--checkout",
            str(ROOT),
            "--toslib",
            str(self.args.toslib),
        ]
        result = subprocess.run(command, capture_output=True, timeout=45)
        output = result.stdout + result.stderr
        if len(output) > 16384:
            raise RuntimeError("faucet helper output bound")
        self.save(self.args.out / (label + ".log"), output)
        if result.returncode:
            raise RuntimeError("faucet submission unknown; never retry")

    def after_send(self, value, receipt):
        scenario = json.loads(self.args.scenario.read_bytes())
        subprocess.run(
            [
                "systemctl",
                "--user",
                "kill",
                "--kill-who=all",
                "--signal=SIGKILL",
                "br1-operator-c.service",
            ],
            check=True,
            timeout=10,
        )
        subprocess.run(
            ["systemctl", "--user", "stop", "br1-operator-c.service"], check=True, timeout=10
        )
        failed_head = self.wait_new_head(self.winner_head_lt)
        self.send_faucet(scenario["target_body"], "wrong-source-replay")
        replay_head = self.wait_new_head(failed_head)
        receipt.update(
            {
                "killed_unit": "br1-operator-c.service",
                "worker_stopped": True,
                "competing_spend_submitted_once": True,
                "wrong_source_replay_submitted_once": True,
                "failed_pool_lt": failed_head,
                "newer_replay_lt": replay_head,
            }
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--scenario", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--client-python", type=Path, required=True)
    parser.add_argument("--toslib", type=Path, required=True)
    args = parser.parse_args()
    args.port, args.upstream_port, args.kill_unit = 34821, 34811, None
    if configuration(args.config)["release"].global_id != 3:
        parser.error("only isolated local network")
    os.umask(0o077)
    args.out.mkdir(mode=0o700, exist_ok=False)
    with (args.out / "proxy.lock").open("xb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with Race(args) as server:
            server.serve_forever()


if __name__ == "__main__":
    main()
