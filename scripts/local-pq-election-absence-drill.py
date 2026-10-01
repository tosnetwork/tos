#!/usr/bin/env python3
"""Operator-absence drill for the local post-quantum development network.

The election driver is stopped before an election opens, so that election closes with
no stake. The elector must give it up when the term it was meant to follow ends and
open a fresh one with a full window. The driver is then restarted, and the set elected
in the fresh election must take office.

This is the failure that once held a development chain without a key block for five
hours: an election closed empty, late stakes were refused, and the elector postponed
the election for ever.

Exit status: 0 when the chain recovered, 1 when it did not (the empty election was
still held after the term, or no set from the fresh election took office), 2 when the
drill could not be set up. The driver is restarted on every path.

Run it from the repository's virtual environment, with passwordless sudo for systemctl:

    .venv/bin/python scripts/local-pq-election-absence-drill.py --out receipt.json
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from pytosiq_core import Cell

ELECTOR = "-1:" + "3" * 64
DRIVER = "tos-pq-elections.service"


class Chain:
    def __init__(self, lite_client, lite_config):
        self.lite_client = lite_client
        self.lite_config = lite_config
        self.scratch = Path(tempfile.mkdtemp(prefix="election-absence-drill-"))

    def lite(self, command):
        result = subprocess.run(
            [self.lite_client, "-C", self.lite_config, "-v", "0", "-c", command],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.stdout + result.stderr

    def account_cell(self, what):
        path = self.scratch / f"elector-{what}.boc"
        path.unlink(missing_ok=True)
        self.lite(f"saveaccount{what} {path} {ELECTOR}")
        if not path.exists():
            raise RuntimeError(f"the lite-client saved no elector {what}")
        return Cell.one_from_boc(path.read_bytes())

    def election(self):
        """The open election record, or None when no election is open."""
        data = self.account_cell("data").begin_parse()
        elect = data.load_maybe_ref()
        if elect is None:
            return None
        record = elect.begin_parse()
        elect_at = record.load_uint(32)
        elect_close = record.load_uint(32)
        record.load_coins()
        total_stake = record.load_coins()
        failed = bool(record.load_int(1))
        finished = bool(record.load_int(1))
        return {
            "elect_at": elect_at,
            "elect_close": elect_close,
            "total_stake": total_stake,
            "failed": failed,
            "finished": finished,
        }

    def current_set_since(self):
        found = re.search(r"cur_validators:\(\S+ utime_since:(\d+)", self.lite("getconfig 34"))
        if not found:
            raise RuntimeError("configuration parameter 34 is unreadable")
        return int(found.group(1))

    def code_hash(self):
        return self.account_cell("code").hash.hex()


def systemctl(action):
    subprocess.run(["sudo", "-n", "systemctl", action, DRIVER], check=True, timeout=120)


def driver_active():
    result = subprocess.run(["systemctl", "is-active", DRIVER], capture_output=True, text=True)
    return result.stdout.strip() == "active"


def wait_until(predicate, deadline, poll, describe):
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(poll)
    raise TimeoutError(describe)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--lite-client", default="/usr/local/bin/tos-lite-client")
    parser.add_argument("--lite-config", default="/data/configs/node-1-lite.json")
    parser.add_argument("--network", default="/data/network.json")
    parser.add_argument("--out", required=True, help="where to write the JSON receipt")
    parser.add_argument("--grace", type=int, default=90, help="seconds allowed after the term")
    parser.add_argument("--poll", type=int, default=10)
    args = parser.parse_args()

    receipt = {"events": [], "result": "not_run"}

    def event(kind, **fields):
        entry = {"at": int(time.time()), "kind": kind, **fields}
        receipt["events"].append(entry)
        print(json.dumps(entry), flush=True)

    status = 2
    stopped = False
    try:
        chain = Chain(args.lite_client, args.lite_config)
        network = json.loads(Path(args.network).read_text())
        receipt["zerostate_root"] = network.get("zerostate_root") or network.get("network_id")
        receipt["elector_code_hash"] = chain.code_hash()
        if not driver_active():
            raise RuntimeError(f"{DRIVER} is not active; the drill needs a running driver")

        # Start between elections, so the driver cannot have staked into the next one.
        current = chain.election()
        event("start", election=current)
        if current is not None:
            deadline = max(current["elect_at"], int(time.time())) + 1200
            wait_until(
                lambda: chain.election() is None,
                deadline,
                args.poll,
                "the election open at the start never finished",
            )
            event("between_elections")

        systemctl("stop")
        stopped = True
        event("driver_stopped")

        empty = wait_until(chain.election, time.time() + 1200, args.poll, "no election opened")
        event("election_opened", election=empty)
        wait_until(
            lambda: time.time() > empty["elect_close"] + args.poll,
            empty["elect_close"] + 600,
            args.poll,
            "the clock did not pass the close",
        )
        closed = chain.election()
        event("election_closed", election=closed)
        if closed is None or closed["elect_at"] != empty["elect_at"]:
            raise RuntimeError("the election changed before its close")
        if closed["total_stake"] != 0:
            raise RuntimeError("stake reached the election before the driver stopped")

        # The point of the drill: the empty election must not outlive the term.
        def fresh_election():
            record = chain.election()
            if record is not None and record["elect_at"] != empty["elect_at"]:
                return record
            return None

        try:
            fresh = wait_until(
                fresh_election,
                empty["elect_at"] + args.grace,
                args.poll,
                "the empty election was still held after the term it was meant to follow",
            )
        except TimeoutError as stuck:
            event("deadlock", election=chain.election(), error=str(stuck))
            receipt["result"] = "fail"
            status = 1
            return status
        observed_at = int(time.time())
        event("fresh_election", election=fresh, observed_at=observed_at)
        if fresh["elect_close"] <= observed_at:
            event("fresh_election_already_closed")
            receipt["result"] = "fail"
            status = 1
            return status

        systemctl("start")
        stopped = False
        event("driver_started")
        try:
            wait_until(
                lambda: chain.current_set_since() == fresh["elect_at"],
                fresh["elect_at"] + 600,
                args.poll,
                "no set from the fresh election took office",
            )
        except TimeoutError as missing:
            event("no_set", error=str(missing), current_set_since=chain.current_set_since())
            receipt["result"] = "fail"
            status = 1
            return status
        event("set_in_office", since=fresh["elect_at"])
        receipt["result"] = "pass"
        status = 0
        return status
    except (RuntimeError, TimeoutError, OSError, subprocess.SubprocessError, ValueError) as error:
        event("setup_failed", error=f"{type(error).__name__}: {error}")
        receipt["result"] = "error"
        return status
    finally:
        if stopped:
            try:
                systemctl("start")
                event("driver_restarted")
            except subprocess.SubprocessError as error:
                event("driver_restart_failed", error=str(error))
                receipt["exit_status"] = 2
                Path(args.out).write_text(json.dumps(receipt, indent=1) + "\n")
                # Raised from `finally`, this replaces whatever the drill returned: a
                # driver left stopped is a setup failure whatever the chain did.
                raise SystemExit(2)
        receipt["exit_status"] = status
        Path(args.out).write_text(json.dumps(receipt, indent=1) + "\n")


if __name__ == "__main__":
    sys.exit(main())
