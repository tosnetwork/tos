#!/usr/bin/env python3
# Copyright (C) 2025-2026 TOS Network.
"""Release-gate the TOSCAN data path against a real local TOS chain.

This test starts a native validator, the read-only ``tosctl explorer``
profile, and the real Agent Economy seed. It verifies route isolation,
canonical indexing, rich transaction/message data, contract discovery, and
durable recovery after restarting the explorer process.

Run it locally before a release, or after any change to the explorer surface::

    python scripts/toscan-explorer-e2e.py

It takes well under a minute on a machine that has already built the node,
which is why it is not wired to run on every push: in CI the same check spent
most of its life being cancelled part-way through the compile in front of it.
The workflow still carries it under ``workflow_dispatch`` for when a result has
to come from a clean machine rather than a developer's.
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_WORKDIR = REPO / "test/integration/.toscan-explorer-e2e"
CONTRACT_KINDS = {
    "agent_account",
    "capability_registry",
    "service_actor",
    "task_escrow",
    "dispute",
}
NOMINATOR_POOL_KIND = "contract.pool.nominator"


def request_json(url: str, body=None, timeout=15):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        raw = error.read()
        return error.code, json.loads(raw.decode()) if raw else {}


# Waits here are for a chain to produce blocks and an indexer to catch up, and
# both are as fast as the machine underneath them. When this runs in CI it runs
# immediately after compiling the node, on a runner whose caches were cold and
# whose disk has just been saturated for the better part of an hour -- so a
# budget tuned on an idle developer machine expires on work that has nothing to
# do with what is being tested. TOSCAN_E2E_TIMEOUT_SCALE widens every wait
# without moving any of them individually.
TIMEOUT_SCALE = float(os.environ.get("TOSCAN_E2E_TIMEOUT_SCALE", "1"))


def wait_until(label: str, predicate, timeout=180):
    budget = timeout * TIMEOUT_SCALE
    deadline = time.monotonic() + budget
    started = time.monotonic()
    last_error = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                print(f"PASS: {label} ({time.monotonic() - started:.0f}s)")
                return value
        except Exception as error:  # endpoint can be absent during startup
            last_error = error
        time.sleep(1)
    raise TimeoutError(
        f"{label} timed out after {budget:.0f}s "
        f"(scale {TIMEOUT_SCALE:g}): {last_error}"
    )


def start(command: list[str], cwd: Path, log_path: Path, env=None):
    output = log_path.open("ab")
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=output,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    process._toscan_log = output  # type: ignore[attr-defined]
    return process


def stop(process):
    if process is None:
        return
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    process._toscan_log.close()  # type: ignore[attr-defined]


def generate_explorer_config(tosctl: Path, path: Path, rpc_origin: str, http_bind: str):
    subprocess.run(
        [str(tosctl), "config", "generate", "-o", str(path), "--force"],
        cwd=REPO,
        check=True,
    )
    config = json.loads(path.read_text())
    config["chain_rpc"] = {"urls": [f"{rpc_origin}/"], "api_key": None}
    config["http"] = {"bind": http_bind, "enable_swagger": False, "auth": None}
    config["master_wallet"] = None
    config["elections"] = None
    config["voting"] = None
    config["tick_interval"] = 1
    config["log"] = None
    path.write_text(json.dumps(config, indent=2) + "\n")


# What a consumer of this script can rely on this revision to do.
#
# The explorer is built from a different repository and its release gate runs
# this script out of whichever TOS revision it happened to check out. Without a
# declared contract a revision that predates a feature does not report a missing
# feature -- it reports an unrecognized argument, which reads like a typo in the
# caller rather than a version mismatch, and a gate that silently stops covering
# something is worse than one that was never written.
CAPABILITIES = {
    "browser-command": (
        "--browser-command runs an external release gate against the live chain"
    ),
    "staking-projection": (
        "/explorer/staking is asserted against Elector election history"
    ),
    "effective-stake-cap": (
        "/explorer/staking reports the stake factor and the cap it implies"
    ),
    "validator-set-decoding": (
        "getConfigParam returns decoded validator sets alongside the raw cell"
    ),
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--capabilities",
        action="store_true",
        help="print what this revision supports, one per line, and exit",
    )
    parser.add_argument(
        "--require",
        action="append",
        default=[],
        metavar="CAPABILITY",
        help="fail immediately unless this revision declares the capability",
    )
    parser.add_argument("--workdir", default=str(DEFAULT_WORKDIR))
    parser.add_argument("--tosctl", default=str(REPO / "tosctl/src/target/debug/tosctl"))
    parser.add_argument("--rpc-port", type=int, default=19451)
    parser.add_argument("--control-port", type=int, default=19452)
    parser.add_argument("--explorer-port", type=int, default=19453)
    parser.add_argument("--base-port", type=int, default=26900)
    parser.add_argument(
        "--browser-command",
        help="optional shell command that release-gates the browser against the running real chain",
    )
    args = parser.parse_args()

    if args.capabilities:
        for name, description in sorted(CAPABILITIES.items()):
            print(f"{name}\t{description}")
        return 0

    missing = [name for name in args.require if name not in CAPABILITIES]
    if missing:
        parser.exit(
            2,
            "this TOS revision does not provide: "
            + ", ".join(missing)
            + "\nit declares: "
            + ", ".join(sorted(CAPABILITIES))
            + "\ncheck out a TOS revision that has them, or drop the requirement\n",
        )

    workdir = Path(args.workdir).resolve()
    tosctl = Path(args.tosctl).resolve()
    if not tosctl.exists():
        parser.error(f"tosctl binary not found: {tosctl}")
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True)
    rpc_origin = f"http://127.0.0.1:{args.rpc_port}"
    control_origin = f"http://127.0.0.1:{args.control_port}"
    explorer_origin = f"http://127.0.0.1:{args.explorer_port}"
    config = workdir / "tosctl-explorer.json"
    manifest = workdir / "seed-manifest.json"
    node = explorer = None

    try:
        node = start(
            [
                sys.executable,
                str(REPO / "scripts/localnet-jsonrpc.py"),
                "--rpc",
                f"127.0.0.1:{args.rpc_port}",
                "--control",
                f"127.0.0.1:{args.control_port}",
                "--validators",
                "1",
                "--workdir",
                str(workdir / "localnet"),
                "--base-port",
                str(args.base_port),
            ],
            REPO,
            workdir / "node.log",
        )
        wait_until(
            "native localnet ready",
            lambda: request_json(f"{control_origin}/readyz")[0] == 200,
        )

        generate_explorer_config(
            tosctl,
            config,
            rpc_origin,
            f"127.0.0.1:{args.explorer_port}",
        )
        explorer = start(
            [str(tosctl), "explorer", "-c", str(config)],
            REPO,
            workdir / "explorer.log",
        )
        wait_until(
            "explorer-only HTTP ready",
            lambda: request_json(f"{explorer_origin}/health")[0] == 200,
            timeout=45,
        )

        subprocess.run(
            [
                sys.executable,
                str(REPO / "scripts/toscan-dev-seed.py"),
                "--rpc",
                rpc_origin,
                "--control",
                control_origin,
                "--config",
                str(workdir / "seed-config.json"),
                "--manifest",
                str(manifest),
                "--tosctl",
                str(tosctl),
            ],
            cwd=REPO,
            check=True,
        )
        seed = json.loads(manifest.read_text())
        assert set(seed["addresses"]) == CONTRACT_KINDS
        pool_address = seed["staking"]["nominator_pool"]
        print("PASS: five Agent Economy contracts and a real Nominator Pool deployed")

        for path in ("/auth/login", "/v1/elections", "/swagger", "/openapi.json"):
            status, _ = request_json(f"{explorer_origin}{path}")
            assert status == 404, f"explorer-only route leaked: {path} returned {status}"
        print("PASS: operator, auth and documentation routes are absent")

        def all_contracts_visible():
            for kind, address in seed["addresses"].items():
                encoded = urllib.parse.quote(address, safe=":")
                status, body = request_json(
                    f"{explorer_origin}/explorer/contracts/{kind}/{encoded}"
                )
                if status != 200 or body.get("result", {}).get("address") != address:
                    return False
            return True

        wait_until("all seeded contracts discovered chain-wide", all_contracts_visible, timeout=180)

        staking_observation = None

        def staking_visible():
            nonlocal staking_observation
            encoded = urllib.parse.quote(pool_address, safe=":")
            pool_status, pool_body = request_json(
                f"{explorer_origin}/explorer/contracts/{NOMINATOR_POOL_KIND}/{encoded}"
            )
            staking_status, staking_body = request_json(
                f"{explorer_origin}/explorer/staking"
            )
            if pool_status != 200 or staking_status != 200:
                observed = {"pool_status": pool_status, "staking_status": staking_status}
                if observed != staking_observation:
                    print(f"  staking gate waiting: {observed}")
                    staking_observation = observed
                return False
            result = staking_body.get("result", {})
            observed = {
                "pool_address": pool_body.get("result", {}).get("address"),
                "pools": result.get("pools"),
                "nominators": result.get("nominators"),
                "total_pool_stake": result.get("total_pool_stake"),
                "cycles": len(staking_body.get("cycles", [])),
            }
            if observed != staking_observation:
                print(f"  staking gate waiting: {observed}")
                staking_observation = observed
            return (
                pool_body.get("result", {}).get("address") == pool_address
                and result.get("pools") == 1
                and result.get("nominators") == 1
                and int(result.get("total_pool_stake", "0")) > 0
                and isinstance(staking_body.get("cycles"), list)
            )

        wait_until(
            "Elector rewards and code-verified Nominator Pool are queryable",
            staking_visible,
            timeout=180,
        )

        # A pool's size next to a network reward rate reads as though the two
        # multiply. Past the Elector's cap they do not: it pays on
        # min(stake, factor * smallest elected stake) and refunds the rest, so
        # capital above the cap earns nothing while still carrying the pool's
        # risk. The page can only say so if the endpoint tells it, and the
        # endpoint is only worth trusting if this asserts the numbers.
        _, staking_body = request_json(f"{explorer_origin}/explorer/staking")
        effective = staking_body["result"]["effective_stake"]
        raw_factor = effective["max_stake_factor_raw"]
        assert raw_factor is not None, "stake limits did not reach the explorer"
        assert raw_factor >= 1 << 16, "a factor below one would cap every validator below the floor"
        assert abs(effective["max_stake_factor"] - raw_factor / (1 << 16)) < 1e-9
        assert effective["surplus_earns"] is (raw_factor > 1 << 16)
        smallest = effective["smallest_elected_stake"]
        if smallest is not None:
            expected_cap = (int(smallest) * raw_factor) >> 16
            assert int(effective["effective_stake_cap"]) == expected_cap
            if not effective["surplus_earns"]:
                assert int(effective["effective_stake_cap"]) == int(smallest), (
                    "at the floor the cap is the smallest elected stake itself"
                )
        print(
            "PASS: effective-stake cap is reported "
            f"(factor {effective['max_stake_factor']}, "
            f"surplus earns: {effective['surplus_earns']})"
        )

        rich = None

        def rich_transaction_visible():
            nonlocal rich
            status, body = request_json(
                f"{explorer_origin}/explorer/transactions?offset=0&limit=200"
            )
            if status != 200:
                return False
            rich = next(
                (
                    item
                    for item in body.get("result", [])
                    if item.get("fee") is not None and item.get("in_msg_hash")
                ),
                None,
            )
            return rich

        wait_until("indexed transaction carries fee and inbound-message hash", rich_transaction_visible)
        assert rich is not None
        status, raw = request_json(
            f"{rpc_origin}/jsonRPC",
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getTransactions",
                "params": {
                    "address": rich["account"],
                    "limit": 1,
                    "lt": rich["lt"],
                    "hash": rich["hash"],
                },
            },
        )
        transaction = raw.get("result", [None])[0]
        assert status == 200 and transaction
        assert transaction.get("fee") is not None
        assert isinstance(transaction.get("in_msg"), dict)
        assert isinstance(transaction.get("out_msgs"), list)
        assert transaction.get("transaction_type") in {
            "ordinary", "storage", "tick", "tock", "split_prepare",
            "split_install", "merge_prepare", "merge_install",
        }
        if transaction.get("transaction_type") in {"ordinary", "tick", "tock"}:
            assert isinstance(transaction.get("aborted"), bool)
            assert isinstance(transaction.get("compute"), dict)
        print("PASS: node returns structured transaction execution and message flow")

        status, config_response = request_json(
            f"{rpc_origin}/jsonRPC",
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "getConfigParam",
                "params": {"param": 34},
            },
        )
        validator_set = config_response.get("result", {}).get("validator_set", {})
        assert status == 200
        assert validator_set.get("total") == len(validator_set.get("validators", []))
        assert validator_set.get("total", 0) > 0
        assert all(item.get("public_key") and item.get("weight") for item in validator_set["validators"])
        print("PASS: current validator membership and weights decode from proved configuration")

        if args.browser_command:
            browser_env = dict(os.environ)
            browser_env.update({
                "TOSCAN_REAL_RPC_ORIGIN": rpc_origin,
                "TOSCAN_REAL_SOURCE_ORIGIN": explorer_origin,
                "TOSCAN_REAL_SEED_MANIFEST": str(manifest),
            })
            subprocess.run(
                args.browser_command,
                cwd=REPO,
                shell=True,
                check=True,
                env=browser_env,
            )
            print("PASS: real-chain browser journey")

        before = request_json(f"{explorer_origin}/explorer/status")[1]["result"]
        stop(explorer)
        explorer = start(
            [str(tosctl), "explorer", "-c", str(config)],
            REPO,
            workdir / "explorer-restart.log",
        )
        wait_until(
            "explorer restarts against the durable index",
            lambda: request_json(f"{explorer_origin}/health")[0] == 200,
            timeout=45,
        )
        after = request_json(f"{explorer_origin}/explorer/status")[1]["result"]
        assert after["blocks"] >= before["blocks"]
        assert after["transactions"] >= before["transactions"]
        assert after["contracts"] == before["contracts"] == 6
        print("PASS: restart preserves block, transaction and contract discovery")
        print("TOSCAN REAL-CHAIN GATE: PASS")
    except Exception:
        for name in ("node.log", "explorer.log", "explorer-restart.log"):
            path = workdir / name
            if path.exists():
                print(f"\n--- {name} (tail) ---", file=sys.stderr)
                print("".join(path.read_text(errors="replace").splitlines(True)[-80:]), file=sys.stderr)
        raise
    finally:
        stop(explorer)
        stop(node)


if __name__ == "__main__":
    main()
