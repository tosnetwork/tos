#!/usr/bin/env python3
"""Exercise one launch-facing tosctl first-stake caller, not a fixture signer.

The fixture only provisions the chain, the support pools and funds. The product
CLI creates its operator wallet before Genesis, so the spare node can be
configured with that wallet as its validator id, then activates it. The selected
caller (interactive command or election daemon) asks the node to authorize the
wallet as the stake's sender and sends the stake straight to the Elector.
Neither mode is a production-duration or independently hosted network claim.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "test/tostester/src"))
from pytosiq_core import Address, Cell  # noqa: E402
from tostester.install import Install  # noqa: E402
from tostester.pq_election_fixture import (  # noqa: E402
    NEW_STAKE_OP,
    STAKE_ACCEPTED_OP,
    parse_stake_order,
)

spec = importlib.util.spec_from_file_location(
    "nominator_pool_lifecycle", REPO / "scripts/nominator-pool-lifecycle-e2e.py"
)
assert spec is not None and spec.loader is not None
lifecycle_module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = lifecycle_module
spec.loader.exec_module(lifecycle_module)

NANO = 1_000_000_000
STAKE = lifecycle_module.POOL_STAKE_VALUE
# Covers the wallet's activation, the stake message's forwarding and its gas.
PRODUCT_WALLET_FEES = 100 * NANO
# The spare node is outside Genesis, so its validator id can be the wallet the
# product CLI creates.
PRODUCT_NODE = 4
PRODUCT_BINDING = "validator-5"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reserve_ports(*ports: int) -> None:
    reservations = []
    try:
        for port in ports:
            sock = socket.socket()
            sock.bind(("127.0.0.1", port))
            reservations.append(sock)
    finally:
        for sock in reservations:
            sock.close()


def wallet_elector_stakes(transactions: list, wallet: Address) -> list[tuple[int, bytes]]:
    """Each NEW_STAKE the product wallet sent straight to the Elector: (query ID, ADNL).

    The ADNL comes from the body the Elector parsed, because the CLI may create a
    fresh transport address rather than use the fixture's.
    """
    stakes = []
    for raw in transactions:
        message = lifecycle_module._decoded_transaction(raw).in_msg
        if (
            message is None
            or not isinstance(message.info, lifecycle_module.InternalMsgInfo)
            or message.info.src != wallet
        ):
            continue
        view = message.body.begin_parse()
        if view.remaining_bits < 96 or view.load_uint(32) != NEW_STAKE_OP:
            continue
        order = parse_stake_order(message.body, with_amount=False)
        stakes.append((order.query_id, order.adnl_addr))
    return stakes


def created_wallet_address(output: str) -> Address:
    lines = [line.split()[-1] for line in output.splitlines() if line.strip().startswith("Address:")]
    if len(lines) != 1:
        raise RuntimeError(f"tosctl wallet create printed {len(lines)} addresses")
    return Address(lines[0])


def observed_json_rpc(address: str, method: str, params: dict) -> dict:
    """Keep the exact JSON-RPC error envelope rather than a generic failure."""
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        f"http://{address}/jsonRPC",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            raw = response.read().decode(errors="replace")
            return {
                "http_status": response.status,
                "raw_response": raw,
                "response": json.loads(raw),
            }
    except urllib.error.HTTPError as error:
        raw = error.read().decode(errors="replace")
        return {"http_status": error.code, "raw_response": raw, "response": json.loads(raw)}


async def cli(
    binary: Path,
    config: Path,
    env: dict[str, str],
    *args: str,
    answers: bytes = b"",
    timeout: int = 120,
) -> str:
    process = await asyncio.create_subprocess_exec(
        str(binary),
        *args,
        "-c",
        str(config),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        out, err = await asyncio.wait_for(process.communicate(answers), timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        raise RuntimeError(f"tosctl {' '.join(args)} timed out")
    output = (out + err).decode(errors="replace")
    if process.returncode:
        raise RuntimeError(f"tosctl {' '.join(args)} exited {process.returncode}: {output[-3000:]}")
    return output


async def product_run(args: argparse.Namespace, run_dir: Path, report: dict) -> None:
    life = lifecycle_module.PoolLifecycle(
        Install(args.build_dir, REPO),
        run_dir,
        args.base_port,
        campaign_run_id="pq-config-wallet-product-first-stake",
        product_rpc_address=f"127.0.0.1:{args.rpc_port}",
    )
    # tosctl refuses to write its configuration and vault under a
    # group-writable checkout; evidence stays in run_dir.
    from tostester.private_dir import make_private_dir

    private_dir = make_private_dir("pq-config-wallet-first-stake")
    report["tosctl_private_dir"] = str(private_dir)
    config = private_dir / "tosctl-config.json"
    binary = args.tosctl.resolve()
    vault = private_dir / "product-vault.json"
    env = dict(os.environ)
    env["VAULT_URL"] = f"file://{vault}?master_key={'0' * 63}1"
    daemon = None
    daemon_log = None
    report["source_commit"] = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
    ).strip()
    report["binary_sha256"] = {
        "tosctl": sha256(binary),
        "validator_engine": sha256(life.install.validator_engine_exe),
    }
    report["caller"] = args.caller
    report["claim_boundary"] = (
        f"one product {args.caller} first stake sent by the operator wallet straight to the "
        "Elector on an accelerated co-located PQ chain; no other caller or scale claim"
    )
    report["test_only_genesis_faucet_nanotos"] = 150_000 * NANO
    try:
        life.artifacts_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [str(binary), "config", "generate", "-o", str(config)],
            check=True,
            capture_output=True,
            text=True,
        )
        config.chmod(0o600)
        # The wallet key and address exist before Genesis: the spare node is
        # configured with the wallet as its validator id, because the Elector
        # names a member by the account that sends its stake.
        wallet = created_wallet_address(
            await cli(
                binary,
                config,
                env,
                "wallet",
                "create",
                "--name",
                "operator",
                "--version",
                "V1R3",
                "--workchain=-1",
            )
        )
        report["product_wallet"] = lifecycle_module.raw_address(wallet)
        life.prepare_pq_election_fixture()
        life.stake_spare_directly(wallet)
        await life.bring_up_network()
        await life.fund_wallets()
        await life.deploy_pool()
        assert life.client is not None and life.network is not None
        node = life.nodes[PRODUCT_NODE]
        held = node.pq_initial_validator
        if held is None or held.validator_id != wallet.hash_part:
            raise AssertionError("the product node's validator id is not the product wallet")

        document = json.loads(config.read_text())
        document["chain_rpc"] = {
            "urls": [f"http://127.0.0.1:{args.rpc_port}/jsonRPC"],
            "api_key": None,
        }
        document["master_wallet"] = None
        document["nodes"][PRODUCT_BINDING] = {
            "server_address": node._engine_console_addr.address,
            "server_key": {
                "type_id": 0,
                "pub_key": base64.b64encode(
                    node._engine_console_server_key.public_key.key
                ).decode(),
            },
            "client_key": {
                "type_id": 0,
                "pvt_key": base64.b64encode(
                    node._engine_console_client_key.private_key.key
                ).decode(),
            },
            "timeouts": 10,
        }
        config.write_text(json.dumps(document, indent=2) + "\n")
        config.chmod(0o600)
        listed = json.loads(await cli(binary, config, env, "wallet", "ls", "--format", "json"))
        if Address(next(item["address"] for item in listed if item["name"] == "operator")) != wallet:
            raise AssertionError("tosctl lists the operator wallet at another address")
        faucet = life.network.zerostate.main_wallet(life.client)
        await life.send(
            faucet,
            dest=wallet,
            amount=STAKE + PRODUCT_WALLET_FEES,
            body=Cell.empty(),
            label="product-wallet-fund",
        )
        await life.retry(
            lambda: life.balance(wallet),
            timeout=60,
            description="product wallet funded",
            predicate=lambda value: value >= STAKE + PRODUCT_WALLET_FEES,
        )
        await cli(binary, config, env, "wallet", "activate", "--name", "operator")
        active = await life.retry(
            lambda: life.client.raw_get_account_state(wallet),
            timeout=60,
            description="product wallet active",
            predicate=lambda value: bool(value.code),
        )
        report["product_wallet_code_sha256"] = hashlib.sha256(active.code).hexdigest()

        document = json.loads(config.read_text())
        document["bindings"][PRODUCT_BINDING] = {
            "wallet": "operator",
            "enable": False,
            "status": "idle",
        }
        if args.caller == "daemon":
            document["master_wallet"] = document["wallets"]["operator"]
            document["bindings"][PRODUCT_BINDING]["enable"] = True
            document["elections"]["policy"] = "minimum"
            document["elections"]["tick_interval"] = 40
            document["tick_interval"] = 40
            document["http"]["bind"] = f"127.0.0.1:{args.service_port}"
        config.write_text(json.dumps(document, indent=2) + "\n")
        config.chmod(0o600)

        # The first election opens 180 s before the 1200 s Genesis set expires; this
        # fixture reaches here within a minute or two of Genesis.
        election = await life.retry(
            life.stakeable_election_id,
            timeout=1200,
            description="open Elector acceptance window",
            predicate=lambda value: value > 0,
            interval=1,
        )
        report["election_id"] = election
        # Preserve the node's actual TVM stack encoding before the product
        # CLI parses it. In particular FunC nil is not always a list entry.
        participant_raw = await asyncio.to_thread(
            lifecycle_module.json_rpc_call,
            f"127.0.0.1:{args.rpc_port}",
            "runGetMethodStd",
            {
                "address": lifecycle_module.raw_address(lifecycle_module.ELECTOR),
                "method": "participant_list_extended",
                "stack": [],
            },
        )
        participant_path = run_dir / "participant-list-extended-raw-open.json"
        participant_path.write_text(json.dumps(participant_raw, indent=2) + "\n")
        raw_stack = participant_raw["result"]["stack"]
        report["participant_list_raw"] = {
            "path": str(participant_path),
            "sha256": sha256(participant_path),
            "exit_code": participant_raw["result"]["exit_code"],
            "index4_type": raw_stack[4]["@type"],
        }
        elector_baseline = (
            await life.client.raw_get_account_state(lifecycle_module.ELECTOR)
        ).last_transaction_id
        wallet_baseline = (await life.client.raw_get_account_state(wallet)).last_transaction_id
        if elector_baseline is None or wallet_baseline is None:
            raise RuntimeError("cannot bound product stake transaction history")
        # The CLI may fail after the wallet message is included. Keep the
        # exact contract feedback in that case instead of ending observation
        # at the CLI exit code and losing the only causal evidence.
        cli_error = None
        if args.caller == "config-wallet":
            try:
                report["stake_cli_output"] = await cli(
                    binary,
                    config,
                    env,
                    "config",
                    "wallet",
                    "stake",
                    "--binding",
                    PRODUCT_BINDING,
                    "--amount",
                    f"{STAKE / NANO:.9f}",
                    answers=b"y\ny\n",
                    timeout=150,
                )
            except Exception as error:
                cli_error = error
                report["stake_cli_error"] = repr(error)
        else:
            log_path = run_dir / "tosctl-election-daemon.log"
            daemon_log = log_path.open("wb")
            daemon = await asyncio.create_subprocess_exec(
                str(binary),
                "service",
                "-c",
                str(config),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=daemon_log,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
            )
            report["daemon"] = {"pid": daemon.pid, "log_path": str(log_path)}
            deadline = time.monotonic() + 150
            while time.monotonic() < deadline:
                if daemon.returncode is not None:
                    raise RuntimeError(f"tosctl service exited before a stake: {daemon.returncode}")
                elector_probe, _, complete, _ = await lifecycle_module._transactions_since(
                    life.client, lifecycle_module.ELECTOR, elector_baseline
                )
                if not complete:
                    raise RuntimeError("daemon Elector transaction window is incomplete")
                if wallet_elector_stakes(elector_probe, wallet):
                    break
                await asyncio.sleep(1)
            else:
                raise RuntimeError("daemon did not send a wallet-to-Elector NEW_STAKE within 150s")
            log_text = log_path.read_text(errors="replace")
            if f"node [{PRODUCT_BINDING}] send stake" not in log_text:
                raise RuntimeError("Elector stake observed but daemon send-stake log is absent")
            report["daemon"]["send_stake_log_seen"] = True

        participant_params = {
            "address": lifecycle_module.raw_address(lifecycle_module.ELECTOR),
            "method": "participant_list_extended",
            "stack": [],
        }
        participant_after = None
        for attempt in range(5):
            try:
                observation = await asyncio.to_thread(
                    observed_json_rpc,
                    f"127.0.0.1:{args.rpc_port}",
                    "runGetMethodStd",
                    participant_params,
                )
            except Exception as error:
                observation = {"transport_error": repr(error)}
            attempt_path = run_dir / f"participant-list-after-attempt-{attempt}.json"
            attempt_path.write_text(json.dumps(observation, indent=2) + "\n")
            report.setdefault("participant_list_after_attempts", []).append(
                {
                    "path": str(attempt_path),
                    "sha256": sha256(attempt_path),
                }
            )
            participant_after = observation.get("response", {}).get("result")
            if participant_after is not None:
                report["participant_list_after_raw"] = {
                    "path": str(attempt_path),
                    "sha256": sha256(attempt_path),
                    "exit_code": participant_after.get("exit_code"),
                    "index4_type": participant_after["stack"][4]["@type"],
                }
                break
            if attempt < 4:
                await asyncio.sleep(2)
        if participant_after is None:
            report["participant_list_after_error"] = "all five JSON-RPC observations failed"
            elector_state = await life.client.raw_get_account_state(lifecycle_module.ELECTOR)
            report["elector_account_after_json_rpc_error"] = {
                "last_transaction_id": str(elector_state.last_transaction_id),
                "block_id": str(getattr(elector_state, "block_id", None)),
            }

        elector_txs, elector_pages, elector_complete, _ = (
            await lifecycle_module._transactions_since(
                life.client, lifecycle_module.ELECTOR, elector_baseline
            )
        )
        report["transaction_coverage"] = {
            "elector_count": len(elector_txs),
            "elector_pages": elector_pages,
            "elector_complete": elector_complete,
        }
        if not elector_complete:
            raise RuntimeError("product stake transaction window is incomplete")
        # A product first-stake acknowledgement must be located by the exact
        # query id of the wallet's stake as the Elector received it.
        stakes = wallet_elector_stakes(elector_txs, wallet)
        report["stake_feedback"] = {"elector_stake_query_ids": [query for query, _ in stakes]}
        if cli_error is not None and len(stakes) != 1:
            raise RuntimeError(
                f"product CLI failed before an exact Elector stake was observed: {cli_error}"
            )
        if len(stakes) != 1:
            raise RuntimeError(f"expected one product stake, found {len(stakes)}")
        query_id, adnl = stakes[0]
        # The Elector answers the sender, so its reply is in the wallet's history.
        # A CLI parse failure can occur before that answer arrives; give the exact
        # query a bounded observation window, and an absent answer at the boundary
        # is still inconclusive.
        reply = None
        wallet_txs: list = []
        wallet_pages = 0
        wallet_complete = False
        feedback_deadline = time.monotonic() + 45
        while True:
            wallet_txs, wallet_pages, wallet_complete, _ = (
                await lifecycle_module._transactions_since(life.client, wallet, wallet_baseline)
            )
            if not wallet_complete:
                raise RuntimeError("wallet feedback transaction window is incomplete")
            reply = lifecycle_module.elector_reply(wallet_txs, query_id)
            if reply is not None or time.monotonic() >= feedback_deadline:
                break
            await asyncio.sleep(1)
        for name, transactions in (("elector", elector_txs), ("wallet", wallet_txs)):
            path = run_dir / f"product-stake-{name}-transactions.json"
            path.write_text(json.dumps([tx.to_dict() for tx in transactions], indent=2) + "\n")
            report["transaction_coverage"][f"{name}_raw_path"] = str(path)
            report["transaction_coverage"][f"{name}_raw_sha256"] = sha256(path)
        report["transaction_coverage"].update(
            {
                "wallet_count": len(wallet_txs),
                "wallet_pages": wallet_pages,
                "wallet_complete": wallet_complete,
            }
        )
        report["stake_feedback"] = {
            "query_id": query_id,
            "elector_reply": reply,
            "elector_stake_seen": True,
            "feedback_window_seconds": 45,
            "classification": "ELECTOR_REPLY_OBSERVED" if reply is not None else "INCONCLUSIVE",
        }
        if daemon is not None:
            daemon.send_signal(signal.SIGINT)
            try:
                await asyncio.wait_for(daemon.wait(), 25)
            except TimeoutError:
                daemon.kill()
                await daemon.wait()
            daemon = None
            daemon_log.close()
            daemon_log = None
            report["daemon"]["log_sha256"] = sha256(log_path)
        if cli_error is not None:
            raise RuntimeError(f"product CLI failed after exact feedback capture: {cli_error}")
        if (
            args.caller == "config-wallet"
            and "Stake accepted by elector" not in report["stake_cli_output"]
        ):
            raise RuntimeError("product command did not report Elector participant acceptance")
        if reply is None or reply[0] != STAKE_ACCEPTED_OP:
            raise RuntimeError(f"exact Elector STAKE_ACCEPTED not observed: {reply}")

        for index in (1, 2, 3):
            await life.stake_support_pool(index, election)
        wallet_hex = wallet.hash_part.hex()
        selection = await life.retry(
            life.config34_selection,
            timeout=900,
            description="product wallet and ADNL paired in live Config34",
            predicate=lambda value: (
                value.utime_since == election
                and (wallet_hex, adnl.hex()) in value.validator_adnl_pairs
            ),
            interval=5,
        )
        report["live_config34"] = {
            "utime_since": selection.utime_since,
            "validator_id": wallet_hex,
            "adnl_id": adnl.hex(),
            "pairs": selection.validator_adnl_pairs,
        }
        config34_path = run_dir / "live-config34.txt"
        config34_path.write_text(await life.lite("time", "getconfig 34"))
        report["live_config34"]["raw_path"] = str(config34_path)
        report["live_config34"]["raw_sha256"] = sha256(config34_path)
        report["passed"] = True
    finally:
        if daemon is not None and daemon.returncode is None:
            daemon.send_signal(signal.SIGINT)
            try:
                await asyncio.wait_for(daemon.wait(), 25)
            except TimeoutError:
                daemon.kill()
                await daemon.wait()
        if daemon_log is not None:
            daemon_log.close()
        if args.caller == "daemon":
            log_path = run_dir / "tosctl-election-daemon.log"
            if log_path.exists():
                report.setdefault("daemon", {})["log_sha256"] = sha256(log_path)
        await life.shutdown()


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=REPO / "build")
    parser.add_argument("--tosctl", type=Path, default=REPO / "tosctl/src/target/debug/tosctl")
    parser.add_argument(
        "--run-root", type=Path, default=REPO / "test/integration/.pq-tosctl-config-wallet-product"
    )
    parser.add_argument("--base-port", type=int, default=25100)
    parser.add_argument("--rpc-port", type=int, default=25120)
    parser.add_argument("--service-port", type=int, default=25130)
    parser.add_argument("--caller", choices=("config-wallet", "daemon"), default="config-wallet")
    args = parser.parse_args()
    reserve_ports(*range(args.base_port, args.base_port + 17), args.rpc_port, args.service_port)
    run_dir = (args.run_root / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")).resolve()
    run_dir.mkdir(parents=True, exist_ok=False)
    report = {
        "schema": "tos.pq.product-first-stake.v3",
        "passed": False,
        "run_dir": str(run_dir),
        "failures": [],
    }
    try:
        await product_run(args, run_dir, report)
    except Exception as error:  # preserve raw artifacts and bounded failure
        report["failures"].append(repr(error))
    finally:
        (run_dir / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"report={run_dir / 'report.json'} passed={report['passed']}", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
