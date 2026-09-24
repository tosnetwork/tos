#!/usr/bin/env python3
"""Exercise the launch-facing tosctl config-wallet stake, not a fixture signer.

The fixture only provisions the chain, admitted controllers, pools and funds.
The product CLI creates/activates its own wallet, imports the controller's
actual deployment transaction, asks the node to authorize, and sends the stake.
This run is not a production-duration or independently hosted network claim.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "test/tostester/src"))
from pytosiq_core import Address, Cell  # noqa: E402
from tostester.install import Install  # noqa: E402
from tostester.pq_election_fixture import make_pool_fixture  # noqa: E402

spec = importlib.util.spec_from_file_location(
    "nominator_pool_lifecycle", REPO / "scripts/nominator-pool-lifecycle-e2e.py"
)
assert spec is not None and spec.loader is not None
lifecycle_module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = lifecycle_module
spec.loader.exec_module(lifecycle_module)

NANO = 1_000_000_000
STAKE = lifecycle_module.POOL_STAKE_VALUE


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


def adnl_from_controller_relay(transactions: list, pool: Address, query_id: int) -> bytes:
    """Read the ADNL address from the exact on-chain pool→controller message."""
    matching = []
    for raw in transactions:
        tx = lifecycle_module._decoded_transaction(raw)
        message = tx.in_msg
        if (message is None or not isinstance(message.info, lifecycle_module.InternalMsgInfo)
                or message.info.src != pool):
            continue
        body = message.body.begin_parse()
        if body.remaining_bits < 32 + 64 + 32 + 32 + 256 + 16:
            continue
        if body.load_uint(32) != 0x5051726C or body.load_uint(64) != query_id:
            continue
        body.load_uint(32)  # stake_at
        body.load_uint(32)  # max_factor
        matching.append(body.load_uint(256).to_bytes(32, "big"))
    if len(matching) != 1:
        raise RuntimeError(f"expected one exact controller relay, found {len(matching)}")
    return matching[0]


async def cli(binary: Path, config: Path, env: dict[str, str], *args: str,
              answers: bytes = b"", timeout: int = 120) -> str:
    process = await asyncio.create_subprocess_exec(
        str(binary), *args, "-c", str(config), stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env,
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
        Install(args.build_dir, REPO), run_dir, args.base_port,
        campaign_run_id="pq-config-wallet-product-first-stake",
        product_rpc_address=f"127.0.0.1:{args.rpc_port}",
    )
    config = run_dir / "tosctl-config.json"
    binary = args.tosctl.resolve()
    vault = run_dir / "product-vault.json"
    env = dict(os.environ)
    env["VAULT_URL"] = f"file://{vault}?master_key={'0' * 63}1"
    report["source_commit"] = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
    ).strip()
    report["binary_sha256"] = {
        "tosctl": sha256(binary),
        "validator_engine": sha256(life.install.validator_engine_exe),
    }
    report["claim_boundary"] = (
        "one product config-wallet first stake through a real pool/controller on an "
        "accelerated co-located PQ chain; no daemon caller or scale claim"
    )
    report["test_only_genesis_faucet_nanotos"] = 150_000 * NANO
    try:
        life.artifacts_dir.mkdir(parents=True, exist_ok=True)
        life.prepare_pq_election_fixture()
        await life.bring_up_network()
        await life.fund_wallets()
        await life.deploy_pool()
        assert life.client is not None and life.network is not None

        # Import the *chain's* original deployment transaction, not the
        # fixture's in-memory StateInit. The import command verifies account,
        # destination, status, and original StateInit before saving the BOC.
        controller = life.controllers[0]
        state = await life.client.raw_get_account_state(controller.address)
        assert state.last_transaction_id is not None
        history = await life.client.raw_get_transactions(
            controller.address, state.last_transaction_id
        )
        if len(history.transactions) != 1:
            raise RuntimeError(
                "controller has more than one transaction before product stake; "
                "deployment transaction selection must be made explicitly"
            )
        deployment_tx = history.transactions[0]
        deployment_path = run_dir / "controller-deployment-transaction.boc"
        deployment_path.write_bytes(deployment_tx.data)
        report["deployment_transaction"] = {
            "path": str(deployment_path), "sha256": sha256(deployment_path),
            "lt": str(deployment_tx.transaction_id.lt),
            "hash": deployment_tx.transaction_id.hash.hex(),
        }

        subprocess.run(
            [str(binary), "config", "generate", "-o", str(config)],
            check=True, capture_output=True, text=True,
        )
        document = json.loads(config.read_text())
        document["chain_rpc"] = {
            "urls": [f"http://127.0.0.1:{args.rpc_port}/jsonRPC"], "api_key": None
        }
        document["master_wallet"] = None
        document["nodes"]["validator-1"] = {
            "server_address": life.nodes[0]._engine_console_addr.address,
            "server_key": {
                "type_id": 0,
                "pub_key": base64.b64encode(
                    life.nodes[0]._engine_console_server_key.public_key.key
                ).decode(),
            },
            "client_key": {
                "type_id": 0,
                "pvt_key": base64.b64encode(
                    life.nodes[0]._engine_console_client_key.private_key.key
                ).decode(),
            },
            "timeouts": 10,
        }
        config.write_text(json.dumps(document, indent=2) + "\n")
        config.chmod(0o600)
        await cli(binary, config, env, "wallet", "create", "--name", "operator",
                  "--version", "V1R3", "--workchain=-1")
        listed = json.loads(await cli(binary, config, env, "wallet", "ls", "--format", "json"))
        wallet_text = next(item["address"] for item in listed if item["name"] == "operator")
        wallet = Address(wallet_text)
        report["product_wallet"] = lifecycle_module.raw_address(wallet)
        faucet = life.network.zerostate.main_wallet(life.client)
        await life.send(faucet, dest=wallet, amount=100 * NANO,
                        body=Cell.empty(), label="product-wallet-fund")
        await cli(binary, config, env, "wallet", "activate", "--name", "operator")
        active = await life.retry(
            lambda: life.client.raw_get_account_state(wallet), timeout=60,
            description="product wallet active", predicate=lambda value: bool(value.code),
        )
        report["product_wallet_code_sha256"] = hashlib.sha256(active.code).hexdigest()

        pool = make_pool_fixture(life.single_pool_code, wallet, controller.address)
        await life.send(faucet, dest=pool.address, amount=10 * NANO,
                        body=Cell.empty(), init=pool.state_init,
                        label="product-single-pool-deploy")
        await life.retry(
            lambda: life.client.raw_get_account_state(pool.address), timeout=60,
            description="product single-nominator pool active",
            predicate=lambda value: bool(value.code),
        )
        # Capital provisioning is fixture work, not the product stake path.
        # The real operator wallet must still authorize and send the stake.
        await life.send(faucet, dest=pool.address,
                        amount=lifecycle_module.SUPPORT_POOL_CAPITAL,
                        body=Cell.empty(), label="product-single-pool-capital")
        pool_capital = await life.retry(
            lambda: life.balance(pool.address), timeout=60,
            description="product pool capital", predicate=lambda value: value >= STAKE,
        )
        report["product_pool_capital_nanotos"] = pool_capital

        document = json.loads(config.read_text())
        document["pools"]["product-pool"] = {
            "kind": "snp", "address": lifecycle_module.raw_address(pool.address),
            "owner": lifecycle_module.raw_address(wallet),
            "controller": lifecycle_module.raw_address(controller.address),
        }
        document["bindings"]["validator-1"] = {
            "wallet": "operator", "pool": "product-pool", "enable": False,
            "status": "idle",
        }
        config.write_text(json.dumps(document, indent=2) + "\n")
        birth = run_dir / "controller-birth-state-init.boc"
        report["birth_import_output"] = await cli(
            binary, config, env, "config", "bind", "import-birth", "--node",
            "validator-1", "--transaction-boc", str(deployment_path), "--output", str(birth),
        )
        report["birth_artifact"] = {"path": str(birth), "sha256": sha256(birth)}
        document = json.loads(config.read_text())
        if document["bindings"]["validator-1"]["controller_birth_state_init_boc"] != str(birth):
            raise AssertionError("import did not bind birth artifact to product operator config")
        report["live_param47"] = {
            "admitted_code_hash": life.controller_code.hash.hex(),
            "read_back": True,  # life.bring_up_network verified the complete live dictionary
        }
        param47_path = run_dir / "live-config47.txt"
        param47_path.write_text(await life.lite("time", "getconfig 47"))
        report["live_param47"]["raw_path"] = str(param47_path)
        report["live_param47"]["raw_sha256"] = sha256(param47_path)

        election = await life.retry(
            life.stakeable_election_id, timeout=900,
            description="open Elector acceptance window",
            predicate=lambda value: value > 0, interval=1,
        )
        report["election_id"] = election
        # Preserve the node's actual TVM stack encoding before the product
        # CLI parses it. In particular FunC nil is not always a list entry.
        participant_raw = await asyncio.to_thread(
            lifecycle_module.json_rpc_call,
            f"127.0.0.1:{args.rpc_port}", "runGetMethodStd",
            {"address": lifecycle_module.raw_address(lifecycle_module.ELECTOR),
             "method": "participant_list_extended", "stack": []},
        )
        participant_path = run_dir / "participant-list-extended-raw-open.json"
        participant_path.write_text(json.dumps(participant_raw, indent=2) + "\n")
        raw_stack = participant_raw["result"]["stack"]
        report["participant_list_raw"] = {
            "path": str(participant_path), "sha256": sha256(participant_path),
            "exit_code": participant_raw["result"]["exit_code"],
            "index4_type": raw_stack[4]["@type"],
        }
        pool_baseline = (await life.client.raw_get_account_state(pool.address)).last_transaction_id
        controller_baseline = (
            await life.client.raw_get_account_state(controller.address)
        ).last_transaction_id
        if pool_baseline is None or controller_baseline is None:
            raise RuntimeError("cannot bound product stake transaction history")
        # The CLI may fail after the wallet message is included. Keep the
        # exact contract feedback in that case instead of ending observation
        # at the CLI exit code and losing the only causal evidence.
        cli_error = None
        try:
            report["stake_cli_output"] = await cli(
                binary, config, env, "config", "wallet", "stake", "--binding", "validator-1",
                "--amount", f"{STAKE / NANO:.9f}", answers=b"y\ny\n", timeout=150,
            )
        except Exception as error:
            cli_error = error
            report["stake_cli_error"] = repr(error)

        participant_after = await asyncio.to_thread(
            lifecycle_module.json_rpc_call,
            f"127.0.0.1:{args.rpc_port}", "runGetMethodStd",
            {"address": lifecycle_module.raw_address(lifecycle_module.ELECTOR),
             "method": "participant_list_extended", "stack": []},
        )
        participant_after_path = run_dir / "participant-list-extended-raw-after-cli.json"
        participant_after_path.write_text(json.dumps(participant_after, indent=2) + "\n")
        report["participant_list_after_cli_raw"] = {
            "path": str(participant_after_path),
            "sha256": sha256(participant_after_path),
            "exit_code": participant_after["result"]["exit_code"],
            "index4_type": participant_after["result"]["stack"][4]["@type"],
        }

        pool_txs, pool_pages, pool_complete, _ = await lifecycle_module._transactions_since(
            life.client, pool.address, pool_baseline
        )
        controller_txs, controller_pages, controller_complete, _ = (
            await lifecycle_module._transactions_since(
                life.client, controller.address, controller_baseline
            )
        )
        report["transaction_coverage"] = {
            "pool_count": len(pool_txs), "pool_pages": pool_pages,
            "pool_complete": pool_complete, "controller_count": len(controller_txs),
            "controller_pages": controller_pages, "controller_complete": controller_complete,
        }
        for name, transactions in (("pool", pool_txs), ("controller", controller_txs)):
            path = run_dir / f"product-stake-{name}-transactions.json"
            path.write_text(json.dumps([tx.to_dict() for tx in transactions], indent=2) + "\n")
            report["transaction_coverage"][f"{name}_raw_path"] = str(path)
            report["transaction_coverage"][f"{name}_raw_sha256"] = sha256(path)
        if not pool_complete or not controller_complete:
            raise RuntimeError("product stake transaction window is incomplete")
        # A product first-stake acknowledgement must be located by the exact
        # query id extracted from the pool's order, then joined to the Elector.
        orders = []
        for tx in pool_txs:
            decoded = lifecycle_module._decoded_transaction(tx)
            msg = decoded.in_msg
            if msg is None or not isinstance(msg.info, lifecycle_module.InternalMsgInfo):
                continue
            cursor = msg.body.begin_parse()
            if cursor.remaining_bits >= 96 and cursor.load_uint(32) == 0x4E73744B:
                orders.append(cursor.load_uint(64))
        report["stake_feedback"] = {"pool_order_query_ids": orders}
        if cli_error is not None and len(orders) != 1:
            raise RuntimeError(f"product CLI failed before an exact pool order was observed: {cli_error}")
        if len(orders) != 1:
            raise RuntimeError(f"expected one product stake order, found {len(orders)}")
        query_id = orders[0]
        # The Elector acknowledges the stake owner (the pool), not the
        # relaying controller. The controller history proves forwarding;
        # the pool history carries the exact acceptance/refusal reply.
        reply = lifecycle_module.elector_reply(pool_txs, query_id)
        # A CLI parse failure can occur before the asynchronous Elector answer
        # reaches the controller. Give that exact query a bounded observation
        # window; an absent answer at the boundary is still inconclusive.
        feedback_deadline = time.monotonic() + 45
        while reply is None and time.monotonic() < feedback_deadline:
            await asyncio.sleep(1)
            pool_txs, pool_pages, pool_complete, _ = (
                await lifecycle_module._transactions_since(
                    life.client, pool.address, pool_baseline
                )
            )
            if not pool_complete:
                raise RuntimeError("pool feedback transaction window is incomplete")
            reply = lifecycle_module.elector_reply(pool_txs, query_id)
        pool_path = run_dir / "product-stake-pool-transactions.json"
        pool_path.write_text(
            json.dumps([tx.to_dict() for tx in pool_txs], indent=2) + "\n"
        )
        report["transaction_coverage"].update({
            "pool_count": len(pool_txs), "pool_pages": pool_pages,
            "pool_complete": pool_complete,
            "pool_raw_sha256": sha256(pool_path),
        })
        report["stake_feedback"] = {
            "query_id": query_id, "elector_reply": reply,
            "pool_order_seen": True,
            "feedback_window_seconds": 45,
            "classification": "ELECTOR_REPLY_OBSERVED" if reply is not None else "INCONCLUSIVE",
        }
        if cli_error is not None:
            raise RuntimeError(f"product CLI failed after exact feedback capture: {cli_error}")
        if "Stake accepted by elector" not in report["stake_cli_output"]:
            raise RuntimeError("product command did not report Elector participant acceptance")
        if reply is None or reply[0] != 0xF374484C:
            raise RuntimeError(f"exact Elector STAKE_ACCEPTED not observed: {reply}")

        for index in (1, 2, 3):
            await life.stake_support_pool(index, election)
        controller_hex = controller.address.hash_part.hex()
        # The CLI may generate a fresh Ed25519 transport address. Read the
        # actual controller relay message, not fixture node.validator_key.
        adnl = adnl_from_controller_relay(controller_txs, pool.address, query_id)
        selection = await life.retry(
            life.config34_selection, timeout=900,
            description="product controller and ADNL paired in live Config34",
            predicate=lambda value: value.utime_since == election and
            (controller_hex, adnl.hex()) in value.validator_adnl_pairs,
            interval=5,
        )
        report["live_config34"] = {
            "utime_since": selection.utime_since,
            "controller_id": controller_hex, "adnl_id": adnl.hex(),
            "pairs": selection.validator_adnl_pairs,
        }
        config34_path = run_dir / "live-config34.txt"
        config34_path.write_text(await life.lite("time", "getconfig 34"))
        report["live_config34"]["raw_path"] = str(config34_path)
        report["live_config34"]["raw_sha256"] = sha256(config34_path)
        report["passed"] = True
    finally:
        await life.shutdown()


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=REPO / "build")
    parser.add_argument("--tosctl", type=Path, default=REPO / "tosctl/src/target/debug/tosctl")
    parser.add_argument("--run-root", type=Path,
                        default=REPO / "test/integration/.pq-tosctl-config-wallet-product")
    parser.add_argument("--base-port", type=int, default=25100)
    parser.add_argument("--rpc-port", type=int, default=25120)
    args = parser.parse_args()
    reserve_ports(*range(args.base_port, args.base_port + 17), args.rpc_port)
    run_dir = (args.run_root / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")).resolve()
    run_dir.mkdir(parents=True, exist_ok=False)
    report = {"schema": "tos.pq.config-wallet-first-stake.v1", "passed": False,
              "run_dir": str(run_dir), "failures": []}
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
