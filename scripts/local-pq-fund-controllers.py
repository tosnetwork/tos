#!/usr/bin/env python3
"""Deploy and authorize the local development validator controllers.

A controller forwards a stake to the Elector only within an explicit
root-signed operating authorization (controller action kind 4). This tool
deploys each candidate controller of a `setup-testnet.sh --rotate` network,
signs that authorization with the disposable development root seed and
submits it from the Genesis wallet, which it binds as payer, then tops up
ordinary capital so the controller can cover its recorded funds plus floor.

Development only: the root seeds are deterministic fixtures and the Genesis
wallet is a local faucet. Run it while `tos-pq-elections` is held: the
election service owns the Genesis wallet whenever it runs.

    sudo env PYTHONPATH=test/tostester/src:scripts .venv/bin/python \
      scripts/local-pq-fund-controllers.py [--check]

The tool is idempotent: a controller whose authorization is unexpired for at
least `--min-remaining` seconds and still covers `--min-funds` is left alone.
"""

import argparse
import asyncio
import base64
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import local_pq_testnet as local
import nacl.signing
from contract import WalletV1
from pytosiq_core import (
    Address,
    Builder,
    Cell,
    InternalMsgInfo,
    MessageAny,
    StateInit,
    WalletMessage,
)
from pytosiq_core.tlb.block import CurrencyCollection
from tosapi import tos_api

from toslib import ToslibCDLL, ToslibClient

DATA = Path("/data")
ELECTIONS = DATA / "elections"
REPO = Path(__file__).resolve().parents[1]
NANO = 10**9
COINS_LIMIT = 1 << 120
CANDIDATES = (1, 2, 3, 4, 7)
# Bounded by the contract: an authorization may be valid at most this far ahead.
AUTHORIZATION_WINDOW = 600


def coins(value, name):
    if not isinstance(value, int) or value <= 0 or value >= COINS_LIMIT:
        raise ValueError(f"{name} must be a positive amount below 2^120 nano-TOS, got {value}")
    return value


def operating_payload(payer: Address, deposit, allowance, limit, floor, expires) -> Cell:
    """Kind 4 payload: payer, deposit, allowance, per-request limit, floor, expiry."""
    if not 0 < expires < 1 << 32:
        raise ValueError("sponsorship expiry must fit in 32 bits")
    return (
        Builder()
        .store_address(payer)
        .store_coins(coins(deposit, "deposit"))
        .store_coins(coins(allowance, "allowance"))
        .store_coins(coins(limit, "per-request limit"))
        .store_coins(coins(floor, "storage floor"))
        .store_uint(expires, 32)
        .end_cell()
    )


def runmethod(address: Address, method: str) -> list[str]:
    proc = subprocess.run(
        [
            str(local.INSTALLED_LITE_CLIENT),
            "-C",
            str(DATA / "configs/node-1-lite.json"),
            "-v",
            "0",
            "-c",
            f"runmethod {address.to_str(is_user_friendly=False)} {method}",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    match = re.search(r"^result:\s*\[(.*)\]\s*$", proc.stdout, re.MULTILINE)
    if proc.returncode or match is None:
        raise ValueError(f"{method} on {address.to_str(is_user_friendly=False)} did not answer")
    return match[1].split()


def operating_state(controller: Address) -> dict:
    values = runmethod(controller, "operating_state")
    names = ("funds", "allowance", "limit", "floor", "expires")
    return {name: int(value) for name, value in zip(names, values[:5], strict=True)}


def controller_state(controller: Address) -> tuple[int, int]:
    values = runmethod(controller, "controller_state")
    return int(values[0]), int(values[1])


def sign(
    seed: Path, global_id: int, controller: Address, epoch: int, nonce: int, payload: Cell
) -> Cell:
    tool = local.require_installed_executable(Path("/usr/local/bin/tos-pq-controller"))
    proc = subprocess.run(
        [
            str(tool),
            "fund-operations",
            str(seed),
            str(global_id),
            controller.hash_part.hex(),
            str(epoch),
            str(nonce),
            str(int(time.time()) + AUTHORIZATION_WINDOW),
            base64.b64encode(payload.to_boc()).decode(),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode:
        raise RuntimeError(f"controller signer refused: {proc.stderr.strip()[-500:]}")
    return Cell.one_from_boc(base64.b64decode(proc.stdout.strip()))


async def wait(predicate, timeout=60):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if await predicate():
            return
        await asyncio.sleep(0.5)
    raise TimeoutError("transaction was not observed in time")


async def send(wallet, dest, amount_nano, body=None, init=None):
    seq = (await wallet.current).seqno
    message = WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True,
                bounce=False,
                bounced=False,
                src=wallet.address,
                dest=dest,
                value=CurrencyCollection(tomis=coins(amount_nano, "message value")),
                ihr_fee=0,
                fwd_fee=0,
                created_lt=0,
                created_at=0,
            ),
            init=init,
            body=body if body is not None else Cell.empty(),
        ),
    )
    await wallet.send(message, seqno=seq)

    async def included():
        return (await wallet.current).seqno >= seq + 1

    await wait(included)


async def balance(client, address: Address) -> int:
    return int((await client.raw_get_account_state(address)).balance)


async def main(args) -> int:
    local.require_installed_executable(local.INSTALLED_LITE_CLIENT)
    network = json.loads((DATA / "network.json").read_text())
    global_id = int(network["global_id"])
    deposit = coins(args.deposit * NANO, "deposit")
    allowance = coins(args.allowance * NANO, "allowance")
    limit = coins(args.per_request_limit * NANO, "per-request limit")
    floor = coins(args.floor * NANO, "storage floor")
    margin = coins(args.capital_margin * NANO, "capital margin")
    cdll = ToslibCDLL(REPO / "build/toslib/libtoslibjson.so")
    cdll.client_set_verbosity_level(0)
    config = tos_api.Liteclient_config_global.from_dict(
        json.loads((DATA / "configs/node-1-lite.json").read_text())
    )
    async with ToslibClient(config, cdll) as client:
        wallet = WalletV1(
            client,
            Address(network["genesis_wallet_address"]),
            nacl.signing.SigningKey((DATA / "testnet/state/main-wallet.pk").read_bytes()),
        )
        for i in CANDIDATES:
            candidate = json.loads((ELECTIONS / f"candidate-{i}.json").read_text())
            controller = Address(candidate["controller"])
            init = StateInit.deserialize(
                Cell.one_from_boc(base64.b64decode(candidate["state_init_b64"])).begin_parse()
            )
            if not (await client.raw_get_account_state(controller)).code:
                if args.check:
                    print(json.dumps({"node": i, "deployed": False}))
                    continue
                await send(wallet, controller, 10 * NANO, init=init)

                async def deployed():
                    raw = await client.raw_get_account_state(controller)
                    return bool(raw.code) and Cell.one_from_boc(raw.code).hash == init.code.hash

                await wait(deployed)
            state = operating_state(controller)
            now = int(time.time())
            current = state["expires"] > now + args.min_remaining and min(
                state["funds"], state["allowance"]
            ) >= coins(args.min_funds * NANO, "minimum funds")
            if not current and not args.check:
                epoch, nonce = controller_state(controller)
                expires = now + args.sponsorship_seconds
                payload = operating_payload(
                    wallet.address, deposit, allowance, limit, floor, expires
                )
                body = sign(
                    ELECTIONS / f"keys/root-{i}.seed", global_id, controller, epoch, nonce, payload
                )
                # The contract refunds what exceeds the deposit and its processing fee.
                await send(
                    wallet,
                    controller,
                    deposit + coins(args.processing_fee * NANO, "processing fee"),
                    body=body,
                )

                async def accepted(nonce=nonce):
                    return controller_state(controller)[1] == nonce + 1

                try:
                    await wait(accepted)
                except TimeoutError as exc:
                    raise RuntimeError(
                        f"controller {i} did not accept the authorization; inspect its last "
                        "transaction before retrying, do not resend blindly"
                    ) from exc
                state = operating_state(controller)
                if (state["allowance"], state["limit"], state["floor"], state["expires"]) != (
                    allowance,
                    limit,
                    floor,
                    expires,
                ) or state["funds"] < deposit:
                    raise RuntimeError(f"controller {i} operating state differs: {state}")
            need = state["funds"] + state["floor"] + margin
            have = await balance(client, controller)
            if have < need and not args.check:
                await send(wallet, controller, need - have)
                have = await balance(client, controller)
            print(
                json.dumps(
                    {
                        "node": i,
                        "controller": controller.to_str(is_user_friendly=False),
                        "operating_state": state,
                        "balance": have,
                        "covers_funds_plus_floor": have >= state["funds"] + state["floor"],
                    }
                ),
                flush=True,
            )
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="report only, send nothing")
    parser.add_argument("--deposit", type=int, default=1000, help="operating deposit, TOS")
    parser.add_argument("--allowance", type=int, default=1000, help="spending allowance, TOS")
    parser.add_argument("--per-request-limit", type=int, default=20, help="TOS")
    parser.add_argument("--floor", type=int, default=10, help="storage floor, TOS")
    parser.add_argument("--capital-margin", type=int, default=20, help="TOS above funds plus floor")
    parser.add_argument("--processing-fee", type=int, default=20, help="TOS sent above the deposit")
    parser.add_argument("--sponsorship-seconds", type=int, default=30 * 86400)
    parser.add_argument("--min-remaining", type=int, default=86400, help="re-authorize below this")
    parser.add_argument("--min-funds", type=int, default=100, help="re-authorize below this, TOS")
    sys.exit(asyncio.run(main(parser.parse_args())))
