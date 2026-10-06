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

Funding is by deficit. The contract adds a deposit to the recorded funds and
replaces every other field, so the tool deposits only `funds_target - funds`
and resets the allowance to its target. It renews only when the
authorization expires within `--renew-days`, or when funds or allowance fall
below `--renew-percent` of their target. A healthy controller gets no
transaction, so the tool is safe to run repeatedly.

The defaults suit the ten-minute `--rotate` profile, where nodes 1, 2 and 3
relay a stake every round. At about 6.44 TOS per relay that is about 930 TOS
per controller per day, so a 50,000 TOS target lasts about 54 days, longer
than the 30-day sponsorship.
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

from toslib import ToslibCDLL, ToslibClient

DATA = Path("/data")
ELECTIONS = DATA / "elections"
REPO = Path(__file__).resolve().parents[1]
NANO = 10**9
COINS_LIMIT = 1 << 120
CANDIDATES = (1, 2, 3, 4, 7)
# Bounded by the contract: an authorization may be valid at most this far ahead.
AUTHORIZATION_WINDOW = 600


def coins(value, name, *, allow_zero=False):
    low = 0 if allow_zero else 1
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value < COINS_LIMIT:
        raise ValueError(f"{name} must be an amount in [{low}, 2^120) nano-TOS, got {value}")
    return value


def plan_renewal(
    state, now, *, funds_target, allowance_target, limit, renew_percent, renew_seconds
):
    """Return the deposit to send, or None when the authorization is healthy.

    The deposit tops funds up to the target; it is zero when only the expiry
    or the allowance needs renewing. Funds above the target are never touched.
    """
    coins(funds_target, "funds target")
    coins(allowance_target, "allowance target")
    coins(limit, "per-request limit")
    if limit > min(funds_target, allowance_target):
        raise ValueError("per-request limit exceeds the funds or allowance target")
    if not 0 < renew_percent < 100:
        raise ValueError("renew percent must be between 0 and 100")
    funds, allowance = state["funds"], state["allowance"]
    healthy = (
        state["expires"] > now + renew_seconds
        and state["limit"] == limit
        and funds * 100 >= funds_target * renew_percent
        and allowance * 100 >= allowance_target * renew_percent
    )
    if healthy:
        return None
    return max(0, funds_target - funds)


def operating_payload(payer: Address, deposit, allowance, limit, floor, expires) -> Cell:
    """Kind 4 payload: payer, deposit, allowance, per-request limit, floor, expiry."""
    if not 0 < expires < 1 << 32:
        raise ValueError("sponsorship expiry must fit in 32 bits")
    return (
        Builder()
        .store_address(payer)
        .store_coins(coins(deposit, "deposit", allow_zero=True))
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


def election_service_active() -> bool:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", "tos-pq-elections"], check=False, timeout=30
    )
    return result.returncode == 0


async def main(args) -> int:
    local.require_installed_executable(local.INSTALLED_LITE_CLIENT)
    if not args.check and election_service_active():
        # Both would spend from the Genesis wallet and relays would change the
        # funds between the read and the readback.
        raise SystemExit("stop tos-pq-elections first; it owns the Genesis wallet while it runs")
    network = json.loads((DATA / "network.json").read_text())
    global_id = int(network["global_id"])
    funds_target = coins(args.funds_target * NANO, "funds target")
    allowance = coins(args.allowance_target * NANO, "allowance target")
    limit = coins(args.per_request_limit * NANO, "per-request limit")
    floor = coins(args.floor * NANO, "storage floor")
    margin = coins(args.capital_margin * NANO, "capital margin")
    cdll = ToslibCDLL(REPO / "build/toslib/libtoslibjson.so")
    cdll.client_set_verbosity_level(0)
    config = local.lite_config(DATA / "configs/node-1-lite.json")
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
            deposit = plan_renewal(
                state,
                now,
                funds_target=funds_target,
                allowance_target=allowance,
                limit=limit,
                renew_percent=args.renew_percent,
                renew_seconds=args.renew_days * 86400,
            )
            if deposit is not None and not args.check:
                old_funds = state["funds"]
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
                ) or state["funds"] != old_funds + deposit:
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
                        "renewal_due": deposit is not None and args.check,
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
    parser.add_argument("--funds-target", type=int, default=50000, help="operating funds, TOS")
    parser.add_argument("--allowance-target", type=int, default=50000, help="allowance, TOS")
    parser.add_argument("--per-request-limit", type=int, default=20, help="TOS")
    parser.add_argument("--floor", type=int, default=10, help="storage floor, TOS")
    parser.add_argument("--capital-margin", type=int, default=20, help="TOS above funds plus floor")
    parser.add_argument("--processing-fee", type=int, default=20, help="TOS sent above the deposit")
    parser.add_argument("--sponsorship-seconds", type=int, default=30 * 86400)
    parser.add_argument("--renew-days", type=int, default=7, help="renew when expiring sooner")
    parser.add_argument("--renew-percent", type=int, default=25, help="renew below this share")
    sys.exit(asyncio.run(main(parser.parse_args())))
