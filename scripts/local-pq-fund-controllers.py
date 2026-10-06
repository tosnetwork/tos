#!/usr/bin/env python3
"""Initialize/check disposable local controllers; the driver owns ongoing renewal.

The default persistent profile provisions 30 days at live fees and renews at 25%
remaining. --deposit is a TARGET (not an amount to add) and is only accepted for
an explicit --rehearsal. Stop the election service before a mutating invocation.
"""

import argparse
import asyncio
import json
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import local_pq_testnet as local
import nacl.signing
from contract import WalletV1
from pytosiq_core import Address
from tosapi import tos_api
from toslib import ToslibCDLL, ToslibClient

from local_pq_funding import CANDIDATES, ensure_operations, verify_local_network
from local_pq_funding import operating_payload as operating_payload
from local_pq_funding_policy import NANO, coins
from local_pq_transactions import Faucet, faucet_lock

DATA = Path("/data")
ELECTIONS = DATA / "elections"
REPO = Path(__file__).resolve().parents[1]


async def main(args):
    if args.deposit is not None and not args.rehearsal:
        raise ValueError("a smaller explicit target requires --rehearsal; persistent uses 30 days")
    if not args.check:
        local.secure_output_dir(ELECTIONS)
    network = json.loads((DATA / "network.json").read_text())
    plan = json.loads((ELECTIONS / "plan.json").read_text())
    cdll = ToslibCDLL(REPO / "build/toslib/libtoslibjson.so")
    cdll.client_set_verbosity_level(0)
    config = tos_api.Liteclient_config_global.from_dict(
        json.loads((DATA / "configs/node-1-lite.json").read_text()))
    with nullcontext() if args.check else faucet_lock(DATA):
        async with ToslibClient(config, cdll) as client:
            await verify_local_network(client, network, plan)
            wallet = SimpleNamespace(address=Address(network["genesis_wallet_address"]))
            if not args.check:
                wallet = WalletV1(client, wallet.address,
                                  nacl.signing.SigningKey((DATA / "testnet/state/main-wallet.pk").read_bytes()))
            sender = Faucet(client, wallet, ELECTIONS / "faucet-journal", network["zerostate_root"], readonly=args.check)
            if not args.check:
                await sender.recover()
            ready = True
            for index in CANDIDATES:
                candidate = json.loads((ELECTIONS / f"candidate-{index}.json").read_text())
                status = await ensure_operations(client, sender, candidate, index, ELECTIONS,
                                                 network["global_id"], check=args.check,
                                                 days=1 if args.rehearsal else 30,
                                                 target=coins(args.deposit * NANO) if args.deposit is not None else None)
                print(json.dumps(status), flush=True)
                ready &= status["ready"]
    return 0 if ready else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="read-only readiness/renewal report")
    parser.add_argument("--rehearsal", action="store_true", help="explicit bounded one-day profile")
    parser.add_argument("--deposit", type=int, help="rehearsal funds target in TOS, never an additive deposit")
    sys.exit(asyncio.run(main(parser.parse_args())))
