#!/usr/bin/env python3
"""One disposable global-id-3 faucet transfer for a controlled competing spend."""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import os
import stat
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--body", type=Path, required=True)
    parser.add_argument("--marker", type=Path, required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--toslib", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads((args.root / "operator-c/provider.json").read_bytes())
    if config["release"]["global_id"] != 3 or args.root.resolve() != args.root:
        parser.error("only this disposable global-id-3 local root is permitted")
    if not 0 < args.body.stat().st_size <= 256 * 1024:
        parser.error("private body size bound")
    os.environ["TOS_ROOT"] = str(args.checkout)
    spec = importlib.util.spec_from_file_location("local_setup", args.root / "prepare.py")
    setup = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(setup)
    import nacl.signing
    from contract import WalletV1
    from pytosiq_core import (
        Address,
        Cell,
        CurrencyCollection,
        InternalMsgInfo,
        MessageAny,
        WalletMessage,
    )
    from toslib.toslib_cdll import ToslibCDLL

    from toslib import ToslibClient

    body = Cell.one_from_boc(args.body.read_bytes())
    view = body.begin_parse()
    if view.load_uint(32) != 0x53485002:
        parser.error("private transact required")
    view.load_uint(64)
    view.load_uint(8)
    view.load_uint(32)
    view.load_uint(32)
    if view.load_coins() or view.load_coins() or view.load_address() is not None:
        parser.error("public output or withdrawal fee forbidden in this control")
    seed_path = args.root / "data/testnet/state/main-wallet.pk"
    fd = os.open(seed_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
            or metadata.st_nlink != 1
            or metadata.st_size != 32
        ):
            raise RuntimeError("unsafe local faucet key")
        seed = os.read(fd, 33)
    finally:
        os.close(fd)
    if len(seed) != 32:
        raise RuntimeError("local faucet seed width")

    async def send_once():
        lite = setup.lite_config(args.root / "data/testnet/node1/lite-client.json", 34811)
        cdll = ToslibCDLL(args.toslib)
        cdll.client_set_verbosity_level(0)
        network = json.loads((args.root / "data/network.json").read_bytes())
        async with ToslibClient(lite, cdll) as client:
            wallet = WalletV1(
                setup.PatientClient(client),
                Address(network["genesis_wallet_address"]),
                nacl.signing.SigningKey(seed),
            )
            # A marker precedes the only possible sign/send. Unknown is inspected
            # read-only by the operator; this helper never retries or replaces it.
            with args.marker.open("x") as marker:
                marker.write("one local private transact; no automatic retry\n")
            args.marker.chmod(0o600)
            await wallet.send(
                WalletMessage(
                    send_mode=3,
                    message=MessageAny(
                        info=InternalMsgInfo(
                            ihr_disabled=True,
                            bounce=True,
                            bounced=False,
                            src=wallet.address,
                            dest=Address(config["release"]["pool"]),
                            value=CurrencyCollection(250000000),
                            ihr_fee=0,
                            fwd_fee=0,
                            created_lt=0,
                            created_at=0,
                        ),
                        init=None,
                        body=body,
                    ),
                )
            )
        print("LOCAL_FAUCET_SUBMITTED_NOT_FINALITY", flush=True)

    asyncio.run(send_once())


if __name__ == "__main__":
    main()
