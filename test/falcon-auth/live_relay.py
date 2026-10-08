#!/usr/bin/env python3
"""Opt-in Falcon AUTH delivery on a disposable, operator-controlled local chain.

PUBLIC TEST DATA ONLY. The local node is this test's trust anchor. Anchoring all
account/config reads to one masterchain block makes a consistent snapshot; it
does not implement production checkpoint discovery or validator authentication.
"""

# Repository-local imports require the explicit path bootstrap below.
# ruff: noqa: E402

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "tools/falcon"),
    str(ROOT / "test/tostester/src"),
    str(ROOT / "test/auth-extensions"),
    str(ROOT / "test/pq-readiness"),
]

import nacl.signing
from backend import Backend
from build_contracts import build_contracts
from contract import AuthState, WalletV5, WalletV5Blueprint, WalletV5State
from contract.falcon_auth import Falcon512ModuleBlueprint, submission
from contract.pq_lite_transport import LiteClientError, LiteClientTransport
from live_chain import funded_payer, wait_for
from provider import AuthProvider, TrustedChainSnapshot
from pytosiq_core import Address, Cell, StateInit


def snapshot(transport, account, module, directory):
    """Proof-checked reads relative to the controlled node's chosen block."""
    block, now = transport.head()
    network_match = re.search(r"global_id:(-?\d+)", transport._run(f"getconfigfrom {block} 19"))
    version_match = re.search(r"version:(\d+)", transport._run(f"getconfigfrom {block} 8"))
    if not network_match or not version_match:
        raise LiteClientError("missing anchored chain configuration")

    def load(address):
        with tempfile.NamedTemporaryFile(dir=directory, suffix=".boc", delete=False) as handle:
            path = Path(handle.name)
        try:
            transport._run(f"saveaccount {path} {address.to_str(False)} {block}")
            if not path.stat().st_size:
                raise LiteClientError("account is absent, uninitialized or frozen")
            init = StateInit.deserialize(Cell.one_from_boc(path.read_bytes()).begin_parse())
            if init.code is None or init.data is None:
                raise LiteClientError("active code and data required")
            return init
        finally:
            path.unlink(missing_ok=True)

    a, m = load(account), load(module)
    return TrustedChainSnapshot(
        int(network_match.group(1)),
        int(version_match.group(1)),
        now,
        account,
        a.code,
        a.data,
        module,
        m.code,
        m.data,
    ), block


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--lite-client", type=Path, required=True)
    parser.add_argument("--lite-config", type=Path, required=True)
    parser.add_argument("--control", default="127.0.0.1:18745")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not args.control.startswith("127.0.0.1:"):
        raise ValueError("this acceptance runner requires an isolated loopback test chain")
    build, out = args.build.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    build_contracts(build, out)
    manifest = json.loads((out / "contracts.json").read_text())
    codes = {
        name: Cell.one_from_boc((out / f"{name}.boc").read_bytes())
        for name in ("wallet-func", "module-func", "module-tol")
    }
    transport = LiteClientTransport(args.lite_client, args.lite_config, attempts=45)
    network, version = transport.global_id(), transport.global_version()
    if version < 19:
        raise ValueError("test chain has not activated the candidate Falcon opcode")
    payer, _ = funded_payer(transport, args.control, codes["wallet-func"], network, tos=120)
    backend = Backend(args.library)
    provider = AuthProvider(backend, manifest)
    events = []
    value, funding = 1_000_000_000, 1_000_000_000

    for language in ("func", "tol"):
        for mode in (2, 3):
            with backend.generate_key() as key:
                module = Falcon512ModuleBlueprint(
                    codes[f"module-{language}"],
                    0,
                    network,
                    key.public_key,
                    backend.validate_public_key,
                )
                asyncio.run(transport.deploy(module, 5_000_000_000))
                classic = nacl.signing.SigningKey(os.urandom(32))
                account = WalletV5Blueprint(
                    codes["wallet-func"],
                    0,
                    network,
                    classic.verify_key.encode(),
                    auth=AuthState(mode, 1, 0, module.address.hash_part),
                )
                asyncio.run(transport.deploy(account, 8_000_000_000))
                state, anchor = snapshot(transport, account.address, module.address, out)
                live = WalletV5State.parse(state.account_data)
                assert live.auth.mode == mode and live.auth.nonce == 0
                target = Address("0:" + "5c" * 32)
                before = transport.balance(target)
                payload = WalletV5(None, account.address, network).transfer_payload(target, value)
                request = provider.buildSigningRequest(
                    state,
                    account.address,
                    dict(kind=0, payload=payload, valid_until=state.now + 600),
                )
                proof = provider.sign(key, request)
                co = classic.sign(request.request.commitment).signature if mode == 3 else None
                body = provider.buildSubmission(request, proof, co)

                # Reach the actual verifier on chain: the production provider
                # would correctly refuse this deliberately corrupted proof.
                broken = bytearray(proof.signature)
                broken[50] ^= 1
                previous = transport.last_transaction(module.address)[1]
                asyncio.run(
                    transport.submit_internal(
                        module.address, submission(request.request, bytes(broken), co), funding
                    )
                )

                def rejected():
                    code, transaction = transport.last_transaction(module.address)
                    return transaction if transaction != previous and code == 1808 else None

                bad_transaction = wait_for(rejected, "paid invalid Falcon proof is rejected")
                assert transport.balance(target) == before
                assert transport.read_auth(account.address).nonce == 0

                broadcast = asyncio.run(transport.submit_internal(module.address, body, funding))
                wait_for(
                    lambda: transport.read_auth(account.address).nonce == 1,
                    "target consumes the Falcon-authorized nonce",
                )
                wait_for(
                    lambda: transport.balance(target) - before >= value - 10_000_000,
                    "the authorized outgoing transfer reaches its destination",
                )
                moved = transport.balance(target) - before
                assert value - 10_000_000 <= moved <= value
                module_exit, module_tx = transport.last_transaction(module.address)
                account_exit, account_tx = transport.last_transaction(account.address)
                assert module_exit == 0 and account_exit == 0 and module_tx and account_tx

                # Deliver the same envelope again; the module may relay it,
                # while the existing account's nonce guard refuses a second spend.
                prior = account_tx
                asyncio.run(transport.submit_internal(module.address, body, funding))

                def replayed():
                    code, transaction = transport.last_transaction(account.address)
                    return (code, transaction) if transaction != prior else None

                replay_exit, replay_tx = wait_for(replayed, "target refuses the actual replay")
                assert replay_exit != 0 and transport.read_auth(account.address).nonce == 1
                assert transport.balance(target) - before == moved
                events.append(
                    dict(
                        language=language,
                        mode=mode,
                        anchor=anchor,
                        account=account.address.to_str(False),
                        module=module.address.to_str(False),
                        commitment=request.request.commitment.hex(),
                        rejected_module_tx=bad_transaction,
                        broadcast=broadcast,
                        module_tx=module_tx,
                        account_tx=account_tx,
                        replay_tx=replay_tx,
                        replay_exit=replay_exit,
                        target_received=moved,
                        nonce=1,
                    )
                )

    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    report = dict(
        success=True,
        scope="disposable-controlled-live-chain",
        network=network,
        global_version=version,
        source_commit=commit,
        cases=len(events),
        events=events,
        trust="operator-controlled local node; production checkpoint authentication not claimed",
    )
    (out / "live-falcon.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "events"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
