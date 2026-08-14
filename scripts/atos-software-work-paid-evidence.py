#!/usr/bin/env python3
"""Independently reconstruct the paid software-work transaction from TOS state."""

import argparse
import base64
import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO / "scripts"), str(REPO / "test/tostester/src")]
spec = importlib.util.spec_from_file_location("usdt", REPO / "scripts/atos-test-usdt-deploy.py")
usdt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(usdt)

ESCROW = usdt.Address("0:fe2973464fb88997c6271eefc6d627101db28b2b1b8a076915e461dadd04d916")
BUYER_WALLET = usdt.Address("EQC0_F_vMgzXUiy-R0A9Ccf51QB5-ABne0PrwhZcMdrG_OFy")
PROVIDER_WALLET = usdt.Address("EQCzUwtoLxFZjSI1PQMhulsp4j665-RgoP3C90OX-btu7bOJ")


def escrow_view(data):
    root = data.begin_parse()
    if root.load_uint(32) != 0x4E455331 or root.load_uint(16) != 1:
        raise RuntimeError("invalid escrow data")
    status = root.load_uint(8)
    root.load_uint(256); root.load_uint(256); root.load_uint(256)
    root.load_ref(); root.load_ref(); root.load_ref()
    runtime = root.load_ref().begin_parse()
    if runtime.load_uint(32) != 0x4E455231 or runtime.load_uint(16) != 1:
        raise RuntimeError("invalid escrow runtime")
    funded, settled = runtime.load_uint(128), runtime.load_uint(128)
    receipt, query = runtime.load_uint(256), runtime.load_uint(64)
    return {"status": status, "funded_atomic": str(funded), "settled_atomic": str(settled),
            "receipt_commitment": "tvm-cell-sha256:" + receipt.to_bytes(32, "big").hex(), "pending_query_id": query}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--outcome", required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    outcome = json.loads(Path(args.outcome).read_text())
    release = json.loads(Path(args.release).read_text())
    endpoints = [f"http://127.0.0.1:{port}/jsonRPC" for port in (8011, 8012, 8013)]
    checkpoint = min(usdt.rpc(endpoint, "getMasterchainInfo")["last"]["seqno"] for endpoint in endpoints)
    observations, votes = [], set()
    for endpoint in endpoints:
        escrow_info, _, escrow_data = usdt.endpoint_account(endpoint, ESCROW, checkpoint)
        buyer_info, _, buyer_data = usdt.endpoint_account(endpoint, BUYER_WALLET, checkpoint)
        provider_info, _, provider_data = usdt.endpoint_account(endpoint, PROVIDER_WALLET, checkpoint)
        state, buyer, provider = escrow_view(escrow_data), usdt.wallet_view(buyer_data), usdt.wallet_view(provider_data)
        vote = (escrow_data.hash.hex(), buyer_data.hash.hex(), provider_data.hash.hex())
        votes.add(vote)
        observations.append({"endpoint": endpoint, "checkpoint": checkpoint,
            "block_root_hash": escrow_info["block_id"]["root_hash"], "block_file_hash": escrow_info["block_id"]["file_hash"],
            "escrow_data_hash": "tvm-cell-sha256:" + vote[0], "buyer_wallet_data_hash": "tvm-cell-sha256:" + vote[1],
            "provider_wallet_data_hash": "tvm-cell-sha256:" + vote[2], "escrow": state,
            "buyer_balance_atomic": buyer["balance"], "provider_balance_atomic": provider["balance"]})
    if len(votes) != 1 or observations[0]["escrow"]["status"] != 2 or observations[0]["provider_balance_atomic"] != "25000000":
        raise RuntimeError("paid settlement did not reach one finalized quorum state")
    evidence = {"schema": "atos.native.paid-software-work.v1", "capability_version": "1.2.0",
        "manifest_digest": "sha256:9d39a2d3f5c34a4bfeb63324681e0f457437b756ffb79da8a1681aa79bf9f3e5",
        "quote_commitment": outcome["quote_commitment"], "escrow_address": ESCROW.to_str(),
        "funding": {"query_id": 1786719306, "amount_atomic": "25000000"}, "execution": outcome,
        "release": release, "escrow_transaction": usdt.account_transaction(Path("/data/tos-global.json"), ESCROW.to_str()),
        "provider_wallet": PROVIDER_WALLET.to_str(), "provider_wallet_transaction": usdt.account_transaction(Path("/data/tos-global.json"), PROVIDER_WALLET.to_str()),
        "artifacts": ["deployments/artifacts/sha256-6a5807a8ac4732c47805f2925393f9858b0f6e19caa2a299de261733749c00bb.tar",
                      "deployments/artifacts/sha256-9a29890ffa88bcb2f9e131964c22d1bececf927405f85e34567b8b6e51d1cc08.json"],
        "quorum": 2, "endpoint_verification": observations, "verdict": "PASS_INDEPENDENT_PAID_SOFTWARE_WORK_SETTLEMENT"}
    Path(args.evidence).write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
