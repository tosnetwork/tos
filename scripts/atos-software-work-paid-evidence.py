#!/usr/bin/env python3
"""Independently reconstruct and verify a paid software-work settlement."""

import argparse
import base64
import hashlib
import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO / "scripts"), str(REPO / "test/tostester/src")]
spec = importlib.util.spec_from_file_location(
    "usdt", REPO / "scripts/atos-test-usdt-deploy.py"
)
usdt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(usdt)

DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
CELL_DIGEST_PATTERN = re.compile(r"^tvm-cell-sha256:[0-9a-f]{64}$")


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def cell_digest(cell) -> str:
    return "tvm-cell-sha256:" + cell.hash.hex()


def require_empty(slice_, name: str):
    if slice_.remaining_bits or slice_.remaining_refs:
        raise RuntimeError(f"non-canonical {name} cell shape")


def receipt_view(receipt):
    root = receipt.begin_parse()
    if root.load_uint(32) != 0x4E575231 or root.load_uint(16) != 1:
        raise RuntimeError("invalid Receipt header")
    completed_at = root.load_uint(64)
    exit_code = root.load_int(32)
    binding = root.load_ref().begin_parse()
    outcome = root.load_ref().begin_parse()
    evidence = root.load_ref().begin_parse()
    economic = root.load_ref().begin_parse()
    require_empty(root, "Receipt root")

    result = {
        "quote_commitment": "tvm-cell-sha256:"
        + binding.load_uint(256).to_bytes(32, "big").hex(),
        "execution_id": "sha256:"
        + binding.load_uint(256).to_bytes(32, "big").hex(),
        "input_digest": "sha256:"
        + binding.load_uint(256).to_bytes(32, "big").hex(),
        "result_digest": "sha256:"
        + outcome.load_uint(256).to_bytes(32, "big").hex(),
        "artifact_digest": "sha256:"
        + outcome.load_uint(256).to_bytes(32, "big").hex(),
        "report_digest": "sha256:"
        + outcome.load_uint(256).to_bytes(32, "big").hex(),
        "source_digest": "sha256:"
        + evidence.load_uint(256).to_bytes(32, "big").hex(),
        "toolchain_digest": "sha256:"
        + evidence.load_uint(256).to_bytes(32, "big").hex(),
        "sandbox_digest": "sha256:"
        + evidence.load_uint(256).to_bytes(32, "big").hex(),
        "charged_atomic_amount": str(economic.load_uint(128)),
        "provider_agent_id": "agent_"
        + economic.load_uint(256).to_bytes(32, "big").hex(),
        "completed_at_unix": completed_at,
        "exit_code": exit_code,
    }
    for name, slice_ in (
        ("Receipt binding", binding),
        ("Receipt outcome", outcome),
        ("Receipt evidence", evidence),
        ("Receipt economic", economic),
    ):
        require_empty(slice_, name)
    if completed_at == 0 or exit_code != 0 or any(
        value.endswith("0" * 64)
        for key, value in result.items()
        if key.endswith("digest") or key.endswith("_id") or key.endswith("commitment")
    ):
        raise RuntimeError("Receipt contains an invalid success value")
    return result


def escrow_view(data):
    root = data.begin_parse()
    if root.load_uint(32) != 0x4E455331 or root.load_uint(16) != 1:
        raise RuntimeError("invalid escrow data")
    status = root.load_uint(8)
    root.load_uint(256)
    root.load_uint(256)
    root.load_uint(256)
    root.load_ref()
    root.load_ref()
    root.load_ref()
    runtime = root.load_ref().begin_parse()
    require_empty(root, "escrow root")
    if runtime.load_uint(32) != 0x4E455231 or runtime.load_uint(16) != 1:
        raise RuntimeError("invalid escrow runtime")
    funded, settled = runtime.load_uint(128), runtime.load_uint(128)
    receipt, query = runtime.load_uint(256), runtime.load_uint(64)
    runtime.load_ref()
    runtime.load_ref()
    runtime.load_ref()
    require_empty(runtime, "escrow runtime")
    return {
        "status": status,
        "funded_atomic": str(funded),
        "settled_atomic": str(settled),
        "receipt_commitment": "tvm-cell-sha256:"
        + receipt.to_bytes(32, "big").hex(),
        "pending_query_id": query,
    }


def transaction(info):
    value = info.get("last_transaction_id", {})
    try:
        return {
            "logical_time": int(value["lt"]),
            "hash": "sha256:" + base64.b64decode(value["hash"]).hex(),
        }
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError("endpoint omitted the account transaction identity") from error


def verify_object(root: Path, descriptor: dict, suffix: str) -> str:
    expected = descriptor["Digest"]
    if not DIGEST_PATTERN.fullmatch(expected):
        raise RuntimeError("invalid content-addressed object digest")
    path = root / ("sha256-" + expected.removeprefix("sha256:") + suffix)
    body = path.read_bytes()
    if digest(body) != expected or len(body) != descriptor["SizeBytes"]:
        raise RuntimeError(f"content-addressed object mismatch: {path}")
    return path.name


def verify_receipt(
    outcome: dict,
    release: dict,
    vector: dict,
    artifact_root: Path,
    escrow,
):
    quote = vector["quote"]
    quote_cell = usdt.Cell.one_from_boc(
        base64.b64decode(vector["expected"]["boc_base64"])
    )
    if cell_digest(quote_cell) != vector["expected"]["commitment"]:
        raise RuntimeError("Accepted Quote BOC does not match its commitment")
    receipt = usdt.Cell.one_from_boc(base64.b64decode(release["receipt_boc_base64"]))
    commitment = cell_digest(receipt)
    if (
        not CELL_DIGEST_PATTERN.fullmatch(release["receipt_commitment"])
        or release["receipt_commitment"] != commitment
    ):
        raise RuntimeError("Receipt BOC does not match its claimed commitment")
    view = receipt_view(receipt)
    expected = {
        "quote_commitment": outcome["quote_commitment"],
        "execution_id": outcome["execution_id"],
        "input_digest": outcome["input_digest"],
        "result_digest": outcome["result_digest"],
        "artifact_digest": outcome["artifact"]["Digest"],
        "report_digest": outcome["report"]["Digest"],
        "source_digest": outcome["source_digest"],
        "toolchain_digest": outcome["toolchain_digest"],
        "sandbox_digest": outcome["sandbox_digest"],
        "charged_atomic_amount": quote["maximum_atomic_amount"],
        "provider_agent_id": quote["provider_agent_id"],
        "completed_at_unix": outcome["completed_at_unix"],
        "exit_code": outcome["exit_code"],
    }
    if view != expected:
        raise RuntimeError("Receipt fields do not exactly match Quote and execution outcome")
    artifact = verify_object(artifact_root, outcome["artifact"], ".tar")
    report_path = verify_object(artifact_root, outcome["report"], ".json")
    if (
        outcome["artifact"].get("MediaType")
        != "application/vnd.atos.software-artifact.v1+tar"
        or outcome["report"].get("MediaType")
        != "application/vnd.atos.test-report.v1+json"
    ):
        raise RuntimeError("execution outcome uses a non-canonical object media type")
    report = json.loads((artifact_root / report_path).read_text())
    if (
        report.get("schema") != "atos.software-work-report.v1"
        or report.get("execution_id") != outcome["execution_id"]
        or report.get("result_digest") != outcome["result_digest"]
        or report.get("exit_code") != 0
        or report.get("completed_at_unix") != outcome["completed_at_unix"]
    ):
        raise RuntimeError("canonical report does not match execution outcome")

    release_body = usdt.Cell.one_from_boc(
        base64.b64decode(release["release_body_boc_base64"])
    ).begin_parse()
    if release_body.load_uint(32) != 0x4E450001:
        raise RuntimeError("release body has the wrong opcode")
    query_id = release_body.load_uint(64)
    signature = release_body.load_bytes(64)
    body_receipt = release_body.load_ref()
    require_empty(release_body, "release body")
    if (
        query_id != release["query_id"]
        or signature.hex() != release["signature_hex"]
        or body_receipt.hash != receipt.hash
    ):
        raise RuntimeError("release body does not bind the claimed Receipt and query")
    amount = int(quote["maximum_atomic_amount"])
    intent = (
        usdt.Builder()
        .store_uint(0x4E534931, 32)
        .store_uint(1, 16)
        .store_uint(query_id, 64)
        .store_uint(amount, 128)
        .store_address(escrow)
        .store_uint(int(vector["expected"]["commitment"].split(":", 1)[1], 16), 256)
        .store_uint(int(commitment.split(":", 1)[1], 16), 256)
        .end_cell()
    )
    if cell_digest(intent) != release["settlement_intent"]:
        raise RuntimeError("release signature does not bind the canonical settlement intent")
    try:
        usdt.nacl.signing.VerifyKey(
            bytes.fromhex(quote["execution_signer_public_key_hex"])
        ).verify(intent.hash, signature)
    except (ValueError, usdt.nacl.exceptions.BadSignatureError) as error:
        raise RuntimeError("invalid execution-signer settlement signature") from error
    return commitment, view, [artifact, report_path]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--outcome", required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--quote-vector", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--escrow", required=True)
    parser.add_argument("--buyer-wallet", required=True)
    parser.add_argument("--provider-wallet", required=True)
    parser.add_argument("--endpoint", action="append", required=True)
    parser.add_argument("--quorum", type=int, default=2)
    parser.add_argument("--funding-query-id", type=int, required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    if args.quorum < 2 or len(set(args.endpoint)) < args.quorum:
        raise RuntimeError("independent verification requires distinct quorum endpoints")

    outcome = json.loads(Path(args.outcome).read_text())
    release = json.loads(Path(args.release).read_text())
    vector = json.loads(Path(args.quote_vector).read_text())
    quote = vector["quote"]
    if outcome["quote_commitment"] != vector["expected"]["commitment"]:
        raise RuntimeError("execution does not bind the canonical Accepted Quote")
    escrow = usdt.Address(args.escrow)
    buyer_wallet = usdt.Address(args.buyer_wallet)
    provider_wallet = usdt.Address(args.provider_wallet)
    receipt_commitment, receipt, artifacts = verify_receipt(
        outcome, release, vector, Path(args.artifact_root), escrow
    )
    if release["query_id"] <= 0 or args.funding_query_id <= 0:
        raise RuntimeError("query IDs must be non-zero")

    checkpoint = min(
        usdt.rpc(endpoint, "getMasterchainInfo")["last"]["seqno"]
        for endpoint in args.endpoint
    )
    observations, votes = [], Counter()
    for endpoint in args.endpoint:
        escrow_info, _, escrow_data = usdt.endpoint_account(endpoint, escrow, checkpoint)
        buyer_info, _, buyer_data = usdt.endpoint_account(
            endpoint, buyer_wallet, checkpoint
        )
        provider_info, _, provider_data = usdt.endpoint_account(
            endpoint, provider_wallet, checkpoint
        )
        state = escrow_view(escrow_data)
        buyer = usdt.wallet_view(buyer_data)
        provider = usdt.wallet_view(provider_data)
        vote = (
            escrow_info["block_id"]["root_hash"],
            escrow_info["block_id"]["file_hash"],
            escrow_data.hash.hex(),
            buyer_data.hash.hex(),
            provider_data.hash.hex(),
            json.dumps(state, sort_keys=True),
            buyer["balance"],
            provider["balance"],
        )
        votes[vote] += 1
        observations.append(
            {
                "endpoint": endpoint,
                "checkpoint": checkpoint,
                "block_root_hash": vote[0],
                "block_file_hash": vote[1],
                "escrow_data_hash": "tvm-cell-sha256:" + vote[2],
                "buyer_wallet_data_hash": "tvm-cell-sha256:" + vote[3],
                "provider_wallet_data_hash": "tvm-cell-sha256:" + vote[4],
                "escrow": state,
                "buyer_balance_atomic": buyer["balance"],
                "provider_balance_atomic": provider["balance"],
                "escrow_transaction": transaction(escrow_info),
                "provider_wallet_transaction": transaction(provider_info),
            }
        )
    winning_vote, count = votes.most_common(1)[0]
    if count < args.quorum:
        raise RuntimeError("endpoints did not reach the required finalized-state quorum")
    winning_state = json.loads(winning_vote[5])
    amount = quote["maximum_atomic_amount"]
    if (
        winning_state["status"] != 2
        or winning_state["funded_atomic"] != amount
        or winning_state["settled_atomic"] != amount
        or winning_state["receipt_commitment"] != receipt_commitment
        or winning_state["pending_query_id"] != release["query_id"]
        or winning_vote[7] != amount
    ):
        raise RuntimeError("paid settlement did not match Receipt and Quote")

    evidence = {
        "schema": "atos.native.paid-software-work.v1",
        "capability_version": quote["capability_version"],
        "capability_id": quote["capability_id"],
        "manifest_digest": quote["manifest_digest"],
        "quote_commitment": outcome["quote_commitment"],
        "escrow_address": escrow.to_str(),
        "funding": {
            "query_id": args.funding_query_id,
            "amount_atomic": amount,
        },
        "execution": outcome,
        "release": release,
        "receipt": receipt,
        "provider_wallet": provider_wallet.to_str(),
        "artifacts": artifacts,
        "quorum": args.quorum,
        "quorum_votes": count,
        "endpoint_verification": observations,
        "verdict": "PASS_INDEPENDENT_PAID_SOFTWARE_WORK_SETTLEMENT",
    }
    Path(args.evidence).write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
