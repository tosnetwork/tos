#!/usr/bin/env python3
"""Run a same-host, real-chain paid software-work rehearsal.

This script deliberately produces LOCAL_REHEARSAL_ONLY evidence. It exercises
the deployed Native Capability, Accepted Quote, stablecoin escrow, buyer
funding, deterministic work, Receipt signature, and provider settlement on a
local TOS chain, but it does not claim independent organizations or public
infrastructure.
"""

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PROTOCOL = REPO.parent / "tos-service-protocol"
SPEC = REPO.parent / "tos-service-spec"
sys.path[:0] = [str(REPO / "scripts"), str(REPO / "test/tostester/src")]

import nacl.signing  # noqa: E402
from contract import WalletV1Blueprint  # noqa: E402
from pytosiq_core import Address, Builder, Cell, StateInit  # noqa: E402
from tos_service_test_identities import load_test_identity  # noqa: E402


def load_script(name: str, file_name: str):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file_name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load_script("native_gate_c", "tos-service-native-registry-local-gate-c.py")
usdt = load_script("test_usdt", "tos-service-test-usdt-deploy.py")
paid = load_script("paid_evidence", "tos-service-software-work-paid-evidence.py")

OP_TRANSFER = 0x0F8A7EA5
OP_RELEASE = 0x4E450001
MAGIC_AUTHORIZATION = 0x4E454131
MAGIC_TRANSPORT = 0x4E544231
MAGIC_DISPUTE = 0x4E445031
MAGIC_RECEIPT = 0x4E575231
MAGIC_INTENT = 0x4E534931
NANO = 1_000_000_000
AMOUNT = 25_000_000


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def cell_digest(value: Cell) -> str:
    return "tvm-cell-sha256:" + value.hash.hex()


def identity_record(path: Path, role: str) -> dict:
    document = json.loads(path.read_text())
    return next(item for item in document["identities"] if item["role"] == role)


def raw_address(value: str) -> str:
    account = Address(value).to_tl_account_id()
    return f"{account['workchain']}:{account['id']}"


def command_json(argv: list[str], cwd: Path) -> dict:
    result = subprocess.run(argv, cwd=cwd, check=True, text=True, capture_output=True)
    return json.loads(result.stdout)


def escrow_view(data: Cell) -> dict:
    return paid.escrow_view(data)


def wait_escrow(config: Path, address: Address, status: int, timeout: int = 60) -> dict:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = escrow_view(usdt.account_cell(config, address.to_str(), "data"))
            if last["status"] == status:
                return last
        except Exception as error:
            last = error
        time.sleep(0.75)
    raise RuntimeError(f"escrow status {status} was not finalized: {last}")


def common_checkpoint(endpoints: list[str]) -> int:
    return min(usdt.rpc(endpoint, "getMasterchainInfo")["last"]["seqno"] for endpoint in endpoints)


def wait_funded_checkpoint(endpoints: list[str], address: Address, timeout: int = 60) -> int:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        checkpoint = common_checkpoint(endpoints)
        try:
            views = []
            for endpoint in endpoints:
                _, _, data = usdt.endpoint_account(endpoint, address, checkpoint)
                views.append(escrow_view(data))
            if all(view["status"] == 1 and view["funded_atomic"] == str(AMOUNT) for view in views):
                return checkpoint
            last = views
        except Exception as error:
            last = error
        time.sleep(0.75)
    raise RuntimeError(f"funded state did not reach all endpoints: {last}")


def endpoint_native_balance(endpoint: str, address: Address, checkpoint: int) -> int:
    info = usdt.rpc(
        endpoint,
        "getAddressInformation",
        address=address.to_str(),
        seqno=checkpoint,
    )
    if info["block_id"]["seqno"] != checkpoint:
        raise RuntimeError(f"non-finalized account response from {endpoint}")
    return int(info["balance"])


def wait_native_balance(
    endpoints: list[str], address: Address, minimum: int, timeout: int = 60
) -> int:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        checkpoint = common_checkpoint(endpoints)
        try:
            balances = [
                endpoint_native_balance(endpoint, address, checkpoint)
                for endpoint in endpoints
            ]
            if all(balance >= minimum for balance in balances):
                return checkpoint
            last = balances
        except Exception as error:
            last = error
        time.sleep(0.75)
    raise RuntimeError(
        f"native balance {minimum} did not reach all endpoints: {last}"
    )


def deterministic_tar(test_output: bytes) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        item = tarfile.TarInfo("go-test-output.txt")
        item.size = len(test_output)
        item.mode = 0o644
        item.mtime = 0
        item.uid = item.gid = 0
        item.uname = item.gname = ""
        archive.addfile(item, io.BytesIO(test_output))
    return stream.getvalue()


def deterministic_source_tar() -> bytes:
    files = {
        "go.mod": b"module example.test/tos-service-paid\n\ngo 1.26.5\n",
        # `go test ./...` still performs a real compile and package validation,
        # while avoiding a cold build of the large `testing` standard-library
        # dependency under the local Apple-Silicon x86_64 QEMU boundary.
        "paid.go": b"package paid\n\nconst Answer = 42\n",
    }
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(files):
            body = files[name]
            item = tarfile.TarInfo(name)
            item.size = len(body)
            item.mode = 0o644
            item.mtime = 0
            item.uid = item.gid = 0
            item.uname = item.gname = ""
            archive.addfile(item, io.BytesIO(body))
    return stream.getvalue()


def ensure_native_wallet_funded(
    config: Path,
    state_dir: Path,
    endpoints: list[str],
    target: Address,
    minimum: int,
    top_up: int,
) -> int:
    checkpoint = common_checkpoint(endpoints)
    balances = [
        endpoint_native_balance(endpoint, target, checkpoint)
        for endpoint in endpoints
    ]
    if all(balance >= minimum for balance in balances):
        return checkpoint

    payer_key = nacl.signing.SigningKey(gate.read_private(state_dir / "main-wallet.pk"))
    payer_file = gate.read_private(state_dir / "main-wallet.addr")
    payer = Address(
        (int.from_bytes(payer_file[32:36], "big", signed=True), payer_file[:32])
    )
    gate.send_wallet_message(config, payer_key, payer, target, top_up, Cell.empty())
    return wait_native_balance(endpoints, target, minimum)


def ensure_provider_wallet_funded(
    config: Path,
    state_dir: Path,
    endpoints: list[str],
    identities: Path,
    expected_raw: str,
) -> Address:
    load_test_identity(identities, "provider-controller")
    provider = Address(identity_record(identities, "provider-controller")["address"])
    if raw_address(provider.to_str()) != expected_raw:
        raise RuntimeError("provider test fixture does not match Accepted Quote provider")

    # tosctl owns the exact wallet StateInit and attaches it to the first signed
    # outbound message. The local chain only needs to pre-fund that deterministic
    # address; guessing a wallet contract here would create a different account.
    ensure_native_wallet_funded(
        config, state_dir, endpoints, provider, 5 * NANO, 10 * NANO
    )
    return provider


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--global-config", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--network-id", required=True)
    parser.add_argument("--capability-evidence", required=True)
    parser.add_argument("--stablecoin-evidence", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="stop after finalized funding and emit a task for the real provider",
    )
    parser.add_argument(
        "--test-identities",
        default=str(SPEC / "test-vectors/tos-service-test-identities-v1.json"),
    )
    parser.add_argument(
        "--lite-client", default=str(REPO / "build/lite-client/lite-client")
    )
    parser.add_argument(
        "--endpoint",
        action="append",
        default=[],
        help="repeat for each local JSON-RPC endpoint",
    )
    args = parser.parse_args()

    config = Path(args.global_config).resolve()
    state_dir = Path(args.state_dir).resolve()
    identities = Path(args.test_identities).resolve()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    endpoints = args.endpoint or [
        "http://127.0.0.1:8011/jsonRPC",
        "http://127.0.0.1:8012/jsonRPC",
        "http://127.0.0.1:8013/jsonRPC",
    ]
    if len(set(endpoints)) < 2:
        raise RuntimeError("local rehearsal still requires at least two endpoint views")

    capability = json.loads(Path(args.capability_evidence).read_text())
    stablecoin = json.loads(Path(args.stablecoin_evidence).read_text())
    if capability.get("verdict") != "PASS_SOFTWARE_WORK_CAPABILITY_VERSION_BINDING":
        raise RuntimeError("software-work Capability evidence is not accepted")
    if stablecoin.get("verdict") != "PASS_TEST_STABLECOIN_DEPLOYMENT":
        raise RuntimeError("test stablecoin evidence is not accepted")
    if capability["network"] != stablecoin["network"]:
        raise RuntimeError("Capability and stablecoin evidence refer to different networks")

    provider_record = identity_record(identities, "provider-controller")
    signer_record = identity_record(identities, "execution-signer")
    buyer_key = load_test_identity(identities, "test-usdt-buyer")
    signer_key = load_test_identity(identities, "execution-signer")
    buyer_blueprint = WalletV1Blueprint(workchain=0, private_key=buyer_key)
    buyer = buyer_blueprint.address
    if buyer.to_str() != stablecoin["asset"]["test_buyer_wallet"]:
        raise RuntimeError("stablecoin buyer wallet does not match the current test identity")
    provider_raw = raw_address(provider_record["address"])

    now = gate.master_checkpoint(config)["unix_time"]
    funding_deadline = now + 86_400
    refund_available_at = funding_deadline + 3_600
    authorization = (
        Builder()
        .store_uint(MAGIC_AUTHORIZATION, 32)
        .store_uint(1, 16)
        .store_bytes(bytes.fromhex(signer_record["public_key_hex"]))
        .end_cell()
    )
    endpoint_cell = Builder().store_bytes(b"http://127.0.0.1:8080").end_cell()
    transport = (
        Builder()
        .store_uint(MAGIC_TRANSPORT, 32)
        .store_uint(1, 16)
        .store_uint(0, 8)
        .store_uint(16_777_216, 32)
        .store_ref(endpoint_cell)
        .end_cell()
    )
    dispute = (
        Builder()
        .store_uint(MAGIC_DISPUTE, 32)
        .store_uint(1, 16)
        .store_uint(0, 8)
        .store_uint(1, 8)
        .store_uint(1, 8)
        .end_cell()
    )
    master_raw = stablecoin["asset"]["master_contract_raw"]
    quote_input = {
        "schema": "tos.service.accepted-quote.v1.vector",
        "network": capability["network"],
        "quote": {
            "proposal_id": "local-paid-software-work-rehearsal-20260816",
            "capability_id": capability["capability_id"],
            "capability_version": capability["capability_version"],
            "provider_agent_id": capability["provider_agent_id"],
            "manifest_digest": capability["manifest"]["digest"],
            "transport_binding_digest": "sha256:" + transport.hash.hex(),
            "asset": {
                "workchain": int(master_raw.split(":", 1)[0]),
                "master_account_id": master_raw.split(":", 1)[1],
                "master_code_hash": stablecoin["release"]["minter_code_hash"],
                "wallet_code_hash": stablecoin["release"]["wallet_code_hash"],
                "decimals": stablecoin["asset"]["decimals"],
            },
            "maximum_atomic_amount": str(AMOUNT),
            "escrow_terms_digest": "sha256:" + "00" * 32,
            "escrow_terms": {
                "buyer_address": raw_address(buyer.to_str()),
                "provider_address": provider_raw,
                "funding_deadline_unix_seconds": funding_deadline,
                "refund_available_at_unix_seconds": refund_available_at,
            },
            "dispute_policy_digest": "sha256:" + dispute.hash.hex(),
            "expires_at_unix_seconds": funding_deadline,
            "execution_signer_authorization": "sha256:" + authorization.hash.hex(),
            "execution_signer_public_key_hex": signer_record["public_key_hex"],
            "transport_binding": {
                "security_mode": 0,
                "max_request_bytes": 16_777_216,
                "base_url": "http://127.0.0.1:8080",
            },
            "dispute_policy": {"mode": 0, "release_rule": 1, "refund_rule": 1},
        },
        "expected": {"commitment": "", "boc_base64": ""},
    }
    with tempfile.TemporaryDirectory() as temporary:
        quote_input_path = Path(temporary) / "quote-input.json"
        quote_input_path.write_text(json.dumps(quote_input, indent=2) + "\n")
        quote = command_json(
            ["go", "run", "./cmd/native-quote-vector", "--input", str(quote_input_path)],
            PROTOCOL,
        )
    quote_path = output / "accepted-quote-local.json"
    quote_path.write_text(json.dumps(quote, indent=2) + "\n")

    escrow_vector = command_json(
        [
            "go",
            "run",
            "./cmd/native-escrow-vector",
            "--quote-vector",
            str(quote_path),
            "--escrow-code",
            str(REPO / "crypto/smartcont/tos-service-stablecoin-escrow-v1.boc.base64"),
            "--wallet-code",
            str(REPO / "crypto/smartcont/test-usdt-wallet-code.boc.base64"),
        ],
        PROTOCOL,
    )
    escrow_vector_path = output / "escrow-state-init-local.json"
    escrow_vector_path.write_text(json.dumps(escrow_vector, indent=2) + "\n")
    escrow = Address(escrow_vector["escrow_address"])

    deploy_evidence = output / "escrow-deployment-local.json"
    environment = dict(os.environ, TOS_LITE_CLIENT=str(Path(args.lite_client).resolve()))
    deployment = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts/tos-service-stablecoin-escrow-deploy.py"),
            "--global-config",
            str(config),
            "--state-dir",
            str(state_dir),
            "--network-id",
            args.network_id,
            "--state-init-vector",
            str(escrow_vector_path),
            "--evidence",
            str(deploy_evidence),
        ],
        env=environment,
        text=True,
        capture_output=True,
    )
    if deployment.returncode:
        raise RuntimeError(
            "escrow deployment failed: " + deployment.stderr[-4096:]
        )

    # The jetton transfer attaches native currency for escrow execution. Confirm
    # the buyer can afford it at a common finalized checkpoint before signing,
    # instead of discovering an insufficient balance after consuming its seqno.
    ensure_native_wallet_funded(
        config, state_dir, endpoints, buyer, 5 * NANO, 10 * NANO
    )

    query_id = int(time.time_ns()) & ((1 << 64) - 1)
    funding_body = (
        Builder()
        .store_uint(OP_TRANSFER, 32)
        .store_uint(query_id, 64)
        .store_coins(AMOUNT)
        .store_address(escrow)
        .store_address(buyer)
        .store_bit(0)
        .store_coins(NANO)
        .store_bit(0)
        .end_cell()
    )
    usdt.send_wallet_message(
        config,
        buyer_key,
        buyer,
        Address(stablecoin["asset"]["test_buyer_jetton_wallet_contract"]),
        2 * NANO,
        funding_body,
    )
    wait_escrow(config, escrow, 1)
    funded_checkpoint = wait_funded_checkpoint(endpoints, escrow)

    if args.prepare_only:
        provider_wallet = ensure_provider_wallet_funded(
            config, state_dir, endpoints, identities, provider_raw
        )
        quote_cell = Cell.one_from_boc(base64.b64decode(quote["expected"]["boc_base64"]))
        source_archive = deterministic_source_tar()
        source_digest = digest(source_archive)
        execution_id = digest(
            b"tos-service-real-provider-e2e-v1\0" + quote_cell.hash
        )
        input_digest = digest(quote_cell.to_boc())
        source_path = output / (
            "sha256-" + source_digest.removeprefix("sha256:") + ".source.tar"
        )
        source_path.write_bytes(source_archive)
        task = {
            "schema": "tos.service.local-funded-task.v1",
            "network": capability["network"],
            "escrow_address": raw_address(escrow.to_str()),
            "quote_commitment": cell_digest(quote_cell),
            "execution_id": execution_id,
            "input_digest": input_digest,
            "source_digest": source_digest,
            "source_archive": str(source_path),
            "funding_query_id": query_id,
            "funded_checkpoint": funded_checkpoint,
            "provider_custody_wallet": raw_address(provider_wallet.to_str()),
            "accepted_quote": str(quote_path),
            "escrow_state_init": str(escrow_vector_path),
            "escrow_deployment_evidence": str(deploy_evidence),
        }
        task_path = output / "funded-task-local.json"
        task_path.write_text(json.dumps(task, indent=2) + "\n")
        print(f"PASS finalized paid task prepared for real provider: {task_path}")
        return 0

    test_environment = dict(os.environ, GOMAXPROCS="2")
    work = subprocess.run(
        ["go", "test", "-count=1", "./..."],
        cwd=PROTOCOL,
        env=test_environment,
        text=False,
        capture_output=True,
        timeout=300,
    )
    test_output = work.stdout + work.stderr
    if work.returncode:
        raise RuntimeError(test_output.decode(errors="replace"))
    completed_at = gate.master_checkpoint(config)["unix_time"]
    quote_cell = Cell.one_from_boc(base64.b64decode(quote["expected"]["boc_base64"]))
    execution_id = digest(b"tos-service-local-paid-rehearsal-v1\0" + quote_cell.hash)
    input_digest = digest(quote_cell.to_boc())
    result_digest = digest(test_output)
    artifact_body = deterministic_tar(test_output)
    artifact_digest = digest(artifact_body)
    source_digest = digest(gate.git_head(PROTOCOL).encode())
    toolchain_digest = digest(
        subprocess.run(["go", "version"], check=True, capture_output=True).stdout.strip()
    )
    sandbox_digest = digest(b"local-macos-process-rehearsal-v1")

    report = {
        "schema": "tos.service.software-work-report.v1",
        "execution_id": execution_id,
        "result_digest": result_digest,
        "exit_code": 0,
        "completed_at_unix": completed_at,
        "command": ["go", "test", "-count=1", "./..."],
    }
    report_body = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    report_digest = digest(report_body)
    artifact_path = output / ("sha256-" + artifact_digest.removeprefix("sha256:") + ".tar")
    report_path = output / ("sha256-" + report_digest.removeprefix("sha256:") + ".json")
    artifact_path.write_bytes(artifact_body)
    report_path.write_bytes(report_body)

    provider_id = bytes.fromhex(capability["provider_agent_id"].removeprefix("agent_"))
    binding = (
        Builder()
        .store_bytes(quote_cell.hash)
        .store_bytes(bytes.fromhex(execution_id.removeprefix("sha256:")))
        .store_bytes(bytes.fromhex(input_digest.removeprefix("sha256:")))
        .end_cell()
    )
    outcome_cell = (
        Builder()
        .store_bytes(bytes.fromhex(result_digest.removeprefix("sha256:")))
        .store_bytes(bytes.fromhex(artifact_digest.removeprefix("sha256:")))
        .store_bytes(bytes.fromhex(report_digest.removeprefix("sha256:")))
        .end_cell()
    )
    execution_evidence = (
        Builder()
        .store_bytes(bytes.fromhex(source_digest.removeprefix("sha256:")))
        .store_bytes(bytes.fromhex(toolchain_digest.removeprefix("sha256:")))
        .store_bytes(bytes.fromhex(sandbox_digest.removeprefix("sha256:")))
        .end_cell()
    )
    economic = Builder().store_uint(AMOUNT, 128).store_bytes(provider_id).end_cell()
    receipt = (
        Builder()
        .store_uint(MAGIC_RECEIPT, 32)
        .store_uint(1, 16)
        .store_uint(completed_at, 64)
        .store_int(0, 32)
        .store_ref(binding)
        .store_ref(outcome_cell)
        .store_ref(execution_evidence)
        .store_ref(economic)
        .end_cell()
    )
    release_query_id = (query_id + 1) & ((1 << 64) - 1) or 1
    intent = (
        Builder()
        .store_uint(MAGIC_INTENT, 32)
        .store_uint(1, 16)
        .store_uint(release_query_id, 64)
        .store_uint(AMOUNT, 128)
        .store_address(escrow)
        .store_bytes(quote_cell.hash)
        .store_bytes(receipt.hash)
        .end_cell()
    )
    signature = signer_key.sign(intent.hash).signature
    release_body = (
        Builder()
        .store_uint(OP_RELEASE, 32)
        .store_uint(release_query_id, 64)
        .store_bytes(signature)
        .store_ref(receipt)
        .end_cell()
    )
    outcome = {
        "quote_commitment": cell_digest(quote_cell),
        "execution_id": execution_id,
        "input_digest": input_digest,
        "result_digest": result_digest,
        "artifact": {
            "Digest": artifact_digest,
            "MediaType": "application/vnd.tos.service.software-artifact.v1+tar",
            "SizeBytes": len(artifact_body),
        },
        "report": {
            "Digest": report_digest,
            "MediaType": "application/vnd.tos.service.test-report.v1+json",
            "SizeBytes": len(report_body),
        },
        "source_digest": source_digest,
        "toolchain_digest": toolchain_digest,
        "sandbox_digest": sandbox_digest,
        "exit_code": 0,
        "completed_at_unix": completed_at,
    }
    release = {
        "query_id": release_query_id,
        "receipt_boc_base64": base64.b64encode(receipt.to_boc()).decode(),
        "receipt_commitment": cell_digest(receipt),
        "release_body_boc_base64": base64.b64encode(release_body.to_boc()).decode(),
        "settlement_intent": cell_digest(intent),
        "signature_hex": signature.hex(),
    }
    outcome_path = output / "execution-outcome-local.json"
    release_path = output / "release-local.json"
    outcome_path.write_text(json.dumps(outcome, indent=2) + "\n")
    release_path.write_text(json.dumps(release, indent=2) + "\n")

    wallet_code = Cell.one_from_boc(
        base64.b64decode(
            "".join(
                (REPO / "crypto/smartcont/test-usdt-wallet-code.boc.base64")
                .read_text()
                .split()
            )
        )
    )
    provider = Address(provider_raw)
    master = Address(stablecoin["asset"]["master_contract"])
    provider_wallet_data = (
        Builder()
        .store_uint(0, 4)
        .store_coins(0)
        .store_address(provider)
        .store_address(master)
        .end_cell()
    )
    provider_wallet = Address(
        (0, StateInit(code=wallet_code, data=provider_wallet_data).serialize().hash)
    )

    payer_key = nacl.signing.SigningKey(gate.read_private(state_dir / "main-wallet.pk"))
    payer_file = gate.read_private(state_dir / "main-wallet.addr")
    payer = Address(
        (int.from_bytes(payer_file[32:36], "big", signed=True), payer_file[:32])
    )
    gate.send_wallet_message(config, payer_key, payer, escrow, 2 * NANO, release_body)
    settled = wait_escrow(config, escrow, 2)
    if settled["settled_atomic"] != str(AMOUNT):
        raise RuntimeError(f"unexpected settled state: {settled}")
    usdt.wait_view(
        config,
        provider_wallet,
        usdt.wallet_view,
        lambda view: view["balance"] == str(AMOUNT),
    )

    evidence_path = output / "paid-software-work-local.json"
    verifier = [
        sys.executable,
        str(REPO / "scripts/tos-service-software-work-paid-evidence.py"),
        "--outcome",
        str(outcome_path),
        "--release",
        str(release_path),
        "--quote-vector",
        str(quote_path),
        "--artifact-root",
        str(output),
        "--escrow",
        escrow.to_str(),
        "--buyer-wallet",
        stablecoin["asset"]["test_buyer_jetton_wallet_contract"],
        "--provider-wallet",
        provider_wallet.to_str(),
        "--quorum",
        "2",
        "--funding-query-id",
        str(query_id),
        "--funded-checkpoint",
        str(funded_checkpoint),
        "--evidence",
        str(evidence_path),
        "--local-rehearsal",
    ]
    for endpoint in endpoints:
        verifier.extend(["--endpoint", endpoint])
    subprocess.run(verifier, check=True, env=environment)
    print(f"PASS local paid software-work rehearsal: {evidence_path}")
    print("NOT ACCEPTED as an external gate: infrastructure and work orchestration are same-host")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
