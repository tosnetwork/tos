"""Test-only accounts for a real PQ pool -> controller -> elector rehearsal.

The contracts come from their production sources. This module does not install
ConfigParam 47; that must be done through the chain's configuration contract.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from contract.pq_auth import byte_chain
from pytosiq_core import Address, Builder, Cell, StateInit
from tosapi import toslib_api

from .install import Install
from .pq_initial_validator import deterministic_pq_initial_validator_seed

_ROOT_DOMAIN = b"tos-test-pq-election-controller-root-v1\x00"
_KEY_ID = re.compile(r"^key_id\s+([0-9a-f]{64})$", re.MULTILINE)
_PUBLIC = re.compile(r"^public\s+([0-9a-f]{2624})$", re.MULTILINE)
_AUTHORIZATION_FIELDS = {
    "validator_id", "key_id", "algorithm_id", "public_key", "signature",
}


def require_pq_stake_authorization_binding(response_type: type) -> None:
    """Fail before node boot when ignored generated Python TL is stale."""
    actual = set(inspect.signature(response_type).parameters)
    missing = _AUTHORIZATION_FIELDS - actual
    if missing:
        raise RuntimeError(
            "generated Python TL stake authorization is stale: "
            f"missing={sorted(missing)}; run uv run python test/tostester/generate_tl.py"
        )


@dataclass(frozen=True)
class FixtureKey:
    seed: bytes
    key_id: bytes
    public_key: bytes


@dataclass(frozen=True)
class ControllerFixture:
    address: Address
    state_init: StateInit
    birth_witness: Cell
    consensus: FixtureKey


@dataclass(frozen=True)
class PoolFixture:
    address: Address
    state_init: StateInit


def _import_key(install: Install, output: Path, seed: bytes) -> FixtureKey:
    if len(seed) != 32:
        raise ValueError("PQ fixture seed must be 32 bytes")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.parent.chmod(0o700)
    result = subprocess.run(
        [str(install.pq_consensus_key_exe), "import", str(output)],
        input=seed.hex() + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"PQ fixture key import failed: {result.stderr.strip()}")
    key_id = _KEY_ID.search(result.stdout)
    public = _PUBLIC.search(result.stdout)
    if key_id is None or public is None:
        raise RuntimeError("PQ fixture key tool did not report key_id and public key")
    return FixtureKey(seed, bytes.fromhex(key_id.group(1)), bytes.fromhex(public.group(1)))


def compile_controller_code(install: Install, output_dir: Path) -> Cell:
    """Compile the production controller, including its PQ Fift instruction."""
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    compiled_fif = output_dir / "validator-controller-v1.fif"
    compiled_boc = output_dir / "validator-controller-v1.boc"
    source = install.source_dir / "crypto/smartcont"
    subprocess.run(
        [
            str(install.build_dir / "crypto/func"),
            "-W", str(compiled_boc), "-AP", "-o", str(compiled_fif),
            str(source / "stdlib.fc"), str(source / "validator-controller-v1.fc"),
        ],
        cwd=install.source_dir,
        check=True,
    )
    generated = compiled_fif.read_text()
    if not generated.startswith('"Asm.fif" include\n'):
        raise RuntimeError("controller compiler changed its Fift preamble")
    compiled_fif.write_text(generated.replace('"Asm.fif" include\n', '"PQ.fif" include\n', 1))
    environment = os.environ.copy()
    environment["FIFTPATH"] = str(install.source_dir / "crypto/fift/lib")
    subprocess.run(
        [str(install.build_dir / "crypto/fift"), str(compiled_fif)],
        cwd=install.source_dir,
        env=environment,
        check=True,
    )
    return Cell.one_from_boc(compiled_boc.read_bytes())


def _packed_key(public_key: bytes) -> Cell:
    if len(public_key) != 1312:
        raise ValueError(f"controller root key must be 1312 bytes, got {len(public_key)}")
    return Builder().store_uint(len(public_key), 32).store_ref(byte_chain(public_key)).end_cell()


def build_pool_stake_order(
    *, query_id: int, stake_amount: int, stake_at: int, max_factor: int,
    adnl_addr: bytes, algorithm_id: int, public_key: bytes, signature: bytes,
    witness: Cell | None,
) -> Cell:
    """NEW_STAKE as consumed by single-nominator's check_new_stake_msg.

    This is a pool order, never an elector-directed body. The value-round-trip
    test pins every field to the contract parser's order.
    """
    if query_id <= 0 or stake_amount <= 0:
        raise ValueError("pool stake order needs a positive query ID and amount")
    if len(adnl_addr) != 32:
        raise ValueError(f"stake ADNL address must be 32 bytes, got {len(adnl_addr)}")
    if algorithm_id != 1:
        raise ValueError(f"pool stake order requires ML-DSA-44 algorithm 1, got {algorithm_id}")
    if len(signature) != 2420:
        raise ValueError(f"ML-DSA-44 signature must be 2420 bytes, got {len(signature)}")
    return (
        Builder()
        .store_uint(0x4E73744B, 32)
        .store_uint(query_id, 64)
        .store_coins(stake_amount)
        .store_uint(stake_at, 32)
        .store_uint(max_factor, 32)
        .store_bytes(adnl_addr)
        .store_uint(algorithm_id, 16)
        .store_ref(_packed_key(public_key))
        .store_ref(Builder().store_uint(len(signature), 32).store_ref(byte_chain(signature)).end_cell())
        .store_maybe_ref(witness)
        .end_cell()
    )


def build_production_pool_stake_order(
    executable: Path, *, query_id: int, stake_amount: int, stake_at: int,
    max_factor: int, adnl_addr: bytes, algorithm_id: int, public_key: bytes, signature: bytes,
    witness: Cell,
) -> Cell:
    """Invoke Rust nominator::new_stake_with_witness, not a second Python encoder."""
    if algorithm_id != 1:
        raise ValueError(f"production pool order requires ML-DSA-44 algorithm 1, got {algorithm_id}")
    payload = {
        "query_id": query_id,
        "stake_amount": stake_amount,
        "stake_at": stake_at,
        "max_factor": max_factor,
        "adnl_addr_hex": adnl_addr.hex(),
        "public_key_hex": public_key.hex(),
        "signature_hex": signature.hex(),
        "witness_boc_hex": witness.to_boc().hex(),
    }
    result = subprocess.run(
        [str(executable)], input=json.dumps(payload), text=True,
        capture_output=True, check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"production PQ pool stake builder failed ({result.returncode}): {result.stderr.strip()}"
        )
    try:
        return Cell.one_from_boc(bytes.fromhex(result.stdout.strip()))
    except ValueError as error:
        raise RuntimeError("production PQ pool stake builder returned invalid BOC hex") from error


def elector_reply(transactions: list, query_id: int) -> tuple[int, int] | None:
    """Find an exact elector answer, ignoring source-less wallet externals."""
    elector = Address((-1, bytes.fromhex("33" * 32)))
    for transaction in transactions:
        message = transaction.in_msg
        if message is None or message.source is None:
            continue
        source_text = message.source.account_address
        if not source_text or Address(source_text) != elector:
            continue
        if not isinstance(message.msg_data, toslib_api.Msg_dataRaw):
            continue
        reply = Cell.one_from_boc(message.msg_data.body).begin_parse()
        if reply.remaining_bits < 96:
            continue
        opcode = reply.load_uint(32)
        if reply.load_uint(64) != query_id:
            continue
        # A successful mature-stake recovery has only opcode + query_id;
        # refusals and stake acknowledgements additionally carry a reason.
        if opcode == 0xF96F7324 and reply.remaining_bits == 0 and reply.remaining_refs == 0:
            return opcode, 0
        if reply.remaining_bits >= 32:
            return opcode, reply.load_uint(32)
    return None


def elector_return_reason(transactions: list, query_id: int) -> int | None:
    reply = elector_reply(transactions, query_id)
    return reply[1] if reply is not None and reply[0] == 0xEE6F454C else None


def participant_ids_from_runmethod(output: str) -> set[int]:
    """Read outer validator IDs from lite-client's decimal get-method stack."""
    match = re.search(r"\bresult:\s*\[[^\n]*?\(\s*(.*?)\s*\)\s+0\s+0\s*\]", output)
    if match is None:
        raise ValueError("participant_list_extended has no parseable result")
    ids = {int(value) for value in re.findall(r"\[(\d+)\s+\[", match.group(1))}
    if not ids:
        raise ValueError("participant_list_extended has no validator entries")
    return ids


def parse_past_elections_list(output: str) -> dict[int, dict[str, int]]:
    """Read the Elector's actual, possibly reset unfreeze times."""
    result = re.search(r"\bresult:\s*\[(.*?)\]\s*remote result", output, re.S)
    if result is None:
        raise ValueError("Elector past_elections_list has no trusted result")
    body = result.group(1)
    entries = re.findall(r"\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", body)
    if len(entries) != len(re.findall(r"\[\s*\d+", body)):
        raise ValueError("Elector past_elections_list has an unparsed record")
    if not entries and not re.fullmatch(r"\s*\(\s*\)\s*", body):
        raise ValueError("Elector past_elections_list has an unknown empty shape")
    parsed = {
        int(election_id): {
            "unfreeze_at": int(unfreeze_at),
            "vset_hash": int(vset_hash),
            "stake_held": int(stake_held),
        }
        for election_id, unfreeze_at, vset_hash, stake_held in entries
    }
    if len(parsed) != len(entries):
        raise ValueError("Elector past_elections_list repeats an election ID")
    return parsed


def _birth_witness(code: Cell, data: Cell) -> Cell:
    """The exact four-number controller_birth_witness_v1 sent to the elector."""
    return (
        Builder()
        .store_bytes(code.hash)
        .store_uint(code.get_depth(0), 16)
        .store_bytes(data.hash)
        .store_uint(data.get_depth(0), 16)
        .end_cell()
    )


def make_controller_fixture(
    install: Install, key_dir: Path, code: Cell, index: int
) -> ControllerFixture:
    consensus = _import_key(
        install, key_dir / f"consensus-{index}.seed", deterministic_pq_initial_validator_seed(index)
    )
    root_seed = hashlib.sha256(_ROOT_DOMAIN + index.to_bytes(4, "big")).digest()
    root = _import_key(install, key_dir / f"root-{index}.seed", root_seed)
    if root.key_id == consensus.key_id:
        raise AssertionError(f"controller {index} root and consensus key unexpectedly coincide")
    data = (
        Builder()
        .store_uint(0, 64)  # authority epoch
        .store_uint(0, 64)  # root nonce
        .store_uint(1, 16)  # bound ML-DSA-44 consensus key
        .store_bytes(consensus.key_id)
        .store_ref(_packed_key(root.public_key))
        .end_cell()
    )
    init = StateInit(code=code, data=data)
    address = Address((-1, init.serialize().hash))
    return ControllerFixture(address, init, _birth_witness(code, data), consensus)


def make_pool_fixture(code: Cell, owner: Address, controller: Address) -> PoolFixture:
    if owner.wc != -1 or controller.wc != -1:
        raise ValueError("PQ election fixture needs masterchain owner and controller")
    data = (
        Builder()
        .store_address(owner)
        .store_address(owner)  # operator wallet may order a stake
        .store_address(controller)
        .end_cell()
    )
    init = StateInit(code=code, data=data)
    return PoolFixture(Address((-1, init.serialize().hash)), init)


def assert_controller_identity(node, controller: ControllerFixture, *, index: int) -> None:
    held = node.pq_initial_validator
    if held is None:
        raise AssertionError(f"validator {index} has no PQ consensus identity")
    expected = controller.address.hash_part
    if held.validator_id != expected:
        raise AssertionError(
            f"validator {index} controller address and PQ validator_id differ: "
            f"controller={expected.hex()} validator_id={held.validator_id.hex()}"
        )
    if held.key_id != controller.consensus.key_id:
        raise AssertionError(
            f"validator {index} controller-bound consensus key and node key differ: "
            f"controller={controller.consensus.key_id.hex()} node={held.key_id.hex()}"
        )
