"""Test-only accounts for a real PQ pool -> controller -> elector rehearsal.

The contracts come from their production sources. This module does not install
ConfigParam 47; that must be done through the chain's configuration contract.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from contract.pq_auth import byte_chain
from pytosiq_core import Address, Builder, Cell, StateInit

from .install import Install
from .pq_initial_validator import deterministic_pq_initial_validator_seed

_ROOT_DOMAIN = b"tos-test-pq-election-controller-root-v1\x00"
_KEY_ID = re.compile(r"^key_id\s+([0-9a-f]{64})$", re.MULTILINE)
_PUBLIC = re.compile(r"^public\s+([0-9a-f]{2624})$", re.MULTILINE)


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
