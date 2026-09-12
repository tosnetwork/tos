"""Exact PQ authorization wire format and explicit funded deployment.

The signing interface accepts public commitment bytes only. Secret material stays
in the caller's keystore adapter. A submitted message is not a delivery receipt.
"""
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
import subprocess

from pytosiq_core import (Address, Cell, Builder, StateInit, MessageAny,
                           InternalMsgInfo, CurrencyCollection)
from .contract import Blueprint

CONTEXT = b"TOS-AUTH-ML-DSA-44-v1"
MAX_COINS = (1 << 120) - 1


def uint(value: int, bits: int) -> int:
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ValueError(f"expected uint{bits}")
    return value


def network_id(value: int) -> int:
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise ValueError("network ID must fit int32")
    return value


def address(value: Address) -> Address:
    if not isinstance(value, Address) or value.anycast is not None:
        raise ValueError("canonical internal address required")
    if type(value.wc) is not int or not -128 <= value.wc < 128 or len(value.hash_part) != 32:
        raise ValueError("invalid standard address")
    return value


def exact_end(s) -> None:
    if s.remaining_bits or s.remaining_refs:
        raise ValueError("unexpected trailing account data")


def key_bytes(key: bytes, size: int) -> bytes:
    if type(key) is not bytes or len(key) != size:
        raise ValueError(f"expected {size} key/signature bytes")
    return key


def byte_chain(data: bytes) -> Cell:
    if type(data) is not bytes:
        raise TypeError("bytes required")
    if not data:
        return Cell.empty()
    parts = [data[i:i+127] for i in range(0, len(data), 127)]
    tail = Builder().store_bytes(parts[-1]).end_cell()
    for part in reversed(parts[:-1]):
        tail = Builder().store_bytes(part).store_ref(tail).end_cell()
    return tail


@dataclass(frozen=True)
class AuthState:
    mode: int
    epoch: int
    nonce: int
    module_hash: bytes

    def serialize(self) -> Cell:
        if self.mode not in (1, 2, 3):
            raise ValueError("invalid authorization mode")
        return (Builder().store_uint(self.mode, 2).store_uint(uint(self.epoch, 64), 64)
                .store_uint(uint(self.nonce, 64), 64)
                .store_bytes(key_bytes(self.module_hash, 32)).end_cell())

    @classmethod
    def parse(cls, cell: Cell):
        s = cell.begin_parse()
        result = cls(s.load_uint(2), s.load_uint(64), s.load_uint(64), s.load_bytes(32))
        exact_end(s)
        result.serialize()
        return result


@dataclass(frozen=True)
class AuthRequest:
    network: int
    account: Address
    epoch: int
    nonce: int
    valid_until: int
    kind: int
    payload: Cell

    def serialize(self) -> Cell:
        if self.kind not in (0, 1, 2):
            raise ValueError("unsupported authorization operation")
        return (Builder().store_int(network_id(self.network), 32).store_address(address(self.account))
                .store_uint(uint(self.epoch, 64), 64).store_uint(uint(self.nonce, 64), 64)
                .store_uint(uint(self.valid_until, 32), 32).store_uint(self.kind, 8)
                .store_ref(self.payload).end_cell())

    @property
    def commitment(self) -> bytes:
        return Builder().store_bytes(b"TOS-AUTH").store_ref(self.serialize()).end_cell().hash

    def envelope(self, classical_signature: bytes | None = None) -> Cell:
        co = None if classical_signature is None else Builder().store_bytes(key_bytes(classical_signature, 64)).end_cell()
        return Builder().store_uint(0x41555448, 32).store_ref(self.serialize()).store_maybe_ref(co).end_cell()

    def submission(self, signature: bytes, classical_signature: bytes | None = None, query_id: int = 0) -> Cell:
        return (Builder().store_uint(0x4d4c4434, 32).store_uint(uint(query_id, 64), 64)
                .store_ref(self.envelope(classical_signature))
                .store_ref(byte_chain(key_bytes(signature, 2420))).end_cell())


def transfer_message(sender: Address, destination: Address, value: int, body: Cell | None = None,
                     init: StateInit | None = None, bounce: bool = False) -> MessageAny:
    return MessageAny(info=InternalMsgInfo(ihr_disabled=True, bounce=bounce, bounced=False,
        src=address(sender), dest=address(destination), value=CurrencyCollection(tomis=uint(value, 120)),
        ihr_fee=0, fwd_fee=0, created_lt=0, created_at=0), init=init,
        body=Cell.empty() if body is None else body)


class FundedBlueprint(Blueprint):
    """No free external deployment and no implicit acknowledgement of delivery."""
    async def deploy(self, provider):
        raise ValueError("use a funded internal StateInit message and confirm the resulting account")

    def deployment_message(self, sender: Address, value: int) -> MessageAny:
        if value <= 0:
            raise ValueError("deployment needs positive funding")
        return transfer_message(sender, self.address, value, init=self.state_init, bounce=False)


@dataclass(frozen=True)
class MldsaModuleState:
    network: int
    public_key: bytes

    def serialize(self) -> Cell:
        return (Builder().store_int(network_id(self.network), 32)
                .store_ref(byte_chain(key_bytes(self.public_key, 1312))).end_cell())


class Mldsa44ModuleBlueprint(FundedBlueprint):
    def __init__(self, code: Cell, workchain: int, network: int, public_key: bytes):
        address(Address((workchain, bytes(32))))
        self.CODE_BOC = code
        super().__init__(workchain, MldsaModuleState(network, public_key))

    def materialize(self, provider):
        # The module has no owner, withdrawal or mutation API.
        return self.address


class PqSigner(Protocol):
    def public_key(self) -> bytes: ...
    def sign(self, commitment: bytes, context: bytes = CONTEXT) -> bytes: ...


@dataclass(frozen=True)
class NativeMldsa44Signer:
    executable: Path
    key_file: Path

    def _run(self, *args: str) -> bytes:
        result = subprocess.run([str(self.executable.resolve()), *args], capture_output=True,
                                text=True, timeout=30, check=False)
        if result.returncode:
            raise RuntimeError("PQ keystore operation failed: " + result.stderr.strip())
        return bytes.fromhex(result.stdout.strip())

    def public_key(self) -> bytes:
        return key_bytes(self._run("public", str(self.key_file.absolute())), 1312)

    def sign(self, commitment: bytes, context: bytes = CONTEXT) -> bytes:
        key_bytes(commitment, 32)
        if context != CONTEXT:
            raise ValueError("unsupported authorization signing profile")
        return key_bytes(self._run("sign", str(self.key_file.absolute()), commitment.hex(), context.hex()), 2420)
