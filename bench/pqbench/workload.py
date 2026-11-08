"""Deterministic self-pay Quantum wallets and the exact external messages the bench sends.

Every account the bench uses, load and setup alike, is a self-pay Quantum
wallet (``wallet-quantum-self-pay.fc``): one external carries a request signed
with the account's ML-DSA-44 PRIMARY key, the wallet verifies it on chain, pays
its own fees and executes the Wallet V5-format action list in the request.
There is no carrier, relayer or classical key anywhere in the path.

Keys are public test material derived from a public run seed.
"""

import hashlib
from dataclasses import dataclass

from pytosiq_core import Address, Builder, Cell, ExternalMsgInfo, MessageAny, StateInit

from contract.pq_auth import transfer_message

ACTION_SEND_MSG = 0x0EC3C86D
MAX_ACTIONS = 255
QSP_REQUEST = 0x51535031
QSP_EXECUTE_TAG = 0x45584543
QSP_PRIMARY_CONTEXT = b"TOS-QSP-MLDSA44-v1"
ROLE_PRIMARY = 1
KIND_EXECUTE = 0
PUBLIC_KEY_BYTES = 1312
SIGNATURE_BYTES = 2420


def derive_seed(run_seed: bytes, tag: str, index: int) -> bytes:
    if type(run_seed) is not bytes or len(run_seed) != 32:
        raise ValueError("run seed must be 32 bytes")
    if type(index) is not int or not 0 <= index < (1 << 32):
        raise ValueError("account index must fit uint32")
    return hashlib.sha256(run_seed + tag.encode() + index.to_bytes(4, "big")).digest()


def out_list(messages: list[MessageAny], mode: int = 3) -> Cell:
    """A Wallet V5-format action list with one send action per message, in order."""
    if not 1 <= len(messages) <= MAX_ACTIONS:
        raise ValueError(f"an action list holds 1..{MAX_ACTIONS} messages")
    prev = Cell.empty()
    for message in messages:
        prev = (
            Builder()
            .store_uint(ACTION_SEND_MSG, 32)
            .store_uint(mode, 8)
            .store_ref(prev)
            .store_ref(message.serialize())
            .end_cell()
        )
    return prev


def byte_chain(data: bytes) -> Cell:
    """Bytes as a chain of 127-byte cells, the encoding the PQ verifiers read."""
    if not data:
        raise ValueError("empty byte chain")
    tail = None
    for offset in reversed(range(0, len(data), 127)):
        b = Builder().store_bytes(data[offset : offset + 127])
        if tail is not None:
            b.store_ref(tail)
        tail = b.end_cell()
    assert tail is not None
    return tail


@dataclass(frozen=True)
class QuantumWallet:
    """A self-pay Quantum wallet: all authority from an external ML-DSA-44 PRIMARY signature."""

    code: Cell
    authority: Cell
    wallet_id: int
    pq_seed: bytes
    global_id: int
    network: bytes

    @classmethod
    def derive(cls, code: Cell, global_id: int, network: bytes, run_seed: bytes, tag: str,
               index: int, public_key: bytes, pq_seed: bytes, rescue: bytes | None = None):
        if len(public_key) != PUBLIC_KEY_BYTES or len(network) != 32:
            raise ValueError("ML-DSA-44 public key and 32-byte AUTH namespace required")
        if type(global_id) is not int or not -(1 << 31) <= global_id < (1 << 31):
            raise ValueError("global id must fit int32")
        # The RESCUE slot holds a 32-byte SLH-DSA public key; the bench only spends
        # with PRIMARY, so a derived public commitment fills it.
        if rescue is None:
            rescue = derive_seed(run_seed, tag + "/rescue-commitment", index)
        if len(rescue) != 32:
            raise ValueError("RESCUE public key must be 32 bytes")
        authority = (
            Builder()
            .store_uint(1, 8)
            .store_int(global_id, 32)
            .store_bytes(network)
            .store_uint(1, 8)  # daily primary policy
            .store_ref(byte_chain(public_key))
            .store_bytes(rescue)
            .store_uint(1, 8)  # policy 1: PRIMARY may execute
            .end_cell()
        )
        return cls(code, authority, index, pq_seed, global_id, network)

    def data(self) -> Cell:
        return (
            Builder()
            .store_uint(1, 8)
            .store_uint(0, 32)  # seqno
            .store_uint(self.wallet_id, 32)
            .store_uint(0, 16)  # retired
            .store_uint(0, 64)  # epoch
            .store_uint(0, 64)  # primary nonce
            .store_uint(0, 64)  # rescue nonce
            .store_ref(self.authority)
            .end_cell()
        )

    @property
    def state_init(self) -> StateInit:
        return StateInit(code=self.code, data=self.data())

    @property
    def address(self) -> Address:
        return Address((0, self.state_init.serialize().hash))

    def deployment_message(self, sender: Address, value: int) -> MessageAny:
        if type(value) is not int or value <= 0:
            raise ValueError("deployment needs positive funding")
        return transfer_message(sender, self.address, value, init=self.state_init, bounce=False)

    def request(self, nonce: int, actions: list[MessageAny], deadline: int, epoch: int = 0) -> Cell:
        for name, value, bits in (("nonce", nonce, 64), ("deadline", deadline, 32), ("epoch", epoch, 64)):
            if type(value) is not int or not 0 <= value < (1 << bits):
                raise ValueError(f"{name} must fit uint{bits}")
        payload = Builder().store_uint(QSP_EXECUTE_TAG, 32).store_ref(out_list(actions)).end_cell()
        return (
            Builder()
            .store_uint(QSP_REQUEST, 32)
            .store_int(self.global_id, 32)
            .store_bytes(self.network)
            .store_address(self.address)
            .store_bytes(self.authority.hash)
            .store_uint(ROLE_PRIMARY, 8)
            .store_uint(epoch, 64)
            .store_uint(nonce, 64)
            .store_uint(deadline, 32)
            .store_uint(KIND_EXECUTE, 8)
            .store_ref(payload)
            .end_cell()
        )

    def transfer(self, destination: Address, value: int) -> MessageAny:
        return transfer_message(self.address, destination, value)

    def external(self, request: Cell, signature: bytes) -> MessageAny:
        if type(signature) is not bytes or len(signature) != SIGNATURE_BYTES:
            raise ValueError("ML-DSA-44 signature must be 2420 bytes")
        body = Builder().store_ref(request).store_ref(byte_chain(signature)).end_cell()
        return MessageAny(info=ExternalMsgInfo(None, self.address, 0), init=None, body=body)


def quantum_seed(run_seed: bytes, tag: str, index: int) -> bytes:
    return derive_seed(run_seed, tag + "/mldsa44", index)


def primary_nonce(data: Cell) -> int:
    """The PRIMARY nonce from a self-pay wallet's data cell."""
    s = data.begin_parse()
    if s.load_uint(8) != 1:
        raise ValueError("not a self-pay Quantum wallet state")
    s.skip_bits(32 + 32 + 16 + 64)
    return s.load_uint(64)


def sinks(count: int, run_seed: bytes) -> list[Address]:
    """Destinations outside every bench account set, so a wallet transaction is one executed transfer."""
    if not 1 <= count <= 65536:
        raise ValueError("sink count must be 1..65536")
    return [Address((0, derive_seed(run_seed, "sink", i))) for i in range(count)]
