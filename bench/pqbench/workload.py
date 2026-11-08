"""Deterministic bench accounts and the exact on-chain messages each workload sends.

Every message is built with the same client types the PQ regression suite uses,
so the bench measures the production wire format rather than a lookalike:

* ``classical``: a Wallet V5 external signed with Ed25519 (the baseline).
* ``pq-relay``: a Wallet V5 whose strict authorization root is an ML-DSA-44
  module. A relayer wallet carries signed AUTH submissions to each module, the
  module verifies the ML-DSA-44 proof on chain and forwards the envelope, and the
  wallet executes the transfer.

Keys are public test material derived from a public run seed.
"""

import hashlib
from dataclasses import dataclass

import nacl.signing
from pytosiq_core import Address, Builder, Cell, ExternalMsgInfo, MessageAny

from contract import (
    AuthState,
    Mldsa44ModuleBlueprint,
    WalletV5,
    WalletV5Blueprint,
    WalletV5State,
)
from contract.pq_auth import AuthRequest, transfer_message

ACTION_SEND_MSG = 0x0EC3C86D
MAX_ACTIONS = 255
WORKLOADS = ("classical", "pq-relay")


def derive_seed(run_seed: bytes, tag: str, index: int) -> bytes:
    if type(run_seed) is not bytes or len(run_seed) != 32:
        raise ValueError("run seed must be 32 bytes")
    if type(index) is not int or not 0 <= index < (1 << 32):
        raise ValueError("account index must fit uint32")
    return hashlib.sha256(run_seed + tag.encode() + index.to_bytes(4, "big")).digest()


def out_list(messages: list[MessageAny], mode: int = 3) -> Cell:
    """A Wallet V5 action list with one send action per message, in order."""
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


@dataclass(frozen=True)
class ClassicalWallet:
    """A Wallet V5 controlled by an Ed25519 key (relayers, funders, baseline load)."""

    blueprint: WalletV5Blueprint
    key: nacl.signing.SigningKey
    network: int

    @classmethod
    def derive(cls, code: Cell, network: int, run_seed: bytes, tag: str, index: int):
        key = nacl.signing.SigningKey(derive_seed(run_seed, tag + "/ed25519", index))
        blueprint = WalletV5Blueprint(code, 0, network, key.verify_key.encode(), key=key)
        return cls(blueprint, key, network)

    @property
    def address(self) -> Address:
        return self.blueprint.address

    def view(self) -> WalletV5:
        return WalletV5(None, self.address, self.network, self.key)

    def external(self, seqno: int, actions: list[MessageAny], valid_until: int) -> MessageAny:
        state = WalletV5State(True, seqno, 0, self.key.verify_key.encode())
        body = self.view().sign(out_list(actions), state, valid_until)
        return MessageAny(info=ExternalMsgInfo(None, self.address, 0), init=None, body=body)

    def transfer(self, destination: Address, value: int) -> MessageAny:
        return transfer_message(self.address, destination, value)


@dataclass(frozen=True)
class PqWallet:
    """A Wallet V5 in strict PQ mode and the ML-DSA-44 module that authorizes it."""

    wallet: WalletV5Blueprint
    module: Mldsa44ModuleBlueprint
    key: nacl.signing.SigningKey
    pq_seed: bytes
    network: int

    EPOCH = 1

    @classmethod
    def derive(
        cls,
        wallet_code: Cell,
        module_code: Cell,
        network: int,
        run_seed: bytes,
        index: int,
        public_key: bytes,
        pq_seed: bytes,
    ):
        key = nacl.signing.SigningKey(derive_seed(run_seed, "pq-relay/ed25519", index))
        module = Mldsa44ModuleBlueprint(module_code, 0, network, public_key)
        auth = AuthState(2, cls.EPOCH, 0, module.address.hash_part)
        wallet = WalletV5Blueprint(
            wallet_code, 0, network, key.verify_key.encode(), auth=auth, key=key
        )
        return cls(wallet, module, key, pq_seed, network)

    @property
    def address(self) -> Address:
        return self.wallet.address

    def request(self, nonce: int, destination: Address, value: int, valid_until: int):
        view = WalletV5(None, self.address, self.network, self.key)
        payload = view.transfer_payload(destination, value)
        return AuthRequest(self.network, self.address, self.EPOCH, nonce, valid_until, 0, payload)


def pq_seed(run_seed: bytes, index: int) -> bytes:
    return derive_seed(run_seed, "pq-relay/mldsa44", index)


def submission(
    relayer: Address, module: Address, request: AuthRequest, signature: bytes, value: int,
    query_id: int,
) -> MessageAny:
    """The internal message a relayer sends to a module, as the PQ relayer builds it."""
    return transfer_message(relayer, module, value, body=request.submission(signature, None, query_id))


def sinks(count: int, run_seed: bytes) -> list[Address]:
    """Destinations outside every bench account set, so wallet transactions count executions."""
    if not 1 <= count <= 65536:
        raise ValueError("sink count must be 1..65536")
    return [Address((0, derive_seed(run_seed, "sink", i))) for i in range(count)]
