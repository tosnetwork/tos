"""Wallet V5 deployment, classic signing and PQ request construction."""
from dataclasses import dataclass
from pytosiq_core import Address, Cell, Builder, WalletMessage
import nacl.signing
from .contract import ContractView
from .pq_auth import (AuthState, AuthRequest, FundedBlueprint, uint, network_id,
                      key_bytes, exact_end, address, transfer_message)


@dataclass(frozen=True)
class WalletV5State:
    signature_allowed: bool
    seqno: int
    wallet_id: int
    public_key: bytes
    extensions: Cell | None = None
    auth: AuthState | None = None

    def serialize(self) -> Cell:
        b = (Builder().store_uint(int(self.signature_allowed), 1).store_uint(uint(self.seqno, 32), 32)
             .store_uint(uint(self.wallet_id, 32), 32).store_bytes(key_bytes(self.public_key, 32))
             .store_maybe_ref(self.extensions))
        if self.auth is not None:
            b.store_ref(self.auth.serialize())
        return b.end_cell()

    @classmethod
    def parse(cls, cell: Cell):
        s = cell.begin_parse()
        result = cls(bool(s.load_uint(1)), s.load_uint(32), s.load_uint(32), s.load_bytes(32),
                     s.load_maybe_ref(), AuthState.parse(s.load_ref()) if s.remaining_refs else None)
        exact_end(s)
        return result


@dataclass
class WalletV5(ContractView[WalletV5State]):
    network: int
    key: nacl.signing.SigningKey | None = None

    def _parse_state(self, state: Cell) -> WalletV5State:
        return WalletV5State.parse(state)

    def transfer_payload(self, destination: Address, value: int, body: Cell | None = None,
                         state_init=None) -> Cell:
        msg = transfer_message(self.address, destination, value, body, init=state_init)
        return (Builder().store_uint(0x0ec3c86d, 32).store_uint(3, 8)
                .store_ref(Cell.empty()).store_ref(msg.serialize()).end_cell())

    def sign(self, payload: Cell, state: WalletV5State, valid_until: int) -> Cell:
        if self.key is None or self.key.verify_key.encode() != state.public_key:
            raise ValueError("matching classical key is required")
        if not state.signature_allowed or (state.auth and state.auth.mode >= 2):
            raise ValueError("classical authorization is disabled")
        b = (Builder().store_uint(0x7369676e, 32).store_int(network_id(self.network), 32)
             .store_uint(state.wallet_id, 32).store_uint(uint(valid_until, 32), 32)
             .store_uint(state.seqno, 32).store_maybe_ref(payload).store_uint(0, 1).end_cell())
        return Builder().store_cell(b).store_bytes(self.key.sign(b.hash).signature).end_cell()

    async def send(self, destination: Address, value: int, valid_until: int):
        state = await self.current
        return await self.send_external(body=self.sign(self.transfer_payload(destination, value), state, valid_until))

    def pq_request(self, state: WalletV5State, payload: Cell, valid_until: int, kind: int = 0) -> AuthRequest:
        if state.auth is None:
            raise ValueError("no authentication module is installed")
        return AuthRequest(self.network, self.address, state.auth.epoch, state.auth.nonce, valid_until, kind, payload)


class WalletV5Blueprint(FundedBlueprint):
    def __init__(self, code: Cell, workchain: int, network: int, public_key: bytes,
                 wallet_id: int = 0, auth: AuthState | None = None, key: nacl.signing.SigningKey | None = None):
        address(Address((workchain, bytes(32))))
        self.CODE_BOC, self.network, self.key = code, network_id(network), key
        # A strict root, when present, is authoritative regardless of the stored classical key.
        super().__init__(workchain, WalletV5State(True, 0, wallet_id, public_key, auth=auth))

    def materialize(self, provider):
        return WalletV5(provider, self.address, self.network, self.key)
