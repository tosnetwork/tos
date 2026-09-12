"""Agent Account funded deployment, policy state and controller/PQ signing."""
from dataclasses import dataclass
import nacl.signing
from pytosiq_core import Address, Cell, Builder
from .contract import ContractView
from .pq_auth import (AuthState, AuthRequest, FundedBlueprint, uint, network_id,
                      key_bytes, address, exact_end)

CONTROLLER_DOMAIN = bytes.fromhex("ede715a9852fbba2c3c234ed0d27329ae34d6263a82cfb6215da87c91683b471")


@dataclass(frozen=True)
class AgentPolicy:
    max_single: int
    daily_limit: int
    max_ttl: int = 3600

    def serialize(self) -> Cell:
        if not 0 < self.max_ttl <= 3600:
            raise ValueError("invalid policy TTL")
        return (Builder().store_coins(uint(self.max_single, 120)).store_coins(uint(self.daily_limit, 120))
                .store_uint(self.max_ttl, 64).store_uint(0, 2).end_cell())


@dataclass(frozen=True)
class AgentAccountState:
    owner: Address
    public_key: bytes
    agent_id: bytes
    policy_epoch: int
    seqno: int
    spent_day: int
    spent: int
    policy: Cell
    auth: AuthState | None = None

    def serialize(self) -> Cell:
        b = (Builder().store_address(address(self.owner)).store_bytes(key_bytes(self.public_key, 32))
             .store_bytes(key_bytes(self.agent_id, 32)).store_uint(uint(self.policy_epoch, 64), 64)
             .store_uint(uint(self.seqno, 32), 32).store_uint(uint(self.spent_day, 32), 32)
             .store_coins(uint(self.spent, 120)).store_ref(self.policy))
        if self.auth is not None:
            b.store_ref(self.auth.serialize())
        return b.end_cell()

    @classmethod
    def parse(cls, cell: Cell):
        s = cell.begin_parse()
        result = cls(address(s.load_address()), s.load_bytes(32), s.load_bytes(32), s.load_uint(64),
                     s.load_uint(32), s.load_uint(32), s.load_coins(), s.load_ref(),
                     AuthState.parse(s.load_ref()) if s.remaining_refs else None)
        exact_end(s)
        return result


@dataclass
class AgentAccount(ContractView[AgentAccountState]):
    network: int
    key: nacl.signing.SigningKey | None = None

    def _parse_state(self, state: Cell) -> AgentAccountState:
        return AgentAccountState.parse(state)

    def transfer_payload(self, state: AgentAccountState, destination: Address, value: int, valid_until: int) -> Cell:
        return (Builder().store_uint(0x41475004, 32).store_int(network_id(self.network), 32)
                .store_uint(uint(state.policy_epoch, 64), 64).store_uint(uint(state.seqno, 32), 32)
                .store_uint(uint(valid_until, 32), 32).store_address(address(destination))
                .store_coins(uint(value, 120)).end_cell())

    def sign(self, payload: Cell, state: AgentAccountState) -> Cell:
        if self.key is None or self.key.verify_key.encode() != state.public_key:
            raise ValueError("matching controller key is required")
        if state.auth and state.auth.mode >= 2:
            raise ValueError("classical controller authorization is disabled")
        digest = (Builder().store_bytes(CONTROLLER_DOMAIN).store_int(network_id(self.network), 32)
                  .store_int(self.address.wc, 8).store_bytes(self.address.hash_part)
                  .store_bytes(payload.hash).end_cell().hash)
        return Builder().store_bytes(self.key.sign(digest).signature).store_cell(payload).end_cell()

    async def send(self, destination: Address, value: int, valid_until: int):
        state = await self.current
        payload = self.transfer_payload(state, destination, value, valid_until)
        return await self.send_external(body=self.sign(payload, state))

    def pq_request(self, state: AgentAccountState, payload: Cell, valid_until: int, kind: int = 0) -> AuthRequest:
        if state.auth is None:
            raise ValueError("no authentication module is installed")
        return AuthRequest(self.network, self.address, state.auth.epoch, state.auth.nonce, valid_until, kind, payload)


class AgentAccountBlueprint(FundedBlueprint):
    def __init__(self, code: Cell, workchain: int, network: int, owner: Address, public_key: bytes,
                 agent_id: bytes, policy: AgentPolicy, auth: AuthState | None = None,
                 key: nacl.signing.SigningKey | None = None):
        address(Address((workchain, bytes(32))))
        self.CODE_BOC, self.network, self.key = code, network_id(network), key
        super().__init__(workchain, AgentAccountState(owner, public_key, agent_id, 0, 0, 0, 0, policy.serialize(), auth))

    def materialize(self, provider):
        return AgentAccount(provider, self.address, self.network, self.key)
