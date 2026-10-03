"""Fixed-profile funded Falcon AUTH wire codec. Secrets stay in local handles."""

from dataclasses import dataclass

from pytosiq_core import Address, Builder, Cell

from .pq_auth import (
    AuthRequest,
    FundedBlueprint,
    address,
    byte_chain,
    exact_end,
    key_bytes,
    network_id,
    uint,
)

PROFILE = "TOS-FALCON512-PADDED-v1"
TAG = b"TOS-AUTH-FALCON512-PADDED-v1"


def read_chain(cell: Cell, limit: int) -> bytes:
    out = bytearray()
    while True:
        s = cell.begin_parse()
        if (
            cell.is_exotic
            or cell.level_mask.mask != 0
            or s.remaining_bits % 8
            or s.remaining_refs > 1
        ):
            raise ValueError("noncanonical byte chain")
        n, refs = s.remaining_bits // 8, s.remaining_refs
        if n > 127 or (refs and n != 127) or (not n and (out or refs)) or n > limit - len(out):
            raise ValueError("invalid byte chain length")
        out.extend(s.load_bytes(n))
        if not refs:
            return bytes(out)
        cell = s.load_ref()


@dataclass(frozen=True)
class FalconModuleState:
    network: int
    public_key: bytes
    profile_version: int = 1

    def serialize(self):
        if self.profile_version != 1:
            raise ValueError("unsupported module profile")
        return (
            Builder()
            .store_int(network_id(self.network), 32)
            .store_uint(1, 16)
            .store_ref(byte_chain(key_bytes(self.public_key, 897)))
            .end_cell()
        )

    @classmethod
    def parse(cls, cell):
        s = cell.begin_parse()
        network, version, key = s.load_int(32), s.load_uint(16), read_chain(s.load_ref(), 897)
        exact_end(s)
        state = cls(network, key, version)
        state.serialize()
        return state


class Falcon512ModuleBlueprint(FundedBlueprint):
    def __init__(self, code, workchain, network, public_key, validate_key):
        address(Address((workchain, bytes(32))))
        if not validate_key(public_key):
            raise ValueError("noncanonical Falcon public key")
        self.CODE_BOC = code
        super().__init__(workchain, FalconModuleState(network, public_key))

    def materialize(self, provider):
        return self.address


def signing_message(root: Address, request: AuthRequest):
    root, target = address(root), address(request.account)
    if root.wc != target.wc or root.hash_part == target.hash_part:
        raise ValueError("invalid AUTH target")
    return (
        TAG
        + b"\x00"
        + root.wc.to_bytes(4, "big", signed=True)
        + root.hash_part
        + request.commitment
    )


def submission(request, signature, classical_signature=None, query_id=0):
    return (
        Builder()
        .store_uint(0x46414C31, 32)
        .store_uint(uint(query_id, 64), 64)
        .store_ref(request.envelope(classical_signature))
        .store_ref(byte_chain(key_bytes(signature, 666)))
        .end_cell()
    )


def request_identity(request):
    # Stable across relayer retries and randomized Falcon signatures.
    return (
        request.network,
        request.account.to_str(is_user_friendly=False),
        request.epoch,
        request.nonce,
        request.commitment.hex(),
    )
