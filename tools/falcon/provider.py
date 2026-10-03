"""Offline AuthProvider using reviewed chain state and compiler manifests.

A chain adapter must verify the snapshot using its trusted chain/proof source.
This library does not promote an RPC capability string to trusted chain state.
"""

import hashlib
from dataclasses import dataclass

from contract.agent_account import AgentAccountState
from contract.falcon_auth import (
    PROFILE,
    FalconModuleState,
    request_identity,
    signing_message,
    submission,
)
from contract.pq_auth import AuthRequest, address, transfer_message
from contract.wallet_v5 import WalletV5State
from pytosiq_core import Address, Builder, Cell, StateInit


@dataclass(frozen=True)
class TrustedChainSnapshot:
    network: int
    global_version: int
    now: int
    account: Address
    account_code: Cell
    account_data: Cell
    root: Address
    module_code: Cell
    module_data: Cell
    account_status: str = "active"
    module_status: str = "active"


@dataclass(frozen=True)
class TrustedModuleSnapshot:
    network: int
    global_version: int
    now: int
    root: Address
    code: Cell
    data: Cell
    status: str


@dataclass(frozen=True)
class SigningRequest:
    request: AuthRequest
    root: Address
    profile: str
    public_key: bytes
    account_mode: int
    classical_public_key: bytes
    snapshot_commitment: str

    @property
    def message(self):
        if self.profile != PROFILE:
            raise ValueError("unsupported signing profile")
        return signing_message(self.root, self.request)


@dataclass(frozen=True)
class AuthProof:
    profile: str
    identity: tuple
    root: str
    signature: bytes


@dataclass(frozen=True)
class ProfileDescriptor:
    profile: str
    public_key_bytes: int
    secret_key_bytes: int
    signature_bytes: int
    encoding: str
    network: int
    minimum_vm_version: int
    mode: int
    state: str
    root: str
    fingerprint: str
    module_code_hash: str
    compiler_manifest: dict


class AuthProvider:
    def __init__(self, backend, manifest):
        self.backend = backend
        self.manifest = manifest
        for name in ("module-func", "module-tol", "wallet-func", "wallet-tol", "agent"):
            row = manifest.get(name, {})
            for field in ("code_hash", "boc_sha256", "source_commit", "compiler_sha256"):
                value = row.get(field, "")
                size = 40 if field == "source_commit" else 64
                if len(value) != size or any(c not in "0123456789abcdef" for c in value):
                    raise ValueError("incomplete compiler manifest")
            if row.get("profile") != PROFILE:
                raise ValueError("unknown manifest profile")

    def _capability(self, snapshot):
        if not isinstance(snapshot, TrustedChainSnapshot):
            raise TypeError("verified chain snapshot required")
        if type(snapshot.global_version) is not int or snapshot.global_version < 19:
            raise ValueError("Falcon is not activated in the trusted chain snapshot")
        if snapshot.account_status != "active" or snapshot.module_status != "active":
            raise ValueError("frozen, deleted or uninitialized accounts require separate recovery")
        account, root = address(snapshot.account), address(snapshot.root)
        if (
            account.wc not in (-1, 0)
            or root.wc != account.wc
            or account.hash_part == root.hash_part
        ):
            raise ValueError("invalid root address")
        module_hash = snapshot.module_code.hash.hex()
        matches = [
            v
            for k, v in self.manifest.items()
            if k in ("module-func", "module-tol") and v["code_hash"] == module_hash
        ]
        if len(matches) != 1:
            raise ValueError("unknown module code identity")
        state = FalconModuleState.parse(snapshot.module_data)
        if state.network != snapshot.network or not self.backend.validate_public_key(
            state.public_key
        ):
            raise ValueError("module network or public key mismatch")
        init = StateInit(code=snapshot.module_code, data=snapshot.module_data).serialize()
        if init.hash != root.hash_part:
            raise ValueError("module address does not match immutable StateInit")
        code_hash = snapshot.account_code.hash.hex()
        account_matches = [
            k
            for k in ("wallet-func", "wallet-tol", "agent")
            if self.manifest[k]["code_hash"] == code_hash
        ]
        if len(account_matches) != 1:
            raise ValueError("account bytecode does not support the reviewed AUTH ABI")
        state_account = (
            AgentAccountState if account_matches[0] == "agent" else WalletV5State
        ).parse(snapshot.account_data)
        auth = state_account.auth
        if auth is None or auth.module_hash != root.hash_part:
            raise ValueError("selected root is not registered by the account")
        if auth.nonce == (1 << 64) - 1 or auth.epoch == (1 << 64) - 1:
            raise ValueError("AUTH counter exhausted")
        return state, state_account, matches[0]

    def describe(self, snapshot):
        module, account, manifest = self._capability(snapshot)
        states = {
            1: "Staged (classical authorization remains valid)",
            2: "Falcon experimental module-only",
            3: "Ed25519 AND Falcon",
        }
        return ProfileDescriptor(
            PROFILE,
            897,
            1281,
            666,
            "original Falcon padded",
            snapshot.network,
            19,
            account.auth.mode,
            states[account.auth.mode],
            snapshot.root.to_str(is_user_friendly=False),
            hashlib.sha256(module.public_key).hexdigest(),
            snapshot.module_code.hash.hex(),
            manifest,
        )

    def generateKey(self):
        return self.backend.generate_key()

    def buildSigningRequest(self, snapshot, account, intent):
        module, state, _ = self._capability(snapshot)
        if address(account).to_str(is_user_friendly=False) != snapshot.account.to_str(
            is_user_friendly=False
        ):
            raise ValueError("account differs from trusted snapshot")
        if set(intent) != {"kind", "payload", "valid_until"}:
            raise ValueError("unsupported intent field")
        until = intent["valid_until"]
        if type(until) is not int or not snapshot.now < until <= snapshot.now + 3600:
            raise ValueError("expiry outside module window")
        if not isinstance(intent["payload"], Cell):
            raise TypeError("canonical payload cell required")
        request = AuthRequest(
            snapshot.network,
            account,
            state.auth.epoch,
            state.auth.nonce,
            until,
            intent["kind"],
            intent["payload"],
        )
        request.serialize()
        snapshot_hash = hashlib.sha256(
            snapshot.account_code.hash
            + snapshot.account_data.hash
            + snapshot.module_code.hash
            + snapshot.module_data.hash
        ).hexdigest()
        return SigningRequest(
            request,
            snapshot.root,
            PROFILE,
            module.public_key,
            state.auth.mode,
            state.public_key,
            snapshot_hash,
        )

    def sign(self, handle, signing_request):
        if handle.public_key != signing_request.public_key:
            raise ValueError("wrong key handle")
        proof = AuthProof(
            PROFILE,
            request_identity(signing_request.request),
            signing_request.root.to_str(is_user_friendly=False),
            self.backend.sign(handle, signing_request.message),
        )
        if not self.verifyLocal(signing_request, proof):
            raise ValueError("local verification failed")
        return proof

    def verifyLocal(self, signing_request, proof):
        return (
            proof.profile == PROFILE
            and proof.identity == request_identity(signing_request.request)
            and proof.root == signing_request.root.to_str(is_user_friendly=False)
            and self.backend.verify(
                signing_request.message, proof.signature, signing_request.public_key
            )
        )

    def buildSubmission(self, signing_request, proof, optionalEd25519Cosignature=None, query_id=0):
        if not self.verifyLocal(signing_request, proof):
            raise ValueError("proof is not for this request/root")
        if signing_request.account_mode == 3:
            if optionalEd25519Cosignature is None:
                raise ValueError("hybrid mode requires Ed25519")
        if optionalEd25519Cosignature is not None:
            import nacl.signing

            nacl.signing.VerifyKey(signing_request.classical_public_key).verify(
                signing_request.request.commitment, optionalEd25519Cosignature
            )
        return submission(
            signing_request.request, proof.signature, optionalEd25519Cosignature, query_id
        )

    def fundedSubmission(self, signing_request, proof, relayer, value, cosignature=None):
        if type(value) is not int or value <= 0:
            raise ValueError("positive relayer funding required")
        return transfer_message(
            relayer,
            signing_request.root,
            value,
            self.buildSubmission(signing_request, proof, cosignature),
            bounce=True,
        )

    def verifyRecovery(self, raw_backup, password, snapshot):
        from backup import association, restore

        module, _, _ = self._capability(snapshot)
        expected = association(
            snapshot.network,
            snapshot.account.to_str(is_user_friendly=False),
            snapshot.root.to_str(is_user_friendly=False),
        )
        with restore(raw_backup, password, self.backend, expected) as handle:
            if handle.public_key != module.public_key:
                raise ValueError("backup has the wrong key")
            return hashlib.sha256(raw_backup).hexdigest()

    def trackReceipt(self, signing_request, evidence):
        # Evidence must come from a trusted transaction/state adapter. A submission
        # hash or compute success alone cannot produce an action-complete receipt.
        return MultiHopReceipt.from_evidence(request_identity(signing_request.request), evidence)


@dataclass(frozen=True)
class MultiHopReceipt:
    identity: tuple
    state: str
    nonce_consumed: bool
    funds: str

    @classmethod
    def from_evidence(cls, identity, evidence):
        if evidence is None:
            return cls(identity, "waiting for relayer", False, "not observed")
        if evidence.get("identity") != identity:
            raise ValueError("receipt request identity mismatch")
        module = evidence.get("module")
        if not module:
            return cls(identity, "waiting for relayer", False, "not observed")
        if module.get("compute_success") is False:
            return cls(identity, "module computation failed", False, "inspect bounce and reserve")
        if module.get("action_success") is False:
            return cls(identity, "module forwarding failed", False, "inspect bounce and reserve")
        if (
            module.get("compute_success") is not True
            or module.get("action_success") is not True
            or module.get("relay_observed") is not True
        ):
            return cls(identity, "module outcome incomplete", False, "not observed")
        target = evidence.get("target")
        if not target:
            return cls(identity, "waiting for target", False, "forwarded")
        consumed = target.get("nonce_consumed") is True
        if target.get("compute_success") is False:
            return cls(
                identity,
                "target consumed nonce but refused operation" if consumed else "target rejected",
                consumed,
                "inspect bounce",
            )
        if target.get("action_success") is False:
            return cls(identity, "target actions rejected", consumed, "inspect target state")
        if (
            target.get("compute_success") is True
            and target.get("action_success") is True
            and consumed
            and target.get("final_state_verified") is True
        ):
            return cls(identity, "actions completed", True, "bounce/reserve separately observed")
        return cls(identity, "target outcome incomplete", consumed, "not observed")


def buildMigrationRequest(
    provider,
    old_snapshot,
    destination,
    raw_backup,
    password,
    target_mode,
    valid_until,
    confirm_security_change=False,
):
    """Prepare kind=configure for authorization by the CURRENT root and mode.

    The returned request is not authorized by proof of possession of the new key.
    ML-DSA callers sign its D with their existing provider; hybrid callers still
    provide Ed25519 over that same D. Falcon callers use their current provider.
    """
    from backup import association, restore

    if not isinstance(old_snapshot, TrustedChainSnapshot) or not isinstance(
        destination, TrustedModuleSnapshot
    ):
        raise TypeError("verified current account and destination deployment snapshots required")
    if destination.status != "active":
        raise ValueError("destination root must be deployed and active before migration")
    if (
        destination.network != old_snapshot.network
        or destination.global_version < 19
        or destination.now != old_snapshot.now
    ):
        raise ValueError("destination deployment proof is for another network or snapshot")
    new_root, new_code, new_data = address(destination.root), destination.code, destination.data
    address(old_snapshot.account)
    address(old_snapshot.root)
    if target_mode not in (2, 3):
        raise ValueError("strict migration target required")
    if old_snapshot.account_status != "active" or old_snapshot.module_status != "active":
        raise ValueError("storage recovery is not a root migration")
    if old_snapshot.global_version < 19:
        raise ValueError("target profile is not activated")
    if not old_snapshot.now < valid_until <= old_snapshot.now + 3600:
        raise ValueError("invalid migration expiry")
    account_name = next(
        (
            name
            for name in ("wallet-func", "wallet-tol", "agent")
            if provider.manifest[name]["code_hash"] == old_snapshot.account_code.hash.hex()
        ),
        None,
    )
    if account_name is None:
        raise ValueError("unsupported legacy account bytecode")
    state = (AgentAccountState if account_name == "agent" else WalletV5State).parse(
        old_snapshot.account_data
    )
    auth = state.auth
    if (
        auth is None
        or auth.mode not in (1, 2, 3)
        or auth.module_hash != old_snapshot.root.hash_part
    ):
        raise ValueError("current account authority does not match snapshot")
    if auth.epoch == (1 << 64) - 1 or auth.nonce == (1 << 64) - 1:
        raise ValueError("counter exhausted")
    if (
        StateInit(code=old_snapshot.module_code, data=old_snapshot.module_data).serialize().hash
        != old_snapshot.root.hash_part
    ):
        raise ValueError("current authority StateInit mismatch")
    old_hash = old_snapshot.module_code.hash.hex()
    old_profile = next(
        (
            provider.manifest[name]["profile"]
            for name in ("module-func", "module-tol", "mldsa-module-func", "mldsa-module-tol")
            if name in provider.manifest and provider.manifest[name]["code_hash"] == old_hash
        ),
        None,
    )
    if old_profile is None:
        raise ValueError("unknown current authority code")
    if old_profile == PROFILE:
        current_module = FalconModuleState.parse(old_snapshot.module_data)
        if (
            current_module.network != old_snapshot.network
            or not provider.backend.validate_public_key(current_module.public_key)
        ):
            raise ValueError("invalid current Falcon configuration")
    else:
        from contract.falcon_auth import read_chain
        from contract.pq_auth import exact_end

        storage = old_snapshot.module_data.begin_parse()
        if (
            storage.load_int(32) != old_snapshot.network
            or len(read_chain(storage.load_ref(), 1312)) != 1312
        ):
            raise ValueError("invalid current ML-DSA configuration")
        exact_end(storage)
    # Both security category and AND-factor changes require an explicit choice.
    if (old_profile != PROFILE or auth.mode != target_mode) and confirm_security_change is not True:
        raise ValueError("explicit security category/factor confirmation required")
    if new_code.hash.hex() not in [
        provider.manifest[n]["code_hash"] for n in ("module-func", "module-tol")
    ]:
        raise ValueError("unknown destination profile or module code")
    new_root = address(new_root)
    module = FalconModuleState.parse(new_data)
    if module.network != old_snapshot.network or not provider.backend.validate_public_key(
        module.public_key
    ):
        raise ValueError("destination configuration mismatch")
    if (
        new_root.wc != old_snapshot.account.wc
        or new_root.hash_part == old_snapshot.account.hash_part
        or StateInit(code=new_code, data=new_data).serialize().hash != new_root.hash_part
    ):
        raise ValueError("destination root StateInit mismatch")
    expected = association(
        old_snapshot.network,
        old_snapshot.account.to_str(is_user_friendly=False),
        new_root.to_str(is_user_friendly=False),
    )
    with restore(raw_backup, password, provider.backend, expected) as handle:
        if handle.public_key != module.public_key:
            raise ValueError("destination key not recoverable from backup")
        challenge = (
            b"TOS-FALCON-MIGRATION-POK-v1" + new_root.hash_part + old_snapshot.account.hash_part
        )
        proof = provider.backend.sign(handle, challenge)
        if not provider.backend.verify(challenge, proof, module.public_key):
            raise ValueError("new key possession failed")
    payload = Builder().store_uint(target_mode, 2).store_address(new_root).end_cell()
    return AuthRequest(
        old_snapshot.network, old_snapshot.account, auth.epoch, auth.nonce, valid_until, 1, payload
    )
