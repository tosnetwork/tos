"""Request-bound receipts from authenticated transaction and Account cells.

A production adapter must authenticate network, inclusion/finality and account
proofs before constructing TrustedReceiptEvidence. Merely decoding RPC BOCs is
not authentication. This module checks their linkage and operation semantics;
it does not implement a chain light client or predict a payment from a nonce.
"""

from dataclasses import dataclass

from contract.agent_account import AgentAccountState
from contract.pq_auth import address, exact_end
from contract.wallet_v5 import WalletV5State
from pytosiq_core import Builder, Cell, MessageAny
from pytosiq_core.boc.cell import CellError
from pytosiq_core.boc.slice import SliceError
from pytosiq_core.tlb.account import Account
from pytosiq_core.tlb.tlb import TlbError
from pytosiq_core.tlb.transaction import Transaction


@dataclass(frozen=True)
class TrustedTransactionObservation:
    transaction: Cell
    # Full Account cells, not just StateInit/data or a later account snapshot.
    # Their hashes must match this transaction's HASH_UPDATE old/new hashes.
    before: Cell | None = None
    after: Cell | None = None


@dataclass(frozen=True)
class TrustedReceiptEvidence:
    network: int
    module: TrustedTransactionObservation
    target: TrustedTransactionObservation | None = None
    deliveries: tuple[TrustedTransactionObservation, ...] = ()
    bounce_returns: tuple[TrustedTransactionObservation, ...] = ()


def transaction(observation):
    if not isinstance(observation, TrustedTransactionObservation):
        raise ValueError("authenticated transaction observation required")
    if not isinstance(observation.transaction, Cell) or observation.transaction.is_exotic:
        raise ValueError("ordinary transaction cell required")
    tx = Transaction.deserialize(observation.transaction.begin_parse())
    if tx.description.type_ != "ordinary" or len(tx.out_msgs) != tx.outmsg_cnt:
        raise ValueError("incomplete ordinary transaction")
    return tx


def accounts(observation, tx):
    if observation.before is None or observation.after is None:
        raise ValueError("transaction-bound before and after Account proofs required")
    if (
        observation.before.hash != tx.state_update.old_hash
        or observation.after.hash != tx.state_update.new_hash
    ):
        raise ValueError("account proof is not for this transaction")
    before = Account.deserialize(observation.before.begin_parse())
    after = Account.deserialize(observation.after.begin_parse())
    if before is None or after is None or before.addr != after.addr:
        raise ValueError("active account transition required")
    if before.addr.hash_part != tx.account_addr:
        raise ValueError("account address mismatch")
    return before, after


def phase_success(tx):
    d = tx.description
    return (
        getattr(d.compute_ph, "success", False) is True
        and not d.aborted
        and (d.action is None or d.action.success is True)
    )


def message_hash(msg):
    if msg.cell is None:
        raise ValueError("original emitted message cell required")
    return msg.cell.hash


def same_message(expected, emitted, mode):
    # Action-list identity binds all send modes and nominal amounts. Compare
    # immutable message content separately; fees/LT/time are executor outputs.
    if not expected.is_internal or not emitted.is_internal:
        return False
    a, b = expected.info, emitted.info
    init_a = expected.init.serialize().hash if expected.init else None
    init_b = emitted.init.serialize().hash if emitted.init else None
    if (
        a.dest != b.dest
        or a.bounce != b.bounce
        or b.bounced
        or expected.body.hash != emitted.body.hash
        or init_a != init_b
        or a.value.other.dict != b.value.other.dict
    ):
        return False
    if mode & 192:
        return True  # carry-value modes are bound by the authenticated action list
    if mode & 1:
        return a.value.tomis == b.value.tomis
    return 0 <= b.value.tomis <= a.value.tomis  # forwarding fees come out of value


def wallet_actions(payload):
    actions = []
    current = payload
    while True:
        s = current.begin_parse()
        if not s.remaining_bits and not s.remaining_refs:
            break
        if len(actions) >= 255 or s.load_uint(32) != 0x0EC3C86D:
            raise ValueError("unsupported action list")
        mode = s.load_uint(8)
        previous, msg = s.load_ref(), s.load_ref()
        exact_end(s)
        actions.append((mode, msg))
        current = previous
    # OutList is reverse linked; the executor runs the tail first.
    return list(reversed(actions))


def agent_actions(request, old, new):
    """Match the signed controller/owner operation, including sends with StateInit."""
    p = request.payload.begin_parse()
    op = p.load_uint(32)
    if old.owner != new.owner or old.agent_id != new.agent_id:
        raise ValueError("unexpected agent identity change")
    if request.kind == 2:
        p.load_uint(64)  # query ID
        if op == 0x41475001:
            policy = (
                Builder()
                .store_coins(p.load_coins())
                .store_coins(p.load_coins())
                .store_uint(p.load_uint(64), 64)
            )
            for _ in range(2):
                present = p.load_uint(1)
                policy.store_uint(present, 1)
                if present:
                    policy.store_bytes(p.load_bytes(32))
            exact_end(p)
            if (
                new.policy.hash != policy.end_cell().hash
                or new.public_key != old.public_key
                or new.policy_epoch != old.policy_epoch
                or new.seqno != old.seqno
            ):
                raise ValueError("requested policy was not installed")
        elif op == 0x41475002:
            key = p.load_bytes(32)
            exact_end(p)
            if (
                new.public_key != key
                or new.policy_epoch != old.policy_epoch + 1
                or new.seqno != old.seqno + 1
                or new.policy.hash != old.policy.hash
            ):
                raise ValueError("requested controller was not installed")
        else:
            raise ValueError("unsupported owner operation")
        return []
    if request.kind != 0 or p.load_int(32) != request.network:
        raise ValueError("wrong agent operation network")
    if p.load_uint(64) != old.policy_epoch or p.load_uint(32) != old.seqno:
        raise ValueError("wrong controller counters")
    p.load_uint(32)  # expiry was enforced by the authenticated transaction
    if (
        new.seqno != old.seqno + 1
        or new.policy_epoch != old.policy_epoch
        or new.public_key != old.public_key
        or new.policy.hash != old.policy.hash
    ):
        raise ValueError("wrong agent result state")
    if op == 0x41475005:
        exact_end(p)
        return []
    if op not in (0x41475003, 0x41475004, 0x41475006, 0x41475007):
        raise ValueError("unsupported controller operation")
    destination, value = address(p.load_address()), p.load_coins()
    init = p.load_ref() if op == 0x41475006 else None
    checked = op == 0x41475007
    if checked and p.load_uint(8) != 3:
        raise ValueError("unsupported checked-call flags")
    body = p.load_ref() if op != 0x41475004 else None
    exact_end(p)
    message = (
        Builder()
        .store_uint(0x18 if checked else 0x10, 6)
        .store_address(destination)
        .store_coins(value)
        .store_uint(0, 1)
        .store_coins(3 if checked else 0)
        .store_coins(0)
        .store_uint(0, 96)
    )
    if init is not None:
        message.store_uint(3, 2).store_ref(init)
    else:
        message.store_uint(0, 1)
    if body is not None:
        message.store_uint(1, 1).store_ref(body)
    else:
        message.store_uint(0, 1)
    raw = message.end_cell()
    return [(3, raw)]


def action_list(actions):
    tail = Cell.empty()
    for mode, msg in actions:
        tail = (
            Builder()
            .store_uint(0x0EC3C86D, 32)
            .store_uint(mode, 8)
            .store_ref(tail)
            .store_ref(msg)
            .end_cell()
        )
    return tail


@dataclass(frozen=True)
class MultiHopReceipt:
    identity: tuple
    state: str
    nonce_consumed: bool
    funds: str
    expected_actions: int | None = None
    emitted_actions: int | None = None
    delivery: str = "not observed"
    bounce: str = "not observed"
    reserve: str = "not observed"

    @classmethod
    def from_evidence(cls, identity, evidence, *, request=None, root=None, account_types=None):
        if not isinstance(evidence, TrustedReceiptEvidence):
            return cls._legacy(identity, evidence)
        consumed = False
        reserve = "not observed"
        expected_count = emitted_count = None

        def receipt(state, delivery="not observed", bounce="not observed"):
            return cls(
                identity,
                state,
                consumed,
                f"delivery: {delivery}; bounce: {bounce}; reserve: {reserve}",
                expected_count,
                emitted_count,
                delivery,
                bounce,
                reserve,
            )

        try:
            if request is None or root is None or account_types is None:
                return receipt("target outcome incomplete")
            if type(evidence.network) is not int or evidence.network != request.network:
                raise ValueError("receipt network mismatch")
            module = transaction(evidence.module)
            if module.account_addr != address(root).hash_part:
                raise ValueError("receipt module mismatch")
            incoming = module.in_msg
            if incoming is None or not incoming.is_internal or incoming.info.dest != root:
                raise ValueError("missing funded module submission")
            s = incoming.body.begin_parse()
            if s.load_uint(32) != 0x46414C31:
                raise ValueError("wrong module operation")
            s.load_uint(64)
            envelope = s.load_ref()
            s.load_ref()
            exact_end(s)
            auth = envelope.begin_parse()
            if auth.load_uint(32) != 0x41555448 or auth.load_ref().hash != request.serialize().hash:
                raise ValueError("receipt request mismatch")
            auth.load_maybe_ref()
            exact_end(auth)
            if not phase_success(module):
                return receipt("module computation or forwarding failed")
            relay = [
                m
                for m in module.out_msgs
                if m.is_internal
                and m.info.src == root
                and m.info.dest == request.account
                and m.body.hash == envelope.hash
                and not m.info.bounced
            ]
            if len(relay) != 1:
                return receipt("module outcome incomplete")
            if evidence.module.before is not None and evidence.module.after is not None:
                old_module, new_module = accounts(evidence.module, module)
                if old_module.addr != root:
                    raise ValueError("module reserve proof mismatch")
                storage = module.description.storage_ph
                fees = storage.storage_fees_collected if storage is not None else 0
                reserve = (
                    "preserved"
                    if new_module.storage.balance.tomis
                    >= max(0, old_module.storage.balance.tomis - fees)
                    else "spent"
                )
            if evidence.target is None:
                return receipt("waiting for target")
            target = transaction(evidence.target)
            if (
                target.account_addr != request.account.hash_part
                or target.in_msg is None
                or message_hash(target.in_msg) != message_hash(relay[0])
            ):
                raise ValueError("target transaction is not the emitted relay")
            before, after = accounts(evidence.target, target)
            if before.addr != request.account:
                raise ValueError("target account mismatch")
            initial, final = before.storage.state, after.storage.state
            if initial.type_ != "account_active" or final.type_ != "account_active":
                return receipt("target outcome incomplete")
            kind = account_types.get(initial.state_init.code.hash.hex())
            parser = (
                WalletV5State
                if kind == "wallet"
                else AgentAccountState
                if kind == "agent"
                else None
            )
            if parser is None or final.state_init.code.hash != initial.state_init.code.hash:
                return receipt("target outcome incomplete")
            old, new = parser.parse(initial.state_init.data), parser.parse(final.state_init.data)
            if (
                old.auth is None
                or old.auth.epoch != request.epoch
                or old.auth.nonce != request.nonce
                or old.auth.module_hash != root.hash_part
            ):
                raise ValueError("target authority does not match the request")
            if request.kind == 1:
                p = request.payload.begin_parse()
                mode, new_root = p.load_uint(2), address(p.load_address())
                exact_end(p)
                if new_root.wc != request.account.wc:
                    raise ValueError("configured root belongs to another workchain")
                expected_auth = (mode, request.epoch + 1, 0, new_root.hash_part)
                # A reconfiguration consumes the old nonce by advancing epoch.
                consumed = new.auth is not None and new.auth.epoch == request.epoch + 1
            else:
                expected_auth = (old.auth.mode, request.epoch, request.nonce + 1, root.hash_part)
                consumed = (
                    new.auth is not None
                    and new.auth.epoch == request.epoch
                    and new.auth.nonce == request.nonce + 1
                )
            if not phase_success(target):
                return receipt(
                    "target consumed nonce but refused operation" if consumed else "target rejected"
                )
            if (
                new.auth is None
                or (new.auth.mode, new.auth.epoch, new.auth.nonce, new.auth.module_hash)
                != expected_auth
            ):
                return receipt("target outcome incomplete")
            if request.kind == 1:
                expected_count = emitted_count = 0
                if target.out_msgs or (
                    target.description.action is not None
                    and target.description.action.skipped_actions
                ):
                    return receipt("target outcome incomplete")
                return receipt("actions completed", "not applicable", "not applicable")
            if kind == "wallet" and request.kind != 0:
                return receipt("target outcome incomplete")
            expected = (
                wallet_actions(request.payload)
                if kind == "wallet"
                else agent_actions(request, old, new)
            )
            expected_count, emitted_count = len(expected), len(target.out_msgs)
            action = target.description.action
            if action is None:
                if expected_count or emitted_count:
                    return receipt("target outcome incomplete")
                return receipt("actions completed", "not applicable", "not applicable")
            expected_hash = request.payload.hash if kind == "wallet" else action_list(expected).hash
            if (
                action.action_list_hash != expected_hash
                or action.msgs_created != emitted_count
                or action.tot_actions != expected_count
                or action.skipped_actions + emitted_count != expected_count
            ):
                return receipt("target outcome incomplete")
            partial = False
            if action.skipped_actions:
                if emitted_count == 0:
                    return receipt("target actions skipped", "incomplete")
                partial = True
            if not partial and emitted_count != expected_count:
                return receipt("target outcome incomplete")
            cursor = iter(expected)
            for emitted in target.out_msgs:
                matched = False
                for mode, raw in cursor:
                    try:
                        wanted = MessageAny.deserialize(raw.begin_parse())
                    except (ValueError, TlbError, CellError, SliceError, IndexError):
                        if not partial:
                            raise
                        continue
                    if same_message(wanted, emitted, mode):
                        matched = True
                        break
                    if not partial:
                        break
                if not matched or emitted.info.src != request.account:
                    return receipt("target outcome incomplete")
            if not expected_count:
                return receipt("actions completed", "not applicable", "not applicable")
            observed = {}
            bounced = []
            for observation in evidence.deliveries:
                tx = transaction(observation)
                if tx.in_msg is None or message_hash(tx.in_msg) in observed:
                    raise ValueError("missing or duplicate recipient observation")
                observed[message_hash(tx.in_msg)] = tx
            delivered = failed = 0
            for emitted in target.out_msgs:
                tx = observed.get(message_hash(emitted))
                if tx is None:
                    continue
                if tx.account_addr != emitted.info.dest.hash_part:
                    raise ValueError("recipient transaction address mismatch")
                if phase_success(tx) and tx.description.credit_ph is not None:
                    delivered += 1
                else:
                    failed += 1
                    bounced.extend(
                        m
                        for m in tx.out_msgs
                        if m.is_internal
                        and m.info.bounced
                        and m.info.dest == request.account
                        and m.info.src == emitted.info.dest
                    )
            if set(observed) - {message_hash(m) for m in target.out_msgs}:
                raise ValueError("unrelated recipient evidence")
            bounce = "not observed"
            if bounced:
                bounce = "emitted; return pending"
                returned = set()
                for observation in evidence.bounce_returns:
                    tx = transaction(observation)
                    if tx.in_msg is None or message_hash(tx.in_msg) not in {
                        message_hash(m) for m in bounced
                    }:
                        raise ValueError("unrelated bounce return")
                    old_account, new_account = accounts(observation, tx)
                    if (
                        tx.account_addr != request.account.hash_part
                        or old_account.addr != request.account
                        or not phase_success(tx)
                        or tx.description.credit_ph is None
                    ):
                        raise ValueError("bounce was not credited to the source account")
                    returned.add(message_hash(tx.in_msg))
                if len(returned) == len(bounced):
                    bounce = "returned"
            elif evidence.bounce_returns:
                raise ValueError("bounce return without a matching emitted bounce")
            if partial:
                # Later recipient/bounce observations refine the funds outcome
                # of emitted sends, but cannot complete a batch with skips.
                delivery = (
                    "partial"
                    if failed and delivered
                    else "failed"
                    if failed
                    else "confirmed for emitted subset"
                    if delivered == emitted_count
                    else "pending"
                )
                return receipt("target actions partially completed", delivery, bounce)
            if failed:
                return receipt(
                    "target delivery partially completed"
                    if delivered
                    else "target delivery failed",
                    "partial" if delivered else "failed",
                    bounce,
                )
            if delivered != expected_count:
                return receipt("actions emitted; delivery pending", "pending", bounce)
            return receipt("actions completed", "confirmed", bounce)
        except (
            ValueError,
            TypeError,
            AttributeError,
            IndexError,
            KeyError,
            TlbError,
            CellError,
            SliceError,
        ):
            return receipt("target outcome incomplete")

    @classmethod
    def _legacy(cls, identity, evidence):
        # Preserve progress/failure hints for old adapters. The old boolean-only
        # contract can never certify an operation or observed bounce/reserve.
        if evidence is None:
            return cls(identity, "waiting for relayer", False, "not observed")
        if evidence.get("identity") != identity:
            raise ValueError("receipt request identity mismatch")
        module = evidence.get("module")
        if not module:
            return cls(identity, "waiting for relayer", False, "not observed")
        if module.get("compute_success") is False:
            return cls(identity, "module computation failed", False, "not observed")
        if module.get("action_success") is False:
            return cls(identity, "module forwarding failed", False, "not observed")
        if not all(
            module.get(k) is True for k in ("compute_success", "action_success", "relay_observed")
        ):
            return cls(identity, "module outcome incomplete", False, "not observed")
        target = evidence.get("target")
        if not target:
            return cls(identity, "waiting for target", False, "not observed")
        consumed = target.get("nonce_consumed") is True
        if target.get("compute_success") is False:
            return cls(
                identity,
                "target consumed nonce but refused operation" if consumed else "target rejected",
                consumed,
                "not observed",
            )
        if target.get("action_success") is False:
            return cls(identity, "target actions rejected", consumed, "not observed")
        return cls(identity, "target outcome incomplete", consumed, "not observed")
