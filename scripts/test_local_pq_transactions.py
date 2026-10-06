"""The real sender/decoder with a deterministic RPC transport (not a chain VM)."""
import asyncio
from types import SimpleNamespace as Obj

import nacl.signing
import pytest
from contract import WalletV1
from pytosiq_core import Cell, ExternalMsgInfo, MessageAny

from local_pq_test_wire import address, message, transaction
from local_pq_transactions import (Faucet, atomic_json, cursor, decoded, faucet_lock,
                                   history_since, read_json, successful)


class Network:
    def __init__(self):
        self.seqno = 0
        self.history = {}
        self.broadcasts = []
        self.deliver = True
        self.refuse = False
        self.fail_after_delivery = False
        self.fail_before_delivery = False
        self.on_broadcast = None
        self.clock = 10
        self.client_wallet = None

    def add(self, addr, inbound, outputs=(), **kwargs):
        items = self.history.setdefault(addr.to_str(False), [])
        self.clock += 10
        item = transaction(addr, self.clock, inbound, outputs,
                           previous=items[0].transaction_id if items else None, **kwargs)
        items.insert(0, item)
        return item

    async def raw_get_account_state(self, addr):
        items = self.history.get(addr.to_str(False), [])
        return Obj(last_transaction_id=items[0].transaction_id if items else None)

    async def raw_get_transactions(self, addr, pos):
        items = self.history.get(addr.to_str(False), [])
        offset = next(i for i, item in enumerate(items) if item.transaction_id.lt == pos.lt)
        page = items[offset:offset + 2]  # Deliberately exercise pagination.
        tail = items[offset + 2:]
        return Obj(transactions=page,
                   previous_transaction_id=tail[0].transaction_id if tail else None)

    async def broadcast(self, signed):
        self.broadcasts.append(signed.to_boc())
        if self.on_broadcast:
            self.on_broadcast(signed)
        if self.fail_before_delivery:
            raise ConnectionError("transport lost before inclusion")
        cs = signed.begin_parse()
        cs.load_bytes(64)
        seqno = cs.load_uint(32)
        mode = cs.load_uint(8)
        assert mode == 3
        outgoing = MessageAny.deserialize(cs.load_ref().begin_parse())
        if seqno != self.seqno:
            return  # WalletV1 refuses a repeated signed request at an old seqno.
        self.seqno += 1
        outgoing.info.created_lt = self.clock + 5
        external = MessageAny(ExternalMsgInfo(None, self.client_wallet.address, 0), None, signed)
        self.add(self.client_wallet.address, external, [outgoing])
        if self.deliver:
            self.add(outgoing.info.dest, outgoing, success=not self.refuse,
                     exit_code=180 if self.refuse else 0)
        if self.fail_after_delivery:
            raise ConnectionError("transport lost after inclusion")


class Wallet:
    def __init__(self, network):
        self.address = address(1)
        self.signer = WalletV1(network, self.address, nacl.signing.SigningKey(bytes(32)))
        self.network = network
        network.client_wallet = self

    @property
    async def current(self):
        return Obj(seqno=self.network.seqno)

    def sign(self, value, seqno):
        return self.signer.sign(value, seqno)

    async def send_external(self, *, body):
        return await self.network.broadcast(body)


def setup(tmp_path):
    network = Network()
    wallet = Wallet(network)
    return network, Faucet(network, wallet, tmp_path / "journal", "root")


def test_journal_exists_before_broadcast_and_done_has_destination_receipt(tmp_path):
    net, sender = setup(tmp_path)
    net.on_broadcast = lambda signed: (
        read_json(sender.pending)["signed"] is not None or pytest.fail("missing WAL"))
    result = asyncio.run(sender.transfer("one", address(2), 123))
    assert result["ok"] and result["transaction"]["lt"] == 30
    assert not sender.pending.exists() and sender.path("one").exists()
    assert len(net.broadcasts) == 1
    asyncio.run(sender.transfer("one", address(2), 123))
    assert len(net.broadcasts) == 1


@pytest.mark.parametrize("crash", ["before", "after"])
def test_restart_never_rebuilds_a_payment_at_a_new_seqno(tmp_path, crash):
    net, sender = setup(tmp_path)
    setattr(net, f"fail_{crash}_delivery", True)
    with pytest.raises(ConnectionError):
        asyncio.run(sender.transfer("one", address(2), 123))
    assert sender.pending.exists()
    setattr(net, f"fail_{crash}_delivery", False)
    restarted = Faucet(net, sender.wallet, sender.directory, "root")
    receipts = asyncio.run(restarted.recover())
    assert receipts[0]["ok"] and net.seqno == 1
    assert len(net.history[address(2).to_str(False)]) == 1
    assert all(wire == net.broadcasts[0] for wire in net.broadcasts)


def test_wallet_seqno_alone_does_not_prove_destination_acceptance(tmp_path):
    net, sender = setup(tmp_path)
    net.refuse = True
    receipt = asyncio.run(sender.transfer("one", address(2), 123))
    assert net.seqno == 1 and receipt["ok"] is False and receipt["exit_code"] == 180


def test_unobserved_destination_remains_pending(tmp_path):
    net, sender = setup(tmp_path)
    net.deliver = False
    net.fail_after_delivery = True
    with pytest.raises(ConnectionError):
        asyncio.run(sender.transfer("one", address(2), 123))
    net.fail_after_delivery = False
    with pytest.raises(TimeoutError, match="unresolved"):
        asyncio.run(sender.finish(read_json(sender.pending), timeout=0))
    assert sender.pending.exists() and net.seqno == 1


def test_network_or_payment_mismatch_never_broadcasts(tmp_path):
    net, sender = setup(tmp_path)
    asyncio.run(sender.transfer("one", address(2), 123))
    for changes in (dict(dest=address(3), amount=123), dict(dest=address(2), amount=124),
                    dict(dest=address(2), amount=123, bounce=True)):
        with pytest.raises(ValueError, match="different payment"):
            asyncio.run(sender.transfer("one", **changes))
    changed = Faucet(net, sender.wallet, sender.directory, "another-root")
    with pytest.raises(ValueError, match="another chain"):
        changed.record("one")
    assert len(net.broadcasts) == 1


def test_locks_exclude_other_faucet_users(tmp_path):
    with faucet_lock(tmp_path), pytest.raises(BlockingIOError):
        with faucet_lock(tmp_path):
            pytest.fail("two owners")


def test_readonly_sender_creates_nothing(tmp_path):
    net = Network()
    path = tmp_path / "absent"
    Faucet(net, Wallet(net), path, "root", readonly=True)
    assert not path.exists()


def test_history_paginates_and_checks_exact_baseline():
    net = Network()
    base = net.add(address(2), message(address(1), address(2)))
    for _ in range(5):
        net.add(address(2), message(address(1), address(2)))
    assert len(asyncio.run(history_since(net, address(2), cursor(base.transaction_id)))) == 5
    with pytest.raises(ValueError, match="hash changed"):
        asyncio.run(history_since(net, address(2), {"lt": base.transaction_id.lt, "hash": "ff" * 32}))
    with pytest.raises(ValueError, match="bounded"):
        asyncio.run(history_since(net, address(2), cursor(base.transaction_id), max_pages=1))


@pytest.mark.parametrize("compute,action,expected", [(True,None,True), (False,None,False),
                                                      (True,37,False), (True,0,True)])
def test_real_transaction_boc_compute_and_action_are_both_required(compute, action, expected):
    tx = transaction(address(1), 10, message(address(2), address(1)),
                     success=compute, exit_code=180 if not compute else 0, action_code=action)
    assert successful(decoded(tx)) is expected


def test_atomic_records_are_private(tmp_path):
    path = tmp_path / "record.json"
    atomic_json(path, {"before": 1})
    atomic_json(path, {"after": 2})
    assert read_json(path) == {"after": 2}
    assert path.stat().st_mode & 0o777 == 0o600
