"""A submitted message alone cannot satisfy the transfer verification checks."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest
from pytosiq_core import Address

spec = importlib.util.spec_from_file_location(
    "transfers", Path(__file__).with_name("local-pq-transfers.py")
)
transfers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transfers)


def test_exact_amount():
    assert transfers.nanos("0.01") == 10_000_000
    assert transfers.nanos("0.000000001") == 1


@pytest.mark.parametrize("value", ["0", "-1", "0.0000000001", "NaN", "Infinity"])
def test_invalid_amount(value):
    with pytest.raises(ValueError):
        transfers.nanos(value)


def test_balance_and_seqno_positive():
    transfers.verify_transfer(1000, 890, 500, 597, 10, 11, 100, 3)


@pytest.mark.parametrize(
    "field,value",
    [
        ("seq_after", 10),
        ("seq_after", 12),
        ("sender_after", 950),
        ("recipient_after", 500),
        ("recipient_after", 598),
        ("fee", -1),
    ],
)
def test_balance_and_seqno_negatives(field, value):
    args = dict(
        sender_before=1000,
        sender_after=890,
        recipient_before=500,
        recipient_after=597,
        seq_before=10,
        seq_after=11,
        amount=100,
        fee=3,
    )
    args[field] = value
    with pytest.raises(ValueError):
        transfers.verify_transfer(**args)


def message():
    sender, recipient = "0:" + "aa" * 32, "0:" + "bb" * 32
    msg = SimpleNamespace(
        source=SimpleNamespace(account_address=sender),
        destination=SimpleNamespace(account_address=recipient),
        value=100,
        body_hash=b"c" * 32,
    )
    return msg, sender, recipient


def test_friendly_addresses_bind_same_account():
    msg, sender, recipient = message()
    msg.source.account_address = Address(sender).to_str()
    transfers.verify_message(msg, sender, recipient, 100, b"c" * 32)


@pytest.mark.parametrize("field", ["source", "destination", "value", "body_hash"])
def test_message_single_point_negatives(field):
    msg, sender, recipient = message()
    if field in ("source", "destination"):
        setattr(msg, field, SimpleNamespace(account_address="0:" + "dd" * 32))
    else:
        setattr(msg, field, 99 if field == "value" else b"d" * 32)
    with pytest.raises(ValueError):
        transfers.verify_message(msg, sender, recipient, 100, b"c" * 32)


def test_failed_compute_or_action_is_not_a_receipt(monkeypatch):
    tx = SimpleNamespace(
        description=SimpleNamespace(
            aborted=False, compute_ph=SimpleNamespace(success=True, exit_code=0), action=None
        )
    )
    monkeypatch.setattr(
        transfers, "begin_cell_from_boc", lambda data: SimpleNamespace(begin_parse=lambda: None)
    )
    monkeypatch.setattr(transfers.Transaction, "deserialize", lambda data: tx)
    assert transfers.check_transaction(SimpleNamespace(data=b"")) is tx
    tx.description.compute_ph.success = False
    with pytest.raises(ValueError, match="computation"):
        transfers.check_transaction(SimpleNamespace(data=b""))
    tx.description.compute_ph.success = True
    tx.description.action = SimpleNamespace(success=False)
    with pytest.raises(ValueError, match="action"):
        transfers.check_transaction(SimpleNamespace(data=b""))
    tx.description.action = None
    tx.description.aborted = True
    with pytest.raises(ValueError, match="aborted"):
        transfers.check_transaction(SimpleNamespace(data=b""))
