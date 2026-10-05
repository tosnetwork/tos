"""Checks the pool traffic verifier against single-point false positives."""

import asyncio
import importlib.util
import random
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location(
    "privacy", Path(__file__).with_name("local-pq-privacy.py")
)
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)


def state():
    return dict(
        commitment_root="123",
        nullifier_root="456",
        commitment_next_index=7,
        nullifier_next_index=3,
        native_liability=100,
        backed=-1,
    )


def test_exact_state():
    privacy.verify_state(state(), state())


@pytest.mark.parametrize("name", privacy.METHODS)
def test_state_mutation(name):
    actual = state()
    actual[name] = int(actual[name]) + 1
    with pytest.raises(ValueError, match="differ"):
        privacy.verify_state(actual, state())


def test_missing_state():
    actual = state()
    actual.pop("backed")
    with pytest.raises(ValueError, match="incomplete"):
        privacy.verify_state(actual, state())


def test_choose_initial_and_random():
    notes = {"notes": [{"index": i, "amount": 10**9, "owner": i % 3} for i in range(4)]}
    for seq, op in enumerate(("deposit", "deposit", "transfer", "withdraw")):
        assert privacy.choose(notes, random.Random(seq), seq)["operation"] == op
    for seq in range(4, 104):
        req = privacy.choose(notes, random.Random(seq), seq)
        if req["operation"] != "deposit":
            assert len(set(req["inputs"])) == 2
            assert 0 < req["amount"] <= 10**9
            if req["operation"] == "withdraw":
                assert req["amount"] in (10**9, 10**10, 10**11, 10**12)
            assert req["amount"] + (20_000_000 if req["operation"] == "withdraw" else 0) < 2 * 10**9


def test_no_notes_deposits():
    assert privacy.choose({"notes": []}, random.Random(0), 3)["operation"] == "deposit"


def message(value=100, digest=b"a", source="0:" + "11" * 32, dest="0:" + "22" * 32):
    return SimpleNamespace(
        hash=digest,
        value=value,
        source=SimpleNamespace(account_address=source),
        destination=SimpleNamespace(account_address=dest),
    )


def test_payout():
    msg = message()
    privacy.verify_withdrawal(200, 298, 100, 2, msg, msg, "0:" + "11" * 32, "0:" + "22" * 32)


@pytest.mark.parametrize("change", ["delta", "fee", "hash", "value", "source", "destination"])
def test_wrong_payout(change):
    sent, received = message(), message()
    after, fee = 298, 2
    if change == "delta":
        after += 1
    if change == "fee":
        fee = -1
    if change == "hash":
        received.hash = b"b"
    if change == "value":
        received.value += 1
    if change == "source":
        received.source.account_address = "0:" + "33" * 32
    if change == "destination":
        received.destination.account_address = "0:" + "33" * 32
    with pytest.raises(ValueError):
        privacy.verify_withdrawal(
            200, after, 100, fee, sent, received, "0:" + "11" * 32, "0:" + "22" * 32
        )


def test_low_private_value_adds_deposit_before_withdrawal():
    notes = {"notes": [{"index": i, "amount": 100_000_000, "owner": i} for i in range(2)]}
    assert privacy.choose(notes, random.Random(0), 3)["operation"] == "deposit"


def test_a_missing_lite_client_is_refused_before_anything_is_written(tmp_path):
    # The service runs from a snapshot without a build tree; it must use the
    # installed lite-client and refuse to start when that is absent.
    args = SimpleNamespace(
        nodes=7,
        min_interval=20.0,
        max_interval=60.0,
        count=0,
        lite_client=tmp_path / "absent-lite-client",
        output=tmp_path / "out",
    )
    with pytest.raises(RuntimeError, match="does not exist"):
        asyncio.run(privacy.run(args))
    assert not args.output.exists()


def test_pool_state_queries_the_validated_lite_client(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        privacy.local,
        "get_method",
        lambda lite_client, data, address, name: calls.append(lite_client) or 0,
    )
    lite_client = tmp_path / "tos-lite-client"
    args = SimpleNamespace(lite_client=lite_client, data=tmp_path, build=tmp_path / "build")
    asyncio.run(privacy.pool_state(args, "0:" + "ab" * 32))
    assert calls and set(calls) == {lite_client}


def test_the_lite_client_defaults_to_the_installed_binary(monkeypatch):
    seen = {}

    def capture(coroutine):
        seen["args"] = coroutine.cr_frame.f_locals["args"]
        coroutine.close()

    monkeypatch.setattr(privacy.asyncio, "run", capture)
    monkeypatch.setattr(sys, "argv", ["local-pq-privacy.py"])
    privacy.main()
    assert seen["args"].lite_client == privacy.local.INSTALLED_LITE_CLIENT
