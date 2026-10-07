"""Envelope/allocation checks; these do not replace native shard dictionary validation."""

import pytest
from pytosiq_core import Builder
from tostester.zerostate import basechain_fixture_balance


def fixture(global_id=1, workchain=0, balance=100, total=100, seqno=0):
    accounts = (
        Builder()
        .store_bit(1)
        .store_uint(0, 5)
        .store_coins(balance)
        .store_bit(0)
        .store_ref(Builder().end_cell())
        .end_cell()
    )
    totals = (
        Builder()
        .store_uint(0, 128)
        .store_coins(total)
        .store_bit(0)
        .store_coins(0)
        .store_bit(0)
        .store_bit(0)
        .store_bit(0)
        .end_cell()
    )
    return (
        Builder()
        .store_uint(0x9023AFE2, 32)
        .store_int(global_id, 32)
        .store_uint(0, 8)
        .store_int(workchain, 32)
        .store_uint(0, 64)
        .store_uint(seqno, 32)
        .store_uint(0, 32)
        .store_uint(100, 32)
        .store_uint(0, 64)
        .store_uint(0xFFFFFFFF, 32)
        .store_bit(0)
        .store_bit(0)
        .store_ref(Builder().store_uint(0, 67).end_cell())
        .store_ref(accounts)
        .store_ref(totals)
        .end_cell()
        .to_boc()
    )


def test_basechain_fixture_allocation_is_unsigned_and_exact():
    assert basechain_fixture_balance(fixture(), 1) == 100
    large = (1 << 120) - 1
    assert basechain_fixture_balance(fixture(balance=large, total=large), 1) == large


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(global_id=3),
        dict(workchain=-1),
        dict(seqno=1),
        dict(balance=100, total=101),
        dict(balance=0, total=0),
    ],
)
def test_basechain_fixture_wrong_identity_or_allocation_refuses(kwargs):
    with pytest.raises(ValueError):
        basechain_fixture_balance(fixture(**kwargs), 1)
