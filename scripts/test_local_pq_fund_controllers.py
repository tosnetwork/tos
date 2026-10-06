"""Unit tests for the local controller operating-authorization tool."""

import importlib.util
from pathlib import Path

import pytest
from pytosiq_core import Address

_SPEC = importlib.util.spec_from_file_location(
    "local_pq_fund_controllers", Path(__file__).with_name("local-pq-fund-controllers.py")
)
fund = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(fund)

NANO = 10**9
PAYER = Address("-1:" + "00" * 32)
# Cell hash printed by the production Rust encoder for the same arguments:
#   controller_operating_payload -1:00..00 1000000000000 1000000000000 \
#     20000000000 10000000000 1793838000
RUST_PAYLOAD_HASH = "87c9a79597dc63721d14e954ead48e23ccf683df21f5fecdde8c922d39dbc57f"


def payload(**changes):
    values = dict(
        deposit=1000 * NANO,
        allowance=1000 * NANO,
        limit=20 * NANO,
        floor=10 * NANO,
        expires=1793838000,
    )
    values.update(changes)
    return fund.operating_payload(PAYER, **values)


def test_payload_matches_the_production_encoder():
    assert payload().hash.hex() == RUST_PAYLOAD_HASH


@pytest.mark.parametrize(
    "field,value",
    [
        ("deposit", 999 * NANO),
        ("allowance", 1),
        ("limit", 21 * NANO),
        ("floor", 11 * NANO),
        ("expires", 1793838001),
    ],
)
def test_every_field_is_bound_into_the_payload(field, value):
    assert payload(**{field: value}).hash.hex() != RUST_PAYLOAD_HASH


@pytest.mark.parametrize("field", ["deposit", "allowance", "limit", "floor"])
@pytest.mark.parametrize("value", [-1, 1 << 120])
def test_amounts_must_fit_var_uint16(field, value):
    with pytest.raises(ValueError):
        payload(**{field: value})


@pytest.mark.parametrize("field", ["allowance", "limit", "floor"])
def test_only_the_deposit_may_be_zero(field):
    payload(deposit=0)
    with pytest.raises(ValueError):
        payload(**{field: 0})


@pytest.mark.parametrize("expires", [0, 1 << 32])
def test_expiry_must_fit_uint32(expires):
    with pytest.raises(ValueError):
        payload(expires=expires)


NOW = 1_800_000_000
POLICY = dict(
    funds_target=50_000 * NANO,
    allowance_target=50_000 * NANO,
    limit=20 * NANO,
    renew_percent=25,
    renew_seconds=7 * 86400,
)


def state(**changes):
    values = dict(
        funds=50_000 * NANO,
        allowance=50_000 * NANO,
        limit=20 * NANO,
        floor=10 * NANO,
        expires=NOW + 30 * 86400,
    )
    values.update(changes)
    return values


def test_a_healthy_authorization_is_left_alone():
    assert fund.plan_renewal(state(), NOW, **POLICY) is None


def test_a_new_controller_gets_the_whole_target():
    empty = state(funds=0, allowance=0, limit=0, floor=0, expires=0)
    assert fund.plan_renewal(empty, NOW, **POLICY) == 50_000 * NANO


def test_low_funds_are_topped_up_by_deficit_not_by_the_target():
    # The contract adds the deposit, so sending the full target would overshoot.
    assert fund.plan_renewal(state(funds=12_000 * NANO), NOW, **POLICY) == 38_000 * NANO


def test_low_allowance_alone_renews_without_a_deposit():
    assert fund.plan_renewal(state(allowance=10_000 * NANO), NOW, **POLICY) == 0


def test_an_expiring_authorization_renews_without_a_deposit():
    assert fund.plan_renewal(state(expires=NOW + 86400), NOW, **POLICY) == 0


def test_funds_above_the_target_are_never_withdrawn():
    rich = state(funds=60_000 * NANO, expires=NOW + 3600)
    assert fund.plan_renewal(rich, NOW, **POLICY) == 0


def test_the_threshold_is_inclusive_at_the_renew_percentage():
    at = state(funds=12_500 * NANO, allowance=12_500 * NANO)
    below = state(funds=12_500 * NANO - 1)
    assert fund.plan_renewal(at, NOW, **POLICY) is None
    assert fund.plan_renewal(below, NOW, **POLICY) == 37_500 * NANO + 1


def test_a_changed_per_request_limit_renews():
    assert fund.plan_renewal(state(limit=10 * NANO), NOW, **POLICY) == 0


@pytest.mark.parametrize(
    "change",
    [
        dict(limit=60_000 * NANO),
        dict(renew_percent=0),
        dict(renew_percent=100),
        dict(funds_target=0),
    ],
)
def test_an_inconsistent_policy_is_refused(change):
    with pytest.raises(ValueError):
        fund.plan_renewal(state(), NOW, **{**POLICY, **change})
