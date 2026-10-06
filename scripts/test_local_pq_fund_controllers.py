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
@pytest.mark.parametrize("value", [0, -1, 1 << 120])
def test_amounts_must_be_positive_and_fit_var_uint16(field, value):
    with pytest.raises(ValueError):
        payload(**{field: value})


@pytest.mark.parametrize("expires", [0, 1 << 32])
def test_expiry_must_fit_uint32(expires):
    with pytest.raises(ValueError):
        payload(expires=expires)
