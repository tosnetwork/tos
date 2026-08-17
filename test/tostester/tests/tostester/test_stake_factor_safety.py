"""The stake-factor gate that gets between an operator and ConfigParam 17."""

import importlib.util
from fractions import Fraction
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[4]


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "check_stake_factor_safety", REPO / "scripts/check-stake-factor-safety.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


@pytest.mark.parametrize(
    ("factor", "validators", "share"),
    [
        # The shipped genesis: an equal-weight four-validator set.
        (1, 4, Fraction(1, 4)),
        # Upstream's factor at upstream's scale is harmless...
        (3, 350, Fraction(3, 352)),
        # ...and the same number on a four-validator set hands one party half
        # the weight, which is why the factor cannot be copied on its own.
        (3, 4, Fraction(1, 2)),
        # Eight validators is exactly where a factor of three becomes legal.
        (3, 8, Fraction(3, 10)),
    ],
)
def test_worst_case_share_matches_the_elector_cap(factor, validators, share):
    assert gate.worst_case_share(Fraction(factor), validators) == share


@pytest.mark.parametrize(
    ("validators", "bound"),
    [(4, Fraction(3, 2)), (8, Fraction(7, 2)), (16, Fraction(15, 2))],
)
def test_factor_bound_is_half_the_set_minus_one(validators, bound):
    assert gate.max_safe_factor(validators) == bound
    # The bound is exclusive: sitting on it means exactly one third.
    assert gate.worst_case_share(bound, validators) == Fraction(1, 3)
    assert gate.worst_case_share(bound - Fraction(1, 100), validators) < Fraction(1, 3)


@pytest.mark.parametrize(
    ("factor", "validators"),
    [(1, 4), (Fraction(3, 2), 5), (3, 8), (7, 16)],
)
def test_required_set_size_is_the_smallest_one_that_passes(factor, validators):
    factor = Fraction(factor)
    assert gate.min_validators_for(factor) == validators
    assert gate.worst_case_share(factor, validators) < Fraction(1, 3)
    if validators > 1:
        assert gate.worst_case_share(factor, validators - 1) >= Fraction(1, 3)


def test_gate_rejects_the_upstream_factor_on_a_launch_sized_set(capsys):
    exit_code = _run_gate(["--factor", "3", "--validators", "4"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "50.00%" in captured.err
    assert "8 validators" in captured.err


def test_gate_accepts_the_shipped_genesis_combination(capsys):
    assert _run_gate(["--factor", "1", "--validators", "4"]) == 0
    assert "PASS" in capsys.readouterr().out


def _run_gate(argv: list[str]) -> int:
    import sys

    saved = sys.argv
    sys.argv = ["check-stake-factor-safety.py", *argv]
    try:
        return gate.main()
    finally:
        sys.argv = saved
