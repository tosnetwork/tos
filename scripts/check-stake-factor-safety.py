#!/usr/bin/env python3
"""Gate for ConfigParam 17's max_stake_factor.

The Elector caps every elected validator's effective stake at
``min(stake, max_factor * smallest_elected_stake)`` (elector-code.fc, try_elect)
and hands out weight in proportion to that capped value. So the factor decides
how much heavier the largest participant can be than the smallest one, and the
worst case is one participant staking all the way to the cap while everyone
else sits at the minimum:

    worst_case_share = factor / (factor + validators - 1)

The launch policy in https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-validator-only-token-economics.md requires that no
single entry can reach one third of effective weight in the smallest allowed
validator set -- one third is the threshold at which a single party can stall
consensus on its own. Solving ``factor / (factor + n - 1) < 1/3`` gives

    factor < (validators - 1) / 2

which is the whole rule. It is worth stating plainly that the factor is not an
independent knob: a value that is safe on a large network is unsafe on a small
one, so raising it is only ever valid together with a validator count that
supports it.

Usage:

    check-stake-factor-safety.py --factor 3 --validators 8
    check-stake-factor-safety.py --zerostate zerostate.boc
    check-stake-factor-safety.py --factor 3            # report required size

Exits non-zero when the combination violates the rule, so it can gate a
configuration proposal or run in CI.
"""

from __future__ import annotations

import argparse
import sys
from fractions import Fraction
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "test/tostester/src"))

FACTOR_SCALE = 1 << 16
# A single party at or above this share of effective weight can stall consensus.
MAX_SINGLE_ENTRY_SHARE = Fraction(1, 3)


def worst_case_share(factor: Fraction, validators: int) -> Fraction:
    """Largest effective-weight share one entry can hold in a set of that size."""
    if validators < 1:
        raise ValueError("a validator set needs at least one member")
    return factor / (factor + validators - 1)


def max_safe_factor(validators: int) -> Fraction:
    """Exclusive upper bound on the factor for a set of that size."""
    return Fraction(validators - 1, 2)


def min_validators_for(factor: Fraction) -> int:
    """Smallest set size at which the factor satisfies the rule."""
    # factor < (n - 1) / 2  <=>  n > 2 * factor + 1
    bound = 2 * factor + 1
    smallest = bound.numerator // bound.denominator + 1
    return max(smallest, 1)


def _read_config_from_state(path: Path) -> dict:
    """Read the stake limits and validator bounds out of a state BOC."""
    import importlib

    boc = importlib.import_module("pytosiq_core.boc.deserialize")
    core = importlib.import_module("pytosiq_core")
    config_tlb = importlib.import_module("pytosiq_core.tlb.config")

    root = boc.Boc(path.read_bytes()).deserialize()[0]
    state = core.ShardStateUnsplit.deserialize(root.begin_parse())
    config = state.custom.config.config

    param17 = config_tlb.ConfigParam17.deserialize(config[17].copy())
    param16 = config_tlb.ConfigParam16.deserialize(config[16].copy())

    current = None
    if 34 in config:
        current = config_tlb.ConfigParam34.deserialize(config[34].copy()).cur_validators.total

    return {
        "min_stake": param17.min_stake,
        "max_stake": param17.max_stake,
        "min_total_stake": param17.min_total_stake,
        "max_stake_factor": param17.max_stake_factor,
        "min_validators": param16.min_validators,
        "current_validators": current,
        # Lets a proposal pin the value it is replacing, so it cannot land on
        # top of a competing change to the same parameter.
        "current_value_hash": config[17].copy().to_cell().hash.hex(),
    }


def _format_factor(factor: Fraction) -> str:
    return f"{float(factor):g} ({int(factor * FACTOR_SCALE)}/{FACTOR_SCALE})"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--factor", type=Fraction, help="max_stake_factor as a decimal, e.g. 3")
    parser.add_argument("--validators", type=int, help="smallest allowed validator set size")
    parser.add_argument("--zerostate", type=Path, help="read the factor and set size from a state BOC")
    parser.add_argument("--json", action="store_true", help="emit the verdict and the state's stake limits as JSON")
    args = parser.parse_args()

    chain = {}
    current_set = None
    if args.zerostate is not None:
        chain = _read_config_from_state(args.zerostate)
        factor = Fraction(chain["max_stake_factor"], FACTOR_SCALE)
        validators = chain["min_validators"]
        current_set = chain["current_validators"]
        if args.factor is not None:
            factor = args.factor
        if args.validators is not None:
            validators = args.validators
    else:
        if args.factor is None:
            parser.error("--factor is required unless --zerostate is given")
        factor = args.factor
        validators = args.validators

    if args.json:
        import json

        safe = None
        if validators is not None:
            safe = worst_case_share(factor, validators) < MAX_SINGLE_ENTRY_SHARE
        payload = dict(chain)
        payload.update(
            {
                "proposed_max_stake_factor": int(factor * FACTOR_SCALE),
                "checked_validators": validators,
                "required_validators": min_validators_for(factor),
                "safe": safe,
            }
        )
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if safe else 1

    if factor <= 0:
        parser.error("factor must be positive")

    print(f"max_stake_factor      : {_format_factor(factor)}")
    if validators is None:
        needed = min_validators_for(factor)
        print(f"required set size     : at least {needed} validators")
        print(f"  a set of {needed} keeps the largest entry at "
              f"{float(worst_case_share(factor, needed)):.1%} of effective weight")
        print("no validator count given, nothing to verify")
        return 0

    print(f"smallest allowed set  : {validators} validators")
    if current_set is not None:
        print(f"current validator set : {current_set} validators")

    share = worst_case_share(factor, validators)
    bound = max_safe_factor(validators)
    print(f"worst-case entry share: {float(share):.2%} (limit {float(MAX_SINGLE_ENTRY_SHARE):.2%})")
    print(f"factor bound for {validators:>3}   : below {float(bound):g}")

    if share < MAX_SINGLE_ENTRY_SHARE:
        print("PASS: one entry cannot reach a third of effective weight")
        return 0

    needed = min_validators_for(factor)
    print(
        "FAIL: a single entry can reach "
        f"{float(share):.2%} of effective weight, enough to stall consensus alone",
        file=sys.stderr,
    )
    print(
        f"      either keep the factor below {float(bound):g} at {validators} validators, "
        f"or raise the floor to {needed} before raising the factor to {float(factor):g}",
        file=sys.stderr,
    )
    print(
        "      the floor moves first: scripts/propose-validator-count.sh "
        f"--min-validators {needed}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
