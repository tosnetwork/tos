"""The localnet's deployment fee schedule is the deployed chain's.

`tostester` renders its own zerostate from a template, and
`crypto/smartcont/gen-zerostate.fif` is what `create-state` renders the
deployed chain's from. They are two files, and the fee schedule appears in
both. A harness that measures what a transaction costs is only measuring
something real while the two agree, so this compares them rather than trusting
that whoever last changed one also changed the other.

It compares only the four fee lines, and only when the deployment schedule is
asked for. The cheap test schedule is deliberately different and is not
checked against anything.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from tostester.zerostate import NetworkConfig, fee_schedule_for

REPO = Path(__file__).resolve().parents[4]
GEN_ZEROSTATE = REPO / "crypto/smartcont/gen-zerostate.fif"

LINES = ("gas_prices", "mc_gas_prices", "fwd_prices", "mc_fwd_prices")


def normalise(line: str) -> str:
    """Whitespace between Fift words carries no meaning; everything else does."""
    return " ".join(line.split())


def fif_line(source: str, name: str) -> str:
    pattern = re.compile(rf"^(?!//)(.*\bconfig\.{name}!)\s*$", re.MULTILINE)
    matches = pattern.findall(source)
    expected = 1
    if len(matches) != expected:
        raise AssertionError(f"{name}: {len(matches)} definitions in gen-zerostate.fif")
    return normalise(matches[0])


@pytest.mark.parametrize("name", LINES)
def test_the_deployment_schedule_is_the_one_gen_zerostate_writes(name: str) -> None:
    if not GEN_ZEROSTATE.exists():
        pytest.skip(f"{GEN_ZEROSTATE} is not in this checkout")
    source = GEN_ZEROSTATE.read_text()
    schedule = fee_schedule_for(NetworkConfig(deployment_fee_schedule=True))
    rendered = normalise(schedule[name].splitlines()[-1])
    assert rendered == fif_line(source, name), (
        f"the localnet's {name} is not the deployed chain's. A fee measured on a localnet "
        f"built this way is a fee on a chain nobody runs."
    )


def test_the_test_schedule_is_deliberately_not_the_deployment_one() -> None:
    cheap = fee_schedule_for(NetworkConfig())
    deployed = fee_schedule_for(NetworkConfig(deployment_fee_schedule=True))
    assert cheap != deployed, (
        "the default localnet schedule has become the deployment one; either the option is "
        "no longer doing anything, or every existing test's fee assumptions have just moved"
    )


def test_masterchain_prices_are_reduced_without_changing_resource_or_debt_limits() -> None:
    schedule = fee_schedule_for(NetworkConfig(deployment_fee_schedule=True))
    assert normalise(schedule["mc_gas_prices"]) == (
        "32768000 1 *M 70 *M 10000 2500000 TM$0.1 TM$1.0 100 50000 config.mc_gas_prices!"
    )
    assert normalise(schedule["mc_fwd_prices"]) == (
        "500000 32768000 3276800000 3/2 sg*/ 1/3 sg*/ 1/3 sg*/ config.mc_fwd_prices!"
    )
    cheap = fee_schedule_for(NetworkConfig())
    assert normalise(cheap["mc_gas_prices"]) == (
        "10 sg* 1 *M 20 *M 10000 1000 *M TM$0.1 TM$1.0 100 1000 config.mc_gas_prices!"
    )
    assert normalise(cheap["mc_fwd_prices"]) == (
        "100 10 sg* 10 sg* 3/2 sg*/ 1/3 sg*/ 1/3 sg*/ config.mc_fwd_prices!"
    )
