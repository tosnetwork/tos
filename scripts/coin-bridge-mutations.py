#!/usr/bin/env python3
"""Mutation controls for the coin bridge's oracle multisigs and reward vote.

Each control removes one guard in a copy of the sources and runs the
bridge_multisig_sandbox test that names it; the control is red only when that
test fails for its named reason. The multisig guards are also exclusive: under
the mutation every other guard test still passes, so each guard is held by
exactly its own test. Before the mutations every named test runs once against
the unmutated copy and must pass.

The runner, the scratch copy and the options are those of
scripts/token-bridge-mutations.py.

Usage: coin-bridge-mutations.py [--only ID[,ID...]] [--results FILE] [--show] [--no-controls]
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "token_bridge_mutations", Path(__file__).resolve().parent / "token-bridge-mutations.py"
)
assert _SPEC is not None and _SPEC.loader is not None
runner = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = runner
_SPEC.loader.exec_module(runner)

TVM = "crosschain/coin-bridge/tvm"


def reward_controls(prefix: str, network: str) -> list:
    code = f"{TVM}/{network}/bridge_code.fc"
    return [
        runner.Mutation(
            f"{prefix}1",
            "get_reward pays an address it does not validate",
            code,
            "throw_unless(308, reward_address_ok?(reward_address));\n",
            "",
            "coin_get_reward_refuses_a_",
            "exit code 308",
            target="bridge_multisig_sandbox",
        ),
        runner.Mutation(
            f"{prefix}2",
            "get_reward pays the multisig that relayed the vote",
            code,
            ".store_slice(reward_address)",
            ".store_slice(s_addr)",
            "coin_get_reward_pays_",
            "panicked",
            target="bridge_multisig_sandbox",
        ),
        runner.Mutation(
            f"{prefix}3",
            "get_reward ignores data after the reward address",
            code,
            "voting_data.end_parse();\n",
            "",
            "coin_get_reward_refuses_trailing",
            "expected exit code 9",
            target="bridge_multisig_sandbox",
        ),
    ]


MUTATIONS = [
    # The Ethereum multisig: E01 to E06, the BSC multisig: B01 to B06.
    *runner.multisig_controls("E", f"{TVM}/ethereum/multisig-code.fc"),
    *runner.multisig_controls("B", f"{TVM}/bsc/multisig-code.fc"),
    # Operation 5 on each network's bridge.
    *reward_controls("ER", "ethereum"),
    *reward_controls("BR", "bsc"),
]


if __name__ == "__main__":
    sys.exit(runner.main(MUTATIONS))
