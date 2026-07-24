"""Regression test: the local/test genesis template's total supply must be
exactly 5,000,000,000 TOS (see doc/Currency.md, doc/Zerostate.md -- the same
canonical figure the mainnet template targets). A prior version of this
template accidentally minted an extra 1 TOS split across smc3/elector/config
reserves, on top of the 5 B pre-mined to the main wallet.
"""

import os
from pathlib import Path

from pytosiq_core import ShardStateUnsplit
from pytosiq_core.boc.deserialize import Boc
from tostester.install import Install
from tostester.key import Key
from tostester.network import NetworkConfig
from tostester.zerostate import SimplexConsensusConfig, create_zerostate

REPO = Path(__file__).resolve().parents[4]
# Matches test/integration/test_basic.py's convention: CI's build step
# (assembly/native/build-ubuntu-shared.sh) always builds into `build`, not
# `build-remove-workchains-full` (a local-dev-only directory name used by
# some scripts/*.py e2e scripts). TOS_BUILD_DIR still overrides for local use.
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build"))
NANOTOS_PER_TOS = 1_000_000_000
EXPECTED_TOTAL_SUPPLY_TOS = 5_000_000_000
EXPECTED_SIMPLEX_PARAMS = (400, 4, 1000, 250)
EXPECTED_SIMPLEX_PROTOCOL_VERSION = 2


def test_genesis_simplex_parameters_use_v2_with_ton_mainnet_pacing():
    simplex = SimplexConsensusConfig()
    actual = (
        simplex.target_block_rate_ms,
        simplex.slots_per_leader_window,
        simplex.first_block_timeout_ms,
        simplex.max_leader_window_desync,
    )
    assert actual == EXPECTED_SIMPLEX_PARAMS

    genesis = (REPO / "crypto/smartcont/gen-zerostate.fif").read_text()
    assert genesis.count("<b x{22} s, 0 5 u, 2 2 u, 1 1 u, 4 32 u, swap dict, b>") == 2
    assert genesis.count("<b 400 32 u, b> <s 0 rot 8 udict! drop") == 2
    assert simplex.protocol_version == EXPECTED_SIMPLEX_PROTOCOL_VERSION
    assert simplex.use_quic


def test_local_genesis_total_supply_is_exactly_five_billion_tos(tmp_path):
    install = Install(BUILD_DIR, REPO)
    zerostate = create_zerostate(install, tmp_path, NetworkConfig(), [Key()])

    data = zerostate.masterchain.file.read_bytes()
    root_cell = Boc(data).deserialize()[0]
    state = ShardStateUnsplit.deserialize(root_cell.begin_parse())

    total_nanotos = state.total_balance.tomis
    assert total_nanotos == EXPECTED_TOTAL_SUPPLY_TOS * NANOTOS_PER_TOS, (
        "genesis total supply must be exactly 5,000,000,000 TOS, got "
        f"{total_nanotos} nanotos ({total_nanotos / NANOTOS_PER_TOS} TOS)"
    )
