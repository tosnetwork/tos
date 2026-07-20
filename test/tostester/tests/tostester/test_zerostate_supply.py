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
from tostester.zerostate import create_zerostate

REPO = Path(__file__).resolve().parents[4]
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build-remove-workchains-full"))
NANOTOS_PER_TOS = 1_000_000_000
EXPECTED_TOTAL_SUPPLY_TOS = 5_000_000_000


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
