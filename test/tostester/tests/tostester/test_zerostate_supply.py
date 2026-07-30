"""Regression tests for the development and validator-economics zerostates."""

import os
import subprocess
from pathlib import Path

import pytest
from pytosiq_core import ShardStateUnsplit
from pytosiq_core.boc.deserialize import Boc
from pytosiq_core.tlb.config import (
    ConfigParam0,
    ConfigParam2,
    ConfigParam10,
    ConfigParam14,
    ConfigParam15,
    ConfigParam16,
    ConfigParam17,
    ConfigParam28,
    ConfigParam34,
)
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
EXPECTED_VALIDATOR_GENESIS_SUPPLY_TOS = 101_000
EXPECTED_VALIDATOR_COUNT = 4
EXPECTED_SIMPLEX_PARAMS = (400, 4, 1000, 250)
EXPECTED_SIMPLEX_PROTOCOL_VERSION = 2


def _load_masterchain_state(path: Path) -> ShardStateUnsplit:
    root_cell = Boc(path.read_bytes()).deserialize()[0]
    return ShardStateUnsplit.deserialize(root_cell.begin_parse())


def _positive_account_balances(state: ShardStateUnsplit) -> list[int]:
    accounts, _extras = state.accounts
    return sorted(
        shard_account.account.storage.balance.tomis
        for shard_account in accounts.values()
        if shard_account.account is not None
        and shard_account.account.storage.balance.tomis > 0
    )


def _config(state: ShardStateUnsplit, param: int, scheme):
    return scheme.deserialize(state.custom.config.config[param].copy())


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

    state = _load_masterchain_state(zerostate.masterchain.file)

    total_nanotos = state.total_balance.tomis
    assert total_nanotos == EXPECTED_TOTAL_SUPPLY_TOS * NANOTOS_PER_TOS, (
        "genesis total supply must be exactly 5,000,000,000 TOS, got "
        f"{total_nanotos} nanotos ({total_nanotos / NANOTOS_PER_TOS} TOS)"
    )


def test_validator_economics_profile_requires_exactly_four_keys(tmp_path):
    install = Install(BUILD_DIR, REPO)
    config = NetworkConfig(validator_economics_profile=True)

    with pytest.raises(ValueError, match="exactly four genesis validators"):
        create_zerostate(install, tmp_path, config, [Key()] * 3)

    duplicate = Key()
    with pytest.raises(ValueError, match="unique genesis validator keys"):
        create_zerostate(install, tmp_path, config, [duplicate] * 4)


def test_validator_election_stage_a_profile_is_isolated_and_accelerated(tmp_path):
    install = Install(BUILD_DIR, REPO)

    with pytest.raises(
        ValueError,
        match="Stage A profile requires validator economics profile",
    ):
        create_zerostate(
            install,
            tmp_path / "invalid",
            NetworkConfig(validator_election_stage_a_profile=True),
            [Key()],
        )

    keys = [Key() for _ in range(EXPECTED_VALIDATOR_COUNT)]
    config = NetworkConfig(
        shard_validators=EXPECTED_VALIDATOR_COUNT,
        validator_economics_profile=True,
        validator_election_stage_a_profile=True,
    )
    stage_a_dir = tmp_path / "stage-a"
    stage_a_dir.mkdir()
    zerostate = create_zerostate(install, stage_a_dir, config, keys)
    state = _load_masterchain_state(zerostate.masterchain.file)

    param15 = _config(state, 15, ConfigParam15)
    assert (
        param15.validators_elected_for,
        param15.elections_start_before,
        param15.elections_end_before,
        param15.stake_held_for,
    ) == (300, 180, 60, 180)

    validator_set = _config(state, 34, ConfigParam34).cur_validators
    assert validator_set.utime_until - validator_set.utime_since == 600

    # The accelerated profile must retain the production candidate's
    # validator count, stake rules, rewards, minter, and catchain settings.
    assert _config(state, 16, ConfigParam16).min_validators == 4
    assert _config(state, 17, ConfigParam17).min_stake == (
        10_000 * NANOTOS_PER_TOS
    )
    rewards = _config(state, 14, ConfigParam14)
    assert rewards.masterchain_block_fee == 5_699_830_088
    assert rewards.basechain_block_fee == 3_352_841_228
    assert _config(state, 2, ConfigParam2).minter_addr == _config(
        state, 0, ConfigParam0
    ).config_addr
    catchain = _config(state, 28, ConfigParam28)
    assert (
        catchain.mc_catchain_lifetime,
        catchain.shard_catchain_lifetime,
        catchain.shard_validators_lifetime,
        catchain.shard_validators_num,
    ) == (250, 250, 1000, 23)


def test_validator_economics_profile_matches_bootstrap_spec(tmp_path):
    install = Install(BUILD_DIR, REPO)
    keys = [Key() for _ in range(EXPECTED_VALIDATOR_COUNT)]
    config = NetworkConfig(
        shard_validators=EXPECTED_VALIDATOR_COUNT,
        validator_economics_profile=True,
    )
    zerostate = create_zerostate(install, tmp_path, config, keys)
    state = _load_masterchain_state(zerostate.masterchain.file)

    assert (
        state.total_balance.tomis
        == EXPECTED_VALIDATOR_GENESIS_SUPPLY_TOS * NANOTOS_PER_TOS
    )
    assert _positive_account_balances(state) == [
        500 * NANOTOS_PER_TOS,
        500 * NANOTOS_PER_TOS,
        100_000 * NANOTOS_PER_TOS,
    ]

    config_address = _config(state, 0, ConfigParam0).config_addr
    minter_address = _config(state, 2, ConfigParam2).minter_addr
    assert minter_address == config_address
    assert 3 not in state.custom.config.config

    param10 = _config(state, 10, ConfigParam10)
    assert 3 in param10.critical_params

    param14 = _config(state, 14, ConfigParam14)
    assert param14.masterchain_block_fee == 5_699_830_088
    assert param14.basechain_block_fee == 3_352_841_228

    param15 = _config(state, 15, ConfigParam15)
    assert (
        param15.validators_elected_for,
        param15.elections_start_before,
        param15.elections_end_before,
        param15.stake_held_for,
    ) == (65_536, 32_768, 8_192, 32_768)

    param16 = _config(state, 16, ConfigParam16)
    assert (
        param16.max_validators,
        param16.max_main_validators,
        param16.min_validators,
    ) == (400, 100, 4)

    param17 = _config(state, 17, ConfigParam17)
    assert (
        param17.min_stake,
        param17.max_stake,
        param17.min_total_stake,
        param17.max_stake_factor,
    ) == (
        10_000 * NANOTOS_PER_TOS,
        10_000_000 * NANOTOS_PER_TOS,
        40_000 * NANOTOS_PER_TOS,
        1 << 16,
    )

    param28 = _config(state, 28, ConfigParam28)
    assert (
        param28.mc_catchain_lifetime,
        param28.shard_catchain_lifetime,
        param28.shard_validators_lifetime,
        param28.shard_validators_num,
    ) == (250, 250, 1000, 23)

    validator_set = _config(state, 34, ConfigParam34).cur_validators
    assert validator_set.total == EXPECTED_VALIDATOR_COUNT
    assert validator_set.main == EXPECTED_VALIDATOR_COUNT
    assert validator_set.utime_until - validator_set.utime_since == 131_072
    assert validator_set.total_weight == EXPECTED_VALIDATOR_COUNT * 17
    for index, key in enumerate(keys):
        validator = validator_set.list[index]
        assert validator.type_ == "validator_addr"
        assert validator.public_key.pubkey == key.public_key.key
        assert validator.adnl_addr == key.id
        assert validator.weight == 17


def test_canonical_genesis_script_accepts_only_four_validator_keys(tmp_path):
    keys = [Key() for _ in range(EXPECTED_VALIDATOR_COUNT)]
    (tmp_path / "validator-keys.pub").write_bytes(
        b"".join(key.public_key.key for key in keys)
    )

    command = [
        str(BUILD_DIR / "crypto/create-state"),
        "-I",
        str(REPO / "crypto/fift/lib"),
        "-I",
        str(REPO / "crypto/smartcont"),
        "-s",
        str(REPO / "crypto/smartcont/gen-zerostate.fif"),
    ]
    subprocess.run(command, cwd=tmp_path, check=True, capture_output=True, text=True)

    state = _load_masterchain_state(tmp_path / "zerostate.boc")
    assert (
        state.total_balance.tomis
        == EXPECTED_VALIDATOR_GENESIS_SUPPLY_TOS * NANOTOS_PER_TOS
    )
    assert _positive_account_balances(state) == [
        500 * NANOTOS_PER_TOS,
        500 * NANOTOS_PER_TOS,
        100_000 * NANOTOS_PER_TOS,
    ]
    assert _config(state, 2, ConfigParam2).minter_addr == _config(
        state, 0, ConfigParam0
    ).config_addr
    assert 3 not in state.custom.config.config
    canonical_rewards = _config(state, 14, ConfigParam14)
    assert canonical_rewards.masterchain_block_fee == 5_699_830_088
    assert canonical_rewards.basechain_block_fee == 3_352_841_228
    assert _config(state, 16, ConfigParam16).min_validators == 4
    assert _config(state, 17, ConfigParam17).max_stake_factor == 1 << 16
    canonical_catchain = _config(state, 28, ConfigParam28)
    assert (
        canonical_catchain.mc_catchain_lifetime,
        canonical_catchain.shard_catchain_lifetime,
        canonical_catchain.shard_validators_lifetime,
        canonical_catchain.shard_validators_num,
    ) == (250, 250, 1000, 23)
    validator_set = _config(state, 34, ConfigParam34).cur_validators
    assert validator_set.total == EXPECTED_VALIDATOR_COUNT
    assert [
        validator_set.list[index].adnl_addr
        for index in range(EXPECTED_VALIDATOR_COUNT)
    ] == [key.id for key in keys]

    (tmp_path / "validator-keys.pub").write_bytes(
        b"".join(key.public_key.key for key in keys[:3])
    )
    failed = subprocess.run(
        command, cwd=tmp_path, check=False, capture_output=True, text=True
    )
    assert failed.returncode != 0
    assert "exactly four 32-byte public keys" in failed.stderr + failed.stdout

    (tmp_path / "validator-keys.pub").write_bytes(
        b"".join([keys[0].public_key.key] * EXPECTED_VALIDATOR_COUNT)
    )
    failed = subprocess.run(
        command, cwd=tmp_path, check=False, capture_output=True, text=True
    )
    assert failed.returncode != 0
    assert "genesis validator public keys must be unique" in (
        failed.stderr + failed.stdout
    )


def test_validator_key_helper_defaults_to_four_keys(tmp_path):
    command = [
        str(BUILD_DIR / "crypto/fift"),
        "-I",
        str(REPO / "crypto/fift/lib"),
        "-s",
        str(REPO / "scripts/gen-validator-keys.fif"),
    ]
    subprocess.run(command, cwd=tmp_path, check=True, capture_output=True, text=True)

    assert (tmp_path / "validator-keys.pub").stat().st_size == 128
    for index in range(1, EXPECTED_VALIDATOR_COUNT + 1):
        assert (tmp_path / f"val-key-{index}").stat().st_size == 32
