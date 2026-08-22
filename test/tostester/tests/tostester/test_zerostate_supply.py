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
    ConfigParam8,
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


def _create_state_command(script: Path) -> list[str]:
    """Run create-state against source scripts and generated contract includes."""
    return [
        str(BUILD_DIR / "crypto/create-state"),
        "-I",
        str(REPO / "crypto/fift/lib"),
        "-I",
        str(BUILD_DIR / "crypto/smartcont"),
        "-I",
        str(REPO / "crypto/smartcont"),
        "-s",
        str(script),
    ]


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
    assert rewards.masterchain_block_fee == 569_879_384
    assert rewards.basechain_block_fee == 335_223_167
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
    assert 4 in param10.critical_params

    param14 = _config(state, 14, ConfigParam14)
    assert param14.masterchain_block_fee == 569_879_384
    assert param14.basechain_block_fee == 335_223_167

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


def _punishment_config(state) -> dict:
    """Decode ConfigParam 40, which the vendored TLB library does not model."""
    cs = state.custom.config.config[40].copy()
    tag = cs.load_uint(8)
    assert tag == 0x01, f"unexpected MisbehaviourPunishmentConfig tag {tag:#x}"
    flat = cs.load_uint(cs.load_uint(4) * 8)
    decoded = {
        "default_flat_fine": flat,
        "default_proportional_fine": cs.load_uint(32),
        "severity_flat_mult": cs.load_uint(16),
        "severity_proportional_mult": cs.load_uint(16),
        "unpunishable_interval": cs.load_uint(16),
        "long_interval": cs.load_uint(16),
        "long_flat_mult": cs.load_uint(16),
        "long_proportional_mult": cs.load_uint(16),
        "medium_interval": cs.load_uint(16),
        "medium_flat_mult": cs.load_uint(16),
        "medium_proportional_mult": cs.load_uint(16),
    }
    assert cs.remaining_bits == 0
    return decoded


def _punishment_tier(config: dict, severe: bool, interval: int) -> tuple[int, int]:
    """Mirror compute_punishment() in lite-client/lite-client.cpp."""
    flat = config["default_flat_fine"]
    part = config["default_proportional_fine"]
    if severe:
        flat = flat * config["severity_flat_mult"] >> 8
        part = part * config["severity_proportional_mult"] >> 8
    if interval >= config["long_interval"]:
        flat = flat * config["long_flat_mult"] >> 8
        part = part * config["long_proportional_mult"] >> 8
    elif interval >= config["medium_interval"]:
        flat = flat * config["medium_flat_mult"] >> 8
        part = part * config["medium_proportional_mult"] >> 8
    return flat, part


def test_canonical_genesis_sets_a_stake_proportional_punishment_schedule(tmp_path):
    """Without ConfigParam 40 the punishment path falls back to a flat fine with
    no proportional component, so a validator's required own funds stop scaling
    with the stake it controls. Pooled-stake contracts read this parameter to
    size that requirement, so genesis must ship a real schedule."""
    (tmp_path / "validator-keys.pub").write_bytes(
        b"".join(Key().public_key.key for _ in range(EXPECTED_VALIDATOR_COUNT))
    )
    command = _create_state_command(REPO / "crypto/smartcont/gen-zerostate.fif")
    subprocess.run(command, cwd=tmp_path, check=True, capture_output=True, text=True)

    state = _load_masterchain_state(tmp_path / "zerostate.boc")
    punishment = _punishment_config(state)

    assert punishment == {
        "default_flat_fine": 62_500_000_000,
        "default_proportional_fine": 1 << 24,
        "severity_flat_mult": 640,
        "severity_proportional_mult": 1024,
        "unpunishable_interval": 1000,
        "long_interval": 49152,
        "long_flat_mult": 4096,
        "long_proportional_mult": 4096,
        "medium_interval": 16384,
        "medium_flat_mult": 1024,
        "medium_proportional_mult": 1024,
    }

    short, medium, long = 2000, 20000, 60000
    assert _punishment_tier(punishment, False, short) == (
        62_500_000_000,
        1 << 24,
    )
    assert _punishment_tier(punishment, False, medium) == (
        250 * NANOTOS_PER_TOS,
        1 << 26,
    )
    assert _punishment_tier(punishment, False, long) == (
        1000 * NANOTOS_PER_TOS,
        1 << 28,
    )
    assert _punishment_tier(punishment, True, short) == (
        156_250_000_000,
        1 << 26,
    )
    assert _punishment_tier(punishment, True, medium) == (
        625 * NANOTOS_PER_TOS,
        1 << 28,
    )
    assert _punishment_tier(punishment, True, long) == (
        2500 * NANOTOS_PER_TOS,
        1 << 30,
    )

    # Every threshold has to fit a uint16 and stay inside one validation round,
    # otherwise the tier it guards can never be reached.
    elected_for = _config(state, 15, ConfigParam15).validators_elected_for
    for field in ("unpunishable_interval", "medium_interval", "long_interval"):
        assert 0 < punishment[field] < 1 << 16
        assert punishment[field] < elected_for
    assert (
        punishment["unpunishable_interval"]
        < punishment["medium_interval"]
        < punishment["long_interval"]
    )

    # The worst tier is what a pooled-stake contract must reserve against.
    worst_flat, worst_part = _punishment_tier(punishment, True, long)
    required = worst_flat + (100_000 * NANOTOS_PER_TOS) * worst_part // (1 << 32)
    assert required == 27_500 * NANOTOS_PER_TOS


def test_canonical_genesis_script_accepts_only_four_validator_keys(tmp_path):
    keys = [Key() for _ in range(EXPECTED_VALIDATOR_COUNT)]
    (tmp_path / "validator-keys.pub").write_bytes(
        b"".join(key.public_key.key for key in keys)
    )

    command = _create_state_command(REPO / "crypto/smartcont/gen-zerostate.fif")
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
    assert canonical_rewards.masterchain_block_fee == 569_879_384
    assert canonical_rewards.basechain_block_fee == 335_223_167
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


def test_aipow_native_issuance_is_inert_at_genesis(tmp_path):
    # Phase C dark scaffolding: the mainnet genesis template must not activate
    # AIPoW native issuance. capAipow (bit 1024) stays out of the ConfigParam 8
    # capability set, and none of the four AIPoW ConfigParams (90-93) are
    # present, so the mint path is a no-op until a governance config vote turns
    # it on. This locks the "genesis stays off" invariant in place.
    keys = [Key() for _ in range(EXPECTED_VALIDATOR_COUNT)]
    (tmp_path / "validator-keys.pub").write_bytes(
        b"".join(key.public_key.key for key in keys)
    )
    command = _create_state_command(REPO / "crypto/smartcont/gen-zerostate.fif")
    subprocess.run(command, cwd=tmp_path, check=True, capture_output=True, text=True)

    state = _load_masterchain_state(tmp_path / "zerostate.boc")

    cap_aipow = 1 << 10  # capAipow
    capabilities = _config(state, 8, ConfigParam8).capabilities
    assert capabilities & cap_aipow == 0, (
        f"capAipow must be off at genesis, capabilities={capabilities}"
    )
    for param in (90, 91, 92, 93):
        assert param not in state.custom.config.config, (
            f"AIPoW ConfigParam {param} must be absent at genesis"
        )


def test_genesis_refuses_capaipow_without_parameters(tmp_path):
    # The create-state genesis guard must reject a configuration that turns on
    # capAipow without the AIPoW parameter set, mirroring the block-transition
    # check_config_update guard. Patch the capability line to OR in capAipow
    # (bit 1024) while leaving ConfigParams 90-93 unset, and confirm genesis
    # generation fails rather than emitting a half-activated state.
    genesis = (REPO / "crypto/smartcont/gen-zerostate.fif").read_text()
    assert genesis.count("or config.version!") == 1
    patched = genesis.replace("or config.version!", "or 1024 or config.version!")
    bad_script = tmp_path / "gen-zerostate-capaipow.fif"
    bad_script.write_text(patched)

    keys = [Key() for _ in range(EXPECTED_VALIDATOR_COUNT)]
    (tmp_path / "validator-keys.pub").write_bytes(
        b"".join(key.public_key.key for key in keys)
    )
    command = _create_state_command(bad_script)
    failed = subprocess.run(
        command, cwd=tmp_path, check=False, capture_output=True, text=True
    )
    assert failed.returncode != 0
    assert "capAipow" in (failed.stderr + failed.stdout)


# A complete, valid AIPoW parameter set (ConfigParams 90-93) packed as fift, to
# exercise the real C++ accessors + Config::check_aipow_config end to end via
# create-state's genesis guard: k=3/1, cap 1000 TOS, floor 100 TOS, challenge
# multiplier 2/1; 25%/8-epoch/65536s maturation; 4.5B cap; nonzero registry
# anchors (settlement/methodology/rate-card, plus commitment_code_hash and
# reviewer_addr in the ^[...] ref) and an empty distributor-code set (allowed
# under Model B).
_AIPOW_PARAMS_VALID = (
    "<b 3 32 u, 1 32 u, TM$1000 Tomi, TM$100 Tomi, 2 32 u, 1 32 u, b> 90 config!\n"
    "<b 2500 16 u, 8 16 u, 65536 32 u, 0 16 u, b> 91 config!\n"
    "<b TM$4500000000 Tomi, b> 92 config!\n"
    "<b 0xA1 256 u, 0xB2 256 u, 0xC3 256 u, <b 0xD4 256 u, 0xE5 256 u, b> ref, 0 1 u, b> 93 config!\n"
)


def _run_genesis_with_aipow(tmp_path, params_block, *, enable_capaipow=True):
    genesis = (REPO / "crypto/smartcont/gen-zerostate.fif").read_text()
    patched = genesis
    if enable_capaipow:
        patched = patched.replace("or config.version!", "or 1024 or config.version!")
    patched = patched.replace(
        "// ConfigParam 19: global_id",
        params_block + "// ConfigParam 19: global_id",
    )
    script = tmp_path / "gen-zerostate-aipow.fif"
    script.write_text(patched)
    keys = [Key() for _ in range(EXPECTED_VALIDATOR_COUNT)]
    (tmp_path / "validator-keys.pub").write_bytes(
        b"".join(key.public_key.key for key in keys)
    )
    command = _create_state_command(script)
    return subprocess.run(command, cwd=tmp_path, check=False, capture_output=True, text=True)


def test_genesis_accepts_and_round_trips_a_complete_aipow_parameter_set(tmp_path):
    # A genesis that activates capAipow WITH a complete, valid AIPoW parameter
    # set must be accepted. Acceptance means create-state ran the real C++
    # accessors (get_aipow_config/maturation/limits/registry) and
    # Config::check_aipow_config over the fift-packed params -- so a clean run is
    # the positive round-trip + validation signal. Confirm it landed in state.
    result = _run_genesis_with_aipow(tmp_path, _AIPOW_PARAMS_VALID)
    assert result.returncode == 0, result.stderr + result.stdout

    state = _load_masterchain_state(tmp_path / "zerostate.boc")
    assert _config(state, 8, ConfigParam8).capabilities & (1 << 10), "capAipow must be set"
    for param in (90, 91, 92, 93):
        assert param in state.custom.config.config, (
            f"AIPoW ConfigParam {param} must be present"
        )


@pytest.mark.parametrize(
    "params_block",
    [
        _AIPOW_PARAMS_VALID.replace("2500 16 u,", "10001 16 u,"),  # immediate_bps > 10000
        _AIPOW_PARAMS_VALID.replace("3 32 u, 1 32 u,", "3 32 u, 0 32 u,"),  # zero k_den
        _AIPOW_PARAMS_VALID.replace(
            "TM$1000 Tomi, TM$100 Tomi,", "TM$1000 Tomi, TM$2000 Tomi,"
        ),  # cold_start_floor > schedule_cap
        _AIPOW_PARAMS_VALID.replace("0xC3 256 u,", "0 256 u,"),  # zero rate_card_hash
        _AIPOW_PARAMS_VALID.replace("0xD4 256 u,", "0 256 u,"),  # zero commitment_code_hash
        _AIPOW_PARAMS_VALID.replace("0xE5 256 u,", "0 256 u,"),  # zero reviewer_addr
        "".join(
            line + "\n"
            for line in _AIPOW_PARAMS_VALID.splitlines()
            if "92 config!" not in line
        ),  # AipowLimits (92) missing
    ],
    ids=[
        "immediate_bps_over_10000",
        "zero_denominator",
        "floor_exceeds_cap",
        "zero_rate_card_hash",
        "zero_commitment_code_hash",
        "zero_reviewer_addr",
        "missing_limits_param",
    ],
)
def test_genesis_rejects_invalid_or_incomplete_aipow_parameters(tmp_path, params_block):
    # Each variant activates capAipow but breaks one check_aipow_config invariant
    # (or omits a required parameter); create-state's genesis guard must refuse.
    result = _run_genesis_with_aipow(tmp_path, params_block)
    assert result.returncode != 0
    assert "capAipow" in (result.stderr + result.stdout)


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
