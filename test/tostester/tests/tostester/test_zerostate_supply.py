"""Regression tests for the development and validator-economics zerostates."""

import hashlib
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
import tostester.zerostate as zerostate_module
from pytosiq_core import ShardStateUnsplit
from pytosiq_core.boc.deserialize import Boc
from pytosiq_core.tlb.config import (
    ConfigParam0,
    ConfigParam2,
    ConfigParam4,
    ConfigParam8,
    ConfigParam9,
    ConfigParam10,
    ConfigParam14,
    ConfigParam15,
    ConfigParam16,
    ConfigParam17,
    ConfigParam20,
    ConfigParam21,
    ConfigParam28,
    ConfigParam34,
)
from tostester.install import Install
from tostester.key import Key
from tostester.network import NetworkConfig
from tostester.zerostate import (
    PqInitialValidator,
    SimplexConsensusConfig,
    _launch_validator_counts,
    create_zerostate,
)

REPO = Path(__file__).resolve().parents[4]
# Matches test/integration/test_basic.py's convention: CI's build step
# (assembly/native/build-ubuntu-shared.sh) always builds into `build`, not
# `build-remove-workchains-full` (a local-dev-only directory name used by
# some scripts/*.py e2e scripts). TOS_BUILD_DIR still overrides for local use.
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build"))
NANOTOS_PER_TOS = 1_000_000_000
EXPECTED_TOTAL_SUPPLY_TOS = 5_000_000_000
EXPECTED_VALIDATOR_GENESIS_SUPPLY_TOS = 101_000
EXPECTED_VALIDATOR_EXPERIMENT_FAUCET_TOS = 136_120
EXPECTED_VALIDATOR_COUNT = 4
EXPECTED_SIMPLEX_PARAMS = (400, 4, 1000, 250)
EXPECTED_SIMPLEX_PROTOCOL_VERSION = 2
EXPECTED_MAINNET_GENESIS_UTIME = 1_789_434_000
DNS_VECTORS = json.loads((REPO / "domains/packages/protocol/test/vectors.json").read_text())
EXPECTED_DNS_ROOT_ID = DNS_VECTORS["root_address"].removeprefix("-1:")


def test_launch_validator_count_boundary_is_explicit():
    assert _launch_validator_counts(21, 21) == {
        "max_validators": 21,
        "max_main_validators": 21,
        "min_validators": 21,
    }
    with pytest.raises(ValueError, match="genesis validator count 22 exceeds.*cap 21"):
        _launch_validator_counts(22, 21)


def test_controller_policy_uses_genesis_config_dictionary(tmp_path):
    code_hash = bytes(range(32))
    zerostate = create_zerostate(
        Install(BUILD_DIR, REPO),
        tmp_path,
        NetworkConfig(validator_controller_code_hash=code_hash),
        [Key()],
    )
    state = _load_masterchain_state(zerostate.masterchain.file)
    policy = state.custom.config.config[47].copy()
    admitted = policy.load_dict(256)
    assert admitted is not None
    assert set(admitted) == {int.from_bytes(code_hash, "big")}, (
        "genesis ConfigParam 47 did not admit exactly the controller code hash"
    )
    assert policy.remaining_bits == 0 and policy.remaining_refs == 0, (
        "genesis ConfigParam 47 has trailing data"
    )

    with pytest.raises(ValueError, match="controller code hash must be 32 bytes"):
        create_zerostate(
            Install(BUILD_DIR, REPO),
            tmp_path / "invalid",
            NetworkConfig(validator_controller_code_hash=b"short"),
            [Key()],
        )


def test_local_genesis_builds_21_validators_and_refuses_22_before_fift(tmp_path):
    install = Install(BUILD_DIR, REPO)
    keys = [Key() for _ in range(21)]
    config = NetworkConfig(shard_validators=21)
    accepted_dir = tmp_path / "accepted-21"
    accepted_dir.mkdir()
    state = _load_masterchain_state(
        create_zerostate(install, accepted_dir, config, keys).masterchain.file
    )
    limits = _config(state, 16, ConfigParam16)
    validators = _config(state, 34, ConfigParam34).cur_validators
    assert (limits.max_validators, limits.max_main_validators) == (21, 21)
    assert (validators.total, validators.main) == (21, 21)

    with pytest.raises(ValueError, match="genesis validator count 22 exceeds.*cap 21"):
        create_zerostate(
            install,
            tmp_path / "refused-22",
            NetworkConfig(shard_validators=21),
            [Key() for _ in range(22)],
        )


def _load_masterchain_state(path: Path) -> ShardStateUnsplit:
    root_cell = Boc(path.read_bytes()).deserialize()[0]
    return ShardStateUnsplit.deserialize(root_cell.begin_parse())


def _positive_account_balances(state: ShardStateUnsplit) -> list[int]:
    accounts, _extras = state.accounts
    return sorted(
        shard_account.account.storage.balance.tomis
        for shard_account in accounts.values()
        if shard_account.account is not None and shard_account.account.storage.balance.tomis > 0
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


def _mainnet_genesis_env() -> dict[str, str]:
    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = str(EXPECTED_MAINNET_GENESIS_UTIME)
    return env


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


def test_ordinary_local_profile_can_explicitly_extend_bootstrap_validator_set(tmp_path):
    install = Install(BUILD_DIR, REPO)
    zerostate = create_zerostate(
        install,
        tmp_path,
        NetworkConfig(bootstrap_validator_set_valid_for=86_400),
        [Key()],
    )

    state = _load_masterchain_state(zerostate.masterchain.file)
    validator_set = _config(state, 34, ConfigParam34).cur_validators
    assert validator_set.utime_until - validator_set.utime_since == 86_400


@pytest.mark.parametrize("duration", [False, 0, -1, 0x1_0000_0000])
def test_bootstrap_validator_set_lifetime_rejects_invalid_duration(tmp_path, duration):
    install = Install(BUILD_DIR, REPO)
    with pytest.raises(ValueError, match="bootstrap validator-set lifetime"):
        create_zerostate(
            install,
            tmp_path,
            NetworkConfig(bootstrap_validator_set_valid_for=duration),
            [Key()],
        )


def test_validator_economics_profile_requires_exactly_four_keys(tmp_path):
    install = Install(BUILD_DIR, REPO)
    config = NetworkConfig(validator_economics_profile=True)

    with pytest.raises(ValueError, match="exactly four genesis validators"):
        create_zerostate(install, tmp_path, config, [Key()] * 3)

    duplicate = Key()
    with pytest.raises(ValueError, match="unique genesis validator keys"):
        create_zerostate(install, tmp_path, config, [duplicate] * 4)

    pq_validator = PqInitialValidator(
        validator_id=b"v" * 32,
        key_id=b"k" * 32,
        public_key=b"p" * 1312,
        adnl_id=b"a" * 32,
    )
    with pytest.raises(ValueError, match="exactly four genesis validators"):
        create_zerostate(install, tmp_path, config, [], [pq_validator] * 3)
    with pytest.raises(ValueError, match="unique genesis validator keys"):
        create_zerostate(install, tmp_path, config, [], [pq_validator] * 4)


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

    assert state.total_balance.tomis == EXPECTED_VALIDATOR_GENESIS_SUPPLY_TOS * NANOTOS_PER_TOS
    assert _positive_account_balances(state) == [
        500 * NANOTOS_PER_TOS,
        500 * NANOTOS_PER_TOS,
        100_000 * NANOTOS_PER_TOS,
    ]

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
    assert _config(state, 17, ConfigParam17).min_stake == (10_000 * NANOTOS_PER_TOS)
    rewards = _config(state, 14, ConfigParam14)
    assert rewards.masterchain_block_fee == 39_496_630
    assert rewards.basechain_block_fee == 23_233_312
    assert (
        _config(state, 2, ConfigParam2).minter_addr == _config(state, 0, ConfigParam0).config_addr
    )
    catchain = _config(state, 28, ConfigParam28)
    assert (
        catchain.mc_catchain_lifetime,
        catchain.shard_catchain_lifetime,
        catchain.shard_validators_lifetime,
        catchain.shard_validators_num,
    ) == (250, 250, 1000, 21)


def test_stage_a_can_extend_only_the_bootstrap_set_without_changing_election_params(tmp_path):
    install = Install(BUILD_DIR, REPO)
    config = NetworkConfig(
        shard_validators=EXPECTED_VALIDATOR_COUNT,
        validator_economics_profile=True,
        validator_election_stage_a_profile=True,
        bootstrap_validator_set_valid_for=1200,
    )
    zerostate = create_zerostate(
        install, tmp_path, config, [Key() for _ in range(EXPECTED_VALIDATOR_COUNT)]
    )
    state = _load_masterchain_state(zerostate.masterchain.file)
    validator_set = _config(state, 34, ConfigParam34).cur_validators
    assert validator_set.utime_until - validator_set.utime_since == 1200
    param15 = _config(state, 15, ConfigParam15)
    assert (
        param15.validators_elected_for,
        param15.elections_start_before,
        param15.elections_end_before,
        param15.stake_held_for,
    ) == (300, 180, 60, 180)


def test_f01_stage_a_start_override_is_encoded_in_genesis_param15(tmp_path):
    install = Install(BUILD_DIR, REPO)
    config = NetworkConfig(
        shard_validators=EXPECTED_VALIDATOR_COUNT,
        validator_economics_profile=True,
        validator_election_stage_a_profile=True,
        validator_election_stage_a_start_before=240,
    )
    genesis_dir = tmp_path / "f01-extended"
    genesis_dir.mkdir()
    zerostate = create_zerostate(
        install, genesis_dir, config, [Key() for _ in range(EXPECTED_VALIDATOR_COUNT)]
    )
    state = _load_masterchain_state(zerostate.masterchain.file)
    param15 = _config(state, 15, ConfigParam15)
    assert (
        param15.validators_elected_for,
        param15.elections_start_before,
        param15.elections_end_before,
        param15.stake_held_for,
    ) == (300, 240, 60, 180)
    assert (
        _config(state, 34, ConfigParam34).cur_validators.utime_until
        - (_config(state, 34, ConfigParam34).cur_validators.utime_since)
        == 600
    )
    for start in (False, 60, 300, 301):
        with pytest.raises(ValueError, match="Stage A election start"):
            create_zerostate(
                install,
                tmp_path / f"bad-{start}",
                NetworkConfig(
                    validator_economics_profile=True,
                    validator_election_stage_a_profile=True,
                    validator_election_stage_a_start_before=start,
                ),
                [Key() for _ in range(EXPECTED_VALIDATOR_COUNT)],
            )
    with pytest.raises(ValueError, match="requires the Stage A profile"):
        create_zerostate(
            install,
            tmp_path / "not-stage-a",
            NetworkConfig(validator_election_stage_a_start_before=240),
            [Key()],
        )


def test_stage_a_lifecycle_can_extend_elected_sets_without_changing_other_params(tmp_path):
    install = Install(BUILD_DIR, REPO)
    config = NetworkConfig(
        shard_validators=EXPECTED_VALIDATOR_COUNT,
        validator_economics_profile=True,
        validator_election_stage_a_profile=True,
        bootstrap_validator_set_valid_for=1200,
        validator_election_stage_a_elected_for=600,
    )
    zerostate = create_zerostate(
        install, tmp_path, config, [Key() for _ in range(EXPECTED_VALIDATOR_COUNT)]
    )
    state = _load_masterchain_state(zerostate.masterchain.file)
    validator_set = _config(state, 34, ConfigParam34).cur_validators
    assert validator_set.utime_until - validator_set.utime_since == 1200
    param15 = _config(state, 15, ConfigParam15)
    assert (
        param15.validators_elected_for,
        param15.elections_start_before,
        param15.elections_end_before,
        param15.stake_held_for,
    ) == (600, 180, 60, 180)


@pytest.mark.parametrize("duration", [False, 0, 240, 0x1_0000_0000])
def test_stage_a_elected_set_override_rejects_invalid_duration(tmp_path, duration):
    with pytest.raises(ValueError, match="Stage A elected-set duration"):
        create_zerostate(
            Install(BUILD_DIR, REPO),
            tmp_path,
            NetworkConfig(
                shard_validators=EXPECTED_VALIDATOR_COUNT,
                validator_economics_profile=True,
                validator_election_stage_a_profile=True,
                validator_election_stage_a_elected_for=duration,
            ),
            [Key() for _ in range(EXPECTED_VALIDATOR_COUNT)],
        )


def test_elected_set_override_is_rejected_outside_stage_a(tmp_path):
    with pytest.raises(ValueError, match="requires the Stage A profile"):
        create_zerostate(
            Install(BUILD_DIR, REPO),
            tmp_path,
            NetworkConfig(
                validator_economics_profile=True,
                validator_election_stage_a_elected_for=600,
            ),
            [Key() for _ in range(EXPECTED_VALIDATOR_COUNT)],
        )


def test_validator_economics_without_stage_a_rejects_bootstrap_lifetime_override(tmp_path):
    install = Install(BUILD_DIR, REPO)
    config = NetworkConfig(
        validator_economics_profile=True,
        bootstrap_validator_set_valid_for=1200,
    )
    with pytest.raises(ValueError, match="ordinary local or Stage A profile"):
        create_zerostate(
            install, tmp_path, config, [Key() for _ in range(EXPECTED_VALIDATOR_COUNT)]
        )


def test_validator_election_experiment_faucet_override_is_stage_a_only(tmp_path):
    install = Install(BUILD_DIR, REPO)
    keys = [Key() for _ in range(EXPECTED_VALIDATOR_COUNT)]
    experiment_balance = EXPECTED_VALIDATOR_EXPERIMENT_FAUCET_TOS * NANOTOS_PER_TOS

    with pytest.raises(ValueError, match="requires the Stage A profile"):
        create_zerostate(
            install,
            tmp_path / "not-stage-a",
            NetworkConfig(
                validator_economics_profile=True,
                validator_election_experiment_faucet_balance_nanotos=(experiment_balance),
            ),
            keys,
        )
    with pytest.raises(ValueError, match="faucet balance must be positive"):
        create_zerostate(
            install,
            tmp_path / "invalid-balance",
            NetworkConfig(
                validator_economics_profile=True,
                validator_election_stage_a_profile=True,
                validator_election_experiment_faucet_balance_nanotos=0,
            ),
            keys,
        )

    experiment_dir = tmp_path / "experiment"
    experiment_dir.mkdir()
    zerostate = create_zerostate(
        install,
        experiment_dir,
        NetworkConfig(
            shard_validators=EXPECTED_VALIDATOR_COUNT,
            validator_economics_profile=True,
            validator_election_stage_a_profile=True,
            validator_election_experiment_faucet_balance_nanotos=experiment_balance,
        ),
        keys,
    )
    state = _load_masterchain_state(zerostate.masterchain.file)

    assert state.total_balance.tomis == experiment_balance + 1_000 * NANOTOS_PER_TOS
    assert _positive_account_balances(state) == [
        500 * NANOTOS_PER_TOS,
        500 * NANOTOS_PER_TOS,
        experiment_balance,
    ]


def test_validator_economics_profile_matches_bootstrap_spec(tmp_path):
    install = Install(BUILD_DIR, REPO)
    keys = [Key() for _ in range(EXPECTED_VALIDATOR_COUNT)]
    config = NetworkConfig(
        shard_validators=EXPECTED_VALIDATOR_COUNT,
        validator_economics_profile=True,
    )
    zerostate = create_zerostate(install, tmp_path, config, keys)
    state = _load_masterchain_state(zerostate.masterchain.file)

    assert state.total_balance.tomis == EXPECTED_VALIDATOR_GENESIS_SUPPLY_TOS * NANOTOS_PER_TOS
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

    # Every wallet contract compares the signed global_id against
    # ConfigParam 19 and fails closed when it is absent, so no configuration
    # without it may ever be installed (mandatory) and changing it must take
    # a critical-proposal vote.
    param9 = _config(state, 9, ConfigParam9)
    assert 19 in param9.mandatory_params
    assert 19 in param10.critical_params
    assert 19 in state.custom.config.config

    param14 = _config(state, 14, ConfigParam14)
    assert param14.masterchain_block_fee == 39_496_630
    assert param14.basechain_block_fee == 23_233_312

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
    ) == (21, 21, 4)

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
    ) == (250, 250, 1000, 21)

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


def _write_pq_manifest(directory):
    import re

    directory.chmod(0o700)
    records = []
    for index in range(4):
        seed = hashlib.sha256(f"disposable-genesis-{index}".encode()).hexdigest()
        proc = subprocess.run(
            [
                str(BUILD_DIR / "crypto/pq/tos-pq-consensus-key"),
                "import",
                str(directory / f"pq-{index}.seed"),
            ],
            input=seed + "\n",
            text=True,
            capture_output=True,
            check=True,
        )
        public = bytes.fromhex(re.search(r"^public\s+([0-9a-f]+)$", proc.stdout, re.M)[1])
        key_id = bytes.fromhex(re.search(r"^key_id\s+([0-9a-f]+)$", proc.stdout, re.M)[1])
        controller = hashlib.sha256(f"controller-{index}".encode()).digest()
        adnl = hashlib.sha256(f"adnl-{index}".encode()).digest()
        records.append((controller, adnl, public, key_id))
    (directory / "validator-pq.pub").write_bytes(b"".join(c + a + p for c, a, p, _ in records))
    return records


def test_canonical_genesis_sets_a_stake_proportional_punishment_schedule(tmp_path):
    """Without ConfigParam 40 the punishment path falls back to a flat fine with
    no proportional component, so a validator's required own funds stop scaling
    with the stake it controls. Pooled-stake contracts read this parameter to
    size that requirement, so genesis must ship a real schedule."""
    _write_pq_manifest(tmp_path)
    command = _create_state_command(REPO / "crypto/smartcont/gen-zerostate.fif")
    subprocess.run(
        command,
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
        env=_mainnet_genesis_env(),
    )

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
    keys = _write_pq_manifest(tmp_path)

    command = _create_state_command(REPO / "crypto/smartcont/gen-zerostate.fif")
    subprocess.run(
        command,
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
        env=_mainnet_genesis_env(),
    )

    state = _load_masterchain_state(tmp_path / "zerostate.boc")
    assert state.gen_utime == EXPECTED_MAINNET_GENESIS_UTIME
    assert state.total_balance.tomis == EXPECTED_VALIDATOR_GENESIS_SUPPLY_TOS * NANOTOS_PER_TOS
    assert _positive_account_balances(state) == [
        500 * NANOTOS_PER_TOS,
        500 * NANOTOS_PER_TOS,
        100_000 * NANOTOS_PER_TOS,
    ]
    assert (
        _config(state, 2, ConfigParam2).minter_addr == _config(state, 0, ConfigParam0).config_addr
    )
    assert _config(state, 4, ConfigParam4).dns_root_addr_hex == EXPECTED_DNS_ROOT_ID
    assert 3 not in state.custom.config.config
    canonical_rewards = _config(state, 14, ConfigParam14)
    assert canonical_rewards.masterchain_block_fee == 39_496_630
    assert canonical_rewards.basechain_block_fee == 23_233_312
    assert _config(state, 16, ConfigParam16).min_validators == 4
    assert _config(state, 17, ConfigParam17).max_stake_factor == 1 << 16
    canonical_catchain = _config(state, 28, ConfigParam28)
    assert (
        canonical_catchain.mc_catchain_lifetime,
        canonical_catchain.shard_catchain_lifetime,
        canonical_catchain.shard_validators_lifetime,
        canonical_catchain.shard_validators_num,
    ) == (250, 250, 1000, 21)
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "genesis_config34", REPO / "scripts/x02_config34_proof.py"
    )
    decoder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(decoder)
    decode_validator_set = decoder.decode_validator_set

    assert _config(state, 8, ConfigParam8).version == 16
    validator_set = decode_validator_set(state.custom.config.config[34].copy().to_cell())
    assert validator_set["total"] == EXPECTED_VALIDATOR_COUNT
    for actual, (controller, adnl, public, key_id) in zip(validator_set["validators"], keys):
        assert actual["public_key_sha256"] == hashlib.sha256(public).hexdigest()
        assert actual["algorithm_id"] == 1
        assert actual["controller_id_hex"] == controller.hex()
        assert actual["adnl_id_hex"] == adnl.hex()
        assert actual["consensus_key_id_hex"] == key_id.hex()
        assert actual["weight"] == 17
    assert 47 in state.custom.config.config
    admitted = state.custom.config.config[47].copy().load_dict(256)
    # Independently compile the same admission artifact and compare its code hash.
    probe = tmp_path / "controller-hash.fif"
    probe.write_text('"PQ.fif" include "auto/validator-controller-v1-code.fif" include hashu . cr')
    compiled = subprocess.run(
        [
            str(BUILD_DIR / "crypto/fift"),
            "-I",
            str(REPO / "crypto/fift/lib"),
            "-I",
            str(BUILD_DIR / "crypto/smartcont"),
            "-s",
            str(probe),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert set(admitted) == {int(compiled.stdout.strip())}
    for parameter in (8, 47):
        assert parameter in _config(state, 9, ConfigParam9).mandatory_params
        assert parameter in _config(state, 10, ConfigParam10).critical_params

    (tmp_path / "validator-pq.pub").write_bytes(b"".join(c + a + p for c, a, p, _ in keys[:3]))
    failed = subprocess.run(
        command,
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        env=_mainnet_genesis_env(),
    )
    assert failed.returncode != 0
    assert "exactly four 1376-byte records" in failed.stderr + failed.stdout

    (tmp_path / "validator-pq.pub").write_bytes((keys[0][0] + keys[0][1] + keys[0][2]) * 4)
    failed = subprocess.run(
        command,
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        env=_mainnet_genesis_env(),
    )
    assert failed.returncode != 0
    assert "genesis PQ identities, public keys and ADNL IDs must be unique" in (
        failed.stderr + failed.stdout
    )


def test_canonical_genesis_rejects_a_different_timestamp(tmp_path):
    _write_pq_manifest(tmp_path)
    env = _mainnet_genesis_env()
    env["SOURCE_DATE_EPOCH"] = str(EXPECTED_MAINNET_GENESIS_UTIME + 1)
    failed = subprocess.run(
        _create_state_command(REPO / "crypto/smartcont/gen-zerostate.fif"),
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert failed.returncode != 0
    assert "SOURCE_DATE_EPOCH must be 1789434000" in (failed.stderr + failed.stdout)


def test_validator_rewards_are_the_only_native_tos_issuance_path(tmp_path):
    _write_pq_manifest(tmp_path)
    command = _create_state_command(REPO / "crypto/smartcont/gen-zerostate.fif")
    subprocess.run(
        command,
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
        env=_mainnet_genesis_env(),
    )

    state = _load_masterchain_state(tmp_path / "zerostate.boc")
    rewards = _config(state, 14, ConfigParam14)
    assert rewards.masterchain_block_fee > 0
    assert rewards.basechain_block_fee > 0
    assert all(param not in state.custom.config.config for param in (90, 91, 92, 93))

    collator = (REPO / "validator/impl/collator.cpp").read_text()
    validator = (REPO / "validator/impl/validate-query.cpp").read_text()
    assert "value_flow_.created = block::CurrencyCollection{masterchain_create_fee_}" in collator
    assert "basechain_create_fee_ >> tos::shard_prefix_length(shard_)" in collator
    assert "if (s == 1 && curr_id)" in collator
    assert "if (s == 1 && curr_id)" in validator
    assert "value_flow_.minted != to_mint" in validator
    assert "native TOS may only be issued through validator block rewards" in validator


def test_canonical_genesis_makes_global_id_mandatory_and_critical(tmp_path):
    """GLOBALID (used by every wallet's anti-replay check) throws when ConfigParam 19
    is absent, so the canonical genesis must forbid installing a configuration
    without it and must require a critical vote to change it."""
    _write_pq_manifest(tmp_path)
    command = _create_state_command(REPO / "crypto/smartcont/gen-zerostate.fif")
    subprocess.run(
        command,
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
        env=_mainnet_genesis_env(),
    )

    state = _load_masterchain_state(tmp_path / "zerostate.boc")
    assert 19 in state.custom.config.config
    assert 19 in _config(state, 9, ConfigParam9).mandatory_params
    assert 19 in _config(state, 10, ConfigParam10).critical_params


def test_legacy_classical_key_helper_defaults_to_four_keys(tmp_path):
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


@pytest.mark.parametrize("field", [0, 1, 2])
def test_canonical_pq_genesis_rejects_individual_identity_reuse(tmp_path, field):
    keys = _write_pq_manifest(tmp_path)
    records = [list(row[:3]) for row in keys]
    records[1][field] = records[0][field]
    (tmp_path / "validator-pq.pub").write_bytes(b"".join(b"".join(row) for row in records))
    failed = subprocess.run(
        _create_state_command(REPO / "crypto/smartcont/gen-zerostate.fif"),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=_mainnet_genesis_env(),
    )
    assert failed.returncode != 0
    assert (
        "genesis PQ identities, public keys and ADNL IDs must be unique"
        in failed.stderr + failed.stdout
    )


def test_canonical_pq_genesis_rejects_classical_manifest(tmp_path):
    classic = b"".join(Key().public_key.key for _ in range(4))
    (tmp_path / "validator-keys.pub").write_bytes(classic)
    command = _create_state_command(REPO / "crypto/smartcont/gen-zerostate.fif")
    missing = subprocess.run(
        command, cwd=tmp_path, capture_output=True, text=True, env=_mainnet_genesis_env()
    )
    assert missing.returncode != 0
    assert "validator-pq.pub" in missing.stderr + missing.stdout
    (tmp_path / "validator-pq.pub").write_bytes(classic)
    short = subprocess.run(
        command, cwd=tmp_path, capture_output=True, text=True, env=_mainnet_genesis_env()
    )
    assert short.returncode != 0
    assert "exactly four 1376-byte records" in short.stderr + short.stdout


@pytest.mark.parametrize("version", [0, 14, 15])
def test_pq_genesis_rejects_legacy_vm_version(tmp_path, version):
    pq = PqInitialValidator(bytes([1]) * 32, bytes([2]) * 32, bytes([3]) * 1312, bytes([4]) * 32)
    with pytest.raises(ValueError, match="PQ genesis requires global version 16"):
        create_zerostate(
            Install(BUILD_DIR, REPO), tmp_path, NetworkConfig(global_version=version), [], [pq]
        )


def test_public_pq_manifest_packer_roundtrip_and_rejections(tmp_path):
    keys = _write_pq_manifest(tmp_path)
    records = [
        dict(controller_id=c.hex(), adnl_id=a.hex(), public_key=p.hex()) for c, a, p, _ in keys
    ]
    source = tmp_path / "operators.json"
    source.write_text(json.dumps(records))
    dest = tmp_path / "packed.pub"
    import sys

    command = [
        sys.executable,
        str(REPO / "scripts/prepare-pq-genesis-manifest.py"),
        str(source),
        str(dest),
    ]
    subprocess.run(command, check=True, capture_output=True)
    assert dest.read_bytes() == (tmp_path / "validator-pq.pub").read_bytes()
    assert subprocess.run(command, capture_output=True).returncode != 0
    dest.unlink()
    records[1]["controller_id"] = records[0]["controller_id"]
    source.write_text(json.dumps(records))
    assert subprocess.run(command, capture_output=True).returncode != 0
    assert not dest.exists()


def test_canonical_genesis_auth_policy_profile_is_explicit(tmp_path):
    network_tag = bytes(range(32))
    baseline_wc = None
    baseline_mc = None
    for label, enabled, admission in (("default16", False, False), ("candidate17", True, False),
                                       ("admission18", True, True)):
        directory = tmp_path / label
        directory.mkdir()
        _write_pq_manifest(directory)
        (directory / "main-wallet.pk").write_bytes(b"\x53" * 32)
        wrapper = directory / "profile.fif"
        wrapper.write_text(
            (f"0x{network_tag.hex()} constant v5r2-network-tag\n" if enabled else "")
            + ("true constant v5r2-admission-candidate\n" if admission else "")
            + f'"{REPO / "crypto/smartcont/gen-zerostate.fif"}" include\n'
        )
        subprocess.run(
            _create_state_command(wrapper),
            cwd=directory,
            check=True,
            capture_output=True,
            env=_mainnet_genesis_env(),
        )
        state = _load_masterchain_state(directory / "zerostate.boc")
        cfg = state.custom.config.config
        assert ConfigParam8.deserialize(cfg[8].copy()).version == (18 if admission else 17 if enabled else 16)
        mc_gas = ConfigParam20.deserialize(cfg[20].copy())
        wc_gas = ConfigParam21.deserialize(cfg[21].copy())
        assert mc_gas.other.gas_credit == 10000
        assert wc_gas.other.gas_credit == (20000 if admission else 10000)
        wc_fields = dict(vars(wc_gas.other))
        wc_fields.pop("gas_credit")
        wc_fields.update(flat_gas_limit=wc_gas.flat_gas_limit, flat_gas_price=wc_gas.flat_gas_price)
        mc_fields = dict(vars(mc_gas.other))
        mc_fields.update(flat_gas_limit=mc_gas.flat_gas_limit, flat_gas_price=mc_gas.flat_gas_price)
        if baseline_wc is None:
            baseline_wc, baseline_mc = wc_fields, mc_fields
        assert wc_fields == baseline_wc, "candidate changed another basechain gas field"
        assert mc_fields == baseline_mc, "candidate changed a masterchain gas field"
        assert (48 in cfg) == enabled
        assert (48 in ConfigParam9.deserialize(cfg[9].copy()).mandatory_params) == enabled
        assert (48 in ConfigParam10.deserialize(cfg[10].copy()).critical_params) == enabled
        if enabled:
            record = cfg[48].copy()
            assert record.load_uint(8) == 0xA1
            assert record.load_bytes(32) == network_tag
            assert record.load_uint(64) == record.load_uint(16) == 0
            assert record.load_dict(8) is None
            assert (
                record.load_bytes(32).hex()
                == "5e4380aedc95f8cb72de55f7506de0269b47c03ad1d1ed0e5184c332544262c0"
            )
            assert record.remaining_bits == record.remaining_refs == 0


def _generate_admission_candidate(directory, source):
    directory.mkdir()
    _write_pq_manifest(directory)
    (directory / "main-wallet.pk").write_bytes(b"\x53" * 32)
    template = directory / "candidate-template.fif"
    template.write_text(source)
    wrapper = directory / "candidate.fif"
    wrapper.write_text(
        f"0x{bytes(range(32)).hex()} constant v5r2-network-tag\n"
        "true constant v5r2-admission-candidate\n"
        f'"{template}" include\n'
    )
    result = subprocess.run(_create_state_command(wrapper), cwd=directory, capture_output=True,
                            env=_mainnet_genesis_env())
    (directory / "generation.stdout.raw").write_bytes(result.stdout)
    (directory / "generation.stderr.raw").write_bytes(result.stderr)
    result.check_returncode()
    return _load_masterchain_state(directory / "zerostate.boc").custom.config.config


def _assert_admission_candidate(cfg):
    assert ConfigParam8.deserialize(cfg[8].copy()).version == 18, "candidate version"
    assert ConfigParam21.deserialize(cfg[21].copy()).other.gas_credit == 20000, "candidate credit"
    assert ConfigParam20.deserialize(cfg[20].copy()).other.gas_credit == 10000, "masterchain credit"


@pytest.mark.parametrize("boundary", ["version", "credit"])
def test_admission_candidate_parameter_mutation_is_detected(tmp_path, boundary):
    source = (REPO / "crypto/smartcont/gen-zerostate.fif").read_text()
    if boundary == "version":
        anchor, replacement = "18 capCreateStats", "17 capCreateStats"
    else:
        anchor, replacement = "30 *M 30 *M 20000 60 *M", "30 *M 30 *M 10000 60 *M"
    assert source.count(anchor) == 1
    mutated = _generate_admission_candidate(tmp_path / "mutated", source.replace(anchor, replacement))
    with pytest.raises(AssertionError, match="candidate " + boundary):
        _assert_admission_candidate(mutated)
    _assert_admission_candidate(_generate_admission_candidate(tmp_path / "restored", source))


def test_admission_candidate_requires_namespace_before_generating_keys(tmp_path):
    wrapper = tmp_path / "missing-tag.fif"
    wrapper.write_text("true constant v5r2-admission-candidate\n"
                       f'"{REPO / "crypto/smartcont/gen-zerostate.fif"}" include\n')
    result = subprocess.run(_create_state_command(wrapper), cwd=tmp_path, capture_output=True,
                            env=_mainnet_genesis_env())
    assert result.returncode != 0
    assert b"V5R2 admission candidate requires an explicit AUTH network tag" in result.stderr
    assert not (tmp_path / "main-wallet.pk").exists()
    (tmp_path / "guarded.stderr.raw").write_bytes(result.stderr)

    # Removing the early guard must make this boundary check fail, even if a
    # later configuration validation eventually rejects the missing policy.
    source = (REPO / "crypto/smartcont/gen-zerostate.fif").read_text()
    guard = '  def? v5r2-network-tag not abort"V5R2 admission candidate requires an explicit AUTH network tag"'
    assert source.count(guard) == 1
    mutated = tmp_path / "without-guard.fif"
    mutated.write_text(source.replace(guard, "  // Controlled deletion of early namespace validation."))
    wrapper.write_text("true constant v5r2-admission-candidate\n" f'"{mutated}" include\n')
    result = subprocess.run(_create_state_command(wrapper), cwd=tmp_path, capture_output=True,
                            env=_mainnet_genesis_env())
    (tmp_path / "unguarded.stderr.raw").write_bytes(result.stderr)
    with pytest.raises(AssertionError, match="early namespace guard"):
        assert b"V5R2 admission candidate requires an explicit AUTH network tag" in result.stderr, "early namespace guard"
    assert (tmp_path / "main-wallet.pk").exists(), "unguarded candidate reached custody generation"


def test_admission_candidate_localnet_matches_generated_canonical_gas_fields(tmp_path, monkeypatch):
    canonical = _generate_admission_candidate(tmp_path / "canonical",
        (REPO / "crypto/smartcont/gen-zerostate.fif").read_text())
    config = NetworkConfig(global_version=18, auth_network_tag=bytes(range(32)),
                      v5r2_admission_candidate=True, deployment_fee_schedule=True,
                      genesis_time=EXPECTED_MAINNET_GENESIS_UTIME, genesis_wallet_seed=b"\x53" * 32)

    def generate_and_compare(local_dir):
        local_dir.mkdir()
        local = create_zerostate(Install(BUILD_DIR, REPO), local_dir, config, [Key()])
        cfg = _load_masterchain_state(local.masterchain.file).custom.config.config
        _assert_admission_candidate(cfg)
        for param in (20, 21):
            assert cfg[param].to_cell().hash == canonical[param].to_cell().hash, f"ConfigParam {param} differs"

    generate_and_compare(tmp_path / "local")
    original = zerostate_module.fee_schedule_for

    def wrong_credit(cfg):
        schedule = original(cfg)
        assert " 20000 " in schedule["gas_prices"]
        schedule["gas_prices"] = schedule["gas_prices"].replace(" 20000 ", " 10000 ")
        return schedule

    with monkeypatch.context() as context:
        context.setattr(zerostate_module, "fee_schedule_for", wrong_credit)
        with pytest.raises(AssertionError, match="candidate credit"):
            generate_and_compare(tmp_path / "mutated-credit")
    generate_and_compare(tmp_path / "restored")


@pytest.mark.parametrize("change", [{"global_version": 17}, {"global_version": 19},
    {"deployment_fee_schedule": False}, {"auth_network_tag": None}, {"v5r2_admission_candidate": "yes"}])
def test_admission_candidate_localnet_rejects_incompatible_profile(tmp_path, change):
    config = NetworkConfig(global_version=18, auth_network_tag=bytes(range(32)),
        v5r2_admission_candidate=True, deployment_fee_schedule=True)
    with pytest.raises(ValueError, match="V5R2 admission candidate"):
        create_zerostate(Install(BUILD_DIR, REPO), tmp_path, replace(config, **change), [Key()])
    assert not (tmp_path / "main-wallet.pk").exists()


def test_admission_candidate_localnet_validation_deletion_is_detected(tmp_path, monkeypatch):
    config = NetworkConfig(global_version=17, auth_network_tag=bytes(range(32)),
        v5r2_admission_candidate=True, deployment_fee_schedule=True,
        genesis_time=EXPECTED_MAINNET_GENESIS_UTIME, genesis_wallet_seed=b"\x53" * 32)

    def require_rejection(directory):
        directory.mkdir()
        try:
            create_zerostate(Install(BUILD_DIR, REPO), directory, config, [Key()])
        except ValueError as error:
            assert "V5R2 admission candidate" in str(error)
            assert not (directory / "main-wallet.pk").exists()
            return
        raise AssertionError("incompatible candidate reached genesis generation")

    require_rejection(tmp_path / "baseline")
    original = zerostate_module.fee_schedule_for
    with monkeypatch.context() as context:
        context.setattr(zerostate_module, "fee_schedule_for",
            lambda cfg: original(replace(cfg, v5r2_admission_candidate=False)))
        with pytest.raises(AssertionError, match="incompatible candidate reached genesis generation"):
            require_rejection(tmp_path / "mutated")
    require_rejection(tmp_path / "restored")
