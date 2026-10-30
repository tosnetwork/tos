"""Inspect real Genesis cells used by the native init-block join fixture."""

import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
import tostester.zerostate as zerostate_module
from pytosiq_core import ShardStateUnsplit
from pytosiq_core.boc.deserialize import Boc
from pytosiq_core.tlb.tlb import require
from tostester.install import Install
from tostester.pq_initial_validator import deterministic_pq_initial_validator_seed
from tostester.zerostate import NetworkConfig, PqInitialValidator, create_zerostate

REPO = Path(__file__).resolve().parents[4]
BUILD = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build"))
GENESIS_TIME = 1_789_427_711
LIFETIME = 3 * (1 << 17)
CONFIG = NetworkConfig(
    genesis_time=GENESIS_TIME,
    genesis_wallet_seed=bytes([0x63]) * 32,
    auth_network_tag=bytes([0x84]) * 32,
    bootstrap_validator_set_valid_for=LIFETIME,
    bootstrap_next_validator_set_since=GENESIS_TIME + 1,
)
VALIDATOR = PqInitialValidator(bytes([1]) * 32, bytes([2]) * 32, bytes([3]) * 1312, bytes([4]) * 32)


def generate(directory, config=CONFIG):
    directory.mkdir()
    directory.chmod(0o700)
    install = Install(BUILD, REPO)
    generated = subprocess.run(
        [install.pq_consensus_key_exe, "import", directory / "validator.seed"],
        input=deterministic_pq_initial_validator_seed(1).hex() + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    public = dict(line.split(maxsplit=1) for line in generated.stdout.splitlines() if " " in line)
    validator = replace(
        VALIDATOR,
        key_id=bytes.fromhex(public["key_id"]),
        public_key=bytes.fromhex(public["public"]),
    )
    genesis = create_zerostate(install, directory, config, [], [validator])
    root = Boc(genesis.masterchain.file.read_bytes()).deserialize()[0]
    state = require(ShardStateUnsplit.deserialize(root.begin_parse()))
    return require(require(state.custom).config.config)


def assert_next_set(config):
    assert 36 in config, "preloaded next PQ set is absent"
    for number, since in ((34, GENESIS_TIME), (36, GENESIS_TIME + 1)):
        header = config[number].copy()
        assert header.load_uint(8) == 0x12
        assert header.load_uint(32) == since
        assert header.load_uint(32) == since + LIFETIME
        assert header.load_uint(16) == header.load_uint(16) == 1
        assert header.load_uint(64) == 17
        entries = require(header.load_dict(16))
        assert sorted(entries) == [0]
        assert entries[0].load_uint(8) == 0xB3
        assert header.remaining_bits == header.remaining_refs == 0
    # Encoded validator descriptors and dictionary links stay identical; only the
    # set interval changes. The live fixture tests the configuration transaction.
    a, b = config[34].copy(), config[36].copy()
    a.load_uint(8 + 32 + 32)
    b.load_uint(8 + 32 + 32)
    assert a.to_cell().hash == b.to_cell().hash


def test_genesis_preloads_next_pq_set_and_keeps_default_absent(tmp_path):
    assert_next_set(generate(tmp_path / "next"))
    ordinary = generate(
        tmp_path / "ordinary", replace(CONFIG, bootstrap_next_validator_set_since=None)
    )
    assert 36 not in ordinary


def test_missing_next_set_mutation_is_detected(tmp_path, monkeypatch):
    template = zerostate_module._TEMPLATE
    assert template.count("{next_validator_set}") == 1
    with monkeypatch.context() as context:
        context.setattr(zerostate_module, "_TEMPLATE", template.replace("{next_validator_set}", ""))
        with pytest.raises(AssertionError, match="preloaded next PQ set is absent"):
            assert_next_set(generate(tmp_path / "mutated"))
    assert_next_set(generate(tmp_path / "restored"))


@pytest.mark.parametrize("global_id", [1, 2, 4])
def test_next_set_refuses_nonlocal_networks_before_fift(tmp_path, global_id):
    with pytest.raises(ValueError, match="requires fixed local PQ Genesis"):
        create_zerostate(
            Install(BUILD, REPO), tmp_path, replace(CONFIG, global_id=global_id), [], [VALIDATOR]
        )


@pytest.mark.parametrize("since", [True, GENESIS_TIME, GENESIS_TIME - 1, 1 << 32])
def test_next_set_refuses_invalid_start_before_fift(tmp_path, since):
    with pytest.raises(ValueError, match="after Genesis and fit uint32"):
        create_zerostate(
            Install(BUILD, REPO),
            tmp_path,
            replace(CONFIG, bootstrap_next_validator_set_since=since),
            [],
            [VALIDATOR],
        )


@pytest.mark.parametrize("since", [GENESIS_TIME + LIFETIME, (1 << 32) - 1])
def test_next_set_refuses_gaps_or_expiry_overflow(tmp_path, since):
    with pytest.raises(ValueError, match="overlap the initial set and fit uint32"):
        create_zerostate(
            Install(BUILD, REPO),
            tmp_path,
            replace(CONFIG, bootstrap_next_validator_set_since=since),
            [],
            [VALIDATOR],
        )
