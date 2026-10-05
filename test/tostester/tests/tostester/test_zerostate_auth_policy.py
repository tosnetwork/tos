"""Generate real zero states and inspect the mandatory V5R2 AUTH policy."""

import hashlib
import os
import subprocess
from pathlib import Path

import pytest
import tostester.zerostate as zerostate_module
from pytosiq_core import ShardStateUnsplit
from pytosiq_core.boc.deserialize import Boc
from pytosiq_core.tlb.config import ConfigParam8, ConfigParam9, ConfigParam10
from tostester.install import Install
from tostester.key import Key
from tostester.zerostate import NetworkConfig, create_zerostate

ROOT = Path(__file__).resolve().parents[4]
BUILD = Path(os.environ.get("TOS_BUILD_DIR", ROOT / "build"))
NETWORK = bytes(range(32))
PROFILE = b"TOS-AUTH-POLICY-v1;config=48;tag=a1;suite=1;retired=u16;sequence=u64;deadline=u32;network=bits256;monotonic"


def generate(path, version, tag):
    path.mkdir()
    z = create_zerostate(
        Install(BUILD, ROOT),
        path,
        NetworkConfig(
            global_version=version,
            auth_network_tag=tag,
            genesis_time=1789434000,
            genesis_wallet_seed=b"\x53" * 32,
        ),
        [Key()],
    )
    cell = Boc(z.masterchain.file.read_bytes()).deserialize()[0]
    return ShardStateUnsplit.deserialize(cell.begin_parse()).custom.config.config


def assert_initial_policy(cfg):
    assert ConfigParam8.deserialize(cfg[8].copy()).version == 17
    p = cfg[48].copy()
    assert p.load_uint(8) == 0xA1
    assert p.load_bytes(32) == NETWORK
    assert p.load_uint(64) == 0
    assert p.load_uint(16) == 0, "initial retirement bits must be empty"
    assert p.load_dict(8) is None
    assert p.load_bytes(32) == hashlib.sha256(PROFILE).digest()
    assert p.remaining_bits == p.remaining_refs == 0
    assert 48 in ConfigParam9.deserialize(cfg[9].copy()).mandatory_params
    assert 48 in ConfigParam10.deserialize(cfg[10].copy()).critical_params


def test_version17_genesis_installs_frozen_policy(tmp_path):
    assert_initial_policy(generate(tmp_path / "v17", 17, NETWORK))


def test_initial_retirement_value_mutation_is_detected(tmp_path, monkeypatch):
    override = tmp_path / "include"
    override.mkdir()
    source = (ROOT / "crypto/fift/lib/Config.fif").read_text()
    guard = "<b x{a1} s, swap 256 u, 0 64 u, 0 16 u, 0 1 u,"
    assert source.count(guard) == 1
    (override / "Config.fif").write_text(source.replace(guard, guard.replace("0 16 u,", "2 16 u,")))
    original = Install.fift_include_dirs
    with monkeypatch.context() as context:
        context.setattr(
            Install, "fift_include_dirs", property(lambda self: [override, *original.fget(self)])
        )
        cfg = generate(tmp_path / "mutated", 17, NETWORK)
        with pytest.raises(AssertionError, match="initial retirement bits"):
            assert_initial_policy(cfg)
    assert_initial_policy(generate(tmp_path / "restored", 17, NETWORK))


def test_missing_policy_mutation_is_rejected_by_node(tmp_path, monkeypatch):
    template = zerostate_module._TEMPLATE
    assert template.count("{auth_policy_param}") == 1
    with monkeypatch.context() as context:
        context.setattr(zerostate_module, "_TEMPLATE", template.replace("{auth_policy_param}", ""))
        with pytest.raises(subprocess.CalledProcessError):
            generate(tmp_path / "missing", 17, NETWORK)
        error = (tmp_path / "missing" / "generation.stderr.raw").read_text()
        assert "set_config_smc:invalid smart contract configuration data" in error, error[-3000:]
    assert_initial_policy(generate(tmp_path / "present", 17, NETWORK))


def test_version16_retains_legacy_genesis(tmp_path):
    cfg = generate(tmp_path / "v16", 16, None)
    assert ConfigParam8.deserialize(cfg[8].copy()).version == 16
    assert 48 not in cfg
    assert 48 not in ConfigParam9.deserialize(cfg[9].copy()).mandatory_params
    assert 48 not in ConfigParam10.deserialize(cfg[10].copy()).critical_params


@pytest.mark.parametrize(
    "version,tag",
    [(17, None), (17, b""), (17, b"x" * 31), (17, b"x" * 33), (17, "x" * 32), (16, NETWORK)],
)
def test_bad_namespace_refused_before_custody_files(tmp_path, version, tag):
    with pytest.raises(ValueError, match="AUTH network tag"):
        generate(tmp_path / "invalid", version, tag)
    assert not (tmp_path / "invalid" / "main-wallet.pk").exists()
