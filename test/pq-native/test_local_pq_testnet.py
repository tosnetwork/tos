"""Local deployment refuses silent getters and a different validator set."""

import asyncio
import copy
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "scripts/local_pq_testnet.py"
spec = importlib.util.spec_from_file_location(
    "local_pq", os.environ.get("LOCAL_PQ_TEST_SOURCE", SOURCE)
)
local = importlib.util.module_from_spec(spec)
spec.loader.exec_module(local)


def identities():
    ports = [{"validator_id": f"{i:064x}", "pq_key_id": f"{i + 10:064x}"} for i in range(1, 5)]
    decoded = {
        "total": 4,
        "main": 4,
        "validators": [
            {"controller_id_hex": n["validator_id"], "consensus_key_id_hex": n["pq_key_id"]}
            for n in ports
        ],
    }
    return ports, decoded


def test_exact_four_identities():
    ports, decoded = identities()
    local.validate_pq_set(decoded, ports)


@pytest.mark.parametrize(
    "change", ["total", "main", "missing", "foreign-id", "wrong-key", "duplicate"]
)
def test_wrong_live_set_refused(change):
    ports, decoded = identities()
    decoded = copy.deepcopy(decoded)
    if change in ("total", "main"):
        decoded[change] = 3
    elif change == "missing":
        decoded["validators"].pop()
    elif change == "foreign-id":
        decoded["validators"][0]["controller_id_hex"] = "ab" * 32
    elif change == "wrong-key":
        decoded["validators"][0]["consensus_key_id_hex"] = "cd" * 32
    else:
        ports[0] = ports[1]
    with pytest.raises(RuntimeError, match="four provisioned PQ identities"):
        local.validate_pq_set(decoded, ports)


def test_same_height_different_root_is_not_same_block():
    block = dict(workchain=-1, shard="-9223372036854775808", seqno=12, root_hash="a", file_hash="b")
    assert local.block_id(block) != local.block_id({**block, "root_hash": "c"})


@pytest.mark.parametrize("output,exit_code", [("", 0), ("result: []", 0), ("result: [ 50 ]", 1)])
def test_silent_or_failed_getter_refused(monkeypatch, output, exit_code):
    monkeypatch.setattr(
        local.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            stdout=output, stderr="native failed", returncode=exit_code
        ),
    )
    with pytest.raises(RuntimeError, match="get-method"):
        local.get_method(Path("/build"), Path("/data"), "0:" + "aa" * 32, "reserve_floor")


@pytest.mark.parametrize(
    "reserve,backed,passes",
    [(50_000_000_000, -1, True), (49_000_000_000, -1, False), (50_000_000_000, 0, False)],
)
def test_actual_pool_state_required(monkeypatch, reserve, backed, passes):
    monkeypatch.setattr(
        local,
        "get_method",
        lambda build, data, address, name: {"reserve_floor": reserve, "backed": backed}[name],
    )
    args = SimpleNamespace(build=Path("/build"), data=Path("/data"))
    pool = {"address": "0:" + "ab" * 32, "reserve_floor_nanotos": "50000000000"}
    if passes:
        assert asyncio.run(local.pool_methods(args, pool))["backed"] == -1
    else:
        with pytest.raises(RuntimeError, match="pool state differs"):
            asyncio.run(local.pool_methods(args, pool))


def test_planned_roles_and_disjoint_ports(tmp_path):
    plan = local.topology(tmp_path)
    assert [n["role"] for n in plan["nodes"]] == ["validator"] * 4 + ["observer"] * 2
    assert [n["idx"] for n in plan["nodes"] if n["consensus_member"]] == [1, 2, 3, 4]
    ports = [plan["dht_port"]]
    for node in plan["nodes"]:
        ports.extend(
            node[name]
            for name in ("validator_port", "liteserver_port", "console_port", "json_rpc_port")
        )
    assert len(ports) == len(set(ports))
    assert plan["lite_client"]["listen_ports"] == []
    assert plan["lite_client"]["upstream_node_ids"] == [5, 6]


def test_plan_does_not_invoke_native_or_network(tmp_path, monkeypatch):
    def refused(*args, **kwargs):
        raise AssertionError("plan must not execute a binary or query a node")

    monkeypatch.setattr(local.subprocess, "run", refused)
    monkeypatch.setattr(local, "rpc", refused)
    local.write_plan(tmp_path)
    assert not (tmp_path / "testnet").exists()
    assert (tmp_path / "preparation/topology.json").is_file()


def retained_network(tmp_path):
    import json

    (tmp_path / "testnet/node1/static").mkdir(parents=True)
    (tmp_path / "testnet/node1/static/genesis").write_bytes(b"same Genesis")
    (tmp_path / "configs").mkdir()
    template = {
        "@type": "engine.validator.config",
        "validators": [{"id": "old"}],
        "fullnode": "old",
        "adnl": [],
        "dht": [],
        "liteservers": [],
        "control": [],
        "extraconfig": {"pq_consensus": {"consensus_key_file": "old-seed"}},
    }
    (tmp_path / "testnet/node1/config.json").write_text(json.dumps(template))
    (tmp_path / "tos-global.json").write_text(
        json.dumps({"liteservers": [], "validator": {"zero_state": "unchanged"}})
    )
    (tmp_path / "testnet-ports.json").write_text(
        json.dumps({"nodes": [{"idx": i} for i in range(1, 5)]})
    )
    (tmp_path / "network.json").write_text(
        json.dumps({"validators": 4, "zerostate_root": "unchanged"})
    )


def test_offline_observers_have_no_consensus_credentials(tmp_path, monkeypatch):
    import base64
    import hashlib
    import json

    from nacl.signing import SigningKey

    retained_network(tmp_path)

    def refused(*args, **kwargs):
        raise AssertionError("observer preparation must not run native tools")

    monkeypatch.setattr(local.subprocess, "run", refused)
    monkeypatch.setattr(local, "rpc", refused)
    local.prepare_observers(tmp_path)
    fullnode_ids = []
    for idx in (5, 6):
        root = tmp_path / "testnet" / f"node{idx}"
        config = json.loads((root / "config.json").read_text())
        assert config["validators"] == []
        assert "pq_consensus" not in config["extraconfig"]
        assert not (root / "pq-consensus.seed").exists()
        assert (root / "static/genesis").read_bytes() == b"same Genesis"
        fullnode_ids.append(config["fullnode"])
        key_id = base64.b64decode(config["fullnode"])
        path = root / "keyring" / key_id.hex().upper()
        key = SigningKey(path.read_bytes()[4:])
        assert hashlib.sha256(b"\xc6\xb4\x13\x48" + bytes(key.verify_key)).digest() == key_id
        assert path.stat().st_mode & 0o777 == 0o600
    assert len(set(fullnode_ids)) == 2
    global_config = json.loads((tmp_path / "tos-global.json").read_text())
    assert global_config["validator"]["zero_state"] == "unchanged"
    assert [
        server["port"]
        for server in json.loads((tmp_path / "configs/observers-lite.json").read_text())[
            "liteservers"
        ]
    ] == [2015, 2018]


def test_existing_observer_is_not_overwritten(tmp_path):
    retained_network(tmp_path)
    (tmp_path / "testnet/node5").mkdir()
    with pytest.raises(RuntimeError, match="already exists"):
        local.prepare_observers(tmp_path)


def test_plan_refuses_a_symlink_planted_where_it_writes(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    (tmp_path / "preparation").mkdir(mode=0o755)
    (tmp_path / "preparation" / "topology.json").symlink_to(victim)
    with pytest.raises(OSError):
        local.write_plan(tmp_path)
    assert victim.read_text() == "untouched"


def test_plan_refuses_a_preparation_directory_that_is_a_symlink(tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (tmp_path / "preparation").symlink_to(elsewhere)
    with pytest.raises(RuntimeError, match="symlink is refused"):
        local.write_plan(tmp_path)
    assert not any(elsewhere.iterdir())


def test_output_directory_in_a_shared_writable_parent_is_refused(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    with pytest.raises(RuntimeError, match="another user"):
        local.secure_output_dir(shared / "out")
    assert not (shared / "out").exists()


def test_output_directory_is_made_private(tmp_path):
    out = tmp_path / "out"
    out.mkdir(mode=0o755)
    assert local.secure_output_dir(out) == out
    assert out.stat().st_mode & 0o777 == 0o700


def test_json_is_written_with_the_requested_mode_whatever_the_umask(tmp_path):
    previous = os.umask(0o077)
    try:
        local.write_json(tmp_path / "status.json", {"ok": True}, 0o644)
    finally:
        os.umask(previous)
    assert (tmp_path / "status.json").stat().st_mode & 0o777 == 0o644
