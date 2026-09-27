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
