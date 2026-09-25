"""Narrow retry controls for the E03 fresh-basechain read boundary."""

import importlib.util
from pathlib import Path
import urllib.error

import pytest


def load_localnet():
    path = Path(__file__).with_name("localnet-jsonrpc.py")
    spec = importlib.util.spec_from_file_location("e03_localnet", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def http_error(body):
    error = urllib.error.HTTPError("http://127.0.0.1/jsonRPC", 500, "error", {}, None)
    error.json_rpc_body = body.encode()
    return error


@pytest.mark.asyncio
async def test_missing_fresh_basechain_block_is_retried(monkeypatch):
    localnet = load_localnet()
    calls = []

    def balance(*_, **__):
        calls.append(1)
        if len(calls) == 1:
            raise http_error("getAccountState: cannot load block (0,8000000000000000,0):abc : not in db")
        return 0

    monkeypatch.setattr(localnet, "rpc_balance_nano", balance)
    assert await localnet.wait_initial_balance_readable("unused", "wallet") == 0
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_unrelated_json_rpc_500_is_not_retried(monkeypatch):
    localnet = load_localnet()
    calls = []

    def balance(*_, **__):
        calls.append(1)
        raise http_error("getAccountState: malformed account proof")

    monkeypatch.setattr(localnet, "rpc_balance_nano", balance)
    with pytest.raises(urllib.error.HTTPError):
        await localnet.wait_initial_balance_readable("unused", "wallet")
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_missing_block_has_a_deadline(monkeypatch):
    localnet = load_localnet()
    monkeypatch.setattr(localnet, "rpc_balance_nano", lambda *_, **__: (_ for _ in ()).throw(
        http_error("cannot load block (0,8000000000000000,0):abc : not in db")))
    with pytest.raises(TimeoutError, match="not readable"):
        await localnet.wait_initial_balance_readable("unused", "wallet", timeout=0.001)


@pytest.mark.asyncio
@pytest.mark.parametrize("block", [
    "(0,8000000000000000,1)",
    "(-1,8000000000000000,0)",
])
async def test_other_missing_blocks_fail_immediately(monkeypatch, block):
    localnet = load_localnet()
    calls = []

    def balance(*_, **__):
        calls.append(1)
        raise http_error(f"getAccountState: cannot load block {block}:abc : not in db")

    monkeypatch.setattr(localnet, "rpc_balance_nano", balance)
    with pytest.raises(urllib.error.HTTPError):
        await localnet.wait_initial_balance_readable("unused", "wallet")
    assert len(calls) == 1
