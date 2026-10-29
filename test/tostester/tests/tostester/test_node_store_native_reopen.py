"""Capture must wait for basechain progress as well as the masterchain."""

import asyncio
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

SOURCE = Path(__file__).resolve().parents[3] / "integration/node_store_native_reopen.py"
SPEC = importlib.util.spec_from_file_location("node_store_native_reopen", SOURCE)
assert SPEC is not None and SPEC.loader is not None
REOPEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REOPEN)


def console(processed=9):
    return SimpleNamespace(
        request=AsyncMock(
            return_value={
                "@type": "engine.validator.stats",
                "stats": [
                    {
                        "@type": "engine.validator.oneStat",
                        "key": "shardclientmasterchainseqno",
                        "value": str(processed),
                    }
                ],
            }
        )
    )


def block(seqno, workchain=-1):
    return SimpleNamespace(seqno=seqno, workchain=workchain)


@pytest.mark.asyncio
async def test_waits_for_nonzero_basechain_before_capture():
    early, ready = block(5), block(9)
    client = SimpleNamespace(
        get_masterchain_info=AsyncMock(
            side_effect=[SimpleNamespace(last=early), SimpleNamespace(last=ready)]
        ),
        get_shards=AsyncMock(
            side_effect=[
                SimpleNamespace(shards=[block(0, 0)]),
                SimpleNamespace(shards=[block(2, 0)]),
            ]
        ),
    )
    assert await REOPEN.wait_capture_frontier(client, console()) is ready
    assert client.get_shards.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("shards", [[], [block(1, -1)], [block(1, 0), block(0, 0)]])
async def test_incomplete_shard_inventory_times_out(shards):
    client = SimpleNamespace(
        get_masterchain_info=AsyncMock(return_value=SimpleNamespace(last=block(5))),
        get_shards=AsyncMock(return_value=SimpleNamespace(shards=shards)),
    )
    with pytest.raises(TimeoutError):
        await REOPEN.wait_capture_frontier(client, console(), timeout=0.01)
    client.get_shards.assert_awaited_once()


@pytest.mark.asyncio
async def test_missing_masterchain_tip_is_not_ready():
    client = SimpleNamespace(
        get_masterchain_info=AsyncMock(return_value=SimpleNamespace(last=None)),
        get_shards=AsyncMock(),
    )
    with pytest.raises(TimeoutError):
        await REOPEN.wait_capture_frontier(client, console(), timeout=0.01)
    client.get_shards.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancellation_propagates():
    client = SimpleNamespace(get_masterchain_info=AsyncMock(side_effect=asyncio.CancelledError))
    with pytest.raises(asyncio.CancelledError):
        await REOPEN.wait_capture_frontier(client, console())


@pytest.mark.asyncio
async def test_masterchain_progress_does_not_hide_lagging_shard_client():
    client = SimpleNamespace(
        get_masterchain_info=AsyncMock(return_value=SimpleNamespace(last=block(9))),
        get_shards=AsyncMock(return_value=SimpleNamespace(shards=[block(2, 0)])),
    )
    with pytest.raises(TimeoutError):
        await REOPEN.wait_capture_frontier(client, console(5), timeout=0.01)


@pytest.mark.asyncio
async def test_latches_candidate_until_shard_client_catches_up():
    candidate = block(9)
    client = SimpleNamespace(
        get_masterchain_info=AsyncMock(return_value=SimpleNamespace(last=candidate)),
        get_shards=AsyncMock(return_value=SimpleNamespace(shards=[block(2, 0)])),
    )
    control = console()
    control.request.side_effect = [console(5).request.return_value, console(9).request.return_value]
    assert await REOPEN.wait_capture_frontier(client, control) is candidate
    client.get_masterchain_info.assert_awaited_once()
    assert control.request.await_count == 2
