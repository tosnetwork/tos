"""Capture must wait for basechain progress as well as the masterchain."""

import asyncio
import importlib.util
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

SOURCE = Path(__file__).resolve().parents[3] / "integration/node_store_native_reopen.py"
SPEC = importlib.util.spec_from_file_location("node_store_native_reopen", SOURCE)
assert SPEC is not None and SPEC.loader is not None
REOPEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REOPEN)


@pytest.fixture
def progress(monkeypatch):
    read = AsyncMock(return_value=9)
    monkeypatch.setattr(REOPEN, "read_shard_progress", read)
    return read


def block(seqno, workchain=-1):
    return SimpleNamespace(seqno=seqno, workchain=workchain)


@pytest.mark.asyncio
async def test_waits_for_nonzero_basechain_before_capture(progress):
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
    assert await REOPEN.wait_capture_frontier(client, ["native-console"]) is ready
    assert client.get_shards.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("shards", [[], [block(1, -1)], [block(1, 0), block(0, 0)]])
async def test_incomplete_shard_inventory_times_out(shards, progress):
    client = SimpleNamespace(
        get_masterchain_info=AsyncMock(return_value=SimpleNamespace(last=block(5))),
        get_shards=AsyncMock(return_value=SimpleNamespace(shards=shards)),
    )
    with pytest.raises(TimeoutError):
        await REOPEN.wait_capture_frontier(client, ["native-console"], timeout=0.01)
    client.get_shards.assert_awaited_once()


@pytest.mark.asyncio
async def test_missing_masterchain_tip_is_not_ready(progress):
    client = SimpleNamespace(
        get_masterchain_info=AsyncMock(return_value=SimpleNamespace(last=None)),
        get_shards=AsyncMock(),
    )
    with pytest.raises(TimeoutError):
        await REOPEN.wait_capture_frontier(client, ["native-console"], timeout=0.01)
    client.get_shards.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancellation_propagates(progress):
    client = SimpleNamespace(get_masterchain_info=AsyncMock(side_effect=asyncio.CancelledError))
    with pytest.raises(asyncio.CancelledError):
        await REOPEN.wait_capture_frontier(client, ["native-console"])


@pytest.mark.asyncio
async def test_masterchain_progress_does_not_hide_lagging_shard_client(progress):
    progress.return_value = 5
    client = SimpleNamespace(
        get_masterchain_info=AsyncMock(return_value=SimpleNamespace(last=block(9))),
        get_shards=AsyncMock(return_value=SimpleNamespace(shards=[block(2, 0)])),
    )
    with pytest.raises(TimeoutError):
        await REOPEN.wait_capture_frontier(client, ["native-console"], timeout=0.01)


@pytest.mark.asyncio
async def test_latches_candidate_until_shard_client_catches_up(progress):
    candidate = block(9)
    client = SimpleNamespace(
        get_masterchain_info=AsyncMock(return_value=SimpleNamespace(last=candidate)),
        get_shards=AsyncMock(return_value=SimpleNamespace(shards=[block(2, 0)])),
    )
    progress.side_effect = [5, 9]
    assert await REOPEN.wait_capture_frontier(client, ["native-console"]) is candidate
    client.get_masterchain_info.assert_awaited_once()
    assert progress.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "output,expected",
    [
        ("masterchainseqno\t\t10\nshardclientmasterchainseqno\t\t9\n", 9),
        ("shardclientmasterchainseqno 0\n", 0),
        ("masterchainseqno 10\n", None),
    ],
)
async def test_reads_native_console_text_and_command_arguments(tmp_path, output, expected):
    native_header = (
        SOURCE.parents[2] / "validator-engine-console/validator-engine-console-query.h"
    ).read_text()
    declaration = native_header.split("class GetStatsQuery :", 1)[1].split("class QuitQuery :", 1)[
        0
    ]
    command = re.search(r'return "([^"]+)";', declaration)
    assert command is not None
    expected_args = ["-c", command.group(1), "-t", "10"]
    script = tmp_path / "console.py"
    script.write_text(
        f"import sys\nassert sys.argv[1:] == {expected_args!r}\nsys.stdout.write({output!r})\n"
    )
    assert await REOPEN.read_shard_progress([sys.executable, str(script)]) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "output",
    [
        "shardclientmasterchainseqno -1\n",
        "shardclientmasterchainseqno invalid\n",
        "shardclientmasterchainseqno 9 extra\n",
        "shardclientmasterchainseqno 9\nshardclientmasterchainseqno 10\n",
    ],
)
async def test_rejects_malformed_native_progress(tmp_path, output):
    script = tmp_path / "console.py"
    script.write_text(f"print({output!r})\n")
    with pytest.raises(RuntimeError, match="malformed shard progress"):
        await REOPEN.read_shard_progress([sys.executable, str(script)])


@pytest.mark.asyncio
async def test_failed_native_console_does_not_report_progress(tmp_path):
    script = tmp_path / "console.py"
    script.write_text("print('shardclientmasterchainseqno 9')\nraise SystemExit(1)\n")
    with pytest.raises(RuntimeError, match="native get-stats failed"):
        await REOPEN.read_shard_progress([sys.executable, str(script)])


@pytest.mark.asyncio
async def test_cancellation_reaps_native_console(monkeypatch):
    process = SimpleNamespace(
        communicate=AsyncMock(side_effect=asyncio.CancelledError),
        returncode=None,
        kill=lambda: setattr(process, "returncode", -9),
        wait=AsyncMock(),
    )
    monkeypatch.setattr(REOPEN.asyncio, "create_subprocess_exec", AsyncMock(return_value=process))
    with pytest.raises(asyncio.CancelledError):
        await REOPEN.read_shard_progress(["native-console"])
    assert process.returncode == -9
    process.wait.assert_awaited_once()
