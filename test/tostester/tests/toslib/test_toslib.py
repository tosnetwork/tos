# pyright: reportPrivateUsage=false

import asyncio
import base64
import json
import threading
from pathlib import Path
from typing import cast

import pytest
from tonapi import tos_api
from tostester.install import Install

from tl import JSONSerializable
from toslib import ToslibClient, ToslibError

config: dict[str, JSONSerializable] = {
    "@type": "liteclient.config.global",
    "dht": {
        "@type": "dht.config.global",
        "k": 6,
        "a": 3,
        "static_nodes": {"@type": "dht.nodes", "nodes": []},
    },
    "liteservers": [
        {
            "ip": 123,
            "port": 123,
            "id": {"@type": "pub.ed25519", "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
        }
    ],
    "validator": {
        "@type": "validator.config.global",
        "zero_state": {
            "workchain": -1,
            "shard": -9223372036854775808,
            "seqno": 0,
            "root_hash": "F6OpKZKqvqeFp6CQmFomXNMfMj2EnaUSOXN+Mh+wVWk=",
            "file_hash": "XplPz01CXAps5qeSWUtxcyBfdAo5zVb1N979KLSKD24=",
        },
        "init_block": {
            "workchain": -1,
            "shard": -9223372036854775808,
            "seqno": 53986204,
            "root_hash": "uBltuZIIhio2c9EiCTI9cExzf2UhALUDXvUora+eIPg=",
            "file_hash": "JDx4DGuIs+BFo6qhLQnKZmBaYBlKTCeJrO0CgMzjqjQ=",
        },
        "hardforks": [
            {
                "workchain": -1,
                "shard": -9223372036854775808,
                "seqno": 8536841,
                "root_hash": "08Kpc9XxrMKC6BF/FeNHPS3MEL1/Vi/fQU/C9ELUrkc=",
                "file_hash": "t/9VBPODF7Zdh4nsnA49dprO69nQNMqYL+zk5bCjV/8=",
            }
        ],
    },
}


@pytest.fixture()
def toslib_client() -> ToslibClient:
    repo_root = Path(__file__).resolve().parents[4]
    install = Install(repo_root / "build", repo_root)

    return ToslibClient(
        config=tos_api.Liteclient_config_global.from_dict(config),
        toslib=install.toslibjson,
    )


@pytest.mark.asyncio
async def test_client_init(toslib_client: ToslibClient):
    await toslib_client.init()
    assert toslib_client._toslib_wrapper is not None
    await toslib_client.aclose()


@pytest.mark.asyncio
async def test_request(toslib_client: ToslibClient, monkeypatch: pytest.MonkeyPatch):
    h = "FsRgTb2HymFDIkV82C0aA0CPbdQKAVEzZBgVq5rjPNI="

    def mock_send(_, request_json: str) -> None:
        q: dict[str, JSONSerializable] = cast(dict[str, JSONSerializable], json.loads(request_json))
        assert q["@type"] == "blocks.getMasterchainInfo"
        res = {
            "@type": "blocks.masterchainInfo",
            "@extra": q["@extra"],
            "last": {
                "@type": "ton.blockIdExt",
                "workchain": -1,
                "shard": -9223372036854775808,
                "seqno": 1,
                "root_hash": "FsRgTb2HymFDIkV82C0aA0CPbdQKAVEzZBgVq5rjPNI=",
                "file_hash": "JKzTCHqi/c0or9o78mCwo1kigYXdagBQqQ4B2RLXFXY=",
            },
            "state_root_hash": "9DcJlDUeelZCBniBzWseg6KyjbjtkB8r6rX4x6BDT9o=",
            "init": {
                "@type": "ton.blockIdExt",
                "workchain": -1,
                "shard": 0,
                "seqno": 0,
                "root_hash": "4DWqijlo0wfJCuJUZeKkWOvENlS3DdL9z2DXkFQ1UtE=",
                "file_hash": "nv5sO4rQHhrT5PGLTs1f01AtWYuuI5tH41c87vU1zac=",
            },
        }
        monkeypatch.setattr(
            toslib_client._toslib_wrapper._toslib,  # pyright: ignore[reportOptionalMemberAccess]
            "client_json_receive",
            lambda *_: json.dumps(res).encode("utf-8"),  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
        )

    async with toslib_client:
        monkeypatch.setattr(
            toslib_client._toslib_wrapper._toslib,  # pyright: ignore[reportOptionalMemberAccess]
            "client_json_send",
            mock_send,  # pyright: ignore[reportUnknownArgumentType]
        )
        blk = await toslib_client.get_masterchain_info()
        assert blk.last is not None
        assert blk.last.workchain == -1
        assert blk.last.seqno == 1
        assert blk.last.root_hash == base64.b64decode(h)


@pytest.mark.asyncio
async def test_timeout(toslib_client: ToslibClient, monkeypatch: pytest.MonkeyPatch):
    async with toslib_client:
        monkeypatch.setattr(
            toslib_client._toslib_wrapper._toslib,  # pyright: ignore[reportOptionalMemberAccess]
            "client_json_send",
            lambda *_: None,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
        )
        with pytest.raises(TimeoutError):
            _ = await asyncio.wait_for(toslib_client.get_masterchain_info(), timeout=0.1)
        assert toslib_client._toslib_wrapper is not None
        assert not toslib_client._toslib_wrapper._futures


@pytest.mark.asyncio
async def test_error_response(toslib_client: ToslibClient, monkeypatch: pytest.MonkeyPatch):
    def mock_send(_, request_json: str) -> None:
        q: dict[str, JSONSerializable] = cast(dict[str, JSONSerializable], json.loads(request_json))
        assert q["@type"] == "blocks.getMasterchainInfo"
        res = {"@type": "error", "@extra": q["@extra"], "code": 504, "message": "Timeout"}
        monkeypatch.setattr(
            toslib_client._toslib_wrapper._toslib,  # pyright: ignore[reportOptionalMemberAccess]
            "client_json_receive",
            lambda *_: json.dumps(res).encode("utf-8"),  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
        )

    async with toslib_client:
        monkeypatch.setattr(
            toslib_client._toslib_wrapper._toslib,  # pyright: ignore[reportOptionalMemberAccess]
            "client_json_send",
            mock_send,  # pyright: ignore[reportUnknownArgumentType]
        )
        with pytest.raises(ToslibError) as e:
            _ = await toslib_client.get_masterchain_info()
            assert e.value.code == 504
            assert str(e.value) == "Timeout"


@pytest.mark.asyncio
async def test_read_results_error_cancels_inflight_requests(
    toslib_client: ToslibClient, monkeypatch: pytest.MonkeyPatch
):
    send_event = threading.Event()
    call_count = 0

    def mock_receive(*_) -> bytes:
        nonlocal call_count
        call_count += 1

        _ = send_event.wait()

        if call_count == 1:
            raise RuntimeError("Simulated error in _read_results")

        assert False

    def mock_send(*_) -> None:
        send_event.set()

    async with toslib_client:
        monkeypatch.setattr(
            toslib_client._toslib_wrapper._toslib,  # pyright: ignore[reportOptionalMemberAccess]
            "client_json_send",
            mock_send,  # pyright: ignore[reportUnknownArgumentType]
        )
        monkeypatch.setattr(
            toslib_client._toslib_wrapper._toslib,  # pyright: ignore[reportOptionalMemberAccess]
            "client_json_receive",
            mock_receive,  # pyright: ignore[reportUnknownArgumentType]
        )

        task1 = asyncio.create_task(toslib_client.get_masterchain_info())
        task2 = asyncio.create_task(toslib_client.get_masterchain_info())
        task3 = asyncio.create_task(toslib_client.get_masterchain_info())

        send_event.set()

        with pytest.raises(RuntimeError, match="Simulated error in _read_results"):
            await task1
        with pytest.raises(RuntimeError, match="Simulated error in _read_results"):
            await task2
        with pytest.raises(RuntimeError, match="Simulated error in _read_results"):
            await task3

        with pytest.raises(AssertionError, match="TonLib failed with state"):
            _ = await toslib_client.get_masterchain_info()


@pytest.mark.asyncio
async def test_aclose_cancels_requests(
    toslib_client: ToslibClient, monkeypatch: pytest.MonkeyPatch
):
    call_count = 0

    send_event = asyncio.Event()

    def mock_send(*_):
        nonlocal call_count
        call_count += 1
        if call_count == 3:
            send_event.set()

    async with toslib_client:
        monkeypatch.setattr(
            toslib_client._toslib_wrapper._toslib,  # pyright: ignore[reportOptionalMemberAccess]
            "client_json_send",
            mock_send,  # pyright: ignore[reportUnknownArgumentType]
        )

        task1 = asyncio.create_task(toslib_client.get_masterchain_info())
        task2 = asyncio.create_task(toslib_client.get_masterchain_info())
        task3 = asyncio.create_task(toslib_client.get_masterchain_info())

        _ = await send_event.wait()

    with pytest.raises(asyncio.CancelledError):
        await task1
    with pytest.raises(asyncio.CancelledError):
        await task2
    with pytest.raises(asyncio.CancelledError):
        await task3
