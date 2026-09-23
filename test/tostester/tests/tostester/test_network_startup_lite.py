"""Startup retries the exact transport race introduced by ADNL fail-fast."""

import asyncio
from types import SimpleNamespace

from tosapi import toslib_api
from toslib.toslibjson import ToslibError
from tostester import network
from tostester.network import FullNode, _retryable_startup_lite_error


def _error(code: int, message: str) -> ToslibError:
    return ToslibError(toslib_api.Error(code=code, message=message))


def test_startup_recognizes_real_no_connection_status_without_widening_other_errors():
    assert _retryable_startup_lite_error(_error(500, "LITE_SERVER_NETWORKconn not ready"))
    assert _retryable_startup_lite_error(_error(500, "LITE_SERVER_NETWORK"))
    assert _retryable_startup_lite_error(
        _error(500, "LITE_SERVER_NETWORKtimeout for adnl query query")
    )
    assert not _retryable_startup_lite_error(_error(400, "LITE_SERVER_NETWORKconn not ready"))
    assert not _retryable_startup_lite_error(_error(500, "NO_LITE_SERVERS"))
    assert not _retryable_startup_lite_error(RuntimeError("LITE_SERVER_NETWORKconn not ready"))


def test_stopping_full_node_discards_closed_clients_before_restart(monkeypatch):
    """A restarted node must not return a closed cached engine-console handle."""
    closed = []

    class FakeLite:
        async def aclose(self):
            closed.append("lite")

    class FakeConsole:
        def close(self):
            closed.append("console")

    node = object.__new__(FullNode)
    node._client = FakeLite()
    node._engine_console = FakeConsole()
    node._blockchain_explorer = None
    node._Node__process = None
    asyncio.run(node.stop())
    assert closed == ["lite", "console"]
    assert node._client is None and node._engine_console is None

    fresh = object()
    monkeypatch.setattr(network, "EngineConsoleClient", lambda *args: fresh)
    node._network = SimpleNamespace(_toslib=object(), _event_loop=object())
    node._engine_console_addr = SimpleNamespace(address="127.0.0.1:1")
    node._engine_console_server_key = SimpleNamespace(public_key=None)
    node._engine_console_client_key = SimpleNamespace(private_key=None)
    assert node.engine_console is fresh
