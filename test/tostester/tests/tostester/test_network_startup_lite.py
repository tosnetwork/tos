"""Startup retries the exact transport race introduced by ADNL fail-fast."""

from tosapi import toslib_api
from toslib.toslibjson import ToslibError
from tostester.network import _retryable_startup_lite_error


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
