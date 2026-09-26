import pytest
from tosapi import toslib_api
from toslib.toslibjson import ToslibError
from tostester.n6_cluster import _is_lite_transport_error


@pytest.mark.parametrize(
    ("code", "message", "expected"),
    [
        (500, "LITE_SERVER_NETWORKtimeout for adnl query query", True),
        (500, "LITE_SERVER_NETWORK", True),
        (500, "NO_LITE_SERVERS", False),
        (500, "NOT_ENOUGH_FUNDS", False),
        (651, "not in db", False),
        (400, "LITE_SERVER_NETWORKtimeout for adnl query query", False),
    ],
)
def test_real_toslib_transport_error_classifier(code: int, message: str, expected: bool) -> None:
    error = ToslibError(toslib_api.Error(code=code, message=message))
    assert _is_lite_transport_error(error) is expected


@pytest.mark.parametrize("error", [RuntimeError("failure"), ValueError("failure")])
def test_non_toslib_errors_are_not_transport_errors(error: BaseException) -> None:
    assert not _is_lite_transport_error(error)
