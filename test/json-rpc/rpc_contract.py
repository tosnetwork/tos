"""Assertions for the validator-engine JSON-RPC wire contract.

Every answer of every route is a JSON-RPC 2.0 response object: success is
{jsonrpc, id, result}, failure is {jsonrpc, id, error: {code, message,
data: {schema_version, reason, retryable}}}. Method errors are HTTP 200 on all
routes (/jsonRPC, POST /<method>, GET /<method>); only refusals made before a
method runs (401, 404 for an unknown GET path, 405, 415, 429) use another
status, with the same body.
"""

from typing import Any, Optional

import requests

# The basechain / masterchain full shard, written as the server reads and
# writes it: the signed decimal int64 in a JSON string.
SHARD_ALL = "-9223372036854775808"


def assert_success(body: Any) -> Any:
    """Assert a decoded success answer and return its result."""
    assert isinstance(body, dict), f"expected a response object, got {body!r}"
    assert body.get("jsonrpc") == "2.0", body
    assert "ok" not in body, f"legacy 'ok' field in {body}"
    assert "error" not in body, f"expected success, got error {body.get('error')}"
    assert "result" in body, body
    return body["result"]


def assert_error(
    body: Any,
    code: Optional[int] = None,
    reason: Optional[str] = None,
    *,
    retryable: Optional[bool] = None,
) -> dict:
    """Assert a decoded error answer and return its error object."""
    assert isinstance(body, dict), f"expected a response object, got {body!r}"
    assert body.get("jsonrpc") == "2.0", body
    assert "id" in body, body
    for legacy in ("ok", "error_info", "code"):
        assert legacy not in body, f"legacy top-level '{legacy}' in {body}"
    assert "result" not in body, f"expected error, got result {body.get('result')}"
    error = body.get("error")
    assert isinstance(error, dict), f"'error' must be an object: {body}"
    assert isinstance(error.get("code"), int), error
    assert isinstance(error.get("message"), str), error
    data = error.get("data")
    assert isinstance(data, dict), error
    assert data.get("schema_version") == 1, error
    assert isinstance(data.get("reason"), str) and data["reason"], error
    assert isinstance(data.get("retryable"), bool), error
    if code is not None:
        assert error["code"] == code, error
    if reason is not None:
        assert data["reason"] == reason, error
    if retryable is not None:
        assert data["retryable"] is retryable, error
    return error


def error_message(body: Any) -> str:
    """The message of a decoded error answer (asserting the error shape)."""
    return assert_error(body)["message"]


def expect_result(response: requests.Response) -> Any:
    """Assert an HTTP 200 success answer and return its result."""
    assert response.status_code == 200, response.text
    return assert_success(response.json())


def expect_error(
    response: requests.Response,
    code: Optional[int] = None,
    reason: Optional[str] = None,
    *,
    retryable: Optional[bool] = None,
    status: int = 200,
) -> dict:
    """Assert an error answer (HTTP 200 unless a pre-dispatch refusal) and
    return its error object."""
    assert response.status_code == status, response.text
    return assert_error(response.json(), code, reason, retryable=retryable)


def expect_invalid_param(response: requests.Response, name: str) -> dict:
    """Assert a -32602 refusal whose message names the offending parameter."""
    error = expect_error(response, -32602, "INVALID_ARGUMENT", retryable=False)
    assert f"'{name}'" in error["message"], error
    return error


def is_retryable_error(body: Any) -> bool:
    """True when the body is an error answer the server marks retryable."""
    if not isinstance(body, dict):
        return False
    error = body.get("error")
    if not isinstance(error, dict):
        return False
    data = error.get("data")
    return isinstance(data, dict) and data.get("retryable") is True
