"""
Shared fixtures for the TOS JSON-RPC test suite.

Usage:
    pytest test/json-rpc/ --endpoint http://127.0.0.1:8011/
    pytest test/json-rpc/ --endpoint http://127.0.0.1:8011/ --method get
    pytest test/json-rpc/ --endpoint http://127.0.0.1:8011/ --method post --method jsonrpc
"""
import pytest
import requests
from typing import Optional


API_CALL_MODES = ["get", "post", "jsonrpc"]


def pytest_addoption(parser):
    parser.addoption(
        "--endpoint",
        action="store",
        default="http://127.0.0.1:8011/",
        help="TOS JSON-RPC endpoint URL (no /api/v2 prefix)",
    )
    parser.addoption(
        "--apikey",
        action="store",
        default=None,
        help="API key to pass in X-API-Key header",
    )
    parser.addoption(
        "--method",
        action="append",
        choices=API_CALL_MODES + ["all"],
        default=[],
        help="Which API modes to run (may be repeated). "
             "Examples: --method get  |  --method get --method post  |  --method all",
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def endpoint(request) -> str:
    base = request.config.getoption("--endpoint").rstrip("/") + "/"
    return base


@pytest.fixture(scope="module")
def api_key(request) -> Optional[str]:
    return request.config.getoption("--apikey")


def _selected_modes(config) -> list:
    opts = config.getoption("--method") or []
    return API_CALL_MODES if (not opts or "all" in opts) else [m for m in opts if m in API_CALL_MODES]


def pytest_generate_tests(metafunc):
    if "api_mode" in metafunc.fixturenames:
        modes = _selected_modes(metafunc.config)
        metafunc.parametrize("api_mode", modes, ids=modes, scope="module")
    if "api_mode_no_get" in metafunc.fixturenames:
        modes = [x for x in _selected_modes(metafunc.config) if x != "get"]
        metafunc.parametrize("api_mode_no_get", modes, ids=modes, scope="module")


@pytest.fixture(scope="module")
def headers(api_key):
    h = {}
    if api_key:
        h["X-API-Key"] = api_key
    return h


@pytest.fixture(scope="module")
def api_method_call(endpoint, headers, api_mode):
    """
    Call the REST or JSON-RPC endpoint according to the selected api_mode.

    TOS has no /api/v2 prefix -- methods live directly at the root:
        GET  /<method>?param=value
        POST /<method>  {json body}
        POST /jsonRPC   {jsonrpc: "2.0", method: ..., params: {...}, id: 1}
    """
    def _call(__method: str, **kwargs):
        url = endpoint  # already has trailing slash
        with requests.Session() as session:
            if api_mode == "get":
                return session.get(url + __method, params=kwargs, headers=headers)
            if api_mode == "post":
                return session.post(url + __method, json=kwargs, headers=headers)
            # jsonrpc
            return session.post(
                url + "jsonRPC",
                json={"jsonrpc": "2.0", "method": __method, "params": kwargs, "id": 1},
                headers=headers,
            )
    return _call


@pytest.fixture(scope="module")
def api_method_call_no_get(endpoint, headers, api_mode_no_get):
    """
    Same as api_method_call but excludes GET mode.
    Use for POST-only methods (sendBoc, runGetMethod, etc.).
    """
    def _call(__method: str, **kwargs):
        url = endpoint
        with requests.Session() as session:
            if api_mode_no_get == "post":
                return session.post(url + __method, json=kwargs, headers=headers)
            # jsonrpc
            return session.post(
                url + "jsonRPC",
                json={"jsonrpc": "2.0", "method": __method, "params": kwargs, "id": 1},
                headers=headers,
            )
    return _call


@pytest.fixture(scope="module")
def api_method_call_get(endpoint, headers):
    """Direct GET call, bypassing mode parameterisation."""
    def _call(__method: str, **kwargs):
        with requests.Session() as session:
            return session.get(endpoint + __method, params=kwargs, headers=headers)
    return _call


@pytest.fixture(scope="module")
def last_mc_seqno(api_method_call_get):
    """Fetch the latest masterchain seqno (used by many tests as a reference point)."""
    resp = api_method_call_get("getMasterchainInfo")
    resp.raise_for_status()
    return resp.json()["result"]["last"]["seqno"]


# ---------------------------------------------------------------------------
# Header output
# ---------------------------------------------------------------------------

def pytest_report_header(config):
    return f"Selected API modes: {', '.join(_selected_modes(config))}"
