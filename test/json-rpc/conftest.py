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
import time


API_CALL_MODES = ["get", "post", "jsonrpc"]
TRANSIENT_ERROR_MARKERS = (
    "Request timeout",
    "is not applied",
    "node not synced",
)


def _call_with_retry(method, *, retries: int = 8, delay_s: float = 0.5):
    last = None
    for _ in range(retries):
        try:
            last = method()
        except requests.RequestException:
            time.sleep(delay_s)
            continue
        try:
            data = last.json()
        except Exception:
            return last
        error = str(data.get("error", ""))
        if last.status_code == 500 and any(marker in error for marker in TRANSIENT_ERROR_MARKERS):
            time.sleep(delay_s)
            continue
        return last
    return last


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


@pytest.fixture(scope="session", autouse=True)
def wait_for_endpoint_ready(request):
    endpoint = request.config.getoption("--endpoint").rstrip("/") + "/"
    deadline = time.time() + 45
    last_error = None
    while time.time() < deadline:
        try:
            ready = requests.get(endpoint + "readyz", timeout=3)
            if ready.status_code != 200 or ready.text.strip() != "OK":
                time.sleep(1)
                continue
            probe = requests.get(endpoint + "getMasterchainInfo", timeout=5)
            data = probe.json()
            if probe.status_code == 200 and data.get("ok") is True:
                return
            last_error = str(data.get("error", ""))
        except Exception as exc:
            last_error = str(exc)
        time.sleep(1)
    pytest.skip(f"TOS endpoint not ready for live JSON-RPC tests: {last_error}")


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
                return _call_with_retry(
                    lambda: session.get(url + __method, params=kwargs, headers=headers, timeout=10)
                )
            if api_mode == "post":
                return _call_with_retry(
                    lambda: session.post(url + __method, json=kwargs, headers=headers, timeout=10)
                )
            # jsonrpc
            return _call_with_retry(lambda: session.post(
                url + "jsonRPC",
                json={"jsonrpc": "2.0", "method": __method, "params": kwargs, "id": 1},
                headers=headers,
                timeout=10,
            )
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
                return _call_with_retry(
                    lambda: session.post(url + __method, json=kwargs, headers=headers, timeout=10)
                )
            # jsonrpc
            return _call_with_retry(lambda: session.post(
                url + "jsonRPC",
                json={"jsonrpc": "2.0", "method": __method, "params": kwargs, "id": 1},
                headers=headers,
                timeout=10,
            )
            )
    return _call


@pytest.fixture(scope="module")
def api_method_call_get(endpoint, headers):
    """Direct GET call, bypassing mode parameterisation."""
    def _call(__method: str, **kwargs):
        with requests.Session() as session:
            return _call_with_retry(
                lambda: session.get(endpoint + __method, params=kwargs, headers=headers, timeout=10)
            )
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
