"""
Infrastructure / operational endpoint tests for the TOS JSON-RPC server.

Covers:
  - GET /healthcheck   -> 200 OK text
  - GET /readyz        -> JSON with ready, sync_lag_seconds
  - OPTIONS (any path) -> 204 with CORS headers
  - Batch JSON-RPC support (spec-compliant array → array)
  - Method not found -> error -32601 (spec-compliant `error.code`)
"""
import pytest
import requests


# ═══════════════════════════════════════════════════════════════════════════
#  1. Healthcheck
# ═══════════════════════════════════════════════════════════════════════════

class TestHealthcheck:

    def test_healthcheck_returns_200(self, endpoint, headers):
        """GET /healthcheck should return 200 with a text body."""
        url = endpoint.rstrip("/") + "/healthcheck"
        resp = requests.get(url, headers=headers)
        assert resp.status_code == 200
        # Body should be non-empty text (typically "OK" or similar).
        assert len(resp.text) > 0

    def test_healthcheck_trailing_slash(self, endpoint, headers):
        url = endpoint.rstrip("/") + "/healthcheck/"
        resp = requests.get(url, headers=headers)
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════
#  2. Readyz
# ═══════════════════════════════════════════════════════════════════════════

class TestReadyz:

    def test_readyz_returns_json(self, endpoint, headers):
        """GET /readyz should return JSON with at least 'ready' and 'sync_lag_seconds'."""
        url = endpoint.rstrip("/") + "/readyz"
        resp = requests.get(url, headers=headers)
        assert resp.status_code in {200, 503}  # 503 when still syncing
        data = resp.json()
        assert "ready" in data
        assert isinstance(data["ready"], bool)
        assert "sync_lag_seconds" in data
        assert isinstance(data["sync_lag_seconds"], (int, float))

    def test_readyz_trailing_slash(self, endpoint, headers):
        url = endpoint.rstrip("/") + "/readyz/"
        resp = requests.get(url, headers=headers)
        assert resp.status_code in {200, 503}


# ═══════════════════════════════════════════════════════════════════════════
#  3. CORS preflight (OPTIONS)
# ═══════════════════════════════════════════════════════════════════════════

class TestCORS:

    @pytest.mark.parametrize("path", ["/", "/jsonRPC", "/getMasterchainInfo", "/healthcheck"])
    def test_options_returns_204(self, endpoint, headers, path):
        """OPTIONS on any path should return 204 with CORS headers."""
        url = endpoint.rstrip("/") + path
        resp = requests.options(url, headers=headers)
        assert resp.status_code == 204
        assert "Access-Control-Allow-Origin" in resp.headers
        assert "Access-Control-Allow-Methods" in resp.headers

    def test_cors_headers_on_normal_response(self, endpoint, headers):
        """Regular GET responses should also include Access-Control-Allow-Origin."""
        url = endpoint.rstrip("/") + "/healthcheck"
        resp = requests.get(url, headers=headers)
        assert "Access-Control-Allow-Origin" in resp.headers


# ═══════════════════════════════════════════════════════════════════════════
#  4. Batch request support (JSON-RPC 2.0)
# ═══════════════════════════════════════════════════════════════════════════

class TestBatch:

    def test_batch_returns_array(self, endpoint, headers):
        """A JSON-RPC batch must be processed and return an array of responses
        (spec section 6).  Pre-fix the server rejected batches with a single
        error -- that broke Blockscout's catchup pipeline.  See
        test/conformance/blockscout/README.md BUG #2."""
        url = endpoint.rstrip("/") + "/jsonRPC"
        batch = [
            {"jsonrpc": "2.0", "method": "getMasterchainInfo", "params": {}, "id": 1},
            {"jsonrpc": "2.0", "method": "getConsensusBlock", "params": {}, "id": 2},
        ]
        resp = requests.post(url, json=batch, headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list), f"expected JSON array, got {type(data).__name__}"
        assert len(data) == 2
        # Each element is a spec-shape JSON-RPC response.
        for elem, src in zip(data, batch):
            assert elem.get("jsonrpc") == "2.0"
            assert elem.get("id") == src["id"]
            # Must contain either result or error -- not both.
            assert ("result" in elem) ^ ("error" in elem)

    def test_empty_batch_returns_invalid_request(self, endpoint, headers):
        """Per spec, an empty batch must return a single -32600 error."""
        url = endpoint.rstrip("/") + "/jsonRPC"
        resp = requests.post(url, json=[], headers=headers)
        data = resp.json()
        assert isinstance(data, dict)
        # Spec error shape: error.code == -32600
        assert data.get("error", {}).get("code") == -32600

    def test_batch_notification_returns_204(self, endpoint, headers):
        """An all-notification batch (no `id` fields) must produce no body."""
        url = endpoint.rstrip("/") + "/jsonRPC"
        batch = [{"jsonrpc": "2.0", "method": "eth_chainId", "params": []}]
        resp = requests.post(url, json=batch, headers=headers)
        assert resp.status_code == 204
        assert resp.text == ""

    def test_batch_too_large_rejected(self, endpoint, headers):
        """Batches over the 100-element cap are rejected with -32600."""
        url = endpoint.rstrip("/") + "/jsonRPC"
        batch = [{"jsonrpc": "2.0", "id": i, "method": "eth_chainId", "params": []}
                 for i in range(150)]
        resp = requests.post(url, json=batch, headers=headers)
        data = resp.json()
        assert isinstance(data, dict)
        assert data.get("error", {}).get("code") == -32600
        assert "too large" in data.get("error", {}).get("message", "").lower()


# ═══════════════════════════════════════════════════════════════════════════
#  5. Method not found
# ═══════════════════════════════════════════════════════════════════════════

class TestMethodNotFound:

    def test_unknown_method_jsonrpc(self, endpoint, headers):
        """An unknown method via JSON-RPC must return spec-shape -32601."""
        url = endpoint.rstrip("/") + "/jsonRPC"
        payload = {
            "jsonrpc": "2.0",
            "method": "thisMethodDoesNotExist",
            "params": {},
            "id": 1,
        }
        resp = requests.post(url, json=payload, headers=headers)
        # Spec shape: HTTP 200, body has nested error.code/error.message
        assert resp.status_code == 200
        data = resp.json()
        assert "error" in data and isinstance(data["error"], dict)
        assert data["error"].get("code") == -32601
        assert data.get("id") == 1

    def test_unknown_method_rest_post(self, endpoint, headers):
        """An unknown method via REST POST returns an error.  POST to a
        non-REST URL falls through the JSON-RPC envelope handler so the
        body must be valid JSON-RPC; we send an empty object which lacks
        the required `method` field."""
        url = endpoint.rstrip("/") + "/thisMethodDoesNotExist"
        resp = requests.post(url, json={}, headers=headers)
        # Either legacy mapped HTTP status or spec-shape HTTP 200 with
        # error.code -32600 (missing method field) is acceptable.
        if resp.status_code == 200:
            data = resp.json()
            assert "error" in data and isinstance(data["error"], dict)
            assert data["error"].get("code") in {-32600, -32601}
        else:
            assert resp.status_code in {404, 422, 500}

    def test_unknown_method_rest_get(self, endpoint, headers):
        """An unknown method via REST GET should return 404 or equivalent."""
        url = endpoint.rstrip("/") + "/thisMethodDoesNotExist"
        resp = requests.get(url, headers=headers)
        assert resp.status_code in {404, 422, 500}
