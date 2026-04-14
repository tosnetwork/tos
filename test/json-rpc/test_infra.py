"""
Infrastructure / operational endpoint tests for the TOS JSON-RPC server.

Covers:
  - GET /healthcheck   -> 200 OK text
  - GET /readyz        -> JSON with ready, sync_lag_seconds
  - OPTIONS (any path) -> 204 with CORS headers
  - Batch JSON-RPC rejection -> error -32600
  - Method not found -> error -32601
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
#  4. Batch request rejection
# ═══════════════════════════════════════════════════════════════════════════

class TestBatchRejection:

    def test_batch_array_rejected(self, endpoint, headers):
        """Sending a JSON-RPC batch (array) should be rejected with -32600."""
        url = endpoint.rstrip("/") + "/jsonRPC"
        batch = [
            {"jsonrpc": "2.0", "method": "getMasterchainInfo", "params": {}, "id": 1},
            {"jsonrpc": "2.0", "method": "getConsensusBlock", "params": {}, "id": 2},
        ]
        resp = requests.post(url, json=batch, headers=headers)
        # The server should return an error, not process both requests.
        data = resp.json()
        if isinstance(data, dict):
            # Single error response
            assert data.get("code") == -32600 or data.get("ok") is False
        else:
            # If it returns a list, it should still signal an error somehow.
            pytest.fail("Batch requests should not be processed -- expected a single error response")


# ═══════════════════════════════════════════════════════════════════════════
#  5. Method not found
# ═══════════════════════════════════════════════════════════════════════════

class TestMethodNotFound:

    def test_unknown_method_jsonrpc(self, endpoint, headers):
        """An unknown method via JSON-RPC should return -32601."""
        url = endpoint.rstrip("/") + "/jsonRPC"
        payload = {
            "jsonrpc": "2.0",
            "method": "thisMethodDoesNotExist",
            "params": {},
            "id": 1,
        }
        resp = requests.post(url, json=payload, headers=headers)
        data = resp.json()
        # Should contain an error with code -32601
        if "code" in data:
            assert data["code"] == -32601
        else:
            assert data.get("ok") is False

    def test_unknown_method_rest_post(self, endpoint, headers):
        """An unknown method via REST POST should return an error."""
        url = endpoint.rstrip("/") + "/thisMethodDoesNotExist"
        resp = requests.post(url, json={}, headers=headers)
        assert resp.status_code in {404, 422, 500}

    def test_unknown_method_rest_get(self, endpoint, headers):
        """An unknown method via REST GET should return 404 or equivalent."""
        url = endpoint.rstrip("/") + "/thisMethodDoesNotExist"
        resp = requests.get(url, headers=headers)
        assert resp.status_code in {404, 422, 500}
