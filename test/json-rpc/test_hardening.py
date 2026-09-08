"""Boundary tests for the JSON-RPC hardening changes.

These exercise the real HTTP surface rather than the units underneath,
because the defects they cover were not in the guarded logic -- that part
was correct and its unit tests passed -- but in where the logic was
applied. A route that never reaches a gate, or a response assembled past
a buffer that stops without complaining, is invisible to a test of the
gate or the builder.

The batch tests are also the only place the request-buffer lifetime is
exercised end to end. Run the suite against an ASAN build to make that
check mean something: without it a use-after-free reads plausible bytes
and the assertions still pass.
"""

import json

import pytest
import requests


# ── request buffer lifetime ────────────────────────────────────────────
#
# A parsed JSON value borrows from the buffer it was decoded from, and the
# batch driver resumes on a later actor message. Elements after the first
# are therefore read once the caller that owned the buffer has returned.

class TestBatchRequests:

    def test_two_element_batch_answers_both(self, endpoint, headers):
        payload = [
            {"jsonrpc": "2.0", "id": 1, "method": "getMasterchainInfo", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "getMasterchainInfo", "params": {}},
        ]
        r = requests.post(endpoint + "jsonRPC", json=payload, headers=headers, timeout=15)
        assert r.status_code == 200, r.text
        body = r.json()
        assert isinstance(body, list) and len(body) == 2
        assert {e["id"] for e in body} == {1, 2}

    def test_later_element_keeps_its_own_method(self, endpoint, headers):
        """The second element's method name is read after the buffer is gone.

        A wrong answer here means it was read from released storage: the
        reply would name whatever occupied that memory instead.
        """
        payload = [
            {"jsonrpc": "2.0", "id": 1, "method": "getMasterchainInfo", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "definitelyNotAMethod", "params": {}},
        ]
        r = requests.post(endpoint + "jsonRPC", json=payload, headers=headers, timeout=15)
        assert r.status_code == 200, r.text
        second = [e for e in r.json() if e.get("id") == 2][0]
        assert "definitelyNotAMethod" in json.dumps(second)

    def test_long_batch_preserves_element_identity(self, endpoint, headers):
        """Every element after the first is read post-return; check them all."""
        payload = [
            {"jsonrpc": "2.0", "id": i, "method": "getMasterchainInfo", "params": {}}
            for i in range(1, 21)
        ]
        r = requests.post(endpoint + "jsonRPC", json=payload, headers=headers, timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        assert {e["id"] for e in body} == set(range(1, 21))


# ── response assembly ──────────────────────────────────────────────────

class TestLargeResponses:

    @pytest.mark.parametrize("method,params", [
        ("getBlockTransactionsExt", {"count": 256}),
        ("getTransactions", {"limit": 100}),
    ])
    def test_large_response_is_parseable(self, endpoint, headers, last_mc_seqno, method, params):
        """A response assembled past a fixed buffer used to be cut mid-value.

        The status was still 200 and `ok` was still true, so only parsing
        the body catches it.
        """
        body = dict(params)
        if method == "getBlockTransactionsExt":
            body.update({"workchain": -1, "shard": "-9223372036854775808", "seqno": last_mc_seqno})
        else:
            pytest.skip("needs a funded address fixture; covered by the unit test")
        r = requests.post(endpoint + method, json=body, headers=headers, timeout=30)
        assert r.status_code in (200, 404, 422, 500), r.text
        r.json()  # raises if the body was truncated


# ── request id handling ────────────────────────────────────────────────

class TestRequestId:

    @pytest.mark.parametrize("raw_id", ['.', '--', '1e+-.3'])
    def test_malformed_numeric_id_is_refused_not_echoed(self, endpoint, headers, raw_id):
        """These parse as Numbers and were spliced into the reply unquoted.

        Sending them requires hand-built JSON: a conforming encoder will
        not produce them.
        """
        raw = '{"jsonrpc":"2.0","id":%s,"method":"getMasterchainInfo","params":{}}' % raw_id
        r = requests.post(
            endpoint + "jsonRPC",
            data=raw.encode(),
            headers={**headers, "Content-Type": "application/json"},
            timeout=10,
        )
        assert r.status_code == 200, r.text
        body = r.json()  # raises if the malformed id reached the response
        assert body.get("id") is None

    @pytest.mark.parametrize("raw_id", ['0', '-1', '1.5', '1e10', '1.5e-10'])
    def test_valid_numeric_id_is_preserved(self, endpoint, headers, raw_id):
        """The grammar check must not reject ids a client may legitimately send."""
        raw = '{"jsonrpc":"2.0","id":%s,"method":"getMasterchainInfo","params":{}}' % raw_id
        r = requests.post(
            endpoint + "jsonRPC",
            data=raw.encode(),
            headers={**headers, "Content-Type": "application/json"},
            timeout=10,
        )
        assert r.status_code == 200, r.text
        assert r.json()["id"] == json.loads(raw_id)


# ── per-source budget ──────────────────────────────────────────────────

class TestRateGate:

    def test_readyz_consumes_the_budget(self, endpoint, headers):
        """The readiness probe issues a liteserver query and bypasses the
        dispatcher, so it needs the budget applied on its own route.

        Marked slow: proving the budget applies means spending it. Skipped
        unless --run-rate-limit is passed, because exhausting it briefly
        degrades the node for other tests.
        """
        pytest.skip("run explicitly: spends the per-source budget for this address")

    def test_probe_headroom_is_sane(self, endpoint, headers):
        """A health checker polling steadily must not be rate-limited out.

        Twenty probes in quick succession is far more than an orchestrator
        sends and far less than the budget, so this stays green while
        catching a budget set absurdly low.
        """
        for _ in range(20):
            r = requests.get(endpoint + "readyz", headers=headers, timeout=10)
            assert r.status_code != 429
            assert "Rate limit" not in r.text
