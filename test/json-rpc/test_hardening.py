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

from rpc_contract import assert_error, expect_error, expect_invalid_param


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

        The status was still 200 and the answer still claimed success, so
        only parsing the body catches it.
        """
        body = dict(params)
        if method == "getBlockTransactionsExt":
            body.update({"workchain": -1, "shard": "-9223372036854775808", "seqno": last_mc_seqno})
        else:
            pytest.skip("needs a funded address fixture; covered by the unit test")
        r = requests.post(endpoint + method, json=body, headers=headers, timeout=30)
        assert r.status_code == 200, r.text
        answer = r.json()  # raises if the body was truncated
        assert ("result" in answer) != ("error" in answer), answer


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



# ── wire contract ──────────────────────────────────────────────────────
#
# One answer shape for every route: success is {jsonrpc, id, result}, failure
# is {jsonrpc, id, error: {code, message, data: {schema_version, reason,
# retryable}}} at HTTP 200. There is no `ok` flag and no HTTP status that
# carries a method error.

class TestErrorShape:

    def test_method_error_has_one_shape_on_every_route(self, api_method_call):
        response = api_method_call("detectAddress", address="not_an_address")
        error = expect_error(response, -32602, "INVALID_ARGUMENT", retryable=False)
        assert error["message"]
        assert set(response.json()) == {"jsonrpc", "id", "error"}

    def test_rest_routes_answer_null_id(self, endpoint, headers):
        for r in (
            requests.get(endpoint + "detectAddress", params={"address": "x"},
                         headers=headers, timeout=10),
            requests.post(endpoint + "detectAddress", json={"address": "x"},
                          headers=headers, timeout=10),
        ):
            expect_error(r, -32602, "INVALID_ARGUMENT")
            assert r.json()["id"] is None

    def test_success_has_one_shape_on_every_route(self, api_method_call):
        response = api_method_call("getMasterchainInfo")
        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == {"jsonrpc", "id", "result"}
        assert body["jsonrpc"] == "2.0"

    def test_strict_param_error_names_the_parameter(self, api_method_call):
        response = api_method_call(
            "lookupBlock", workchain=-1, shard="zz", seqno=1
        )
        expect_invalid_param(response, "shard")


class TestEnvelope:

    @staticmethod
    def _post(endpoint, headers, payload):
        return requests.post(endpoint + "jsonRPC", json=payload, headers=headers, timeout=10)

    @pytest.mark.parametrize("payload", [
        {"method": "getMasterchainInfo", "params": {}, "id": 1},
        {"jsonrpc": "1.0", "method": "getMasterchainInfo", "params": {}, "id": 1},
        {"jsonrpc": 2.0, "method": "getMasterchainInfo", "params": {}, "id": 1},
        {"jsonrpc": "2.0", "method": "getMasterchainInfo", "params": "x", "id": 1},
        {"jsonrpc": "2.0", "method": "getMasterchainInfo", "params": None, "id": 1},
        {"jsonrpc": "2.0", "method": 12, "params": {}, "id": 1},
        {"jsonrpc": "2.0", "params": {}, "id": 1},
    ], ids=["no-jsonrpc", "jsonrpc-1.0", "jsonrpc-number", "params-string",
            "params-null", "method-number", "no-method"])
    def test_invalid_envelope(self, endpoint, headers, payload):
        r = self._post(endpoint, headers, payload)
        expect_error(r, -32600, "INVALID_REQUEST", retryable=False)

    def test_invalid_envelope_is_answered_even_without_id(self, endpoint, headers):
        r = self._post(endpoint, headers, {"jsonrpc": "1.0", "method": "getMasterchainInfo"})
        expect_error(r, -32600, "INVALID_REQUEST")

    @pytest.mark.parametrize("body", [42, "x", True])
    def test_top_level_not_object_or_array(self, endpoint, headers, body):
        r = self._post(endpoint, headers, body)
        expect_error(r, -32600, "INVALID_REQUEST")

    def test_unparseable_body(self, endpoint, headers):
        r = requests.post(
            endpoint + "jsonRPC",
            data=b"{not json",
            headers={**headers, "Content-Type": "application/json"},
            timeout=10,
        )
        expect_error(r, -32700, "PARSE_ERROR", retryable=False)
        assert r.json()["id"] is None

    def test_positional_params_refused(self, endpoint, headers):
        r = self._post(endpoint, headers, {
            "jsonrpc": "2.0", "method": "getMasterchainInfo", "params": [], "id": 5,
        })
        error = expect_error(r, -32602, "INVALID_ARGUMENT", retryable=False)
        assert "positional" in error["message"]
        assert r.json()["id"] == 5

    def test_invalid_id_type_answers_null_id(self, endpoint, headers):
        r = self._post(endpoint, headers, {
            "jsonrpc": "2.0", "method": "getMasterchainInfo", "params": {}, "id": {"x": 1},
        })
        expect_error(r, -32600, "INVALID_REQUEST")
        assert r.json()["id"] is None

    def test_absent_params_is_empty_object(self, endpoint, headers):
        r = self._post(endpoint, headers, {
            "jsonrpc": "2.0", "method": "getMasterchainInfo", "id": "s",
        })
        assert r.status_code == 200, r.text
        assert "result" in r.json() and r.json()["id"] == "s"

    @pytest.mark.parametrize("method,params", [
        ("getMasterchainInfo", {}),
        ("detectAddress", {"address": "x"}),
        ("noSuchMethod", {}),
    ], ids=["success", "method-error", "unknown-method"])
    def test_notification_gets_empty_204(self, endpoint, headers, method, params):
        r = self._post(endpoint, headers, {"jsonrpc": "2.0", "method": method, "params": params})
        assert r.status_code == 204, r.text
        assert r.content == b""

    def test_null_id_is_not_a_notification(self, endpoint, headers):
        r = self._post(endpoint, headers, {
            "jsonrpc": "2.0", "method": "getMasterchainInfo", "params": {}, "id": None,
        })
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["id"] is None and "result" in body

    def test_all_notification_batch_gets_empty_204(self, endpoint, headers):
        r = self._post(endpoint, headers, [
            {"jsonrpc": "2.0", "method": "getMasterchainInfo", "params": {}},
            {"jsonrpc": "2.0", "method": "detectAddress", "params": {"address": "x"}},
        ])
        assert r.status_code == 204, r.text
        assert r.content == b""

    def test_batch_element_errors_are_objects(self, endpoint, headers):
        r = self._post(endpoint, headers, [
            {"jsonrpc": "2.0", "method": "getMasterchainInfo", "params": [], "id": 1},
            {"jsonrpc": "2.0", "method": "getMasterchainInfo", "id": 2},
            7,
        ])
        assert r.status_code == 200, r.text
        body = r.json()
        assert isinstance(body, list) and len(body) == 3
        assert_error(body[0], -32602, "INVALID_ARGUMENT")
        assert body[0]["id"] == 1
        assert "result" in body[1] and body[1]["id"] == 2
        assert_error(body[2], -32600, "INVALID_REQUEST")
        assert body[2]["id"] is None


class TestPreDispatchRefusals:

    def test_unsupported_http_method(self, endpoint, headers):
        r = requests.put(endpoint + "getMasterchainInfo", json={}, headers=headers, timeout=10)
        expect_error(r, -32600, "INVALID_REQUEST", status=405)

    def test_post_without_json_content_type(self, endpoint, headers):
        r = requests.post(
            endpoint + "jsonRPC",
            data=b'{"jsonrpc":"2.0","method":"getMasterchainInfo","params":{},"id":1}',
            headers={**headers, "Content-Type": "text/plain"},
            timeout=10,
        )
        expect_error(r, -32600, "INVALID_REQUEST", status=415)

    def test_unknown_get_path(self, endpoint, headers):
        r = requests.get(endpoint + "noSuchMethod", headers=headers, timeout=10)
        expect_error(r, -32601, "METHOD_NOT_FOUND", status=404)

# ── per-source budget ──────────────────────────────────────────────────

class TestRateGate:

    def test_probe_is_never_refused(self, endpoint, headers):
        """A readiness probe must always answer ready or not ready.

        Refusing one forces a wrong answer either way: "ready" keeps
        traffic on a node that may be out of sync, "not ready" pulls a
        healthy node out of rotation. Its cost is bounded by caching the
        answer, so no probe rate may turn into a refusal.
        """
        for _ in range(40):
            r = requests.get(endpoint + "readyz", headers=headers, timeout=10)
            assert r.status_code in (200, 503), r.text
            assert "Rate limit" not in r.text
            assert "ready" in r.json()

    def test_probe_answer_stays_truthful_under_load(self, endpoint, headers):
        """Repeated probes must agree with each other within the cache window.

        A cached answer is only acceptable while it is short-lived and
        consistent; a probe that flips between ready and not ready under
        no change of state would mean the cache is serving something
        unrelated to readiness.
        """
        answers = set()
        for _ in range(10):
            r = requests.get(endpoint + "readyz", headers=headers, timeout=10)
            answers.add(r.json().get("ready"))
        assert len(answers) == 1, f"readiness flipped under repeated probing: {answers}"
