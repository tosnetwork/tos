"""
Send-family JSON-RPC method tests for TOS.

Covers:
  - sendBoc
  - sendBocReturnHash
  - sendBocReturnHashNoError  (TOS exclusive)
  - sendQuery                 (TOS exclusive)
  - estimateFee
"""

from rpc_contract import assert_success, expect_error

ELECTOR_ADDRESS = "-1:3333333333333333333333333333333333333333333333333333333333333333"

# A minimal *invalid* BoC (base64) -- useful for testing error paths without
# actually sending a real transaction.  The server should accept the BoC
# parameter and return a structured error (not 422).
INVALID_BOC = "dGVzdA=="  # base64("test")


# ═══════════════════════════════════════════════════════════════════════════
#  1. sendBoc
# ═══════════════════════════════════════════════════════════════════════════


class TestSendBoc:
    METHOD = "sendBoc"

    def test_missing_boc(self, api_method_call_no_get):
        response = api_method_call_no_get(self.METHOD)
        expect_error(response)

    def test_invalid_boc(self, api_method_call_no_get):
        """An invalid BoC should be rejected with a structured error."""
        response = api_method_call_no_get(self.METHOD, boc=INVALID_BOC)
        expect_error(response, retryable=False)


# ═══════════════════════════════════════════════════════════════════════════
#  2. sendBocReturnHash
# ═══════════════════════════════════════════════════════════════════════════


class TestSendBocReturnHash:
    METHOD = "sendBocReturnHash"

    def test_missing_boc(self, api_method_call_no_get):
        response = api_method_call_no_get(self.METHOD)
        expect_error(response)

    def test_invalid_boc(self, api_method_call_no_get):
        response = api_method_call_no_get(self.METHOD, boc=INVALID_BOC)
        expect_error(response, retryable=False)


# ═══════════════════════════════════════════════════════════════════════════
#  3. sendBocReturnHashNoError  (TOS exclusive)
# ═══════════════════════════════════════════════════════════════════════════


class TestSendBocReturnHashNoError:
    METHOD = "sendBocReturnHashNoError"

    def test_missing_boc(self, api_method_call_no_get):
        """Even the NoError variant should reject missing params."""
        response = api_method_call_no_get(self.METHOD)
        expect_error(response, -32602, "INVALID_ARGUMENT")

    def test_invalid_boc(self, api_method_call_no_get):
        """The NoError variant reports a send failure inside its result."""
        response = api_method_call_no_get(self.METHOD, boc=INVALID_BOC)
        assert response.status_code == 200, response.text
        body = response.json()
        if "error" in body:
            expect_error(response)
        else:
            assert_success(body)


# ═══════════════════════════════════════════════════════════════════════════
#  4. sendQuery  (TOS exclusive)
# ═══════════════════════════════════════════════════════════════════════════


class TestSendQuery:
    METHOD = "sendQuery"

    def test_missing_params(self, api_method_call_no_get):
        response = api_method_call_no_get(self.METHOD)
        expect_error(response)

    def test_invalid_body(self, api_method_call_no_get):
        """Send a query with an invalid body -- should produce a structured error."""
        response = api_method_call_no_get(
            self.METHOD,
            address=ELECTOR_ADDRESS,
            body=INVALID_BOC,
        )
        expect_error(response)


# ═══════════════════════════════════════════════════════════════════════════
#  5. estimateFee
# ═══════════════════════════════════════════════════════════════════════════


class TestEstimateFee:
    METHOD = "estimateFee"

    def test_missing_params(self, api_method_call):
        response = api_method_call(self.METHOD)
        expect_error(response)

    def test_with_address_and_body(self, api_method_call):
        """Minimal fee estimation call -- may fail but should return structured JSON."""
        response = api_method_call(
            self.METHOD,
            address=ELECTOR_ADDRESS,
            body=INVALID_BOC,
        )
        # A fee result or a structured error are both acceptable.
        assert response.status_code == 200, response.text
        data = response.json()
        if "error" in data:
            expect_error(response)
        else:
            assert_success(data)
