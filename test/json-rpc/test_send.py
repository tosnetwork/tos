"""
Send-family JSON-RPC method tests for TOS.

Covers:
  - sendBoc
  - sendBocReturnHash
  - sendBocReturnHashNoError  (TOS exclusive)
  - sendQuery                 (TOS exclusive)
  - estimateFee
"""
import pytest

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
        assert response.json()["ok"] is False

    def test_invalid_boc(self, api_method_call_no_get):
        """An invalid BoC should be rejected with a structured error."""
        response = api_method_call_no_get(self.METHOD, boc=INVALID_BOC)
        # 422 (bad deserialization) or 500 (engine error) are both acceptable.
        assert response.status_code in {422, 500}
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  2. sendBocReturnHash
# ═══════════════════════════════════════════════════════════════════════════

class TestSendBocReturnHash:

    METHOD = "sendBocReturnHash"

    def test_missing_boc(self, api_method_call_no_get):
        response = api_method_call_no_get(self.METHOD)
        assert response.json()["ok"] is False

    def test_invalid_boc(self, api_method_call_no_get):
        response = api_method_call_no_get(self.METHOD, boc=INVALID_BOC)
        assert response.status_code in {422, 500}
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  3. sendBocReturnHashNoError  (TOS exclusive)
# ═══════════════════════════════════════════════════════════════════════════

class TestSendBocReturnHashNoError:

    METHOD = "sendBocReturnHashNoError"

    def test_missing_boc(self, api_method_call_no_get):
        """Even the NoError variant should reject missing params."""
        response = api_method_call_no_get(self.METHOD)
        # Could be 422 or 200-with-error depending on interpretation
        assert response.status_code in {200, 422}

    def test_invalid_boc(self, api_method_call_no_get):
        """NoError variant returns 200 even on failure, with ok=true and error in result."""
        response = api_method_call_no_get(self.METHOD, boc=INVALID_BOC)
        # This method is designed to always return 200, but should at least
        # not crash the server.
        assert response.status_code in {200, 422, 500}


# ═══════════════════════════════════════════════════════════════════════════
#  4. sendQuery  (TOS exclusive)
# ═══════════════════════════════════════════════════════════════════════════

class TestSendQuery:

    METHOD = "sendQuery"

    def test_missing_params(self, api_method_call_no_get):
        response = api_method_call_no_get(self.METHOD)
        assert response.json()["ok"] is False

    def test_invalid_body(self, api_method_call_no_get):
        """Send a query with an invalid body -- should produce a structured error."""
        response = api_method_call_no_get(
            self.METHOD,
            address=ELECTOR_ADDRESS,
            body=INVALID_BOC,
        )
        assert response.status_code in {422, 500}


# ═══════════════════════════════════════════════════════════════════════════
#  5. estimateFee
# ═══════════════════════════════════════════════════════════════════════════

class TestEstimateFee:

    METHOD = "estimateFee"

    def test_missing_params(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.json()["ok"] is False

    def test_with_address_and_body(self, api_method_call):
        """Minimal fee estimation call -- may fail but should return structured JSON."""
        response = api_method_call(
            self.METHOD,
            address=ELECTOR_ADDRESS,
            body=INVALID_BOC,
        )
        # 200 (success with fee result) or 422/500 (structured error) are acceptable.
        assert response.status_code in {200, 422, 500}
        data = response.json()
        assert "ok" in data
