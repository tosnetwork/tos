"""
runGetMethod / runGetMethodStd JSON-RPC method tests for TOS.

Covers:
  - runGetMethod     (POST only -- requires stack param)
  - runGetMethodStd  (TOS exclusive, POST only)
"""
import json
import logging
import pytest

logger = logging.getLogger(__name__)

ELECTOR_ADDRESS = "-1:3333333333333333333333333333333333333333333333333333333333333333"


# ═══════════════════════════════════════════════════════════════════════════
#  1. runGetMethod
# ═══════════════════════════════════════════════════════════════════════════

class TestRunGetMethod:

    METHOD = "runGetMethod"

    def test_active_election_id(self, api_method_call_no_get):
        """Call active_election_id on the elector contract -- always succeeds."""
        response = api_method_call_no_get(
            self.METHOD,
            address=ELECTOR_ADDRESS,
            method="active_election_id",
            stack=[],
        )
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True

        result = data["result"]
        assert result["@type"] in {"smc.runResult", "ext.smc.runResult"}
        logger.info("response:\n%s", json.dumps(data, indent=4))

    def test_participant_list(self, api_method_call_no_get):
        """Call participant_list on the elector -- returns a list of validators."""
        response = api_method_call_no_get(
            self.METHOD,
            address=ELECTOR_ADDRESS,
            method="participant_list",
            stack=[],
        )
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] in {"smc.runResult", "ext.smc.runResult"}

    def test_missing_address(self, api_method_call_no_get):
        response = api_method_call_no_get(self.METHOD, method="seqno", stack=[])
        assert response.json()["ok"] is False

    def test_missing_method(self, api_method_call_no_get):
        response = api_method_call_no_get(self.METHOD, address=ELECTOR_ADDRESS, stack=[])
        assert response.json()["ok"] is False

    def test_nonexistent_method(self, api_method_call_no_get):
        """Calling a method that does not exist in the contract should succeed
        at the RPC level but report exit_code != 0."""
        response = api_method_call_no_get(
            self.METHOD,
            address=ELECTOR_ADDRESS,
            method="does_not_exist_xyz",
            stack=[],
        )
        # The server should still return 200 (the query itself succeeded),
        # but the result should have a non-zero exit code.
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["exit_code"] != 0

    def test_with_stack_argument(self, api_method_call_no_get):
        """Call a get-method that takes an argument (e.g. participant_list_extended)."""
        response = api_method_call_no_get(
            self.METHOD,
            address=ELECTOR_ADDRESS,
            method="active_election_id",
            stack=[],
        )
        assert response.status_code == 200
        assert response.json()["ok"] is True


# ═══════════════════════════════════════════════════════════════════════════
#  2. runGetMethodStd  (TOS exclusive)
# ═══════════════════════════════════════════════════════════════════════════

class TestRunGetMethodStd:

    METHOD = "runGetMethodStd"

    def test_basic(self, api_method_call_no_get):
        response = api_method_call_no_get(
            self.METHOD,
            address=ELECTOR_ADDRESS,
            method="active_election_id",
            stack=[],
        )
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True

    def test_missing_address(self, api_method_call_no_get):
        response = api_method_call_no_get(self.METHOD, method="seqno", stack=[])
        assert response.json()["ok"] is False
