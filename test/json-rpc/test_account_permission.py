"""
Account-permission JSON-RPC method tests for TOS.

Covers:
  - getAccountCapability
  - buildTransactionIntent
  - getSigningPayload
  - submitSignedTransaction
"""
import pytest

ELECTOR_ADDRESS = "-1:3333333333333333333333333333333333333333333333333333333333333333"
VALID_EMPTY_CELL_BOC = "te6ccgEBAQEAAgAAAA=="


class TestGetAccountCapability:
    METHOD = "getAccountCapability"

    def test_basic(self, api_method_call):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["@type"] == "account.capability"
        assert result["address"] == ELECTOR_ADDRESS
        assert "account_model" in result
        assert "authorization_version" in result
        assert "supports_delegation" in result
        assert "supports_sessions" in result
        assert "supports_agents" in result
        assert "account_state" in result
        assert "revision" in result

    def test_invalid_address(self, api_method_call):
        response = api_method_call(self.METHOD, address="invalid")
        assert response.json()["ok"] is False


class TestBuildTransactionIntent:
    METHOD = "buildTransactionIntent"

    def test_basic(self, api_method_call_no_get):
        response = api_method_call_no_get(
            self.METHOD,
            address=ELECTOR_ADDRESS,
            body=VALID_EMPTY_CELL_BOC,
        )
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["@type"] == "transaction.intent"
        assert result["from"] == ELECTOR_ADDRESS
        assert result["action"]["@type"] == "transaction.action.externalMessage"
        assert result["authorization_roles"]["@type"] == "account.authorizationRoles"
        assert result["authorization_roles"]["signer"] == ELECTOR_ADDRESS

    def test_missing_body(self, api_method_call_no_get):
        response = api_method_call_no_get(self.METHOD, address=ELECTOR_ADDRESS)
        assert response.json()["ok"] is False


class TestGetSigningPayload:
    METHOD = "getSigningPayload"

    def test_basic(self, api_method_call_no_get):
        response = api_method_call_no_get(
            self.METHOD,
            address=ELECTOR_ADDRESS,
            body=VALID_EMPTY_CELL_BOC,
        )
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["@type"] == "transaction.signingPayload"
        assert result["payload_version"] == 1
        assert result["payload_encoding"] == "boc_base64"
        assert isinstance(result["payload"], str)
        assert len(result["payload"]) > 0
        assert "chain_id" in result

    def test_nested_intent(self, api_method_call_no_get):
        response = api_method_call_no_get(
            self.METHOD,
            intent={
                "from": ELECTOR_ADDRESS,
                "account_model": "unknown",
                "authorization_version": "unknown",
                "action": {
                    "address": ELECTOR_ADDRESS,
                    "body": VALID_EMPTY_CELL_BOC,
                    "init_code": "",
                    "init_data": "",
                },
                "authorization_roles": {
                    "signer": ELECTOR_ADDRESS,
                    "submitter": ELECTOR_ADDRESS,
                    "fee_payer": ELECTOR_ADDRESS,
                },
            },
        )
        assert response.status_code == 200, response.json().get("error")
        assert response.json()["ok"] is True


class TestSubmitSignedTransaction:
    METHOD = "submitSignedTransaction"

    def test_missing_artifact(self, api_method_call_no_get):
        response = api_method_call_no_get(self.METHOD)
        assert response.json()["ok"] is False

    def test_basic(self, api_method_call_no_get):
        payload_resp = api_method_call_no_get(
            "getSigningPayload",
            address=ELECTOR_ADDRESS,
            body=VALID_EMPTY_CELL_BOC,
        )
        assert payload_resp.status_code == 200, payload_resp.json().get("error")
        payload = payload_resp.json()["result"]["payload"]

        response = api_method_call_no_get(self.METHOD, boc=payload, signer=ELECTOR_ADDRESS)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["@type"] == "transaction.submissionResult"
        assert "accepted" in result
        assert "transaction_hash" in result
        assert "submission_id" in result
        assert result["authorization_roles"]["@type"] == "account.authorizationRoles"

    def test_invalid_boc(self, api_method_call_no_get):
        response = api_method_call_no_get(self.METHOD, boc="dGVzdA==")
        assert response.json()["ok"] is False
