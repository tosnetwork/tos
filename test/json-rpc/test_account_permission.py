"""
Account-permission JSON-RPC method tests for TOS.

Covers:
  - getAccountCapability
  - buildTransactionIntent
  - getSigningPayload
  - submitSignedTransaction
"""
import json
import time
from pathlib import Path

import pytest

ELECTOR_ADDRESS = "-1:3333333333333333333333333333333333333333333333333333333333333333"
UNINITIALIZED_ADDRESS = "-1:1111111111111111111111111111111111111111111111111111111111111111"
VALID_EMPTY_CELL_BOC = "te6ccgEBAQEAAgAAAA=="
DEPLOYED_FILE = Path(__file__).parent / "deployed_addresses.json"


def _load_deployed() -> dict:
    if not DEPLOYED_FILE.exists():
        return {}
    return json.loads(DEPLOYED_FILE.read_text())


def _call_until_ok(call, *, retries: int = 12, delay_s: float = 1.0):
    last = None
    for _ in range(retries):
        last = call()
        try:
            data = last.json()
        except Exception:
            time.sleep(delay_s)
            continue
        if last.status_code == 200 and data.get("ok") is True:
            return last
        if "block (" not in str(data.get("error", "")) or "is not applied" not in str(data.get("error", "")):
            return last
        time.sleep(delay_s)
    return last


@pytest.fixture(scope="module")
def wallets():
    data = _load_deployed()
    return data.get("wallets", {})


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
        assert "delegation_source" in result
        assert "session_source" in result
        assert "agent_source" in result
        assert "capability_maturity" in result
        assert "account_state" in result
        assert "revision" in result

    def test_invalid_address(self, api_method_call):
        response = api_method_call(self.METHOD, address="invalid")
        assert response.json()["ok"] is False

    def test_multisig_account_standard_support(self, api_method_call, wallets):
        info = wallets.get("multisig")
        if not info or not info.get("address"):
            pytest.skip("multisig not deployed")
        response = _call_until_ok(lambda: api_method_call(self.METHOD, address=info["address"]))
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["account_model"] == "advanced.wallet.multisig"
        assert result["supports_agents"] is True
        assert result["agent_source"] == "account_standard"
        assert result["capability_maturity"] == "supported"


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

    def test_delegation_reference_rejected(self, api_method_call_no_get):
        response = api_method_call_no_get(
            self.METHOD,
            address=ELECTOR_ADDRESS,
            body=VALID_EMPTY_CELL_BOC,
            delegation_ref="example",
        )
        data = response.json()
        assert data["ok"] is False
        assert "FEATURE_DEFERRED" in data["error"]

    def test_distinct_fee_payer_rejected(self, api_method_call_no_get):
        response = api_method_call_no_get(
            self.METHOD,
            address=ELECTOR_ADDRESS,
            body=VALID_EMPTY_CELL_BOC,
            signer=ELECTOR_ADDRESS,
            fee_payer="-1:1111111111111111111111111111111111111111111111111111111111111111",
        )
        data = response.json()
        assert data["ok"] is False
        assert "FEATURE_DEFERRED" in data["error"]


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

    def test_permission_reference_rejected(self, api_method_call_no_get):
        response = api_method_call_no_get(
            self.METHOD,
            intent={
                "from": ELECTOR_ADDRESS,
                "body": VALID_EMPTY_CELL_BOC,
                "delegation_ref": "example",
            },
        )
        data = response.json()
        assert data["ok"] is False
        assert "FEATURE_DEFERRED" in data["error"]


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


@pytest.mark.parametrize(
    "method_name",
    ["getAccountDelegations", "getAccountSessions", "getAccountAgents"],
)
class TestDeferredPermissionInspection:
    def test_deferred_for_advanced_unknown(self, api_method_call, method_name):
        response = api_method_call(method_name, address=ELECTOR_ADDRESS)
        data = response.json()
        assert data["ok"] is False
        assert "PERMISSION_SOURCE_DEFERRED" in data["error"]

    def test_unsupported_for_uninitialized_account(self, api_method_call, method_name):
        response = api_method_call(method_name, address=UNINITIALIZED_ADDRESS)
        data = response.json()
        assert data["ok"] is False
        assert "PERMISSION_SOURCE_UNSUPPORTED" in data["error"]

    def test_indexed_source_requires_fresh_index(self, api_method_call, method_name):
        response = api_method_call(method_name, address=ELECTOR_ADDRESS, source_tier="indexed")
        data = response.json()
        assert data["ok"] is False
        assert "INDEXED_STATE_STALE" in data["error"]

    def test_invalid_status_filter(self, api_method_call, method_name):
        response = api_method_call(method_name, address=ELECTOR_ADDRESS, status="bad")
        data = response.json()
        assert data["ok"] is False

    def test_invalid_source_tier(self, api_method_call, method_name):
        response = api_method_call(method_name, address=ELECTOR_ADDRESS, source_tier="bogus")
        data = response.json()
        assert data["ok"] is False

    def test_invalid_address(self, api_method_call, method_name):
        response = api_method_call(method_name, address="invalid")
        data = response.json()
        assert data["ok"] is False


class TestAccountStandardAgentInspection:
    METHOD = "getAccountAgents"

    def test_multisig_agents(self, api_method_call, wallets):
        info = wallets.get("multisig")
        if not info or not info.get("address"):
            pytest.skip("multisig not deployed")

        response = _call_until_ok(lambda: api_method_call(self.METHOD, address=info["address"]))
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert isinstance(result, list)
        assert len(result) == info.get("n", 3)

        for agent in result:
            assert agent["@type"] == "account.agentCapability"
            assert agent["account"] == info["address"]
            assert agent["scope"] == "agent_execution"
            assert agent["status"] == "active"
            assert agent["constraints"]["threshold_n"] == info.get("n", 3)
            assert agent["constraints"]["threshold_k"] == info.get("k", 2)
            assert agent["principal"].startswith("ed25519:")
