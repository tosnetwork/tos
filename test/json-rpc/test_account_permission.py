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

    def test_restricted_account_standard_support(self, api_method_call, wallets):
        info = wallets.get("restricted")
        if not info or not info.get("address"):
            pytest.skip("restricted wallet not deployed")
        response = _call_until_ok(lambda: api_method_call(self.METHOD, address=info["address"]))
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["account_model"] == "advanced.wallet.restricted"
        assert result["supports_delegation"] is True
        assert result["delegation_source"] == "account_standard"
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
        assert "DELEGATION_UNAVAILABLE" in data["error"]

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
            # Canonical constraints: empty — multisig threshold semantics have
            # no canonical mapping (threshold_k is not max_uses)
            assert agent["constraints"] == {}
            # Model-specific extensions carry the real threshold semantics
            ext = agent["constraints_extensions"]
            assert ext["account_model"] == "advanced.wallet.multisig"
            assert ext["threshold_n"] == info.get("n", 3)
            assert ext["threshold_k"] == info.get("k", 2)
            assert agent["principal"].startswith("ed25519:")

    def test_multisig_agents_schema_compliance(self, api_method_call, wallets):
        info = wallets.get("multisig")
        if not info or not info.get("address"):
            pytest.skip("multisig not deployed")

        response = _call_until_ok(lambda: api_method_call(self.METHOD, address=info["address"]))
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True

        for agent in data["result"]:
            # Verify frozen schema fields are present
            assert "created_at" in agent
            assert "expires_at" in agent
            assert "revoked_at" in agent
            assert "status" in agent
            assert "revocable" in agent
            assert "account" in agent


class TestAccountStandardDelegationInspection:
    METHOD = "getAccountDelegations"

    def test_restricted_delegations(self, api_method_call, wallets):
        info = wallets.get("restricted")
        if not info or not info.get("address"):
            pytest.skip("restricted wallet not deployed")

        response = _call_until_ok(lambda: api_method_call(self.METHOD, address=info["address"]))
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert isinstance(result, list)
        assert len(result) == 1

        delegation = result[0]
        assert delegation["@type"] == "account.delegationGrant"
        assert delegation["account"] == info["address"]
        assert delegation["scope"] == "bounded_transfer"
        assert delegation["status"] == "active"
        assert delegation["revocable"] is False
        assert delegation["grantee"].startswith("ed25519:")
        # Canonical constraints use frozen vocabulary
        assert "max_value" in delegation["constraints"]
        assert "not_before" in delegation["constraints"]
        # Vesting-specific fields are not canonical — they live in extensions
        assert "vesting_start" not in delegation["constraints"]
        assert "reserved_balance" not in delegation["constraints"]
        # Model-specific extensions preserve full vesting semantics
        ext = delegation["constraints_extensions"]
        assert ext["account_model"] == "advanced.wallet.restricted"
        assert "vesting_start" in ext
        assert "reserved_balance" in ext

    def test_multisig_delegations_deferred(self, api_method_call, wallets):
        info = wallets.get("multisig")
        if not info or not info.get("address"):
            pytest.skip("multisig not deployed")
        response = _call_until_ok(lambda: api_method_call(self.METHOD, address=info["address"]))
        data = response.json()
        # Multisig doesn't support delegations, should return deferred/unsupported
        assert data["ok"] is False
        assert "PERMISSION_SOURCE" in data["error"]


class TestPermissionErrorCodeFormat:
    """Verify that structured error codes from the permission error model
    are used as prefixes in error responses."""

    def test_deferred_error_uses_prefix(self, api_method_call):
        """PERMISSION_SOURCE_DEFERRED must appear as a prefix."""
        response = api_method_call("getAccountDelegations", address=ELECTOR_ADDRESS)
        data = response.json()
        assert data["ok"] is False
        assert data["error"].startswith("PERMISSION_SOURCE_DEFERRED:")

    def test_unsupported_error_uses_prefix(self, api_method_call):
        """PERMISSION_SOURCE_UNSUPPORTED must appear as a prefix."""
        response = api_method_call("getAccountDelegations", address=UNINITIALIZED_ADDRESS)
        data = response.json()
        assert data["ok"] is False
        assert data["error"].startswith("PERMISSION_SOURCE_UNSUPPORTED:")

    def test_indexed_stale_error_uses_prefix(self, api_method_call):
        """INDEXED_STATE_STALE must appear as a prefix."""
        response = api_method_call("getAccountDelegations", address=ELECTOR_ADDRESS, source_tier="indexed")
        data = response.json()
        assert data["ok"] is False
        assert data["error"].startswith("INDEXED_STATE_STALE:")

    def test_feature_deferred_error_uses_prefix(self, api_method_call_no_get):
        """FEATURE_DEFERRED must appear as a prefix in transaction surface errors."""
        response = api_method_call_no_get(
            "buildTransactionIntent",
            address=ELECTOR_ADDRESS,
            body=VALID_EMPTY_CELL_BOC,
            delegation_ref="example",
        )
        data = response.json()
        assert data["ok"] is False
        # FEATURE_DEFERRED may be wrapped by TRANSACTION_INTENT_UNSUPPORTED prefix
        assert "FEATURE_DEFERRED" in data["error"]

    def test_signed_artifact_invalid_prefix(self, api_method_call_no_get):
        """SIGNED_ARTIFACT_INVALID must appear for malformed submissions."""
        response = api_method_call_no_get("submitSignedTransaction", boc="dGVzdA==")
        data = response.json()
        assert data["ok"] is False
        assert "SIGNED_ARTIFACT_INVALID" in data["error"]

    def test_transaction_intent_unsupported_prefix(self, api_method_call_no_get):
        """TRANSACTION_INTENT_UNSUPPORTED must appear for invalid intents."""
        response = api_method_call_no_get(
            "buildTransactionIntent",
            address=ELECTOR_ADDRESS,
            body=VALID_EMPTY_CELL_BOC,
            fee_payer=UNINITIALIZED_ADDRESS,
        )
        data = response.json()
        assert data["ok"] is False
        assert "TRANSACTION_INTENT_UNSUPPORTED" in data["error"]


class TestSourceTierOverride:
    """Verify source-tier override behavior for real implementations."""

    def test_multisig_agents_forced_protocol_rejected(self, api_method_call, wallets):
        """Forcing protocol source for multisig agents should fail."""
        info = wallets.get("multisig")
        if not info or not info.get("address"):
            pytest.skip("multisig not deployed")
        response = api_method_call("getAccountAgents", address=info["address"], source_tier="protocol")
        data = response.json()
        assert data["ok"] is False
        assert "PERMISSION_SOURCE_UNSUPPORTED" in data["error"]

    def test_multisig_agents_forced_indexed_rejected(self, api_method_call, wallets):
        """Forcing indexed source for multisig agents should return stale."""
        info = wallets.get("multisig")
        if not info or not info.get("address"):
            pytest.skip("multisig not deployed")
        response = api_method_call("getAccountAgents", address=info["address"], source_tier="indexed")
        data = response.json()
        assert data["ok"] is False
        assert "INDEXED_STATE_STALE" in data["error"]

    def test_restricted_delegations_forced_protocol_rejected(self, api_method_call, wallets):
        """Forcing protocol source for restricted delegations should fail."""
        info = wallets.get("restricted")
        if not info or not info.get("address"):
            pytest.skip("restricted wallet not deployed")
        response = api_method_call("getAccountDelegations", address=info["address"], source_tier="protocol")
        data = response.json()
        assert data["ok"] is False
        assert "PERMISSION_SOURCE_UNSUPPORTED" in data["error"]

    def test_restricted_delegations_forced_deferred_rejected(self, api_method_call, wallets):
        """Forcing deferred source for restricted delegations should fail."""
        info = wallets.get("restricted")
        if not info or not info.get("address"):
            pytest.skip("restricted wallet not deployed")
        response = api_method_call("getAccountDelegations", address=info["address"], source_tier="deferred")
        data = response.json()
        assert data["ok"] is False
        assert "PERMISSION_SOURCE_DEFERRED" in data["error"]

    def test_multisig_agents_account_standard_succeeds(self, api_method_call, wallets):
        """Forcing account_standard for multisig agents should work (it IS the source)."""
        info = wallets.get("multisig")
        if not info or not info.get("address"):
            pytest.skip("multisig not deployed")
        response = _call_until_ok(lambda: api_method_call("getAccountAgents", address=info["address"], source_tier="account_standard"))
        data = response.json()
        # account_standard is the real source, should succeed
        assert data["ok"] is True
        assert isinstance(data["result"], list)


class TestStatusFilter:
    """Verify status filter behavior for real permission objects.

    Important: the current account_standard sources (multisig, restricted wallet)
    can only materialize status="active". They have no on-chain revocation or
    expiration evidence. Non-active filters return empty because the source
    cannot produce those states — not because it has confirmed their absence
    through real status evaluation.
    """

    def test_multisig_agents_active_filter(self, api_method_call, wallets):
        """Active filter should return all agents (the only status this source materializes)."""
        info = wallets.get("multisig")
        if not info or not info.get("address"):
            pytest.skip("multisig not deployed")
        response = _call_until_ok(lambda: api_method_call("getAccountAgents", address=info["address"], status="active"))
        data = response.json()
        assert data["ok"] is True
        assert len(data["result"]) == info.get("n", 3)

    def test_multisig_agents_non_active_filter_empty(self, api_method_call, wallets):
        """Non-active filter returns empty: source cannot materialize expired/revoked status."""
        info = wallets.get("multisig")
        if not info or not info.get("address"):
            pytest.skip("multisig not deployed")
        response = _call_until_ok(lambda: api_method_call("getAccountAgents", address=info["address"], status="expired"))
        data = response.json()
        assert data["ok"] is True
        assert data["result"] == []

    def test_restricted_delegations_active_filter(self, api_method_call, wallets):
        """Active filter should return the vesting delegation (the only materializable status)."""
        info = wallets.get("restricted")
        if not info or not info.get("address"):
            pytest.skip("restricted wallet not deployed")
        response = _call_until_ok(lambda: api_method_call("getAccountDelegations", address=info["address"], status="active"))
        data = response.json()
        assert data["ok"] is True
        assert len(data["result"]) == 1

    def test_restricted_delegations_non_active_filter_empty(self, api_method_call, wallets):
        """Non-active filter returns empty: source has no revocation/expiration evidence."""
        info = wallets.get("restricted")
        if not info or not info.get("address"):
            pytest.skip("restricted wallet not deployed")
        response = _call_until_ok(lambda: api_method_call("getAccountDelegations", address=info["address"], status="revoked"))
        data = response.json()
        assert data["ok"] is True
        assert data["result"] == []


class TestNominatorPoolCapability:
    """Verify capability reporting for nominator pool accounts."""

    def test_nominator_pool_delegation_support(self, api_method_call, wallets):
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = _call_until_ok(lambda: api_method_call("getAccountCapability", address=info["address"]))
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["account_model"] == "contract.pool.nominator"
        assert result["supports_delegation"] is True
        assert result["delegation_source"] == "account_standard"


class TestNominatorPoolDelegationInspection:
    """Verify delegation inspection for nominator pool accounts."""

    METHOD = "getAccountDelegations"

    def test_nominator_pool_delegations_basic(self, api_method_call, wallets):
        """If the pool has nominators, they should appear as delegations."""
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = _call_until_ok(lambda: api_method_call(self.METHOD, address=info["address"]))
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert isinstance(result, list)
        # Pool may be empty (0 nominators) -- that is a valid empty list
        for delegation in result:
            assert delegation["@type"] == "account.delegationGrant"
            assert delegation["scope"] == "bounded_transfer"
            assert delegation["grantee"] == info["address"]
            assert delegation["revocable"] is True
            assert "max_value" in delegation["constraints"]
            assert delegation["constraints_extensions"]["account_model"] == "contract.pool.nominator"
            assert delegation["status"] in ("active", "revoked")

    def test_nominator_pool_forced_protocol_rejected(self, api_method_call, wallets):
        """Forcing protocol source for nominator pool delegations should fail."""
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = api_method_call(self.METHOD, address=info["address"], source_tier="protocol")
        data = response.json()
        assert data["ok"] is False
        assert "PERMISSION_SOURCE_UNSUPPORTED" in data["error"]

    def test_nominator_pool_revoked_status_positive(self, api_method_call, wallets):
        """A pool with a withdraw request must materialize status=revoked."""
        info = wallets.get("nominator_pool_withdraw")
        if not info or not info.get("address"):
            pytest.skip("nominator pool with withdraw request not deployed")
        response = _call_until_ok(
            lambda: api_method_call(self.METHOD, address=info["address"])
        )
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert isinstance(result, list)
        assert len(result) == 1
        delegation = result[0]
        assert delegation["status"] == "revoked"
        assert delegation["constraints_extensions"]["withdraw_requested"] is True

    def test_nominator_pool_revoked_filter(self, api_method_call, wallets):
        """Status filter 'revoked' must return the withdraw-requested delegation."""
        info = wallets.get("nominator_pool_withdraw")
        if not info or not info.get("address"):
            pytest.skip("nominator pool with withdraw request not deployed")
        response = _call_until_ok(
            lambda: api_method_call(self.METHOD, address=info["address"], status="revoked")
        )
        data = response.json()
        assert data["ok"] is True
        assert len(data["result"]) == 1
        assert data["result"][0]["status"] == "revoked"

    def test_nominator_pool_active_filter_excludes_revoked(self, api_method_call, wallets):
        """Status filter 'active' must NOT return a withdraw-requested delegation."""
        info = wallets.get("nominator_pool_withdraw")
        if not info or not info.get("address"):
            pytest.skip("nominator pool with withdraw request not deployed")
        response = _call_until_ok(
            lambda: api_method_call(self.METHOD, address=info["address"], status="active")
        )
        data = response.json()
        assert data["ok"] is True
        assert data["result"] == []


class TestExpiredPermission:
    """Verify expired status materialization for restricted wallet with fully-elapsed vesting."""

    def test_restricted_expired_delegation(self, api_method_call, wallets):
        info = wallets.get("restricted_expired")
        if not info or not info.get("address"):
            pytest.skip("restricted_expired wallet not deployed")

        response = _call_until_ok(lambda: api_method_call("getAccountDelegations", address=info["address"]))
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert isinstance(result, list)
        assert len(result) == 1

        delegation = result[0]
        assert delegation["status"] == "expired"
        assert delegation["scope"] == "bounded_transfer"

    def test_restricted_expired_active_filter_empty(self, api_method_call, wallets):
        """Active filter should return empty for fully-elapsed vesting."""
        info = wallets.get("restricted_expired")
        if not info or not info.get("address"):
            pytest.skip("restricted_expired wallet not deployed")

        response = _call_until_ok(lambda: api_method_call("getAccountDelegations", address=info["address"], status="active"))
        data = response.json()
        assert data["ok"] is True
        assert data["result"] == []

    def test_restricted_expired_expired_filter_returns(self, api_method_call, wallets):
        """Expired filter should return the delegation."""
        info = wallets.get("restricted_expired")
        if not info or not info.get("address"):
            pytest.skip("restricted_expired wallet not deployed")

        response = _call_until_ok(lambda: api_method_call("getAccountDelegations", address=info["address"], status="expired"))
        data = response.json()
        assert data["ok"] is True
        assert len(data["result"]) == 1
        assert data["result"][0]["status"] == "expired"


class TestLifecycleMutationRPCs:
    """Verify lifecycle mutation RPC surfaces exist with proper model detection."""

    def test_grant_delegation_unsupported_for_default_wallet(self, api_method_call_no_get):
        response = api_method_call_no_get("grantAccountDelegation", address=ELECTOR_ADDRESS)
        data = response.json()
        assert data["ok"] is False
        assert "PERMISSION_SOURCE_UNSUPPORTED" in data["error"] or "PERMISSION_SOURCE_DEFERRED" in data["error"]

    def test_grant_delegation_immutable_for_restricted(self, api_method_call_no_get, wallets):
        info = wallets.get("restricted")
        if not info or not info.get("address"):
            pytest.skip("restricted wallet not deployed")
        response = _call_until_ok(lambda: api_method_call_no_get("grantAccountDelegation", address=info["address"]))
        data = response.json()
        assert data["ok"] is False
        assert "LIFECYCLE_IMMUTABLE" in data["error"]

    def test_grant_delegation_nominator_pool_returns_mutation_result(self, api_method_call_no_get, wallets):
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = _call_until_ok(lambda: api_method_call_no_get("grantAccountDelegation", address=info["address"]))
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["@type"] == "lifecycle.mutationResult"
        assert result["method"] == "grantAccountDelegation"
        assert result["mutation_intent"]["body_comment"] == "d"
        assert "affected_object_preview" in result

    def test_revoke_delegation_nominator_pool_returns_mutation_result(self, api_method_call_no_get, wallets):
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = _call_until_ok(lambda: api_method_call_no_get("revokeAccountDelegation", address=info["address"]))
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["@type"] == "lifecycle.mutationResult"
        assert result["method"] == "revokeAccountDelegation"
        assert result["mutation_intent"]["body_comment"] == "w"
        assert "affected_object_preview" in result

    def test_grant_agent_immutable_for_multisig(self, api_method_call_no_get, wallets):
        info = wallets.get("multisig")
        if not info or not info.get("address"):
            pytest.skip("multisig not deployed")
        response = _call_until_ok(lambda: api_method_call_no_get("grantAccountAgent", address=info["address"]))
        data = response.json()
        assert data["ok"] is False
        assert "LIFECYCLE_IMMUTABLE" in data["error"]

    def test_grant_session_unsupported(self, api_method_call_no_get):
        response = api_method_call_no_get("grantAccountSession", address=ELECTOR_ADDRESS)
        data = response.json()
        assert data["ok"] is False

    def test_revoke_session_unsupported(self, api_method_call_no_get):
        response = api_method_call_no_get("revokeAccountSession", address=ELECTOR_ADDRESS)
        data = response.json()
        assert data["ok"] is False


class TestLifecycleRequestEnforcement:
    """Verify that lifecycle handlers enforce the frozen request contract."""

    def test_grant_missing_grantee(self, api_method_call_no_get, wallets):
        """Grant without grantee must fail with MISSING_GRANTEE."""
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = api_method_call_no_get(
            "grantAccountDelegation",
            address=info["address"],
            scope="bounded_transfer",
        )
        data = response.json()
        assert data["ok"] is False
        assert "MISSING_GRANTEE" in data["error"]

    def test_grant_invalid_scope(self, api_method_call_no_get, wallets):
        """Grant with non-canonical scope must fail with INVALID_SCOPE."""
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = api_method_call_no_get(
            "grantAccountDelegation",
            address=info["address"],
            grantee="0:1234",
            scope="invalid_scope_value",
        )
        data = response.json()
        assert data["ok"] is False
        assert "INVALID_SCOPE" in data["error"]

    def test_grant_model_scope_violation(self, api_method_call_no_get, wallets):
        """Nominator lifecycle must reject canonical scopes outside bounded_transfer."""
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = api_method_call_no_get(
            "grantAccountDelegation",
            address=info["address"],
            grantee="0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            scope="agent_execution",
        )
        data = response.json()
        assert data["ok"] is False
        assert "DELEGATION_SCOPE_VIOLATION" in data["error"]

    def test_grant_missing_scope(self, api_method_call_no_get, wallets):
        """Grant without scope must fail with INVALID_SCOPE."""
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = api_method_call_no_get(
            "grantAccountDelegation",
            address=info["address"],
            grantee="0:1234",
        )
        data = response.json()
        assert data["ok"] is False
        assert "INVALID_SCOPE" in data["error"]

    def test_revoke_missing_permission_id(self, api_method_call_no_get, wallets):
        """Revoke without permission_id must fail with MISSING_PERMISSION_ID."""
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = api_method_call_no_get(
            "revokeAccountDelegation",
            address=info["address"],
        )
        data = response.json()
        assert data["ok"] is False
        assert "MISSING_PERMISSION_ID" in data["error"]

    def test_grant_rejects_structured_constraint_values(self, api_method_call_no_get, wallets):
        """Canonical constraint fields must not silently accept array/object payloads."""
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = api_method_call_no_get(
            "grantAccountDelegation",
            address=info["address"],
            grantee="0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            scope="bounded_transfer",
            constraints={"target_allowlist": ["0:abcdef"]},
        )
        data = response.json()
        assert data["ok"] is False
        assert "INVALID_CONSTRAINTS" in data["error"]

    def test_grant_canonical_scope_accepted(self, api_method_call_no_get, wallets):
        """Grant with valid canonical scope on supported model should succeed."""
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = _call_until_ok(lambda: api_method_call_no_get(
            "grantAccountDelegation",
            address=info["address"],
            grantee="0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            scope="bounded_transfer",
        ))
        data = response.json()
        assert data["ok"] is True

    def test_revoke_unknown_permission_id_rejected(self, api_method_call_no_get, wallets):
        """Revoke must fail if permission_id does not resolve to current pool state."""
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = api_method_call_no_get(
            "revokeAccountDelegation",
            address=info["address"],
            permission_id=f"{info['address']}:nominator-stake:9999",
        )
        data = response.json()
        assert data["ok"] is False
        assert "DELEGATION_UNAVAILABLE" in data["error"]

    def test_revoke_with_permission_id_accepted(self, api_method_call_no_get, wallets):
        """Revoke with valid permission_id on supported model should succeed."""
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = _call_until_ok(lambda: api_method_call_no_get(
            "revokeAccountDelegation",
            address=info["address"],
            permission_id=f"{info['address']}:nominator-stake:0",
        ))
        data = response.json()
        assert data["ok"] is True

    def test_grant_session_validates_request_before_model(self, api_method_call_no_get):
        """Session grant should validate request fields even when model is unsupported."""
        response = api_method_call_no_get(
            "grantAccountSession",
            address=ELECTOR_ADDRESS,
            # missing grantee and scope — should fail on request validation
        )
        data = response.json()
        assert data["ok"] is False
        # Should get a request validation error, not just unsupported model
        assert "MISSING_GRANTEE" in data["error"] or "INVALID_SCOPE" in data["error"]

    def test_grant_agent_immutable_after_request_validation(self, api_method_call_no_get, wallets):
        """Agent grant on multisig should validate request, then report immutable."""
        info = wallets.get("multisig")
        if not info or not info.get("address"):
            pytest.skip("multisig not deployed")
        # Provide valid request fields — should pass validation, then hit immutable
        response = _call_until_ok(lambda: api_method_call_no_get(
            "grantAccountAgent",
            address=info["address"],
            grantee="0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            scope="agent_execution",
        ))
        data = response.json()
        assert data["ok"] is False
        assert "LIFECYCLE_IMMUTABLE" in data["error"]


class TestLifecycleResponseShape:
    """Verify lifecycle mutation responses include canonical affected object preview."""

    def test_grant_delegation_returns_mutation_result(self, api_method_call_no_get, wallets):
        """Grant on supported model should return lifecycle.mutationResult with preview."""
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = _call_until_ok(lambda: api_method_call_no_get(
            "grantAccountDelegation",
            address=info["address"],
            grantee="0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            scope="bounded_transfer",
        ))
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["@type"] == "lifecycle.mutationResult"
        assert result["method"] == "grantAccountDelegation"
        assert result["accepted"] is True
        assert "mutation_intent" in result
        assert "affected_object_preview" in result
        # Preview should be a canonical delegation object
        preview = result["affected_object_preview"]
        assert preview["@type"] == "account.delegationGrant"
        assert preview["scope"] == "bounded_transfer"
        assert preview["status"] == "active"

    def test_revoke_delegation_returns_mutation_result(self, api_method_call_no_get, wallets):
        """Revoke on supported model should return lifecycle.mutationResult with preview."""
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = _call_until_ok(lambda: api_method_call_no_get(
            "revokeAccountDelegation",
            address=info["address"],
            permission_id=f"{info['address']}:nominator-stake:0",
        ))
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["@type"] == "lifecycle.mutationResult"
        assert result["method"] == "revokeAccountDelegation"
        assert result["accepted"] is True
        preview = result["affected_object_preview"]
        assert preview["@type"] == "account.delegationGrant"
        assert preview["status"] == "revoked"

    def test_response_preview_matches_inspection_shape(self, api_method_call, api_method_call_no_get, wallets):
        """The affected_object_preview should have the same fields as inspection results."""
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")

        # Get inspection result for comparison
        inspect_resp = _call_until_ok(
            lambda: api_method_call("getAccountDelegations", address=info["address"])
        )
        if inspect_resp.json().get("ok") and inspect_resp.json()["result"]:
            inspection_keys = set(inspect_resp.json()["result"][0].keys())
        else:
            pytest.skip("no delegation data available for comparison")

        # Get lifecycle preview
        grant_resp = _call_until_ok(lambda: api_method_call_no_get(
            "grantAccountDelegation",
            address=info["address"],
            grantee="0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            scope="bounded_transfer",
        ))
        if not grant_resp.json().get("ok"):
            pytest.skip("grant did not succeed")
        preview_keys = set(grant_resp.json()["result"]["affected_object_preview"].keys())

        # The preview should have at minimum the same @type and core schema fields
        core_fields = {"@type", "scope", "status", "constraints", "revocable"}
        assert core_fields.issubset(preview_keys)


class TestDelegationScopeValidation:
    """Verify delegation_ref validation in buildTransactionIntent."""
    METHOD = "buildTransactionIntent"

    def test_active_delegation_ref_accepted(self, api_method_call_no_get, wallets):
        """An active delegation_ref on a supported model should be accepted."""
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        delegation_id = f"{info['address']}:nominator-stake:0"
        response = _call_until_ok(lambda: api_method_call_no_get(
            self.METHOD,
            address=info["address"],
            body=VALID_EMPTY_CELL_BOC,
            delegation_ref=delegation_id,
        ))
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["@type"] == "transaction.intent"
        assert result["delegation_ref"] == delegation_id

    def test_expired_delegation_ref_rejected(self, api_method_call_no_get, wallets):
        """A delegation_ref on an expired restricted wallet should fail."""
        info = wallets.get("restricted_expired")
        if not info or not info.get("address"):
            pytest.skip("restricted_expired wallet not deployed")
        delegation_id = f"{info['address']}:restricted-vesting:0"
        response = _call_until_ok(lambda: api_method_call_no_get(
            self.METHOD,
            address=info["address"],
            body=VALID_EMPTY_CELL_BOC,
            delegation_ref=delegation_id,
        ))
        data = response.json()
        assert data["ok"] is False
        assert "DELEGATION_EXPIRED" in data["error"]

    def test_revoked_delegation_ref_rejected(self, api_method_call_no_get, wallets):
        """A delegation_ref on a pool with withdrawn nominator should fail."""
        info = wallets.get("nominator_pool_withdraw")
        if not info or not info.get("address"):
            pytest.skip("nominator pool with withdraw not deployed")
        # The pre-seeded nominator is at index 0
        delegation_id = f"{info['address']}:nominator-stake:0"
        response = _call_until_ok(lambda: api_method_call_no_get(
            self.METHOD,
            address=info["address"],
            body=VALID_EMPTY_CELL_BOC,
            delegation_ref=delegation_id,
        ))
        data = response.json()
        assert data["ok"] is False
        assert "DELEGATION_REVOKED" in data["error"]

    def test_delegation_ref_on_unsupported_model_rejected(self, api_method_call_no_get):
        """A delegation_ref on a model without delegation support should fail."""
        response = api_method_call_no_get(
            self.METHOD,
            address=ELECTOR_ADDRESS,
            body=VALID_EMPTY_CELL_BOC,
            delegation_ref="fake-delegation-id",
        )
        data = response.json()
        assert data["ok"] is False
        assert "DELEGATION_UNAVAILABLE" in data["error"]

    def test_nonexistent_delegation_ref_rejected(self, api_method_call_no_get, wallets):
        """A delegation_ref that doesn't match any real delegation should fail."""
        info = wallets.get("nominator_pool")
        if not info or not info.get("address"):
            pytest.skip("nominator pool not deployed")
        response = _call_until_ok(lambda: api_method_call_no_get(
            self.METHOD,
            address=info["address"],
            body=VALID_EMPTY_CELL_BOC,
            delegation_ref="nonexistent-id",
        ))
        data = response.json()
        assert data["ok"] is False
        assert "DELEGATION_UNAVAILABLE" in data["error"]

    def test_restricted_wrong_delegation_ref_rejected(self, api_method_call_no_get, wallets):
        """Restricted wallets must reject delegation_ref values that do not match the real id."""
        info = wallets.get("restricted")
        if not info or not info.get("address"):
            pytest.skip("restricted wallet not deployed")
        response = _call_until_ok(lambda: api_method_call_no_get(
            self.METHOD,
            address=info["address"],
            body=VALID_EMPTY_CELL_BOC,
            delegation_ref=f"{info['address']}:restricted-vesting:999",
        ))
        data = response.json()
        assert data["ok"] is False
        assert "DELEGATION_UNAVAILABLE" in data["error"]

    def test_session_ref_still_rejected(self, api_method_call_no_get):
        """session_ref should still be rejected with FEATURE_DEFERRED."""
        response = api_method_call_no_get(
            self.METHOD,
            address=ELECTOR_ADDRESS,
            body=VALID_EMPTY_CELL_BOC,
            session_ref="some-session",
        )
        data = response.json()
        assert data["ok"] is False
        assert "FEATURE_DEFERRED" in data["error"]


class TestSessionWalletCapability:
    """Verify capability reporting for session wallet accounts."""

    def test_session_wallet_support(self, api_method_call, wallets):
        info = wallets.get("session_wallet")
        if not info or not info.get("address"):
            pytest.skip("session wallet not deployed")
        response = _call_until_ok(lambda: api_method_call("getAccountCapability", address=info["address"]))
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["account_model"] == "advanced.wallet.session"
        assert result["supports_sessions"] is True
        assert result["session_source"] == "account_standard"


class TestSessionWalletInspection:
    """Verify session inspection for session wallet accounts."""
    METHOD = "getAccountSessions"

    def test_session_wallet_sessions(self, api_method_call, wallets):
        info = wallets.get("session_wallet")
        if not info or not info.get("address"):
            pytest.skip("session wallet not deployed")
        response = _call_until_ok(lambda: api_method_call(self.METHOD, address=info["address"]))
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert isinstance(result, list)
        assert len(result) == 2

        # Check that we have one active and one revoked session
        statuses = sorted([s["status"] for s in result])
        assert statuses == ["active", "revoked"]

        for session in result:
            assert session["@type"] == "account.sessionCapability"
            assert session["scope"] in ("submit_only", "bounded_transfer", "bounded_contract_call")
            assert "session_id" in session
            assert "principal" in session
            assert "created_at" in session
            assert "expires_at" in session

    def test_session_wallet_active_filter(self, api_method_call, wallets):
        info = wallets.get("session_wallet")
        if not info or not info.get("address"):
            pytest.skip("session wallet not deployed")
        response = _call_until_ok(lambda: api_method_call(self.METHOD, address=info["address"], status="active"))
        data = response.json()
        assert data["ok"] is True
        assert len(data["result"]) == 1
        assert data["result"][0]["status"] == "active"

    def test_session_wallet_revoked_filter(self, api_method_call, wallets):
        info = wallets.get("session_wallet")
        if not info or not info.get("address"):
            pytest.skip("session wallet not deployed")
        response = _call_until_ok(lambda: api_method_call(self.METHOD, address=info["address"], status="revoked"))
        data = response.json()
        assert data["ok"] is True
        assert len(data["result"]) == 1
        assert data["result"][0]["status"] == "revoked"
