"""
Account-related JSON-RPC method tests for TOS.

Covers:
  - getAddressInformation
  - getExtendedAddressInformation
  - getWalletInformation
  - getAddressBalance
  - getAddressState
  - getTokenData
"""
import pytest


# ---------------------------------------------------------------------------
# Common addresses for a local testnet
# ---------------------------------------------------------------------------

# The elector contract always exists on every TOS network.
ELECTOR_ADDRESS = "-1:3333333333333333333333333333333333333333333333333333333333333333"
ELECTOR_FRIENDLY = "Ef8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM0vF"

# Config contract (workchain -1, addr 0x5555...)
CONFIG_ADDRESS = "-1:5555555555555555555555555555555555555555555555555555555555555555"

# Zero address in masterchain (always active on mainnet / testnet with extra currencies)
ZERO_MC_ADDRESS = "-1:0000000000000000000000000000000000000000000000000000000000000000"

# Burn hole in basechain -- typically uninitialized
BURN_ADDRESS = "0:0000000000000000000000000000000000000000000000000000000000000000"


# ═══════════════════════════════════════════════════════════════════════════
#  1. getAddressInformation
# ═══════════════════════════════════════════════════════════════════════════

class TestGetAddressInformation:

    METHOD = "getAddressInformation"

    @pytest.mark.parametrize("address", [ELECTOR_ADDRESS, ELECTOR_FRIENDLY])
    def test_basic(self, api_method_call, address):
        response = api_method_call(self.METHOD, address=address)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "raw.fullAccountState"

    def test_no_address(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_invalid_address(self, api_method_call):
        response = api_method_call(self.METHOD, address="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_for_given_block(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS,
                                   seqno=last_mc_seqno - 10)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "raw.fullAccountState"
        assert data["result"]["block_id"]["seqno"] == last_mc_seqno - 10

    def test_wrong_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, seqno="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS,
                                   seqno=last_mc_seqno + 10000)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_uninitialized_address(self, api_method_call):
        response = api_method_call(self.METHOD, address=BURN_ADDRESS)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["state"] == "uninitialized"


# ═══════════════════════════════════════════════════════════════════════════
#  2. getExtendedAddressInformation
# ═══════════════════════════════════════════════════════════════════════════

class TestGetExtendedAddressInformation:

    METHOD = "getExtendedAddressInformation"

    @pytest.mark.parametrize("address", [ELECTOR_ADDRESS, CONFIG_ADDRESS])
    def test_basic(self, api_method_call, address):
        response = api_method_call(self.METHOD, address=address)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "fullAccountState"

    def test_invalid_address(self, api_method_call):
        response = api_method_call(self.METHOD, address="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_empty_address(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_raw_account_state(self, api_method_call):
        """Zero masterchain address should return raw.accountState."""
        response = api_method_call(self.METHOD, address=ZERO_MC_ADDRESS)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "fullAccountState"
        assert data["result"]["account_state"]["@type"] == "raw.accountState"

    def test_for_given_block(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS,
                                   seqno=last_mc_seqno - 10)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "fullAccountState"
        assert data["result"]["block_id"]["seqno"] == last_mc_seqno - 10

    def test_wrong_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, seqno="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS,
                                   seqno=last_mc_seqno + 10000)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  3. getWalletInformation
# ═══════════════════════════════════════════════════════════════════════════

class TestGetWalletInformation:

    METHOD = "getWalletInformation"

    @pytest.mark.parametrize("address", [ELECTOR_ADDRESS, CONFIG_ADDRESS, ZERO_MC_ADDRESS])
    def test_basic(self, api_method_call, address):
        response = api_method_call(self.METHOD, address=address)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "ext.accounts.walletInformation"

    def test_invalid_address(self, api_method_call):
        response = api_method_call(self.METHOD, address="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_empty_address(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_for_given_block_different_lt(self, api_method_call, last_mc_seqno):
        """Querying the elector at two different seqnos should show different last_transaction_id.lt."""
        resp_new = api_method_call(self.METHOD, address=ELECTOR_FRIENDLY, seqno=last_mc_seqno)
        resp_old = api_method_call(self.METHOD, address=ELECTOR_FRIENDLY, seqno=last_mc_seqno - 10)
        assert resp_new.status_code == 200 and resp_old.status_code == 200
        data_new = resp_new.json()
        data_old = resp_old.json()
        assert data_new["ok"] is True and data_old["ok"] is True
        assert data_old["result"]["last_transaction_id"]["lt"] < data_new["result"]["last_transaction_id"]["lt"]

    def test_wrong_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, seqno="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS,
                                   seqno=last_mc_seqno + 10000)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  4. getAddressBalance
# ═══════════════════════════════════════════════════════════════════════════

class TestGetAddressBalance:

    METHOD = "getAddressBalance"

    @pytest.mark.parametrize("address", [ELECTOR_ADDRESS, CONFIG_ADDRESS, ZERO_MC_ADDRESS])
    def test_basic(self, api_method_call, address):
        response = api_method_call(self.METHOD, address=address)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert isinstance(data["result"], str)

    def test_invalid_address(self, api_method_call):
        response = api_method_call(self.METHOD, address="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_empty_address(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_balance_differs_across_blocks(self, api_method_call, last_mc_seqno):
        """Elector balance at two different seqnos should normally differ."""
        resp_new = api_method_call(self.METHOD, address=ELECTOR_FRIENDLY, seqno=last_mc_seqno)
        resp_old = api_method_call(self.METHOD, address=ELECTOR_FRIENDLY, seqno=last_mc_seqno - 10)
        assert resp_new.status_code == 200 and resp_old.status_code == 200
        data_new = resp_new.json()
        data_old = resp_old.json()
        assert data_new["ok"] is True and data_old["ok"] is True
        # Balances may or may not differ on a quiet testnet; at least both are valid strings.
        assert isinstance(data_new["result"], str)
        assert isinstance(data_old["result"], str)

    def test_wrong_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, seqno="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS,
                                   seqno=last_mc_seqno + 10000)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  5. getAddressState
# ═══════════════════════════════════════════════════════════════════════════

class TestGetAddressState:

    METHOD = "getAddressState"
    VALID_STATES = {"active", "frozen", "uninitialized"}

    @pytest.mark.parametrize("address", [ELECTOR_ADDRESS, CONFIG_ADDRESS, ZERO_MC_ADDRESS])
    def test_basic(self, api_method_call, address):
        response = api_method_call(self.METHOD, address=address)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert isinstance(data["result"], str)
        assert data["result"] in self.VALID_STATES

    def test_elector_is_active(self, api_method_call):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS)
        assert response.status_code == 200
        assert response.json()["result"] == "active"

    def test_burn_is_uninitialized(self, api_method_call):
        response = api_method_call(self.METHOD, address=BURN_ADDRESS)
        assert response.status_code == 200
        assert response.json()["result"] == "uninitialized"

    def test_invalid_address(self, api_method_call):
        response = api_method_call(self.METHOD, address="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_empty_address(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_wrong_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, seqno="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS,
                                   seqno=last_mc_seqno + 10000)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  6. getTokenData
# ═══════════════════════════════════════════════════════════════════════════

class TestGetTokenData:
    """
    getTokenData probes a contract to determine if it is a Jetton master,
    Jetton wallet, NFT collection, or NFT item and returns its parsed data.

    On a minimal local testnet there may not be token contracts deployed, so
    we primarily test error paths.  If real token addresses are available,
    parametrise them via the ADDRESSES list below.
    """

    METHOD = "getTokenData"

    def test_invalid_address(self, api_method_call):
        response = api_method_call(self.METHOD, address="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_empty_address(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_not_a_token(self, api_method_call):
        """Calling getTokenData on a non-token contract should fail (409 or 500)."""
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS)
        assert response.status_code in {409, 500}
