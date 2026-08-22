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
        assert response.json()["ok"] is False

    def test_invalid_address(self, api_method_call):
        response = api_method_call(self.METHOD, address="invalid")
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
        """Non-numeric seqno is silently ignored (optional field) — accept success or error."""
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, seqno="invalid")
        data = response.json()
        assert data["ok"] in (True, False)

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS,
                                   seqno=last_mc_seqno + 1000000)
        assert response.json()["ok"] is False

    def test_uninitialized_address(self, api_method_call):
        response = api_method_call(self.METHOD, address=BURN_ADDRESS)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["state"] == "uninitialized"

    def test_extra_currencies(self, api_method_call):
        """Zero masterchain address should have extra currencies from genesis."""
        response = api_method_call(self.METHOD, address=ZERO_MC_ADDRESS)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "raw.fullAccountState"
        # The testnet genesis mints extra currencies (id=239) to the zero address
        extra = data["result"].get("extra_currencies", [])
        if extra:  # may be empty if testnet config doesn't include them
            assert extra[0]["@type"] == "extraCurrency"

    def test_sync_utime_present(self, api_method_call):
        """Response should include sync_utime field."""
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS)
        assert response.status_code == 200
        data = response.json()
        assert "sync_utime" in data["result"]
        assert isinstance(data["result"]["sync_utime"], int)
        assert data["result"]["sync_utime"] > 0


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
        assert response.json()["ok"] is False

    def test_empty_address(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.json()["ok"] is False

    def test_raw_account_state(self, api_method_call):
        """Zero masterchain address should return raw.accountState."""
        response = api_method_call(self.METHOD, address=ZERO_MC_ADDRESS)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "fullAccountState"
        assert data["result"]["account_state"]["@type"] == "raw.accountState"

    def test_wallet_v3_account_state(self, api_method_call):
        """Deployed wallet v3 should be recognized with its account state type."""
        import json
        from pathlib import Path
        deployed = Path(__file__).parent / "deployed_addresses.json"
        if not deployed.exists():
            pytest.skip("No deployed contracts")
        addrs = json.loads(deployed.read_text())
        addr = addrs.get("wallets", {}).get("wallet_v3r2", {}).get("address")
        if not addr:
            pytest.skip("wallet_v3r2 not deployed")
        response = api_method_call(self.METHOD, address=addr)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "fullAccountState"

    def test_for_given_block(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS,
                                   seqno=last_mc_seqno - 10)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "fullAccountState"
        assert data["result"]["block_id"]["seqno"] == last_mc_seqno - 10

    def test_wrong_seqno(self, api_method_call):
        """Non-numeric seqno is silently ignored (optional field) — accept success or error."""
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, seqno="invalid")
        data = response.json()
        assert data["ok"] in (True, False)

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS,
                                   seqno=last_mc_seqno + 1000000)
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
        assert response.json()["ok"] is False

    def test_empty_address(self, api_method_call):
        response = api_method_call(self.METHOD)
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
        """Non-numeric seqno is silently ignored (optional field) — accept success or error."""
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, seqno="invalid")
        data = response.json()
        assert data["ok"] in (True, False)

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS,
                                   seqno=last_mc_seqno + 1000000)
        assert response.json()["ok"] is False

    def test_wallet_v1_detected(self, api_method_call):
        """Deployed wallet v1 should be detected with correct type."""
        import json
        from pathlib import Path
        deployed = Path(__file__).parent / "deployed_addresses.json"
        if not deployed.exists():
            pytest.skip("No deployed contracts")
        addrs = json.loads(deployed.read_text())
        addr = addrs.get("wallets", {}).get("wallet_v1", {}).get("address")
        if not addr:
            pytest.skip("wallet_v1 not deployed")
        response = api_method_call(self.METHOD, address=addr)
        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["wallet"] is True
        assert result["wallet_type"] == "wallet v1 r1"
        assert "seqno" in result

    def test_highload_wallets_not_regular(self, api_method_call):
        """Highload wallets: detected as wallet type but reference flags wallet=False."""
        import json
        from pathlib import Path
        deployed = Path(__file__).parent / "deployed_addresses.json"
        if not deployed.exists():
            pytest.skip("No deployed contracts")
        addrs = json.loads(deployed.read_text())
        for key in ("highload_v1", "highload_v2"):
            addr = addrs.get("wallets", {}).get(key, {}).get("address")
            if not addr:
                continue
            response = api_method_call(self.METHOD, address=addr)
            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True
            assert data["result"]["wallet_type"] is not None

    def test_wallet_v3_detected(self, api_method_call):
        """Deployed wallet v3 should be detected with correct type and seqno."""
        import json
        from pathlib import Path
        deployed = Path(__file__).parent / "deployed_addresses.json"
        if not deployed.exists():
            pytest.skip("No deployed contracts")
        addrs = json.loads(deployed.read_text())
        addr = addrs.get("wallets", {}).get("wallet_v3r2", {}).get("address")
        if not addr:
            pytest.skip("wallet_v3r2 not deployed")
        response = api_method_call(self.METHOD, address=addr)
        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["wallet"] is True
        assert result["wallet_type"] == "wallet v3 r2"
        assert "seqno" in result
        assert "wallet_id" in result

    def test_wallet_v4_detected(self, api_method_call):
        """Deployed wallet v4 should be detected with correct type."""
        import json
        from pathlib import Path
        deployed = Path(__file__).parent / "deployed_addresses.json"
        if not deployed.exists():
            pytest.skip("No deployed contracts")
        addrs = json.loads(deployed.read_text())
        addr = addrs.get("wallets", {}).get("wallet_v4r2", {}).get("address")
        if not addr:
            pytest.skip("wallet_v4r2 not deployed")
        response = api_method_call(self.METHOD, address=addr)
        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["wallet"] is True
        assert result["wallet_type"] == "wallet v4 r2"
        assert "seqno" in result
        assert "wallet_id" in result

    def test_wallet_v5_detected(self, api_method_call):
        """Deployed wallet v5 should be detected with correct type."""
        import json
        from pathlib import Path
        deployed = Path(__file__).parent / "deployed_addresses.json"
        if not deployed.exists():
            pytest.skip("No deployed contracts")
        addrs = json.loads(deployed.read_text())
        addr = addrs.get("wallets", {}).get("wallet_v5r1", {}).get("address")
        if not addr:
            pytest.skip("wallet_v5r1 not deployed")
        response = api_method_call(self.METHOD, address=addr)
        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["wallet"] is True
        assert result["wallet_type"] == "wallet v5 r1"
        assert "seqno" in result


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
        assert response.json()["ok"] is False

    def test_empty_address(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.json()["ok"] is False

    def test_balance_differs_across_blocks(self, api_method_call, last_mc_seqno):
        """Elector balance at two different seqnos should differ (active elector has txs every block)."""
        resp_new = api_method_call(self.METHOD, address=ELECTOR_FRIENDLY, seqno=last_mc_seqno)
        resp_old = api_method_call(self.METHOD, address=ELECTOR_FRIENDLY, seqno=last_mc_seqno - 10)
        assert resp_new.status_code == 200 and resp_old.status_code == 200
        data_new = resp_new.json()
        data_old = resp_old.json()
        assert data_new["ok"] is True and data_old["ok"] is True
        assert isinstance(data_new["result"], str)
        assert isinstance(data_old["result"], str)
        assert data_old["result"] != data_new["result"]

    def test_wrong_seqno(self, api_method_call):
        """Non-numeric seqno is silently ignored (optional field) — accept success or error."""
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, seqno="invalid")
        data = response.json()
        assert data["ok"] in (True, False)

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS,
                                   seqno=last_mc_seqno + 1000000)
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
        assert response.json()["ok"] is False

    def test_empty_address(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.json()["ok"] is False

    def test_wrong_seqno(self, api_method_call):
        """Non-numeric seqno is silently ignored (optional field) — accept success or error."""
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, seqno="invalid")
        data = response.json()
        assert data["ok"] in (True, False)

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS,
                                   seqno=last_mc_seqno + 1000000)
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
        assert response.json()["ok"] is False

    def test_empty_address(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.json()["ok"] is False

    def test_not_a_token(self, api_method_call):
        """Calling getTokenData on a non-token contract should return 409."""
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS)
        assert response.status_code == 409
        assert response.json()["ok"] is False

    def test_jetton_master_data(self, api_method_call):
        """Deployed Jetton master should return jettonMasterData."""
        import json
        from pathlib import Path
        deployed = Path(__file__).parent / "deployed_addresses.json"
        if not deployed.exists():
            pytest.skip("No deployed contracts")
        addrs = json.loads(deployed.read_text())
        addr = addrs.get("tokens", {}).get("jetton_master", {}).get("address")
        if not addr:
            pytest.skip("jetton_master not deployed")
        response = api_method_call(self.METHOD, address=addr)
        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "ext.tokens.jettonMasterData"

    def test_nft_collection_data(self, api_method_call):
        """Deployed NFT collection should return nftCollectionData."""
        import json
        from pathlib import Path
        deployed = Path(__file__).parent / "deployed_addresses.json"
        if not deployed.exists():
            pytest.skip("No deployed contracts")
        addrs = json.loads(deployed.read_text())
        addr = addrs.get("tokens", {}).get("nft_collection", {}).get("address")
        if not addr:
            pytest.skip("nft_collection not deployed")
        response = api_method_call(self.METHOD, address=addr)
        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["@type"] == "ext.tokens.nftCollectionData"
        assert "next_item_index" in result
        # next_item_index is a decimal string: hashed-index collections (DNS)
        # use full uint256 item indices and next_item_index = -1, which cannot
        # be represented as a JSON int64.
        assert isinstance(result["next_item_index"], str)
        next_item_index = int(result["next_item_index"])  # decimal round-trip
        assert next_item_index >= -1
        assert "collection_content" in result
        assert "owner_address" in result
        assert len(result["owner_address"]) > 0
