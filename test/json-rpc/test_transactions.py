"""
Transaction-related JSON-RPC method tests for TOS.

Covers:
  - getTransactions
  - getTransactionsStd    (TOS-exclusive)
  - getBlockTransactions
  - getBlockTransactionsExt
  - tryLocateTx
  - tryLocateResultTx
  - tryLocateSourceTx
  - getAccountEvents / getAccountEvent (TOS-native history)
"""
import pytest
from rpc_contract import (
    SHARD_ALL,
    assert_success,
    expect_error,
    expect_invalid_param,
    expect_result,
)

# The elector contract always has recent transactions.
ELECTOR_ADDRESS = "-1:3333333333333333333333333333333333333333333333333333333333333333"


# ═══════════════════════════════════════════════════════════════════════════
#  1. getTransactions
# ═══════════════════════════════════════════════════════════════════════════

class TestGetTransactions:

    METHOD = "getTransactions"

    def test_basic(self, api_method_call):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, limit=5)
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)
        assert isinstance(data["result"], list)
        assert len(data["result"]) > 0
        first_tx = data["result"][0]
        assert first_tx["@type"] == "raw.transaction"
        assert "transaction_id" in first_tx

    def test_limit_respected(self, api_method_call):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, limit=2)
        assert response.status_code == 200
        data = response.json()
        assert len(data["result"]) <= 2

    def test_missing_address(self, api_method_call):
        response = api_method_call(self.METHOD, limit=5)
        expect_error(response)

    def test_invalid_address(self, api_method_call):
        response = api_method_call(self.METHOD, address="invalid", limit=5)
        expect_error(response)

    def test_with_lt_and_hash(self, api_method_call):
        """Fetch latest tx, then use its lt/hash to paginate."""
        resp1 = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, limit=1)
        assert resp1.status_code == 200
        txs = resp1.json()["result"]
        if not txs:
            pytest.skip("No transactions available")
        tx = txs[0]
        lt = tx["transaction_id"]["lt"]
        tx_hash = tx["transaction_id"]["hash"]
        resp2 = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, limit=5,
                                lt=lt, hash=tx_hash)
        assert resp2.status_code == 200
        expect_result(resp2)

    def test_lt_without_hash(self, api_method_call):
        """Providing lt without hash should return an error."""
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, lt="12345")
        expect_error(response)

    def test_hash_without_lt(self, api_method_call):
        """Providing hash without lt should return an error."""
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS,
                                   hash="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        expect_error(response)


# ═══════════════════════════════════════════════════════════════════════════
#  2. getTransactionsStd  (TOS exclusive)
# ═══════════════════════════════════════════════════════════════════════════

class TestGetTransactionsStd:

    METHOD = "getTransactionsStd"

    def test_basic(self, api_method_call):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, limit=5)
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)
        result = data["result"]
        assert result["@type"] == "raw.transactions"
        assert isinstance(result["transactions"], list)
        assert "previous_transaction_id" in result

    def test_missing_address(self, api_method_call):
        response = api_method_call(self.METHOD, limit=5)
        expect_error(response)

    def test_lt_without_hash(self, api_method_call):
        """Providing lt without hash should return an error."""
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, lt="12345")
        expect_error(response)


class TestAccountEvents:

    def test_list_contract_and_cursor(self, api_method_call):
        response = api_method_call("getAccountEvents", address="0:" + "0" * 64, limit=2)
        assert response.status_code == 200
        data = response.json()
        assert_success(data)
        result = data["result"]
        assert result["@type"] == "wallet.accountEvents"
        assert isinstance(result["events"], list)
        assert "next_from" in result
        assert len(result["events"]) <= 2

    def test_invalid_cursor(self, api_method_call):
        response = api_method_call("getAccountEvents", address="0:" + "0" * 64,
                                   before_lt="not-a-number")
        expect_error(response)

    def test_detail_validates_event_id(self, api_method_call):
        response = api_method_call("getAccountEvent", address="0:" + "0" * 64,
                                   event_id="invalid")
        expect_error(response)


# ═══════════════════════════════════════════════════════════════════════════
#  3. getBlockTransactions
# ═══════════════════════════════════════════════════════════════════════════

class TestGetBlockTransactions:

    METHOD = "getBlockTransactions"

    def test_basic(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1,
                                   shard=SHARD_ALL, seqno=last_mc_seqno)
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)
        assert data["result"]["@type"] == "blocks.transactions"
        assert data["result"]["id"]["@type"] == "tos.blockIdExt"

    def test_wrong_workchain(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain="invalid",
                                   shard=SHARD_ALL, seqno=last_mc_seqno)
        expect_invalid_param(response, "workchain")

    def test_malformed_shard(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1,
                                   shard="zz", seqno=last_mc_seqno)
        expect_invalid_param(response, "shard")

    def test_unsigned_shard(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1,
                                   shard="9223372036854775808", seqno=last_mc_seqno)
        expect_invalid_param(response, "shard")

    def test_block_id_shard_is_signed(self, api_method_call, last_mc_seqno):
        result = expect_result(api_method_call(self.METHOD, workchain=-1,
                                               shard=SHARD_ALL, seqno=last_mc_seqno))
        assert result["id"]["shard"] == SHARD_ALL

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL,
                                   seqno=last_mc_seqno + 1000000)
        expect_error(response)


# ═══════════════════════════════════════════════════════════════════════════
#  4. getBlockTransactionsExt
# ═══════════════════════════════════════════════════════════════════════════

class TestGetBlockTransactionsExt:

    METHOD = "getBlockTransactionsExt"

    def test_basic(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1,
                                   shard=SHARD_ALL, seqno=last_mc_seqno)
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)

    def test_malformed_shard(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1,
                                   shard="zz", seqno=last_mc_seqno)
        expect_invalid_param(response, "shard")

    def test_missing_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL)
        expect_invalid_param(response, "seqno")

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL,
                                   seqno=last_mc_seqno + 1000000)
        expect_error(response)


# ═══════════════════════════════════════════════════════════════════════════
#  5. tryLocateTx
# ═══════════════════════════════════════════════════════════════════════════

class TestTryLocateTx:

    METHOD = "tryLocateTx"

    def test_basic(self, api_method_call):
        """Look up a recent elector transaction by its source address + lt."""
        # First fetch a real transaction so we have a valid (source, created_lt) pair.
        resp = api_method_call("getTransactions", address=ELECTOR_ADDRESS, limit=1)
        if resp.status_code != 200 or not resp.json().get("result"):
            pytest.skip("Cannot fetch elector transactions")
        tx = resp.json()["result"][0]
        lt = tx["transaction_id"]["lt"]

        response = api_method_call(
            self.METHOD, source=ELECTOR_ADDRESS,
            destination=ELECTOR_ADDRESS, created_lt=lt,
        )
        # tryLocateTx may succeed or answer a structured error on a local testnet.
        assert response.status_code == 200, response.text
        body = response.json()
        if "error" in body:
            expect_error(response)
        else:
            assert_success(body)

    def test_missing_params(self, api_method_call):
        response = api_method_call(self.METHOD)
        expect_error(response)


# ═══════════════════════════════════════════════════════════════════════════
#  6. tryLocateResultTx
# ═══════════════════════════════════════════════════════════════════════════

class TestTryLocateResultTx:

    METHOD = "tryLocateResultTx"

    def test_missing_params(self, api_method_call):
        response = api_method_call(self.METHOD)
        expect_error(response)


# ═══════════════════════════════════════════════════════════════════════════
#  7. tryLocateSourceTx
# ═══════════════════════════════════════════════════════════════════════════

class TestTryLocateSourceTx:

    METHOD = "tryLocateSourceTx"

    def test_missing_params(self, api_method_call):
        response = api_method_call(self.METHOD)
        expect_error(response)
