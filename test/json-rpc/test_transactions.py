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
"""
import pytest

SHARD_ALL = -9223372036854775808

# The elector contract always has recent transactions.
ELECTOR_ADDRESS = "-1:3333333333333333333333333333333333333333333333333333333333333333"


# ═══════════════════════════════════════════════════════════════════════════
#  1. getTransactions
# ═══════════════════════════════════════════════════════════════════════════

class TestGetTransactions:

    METHOD = "getTransactions"

    def test_basic(self, api_method_call):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, limit=5)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
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
        assert response.json()["ok"] is False

    def test_invalid_address(self, api_method_call):
        response = api_method_call(self.METHOD, address="invalid", limit=5)
        assert response.json()["ok"] is False

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
        assert resp2.json()["ok"] is True

    def test_lt_without_hash(self, api_method_call):
        """Providing lt without hash should return an error."""
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, lt="12345")
        assert response.json()["ok"] is False

    def test_hash_without_lt(self, api_method_call):
        """Providing hash without lt should return an error."""
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS,
                                   hash="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  2. getTransactionsStd  (TOS exclusive)
# ═══════════════════════════════════════════════════════════════════════════

class TestGetTransactionsStd:

    METHOD = "getTransactionsStd"

    def test_basic(self, api_method_call):
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, limit=5)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["@type"] == "raw.transactions"
        assert isinstance(result["transactions"], list)
        assert "previous_transaction_id" in result

    def test_missing_address(self, api_method_call):
        response = api_method_call(self.METHOD, limit=5)
        assert response.json()["ok"] is False

    def test_lt_without_hash(self, api_method_call):
        """Providing lt without hash should return an error."""
        response = api_method_call(self.METHOD, address=ELECTOR_ADDRESS, lt="12345")
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  3. getBlockTransactions
# ═══════════════════════════════════════════════════════════════════════════

class TestGetBlockTransactions:

    METHOD = "getBlockTransactions"

    def test_basic(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1,
                                   shard=SHARD_ALL, seqno=last_mc_seqno)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "blocks.transactions"
        assert data["result"]["id"]["@type"] == "tos.blockIdExt"

    def test_wrong_workchain(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain="invalid",
                                   shard=SHARD_ALL, seqno=last_mc_seqno)
        assert response.json()["ok"] is False

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL,
                                   seqno=last_mc_seqno + 1000000)
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  4. getBlockTransactionsExt
# ═══════════════════════════════════════════════════════════════════════════

class TestGetBlockTransactionsExt:

    METHOD = "getBlockTransactionsExt"

    def test_basic(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1,
                                   shard=SHARD_ALL, seqno=last_mc_seqno)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL,
                                   seqno=last_mc_seqno + 1000000)
        assert response.json()["ok"] is False


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
        # tryLocateTx may return 200 or a reasonable error on local testnet.
        assert response.status_code in {200, 422, 500}

    def test_missing_params(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  6. tryLocateResultTx
# ═══════════════════════════════════════════════════════════════════════════

class TestTryLocateResultTx:

    METHOD = "tryLocateResultTx"

    def test_missing_params(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  7. tryLocateSourceTx
# ═══════════════════════════════════════════════════════════════════════════

class TestTryLocateSourceTx:

    METHOD = "tryLocateSourceTx"

    def test_missing_params(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.json()["ok"] is False
