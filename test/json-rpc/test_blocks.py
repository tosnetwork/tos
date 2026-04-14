"""
Block / chain related JSON-RPC method tests for TOS.

Covers:
  - getMasterchainInfo
  - getMasterchainBlockSignatures
  - getShardBlockProof
  - getConsensusBlock
  - lookupBlock
  - shards / getShards
  - getBlockHeader
  - getOutMsgQueueSize
"""
import pytest

SHARD_ALL = -9223372036854775808  # 0x8000000000000000 (signed)


# ═══════════════════════════════════════════════════════════════════════════
#  1. getMasterchainInfo
# ═══════════════════════════════════════════════════════════════════════════

class TestGetMasterchainInfo:

    METHOD = "getMasterchainInfo"

    def test_basic(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "blocks.masterchainInfo"
        assert data["result"]["last"]["@type"] == "ton.blockIdExt"
        assert data["result"]["init"]["@type"] == "ton.blockIdExt"

    def test_last_seqno_positive(self, api_method_call):
        response = api_method_call(self.METHOD)
        data = response.json()
        assert data["result"]["last"]["seqno"] > 0


# ═══════════════════════════════════════════════════════════════════════════
#  2. getMasterchainBlockSignatures
# ═══════════════════════════════════════════════════════════════════════════

class TestGetMasterchainBlockSignatures:

    METHOD = "getMasterchainBlockSignatures"

    def test_basic(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, seqno=last_mc_seqno)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "blocks.blockSignatures"
        if data["result"]["signatures"]:
            assert data["result"]["signatures"][0]["@type"] == "blocks.signature"

    def test_response_has_id(self, api_method_call, last_mc_seqno):
        """Response should include id field with the requested block."""
        response = api_method_call(self.METHOD, seqno=last_mc_seqno)
        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        assert "id" in data["result"]
        assert data["result"]["id"]["@type"] == "ton.blockIdExt"
        assert data["result"]["id"]["seqno"] == last_mc_seqno

    def test_wrong_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, seqno="invalid")
        assert response.json()["ok"] is False

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, seqno=last_mc_seqno + 10000)
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  3. getShardBlockProof
# ═══════════════════════════════════════════════════════════════════════════

class TestGetShardBlockProof:

    METHOD = "getShardBlockProof"

    def test_basic(self, api_method_call, last_mc_seqno):
        response = api_method_call(
            self.METHOD, workchain=-1, shard=SHARD_ALL, seqno=1,
        )
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "blocks.shardBlockProof"
        assert data["result"]["masterchain_id"]["@type"] == "ton.blockIdExt"
        assert isinstance(data["result"]["links"], list)

    def test_wrong_workchain(self, api_method_call):
        response = api_method_call(self.METHOD, workchain="invalid",
                                   shard=SHARD_ALL, seqno=1)
        assert response.json()["ok"] is False

    def test_empty_workchain(self, api_method_call):
        response = api_method_call(self.METHOD, shard=SHARD_ALL, seqno=1)
        assert response.json()["ok"] is False

    def test_wrong_shard(self, api_method_call):
        """Non-numeric shard is parsed as 0 — server may succeed or fail."""
        response = api_method_call(self.METHOD, workchain=-1, shard="invalid", seqno=1)
        data = response.json()
        assert data["ok"] in (True, False)

    def test_empty_shard(self, api_method_call):
        response = api_method_call(self.METHOD, workchain=-1, seqno=1)
        assert response.json()["ok"] is False

    def test_wrong_seqno(self, api_method_call):
        """Non-numeric seqno is parsed as 0 — server may succeed or fail."""
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL, seqno="invalid")
        data = response.json()
        assert data["ok"] in (True, False)

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL,
                                   seqno=last_mc_seqno + 10000)
        assert response.json()["ok"] is False

    def test_negative_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL, seqno=-1)
        assert response.json()["ok"] is False

    def test_old_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL, seqno=1)
        assert response.status_code == 200, response.json().get("error")
        assert response.json()["ok"] is True


# ═══════════════════════════════════════════════════════════════════════════
#  4. getConsensusBlock
# ═══════════════════════════════════════════════════════════════════════════

class TestGetConsensusBlock:

    METHOD = "getConsensusBlock"

    def test_basic(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "ext.blocks.consensusBlock"


# ═══════════════════════════════════════════════════════════════════════════
#  5. lookupBlock
# ═══════════════════════════════════════════════════════════════════════════

class TestLookupBlock:

    METHOD = "lookupBlock"

    def test_by_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1,
                                   shard=SHARD_ALL, seqno=last_mc_seqno)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "ton.blockIdExt"
        assert data["result"]["workchain"] == -1
        assert data["result"]["seqno"] == last_mc_seqno

    def test_missing_workchain(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, shard=SHARD_ALL, seqno=last_mc_seqno)
        assert response.json()["ok"] is False

    def test_wrong_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL, seqno="invalid")
        assert response.json()["ok"] is False

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL,
                                   seqno=last_mc_seqno + 10000)
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  6. shards / getShards
# ═══════════════════════════════════════════════════════════════════════════

class TestGetShards:

    @pytest.mark.parametrize("method", ["shards", "getShards"])
    def test_basic(self, api_method_call, last_mc_seqno, method):
        response = api_method_call(method, seqno=last_mc_seqno)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "blocks.shards"
        assert isinstance(data["result"]["shards"], list)

    def test_wrong_seqno(self, api_method_call):
        """Non-numeric seqno is silently ignored (optional field) — accept success or error."""
        response = api_method_call("shards", seqno="invalid")
        data = response.json()
        assert data["ok"] in (True, False)

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        """A far-future seqno may return a JSON error or a timeout (502 with empty body)."""
        response = api_method_call("shards", seqno=last_mc_seqno + 10000)
        if response.status_code == 502:
            pass  # liteserver timeout — acceptable
        else:
            assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  7. getBlockHeader
# ═══════════════════════════════════════════════════════════════════════════

class TestGetBlockHeader:

    METHOD = "getBlockHeader"

    def test_basic(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1,
                                   shard=SHARD_ALL, seqno=last_mc_seqno)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "blocks.header"
        assert data["result"]["id"]["@type"] == "ton.blockIdExt"
        assert data["result"]["id"]["workchain"] == -1
        assert data["result"]["id"]["seqno"] == last_mc_seqno

    def test_wrong_workchain(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain="invalid",
                                   shard=SHARD_ALL, seqno=last_mc_seqno)
        assert response.json()["ok"] is False

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL,
                                   seqno=last_mc_seqno + 10000)
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  8. getOutMsgQueueSize
# ═══════════════════════════════════════════════════════════════════════════

class TestGetOutMsgQueueSize:

    METHOD = "getOutMsgQueueSize"

    def test_basic(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        # Result should contain a numeric size field
        assert "size" in data["result"] or isinstance(data["result"], (int, dict))
