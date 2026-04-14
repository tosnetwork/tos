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
        assert data["result"]["signatures"][0]["@type"] == "blocks.signature"

    def test_wrong_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, seqno="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, seqno=last_mc_seqno + 10000)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  3. getShardBlockProof
# ═══════════════════════════════════════════════════════════════════════════

class TestGetShardBlockProof:

    METHOD = "getShardBlockProof"

    def test_basic(self, api_method_call, last_mc_seqno):
        seqno = last_mc_seqno - 100
        from_seqno = last_mc_seqno
        response = api_method_call(
            self.METHOD, workchain=-1, shard=SHARD_ALL,
            seqno=seqno, from_seqno=from_seqno,
        )
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "blocks.shardBlockProof"

        result = data["result"]
        assert result["from"]["@type"] == "ton.blockIdExt"
        assert result["from"]["workchain"] == -1
        assert result["from"]["shard"] == str(SHARD_ALL)
        assert result["from"]["seqno"] == from_seqno

        assert result["mc_id"]["@type"] == "ton.blockIdExt"
        assert result["mc_id"]["workchain"] == -1
        assert result["mc_id"]["shard"] == str(SHARD_ALL)
        assert result["mc_id"]["seqno"] == seqno

        mc_proof = result["mc_proof"][0]
        assert mc_proof["@type"] == "blocks.blockLinkBack"
        assert mc_proof["from"]["@type"] == "ton.blockIdExt"
        assert mc_proof["from"]["workchain"] == -1
        assert mc_proof["from"]["shard"] == str(SHARD_ALL)
        assert mc_proof["from"]["seqno"] == from_seqno
        assert mc_proof["from"]["seqno"] == result["from"]["seqno"]

        assert mc_proof["to"]["@type"] == "ton.blockIdExt"
        assert mc_proof["to"]["workchain"] == -1
        assert mc_proof["to"]["shard"] == str(SHARD_ALL)
        assert mc_proof["to"]["seqno"] == seqno

        assert "dest_proof" in mc_proof
        assert "proof" in mc_proof
        assert "state_proof" in mc_proof

    def test_wrong_workchain(self, api_method_call):
        response = api_method_call(self.METHOD, workchain="invalid",
                                   shard=SHARD_ALL, seqno=1, from_seqno=1)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_empty_workchain(self, api_method_call):
        response = api_method_call(self.METHOD, shard=SHARD_ALL, seqno=1, from_seqno=1)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_wrong_shard(self, api_method_call):
        response = api_method_call(self.METHOD, workchain=-1, shard="invalid", seqno=1)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_empty_shard(self, api_method_call):
        response = api_method_call(self.METHOD, workchain=-1, seqno=1)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_wrong_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL, seqno="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL,
                                   seqno=last_mc_seqno + 10000)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_negative_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL, seqno=-1)
        assert response.status_code == 200
        assert response.json()["ok"] is False
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
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_wrong_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL, seqno="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL,
                                   seqno=last_mc_seqno + 10000)
        assert response.status_code == 200
        assert response.json()["ok"] is False
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
        response = api_method_call("shards", seqno="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call("shards", seqno=last_mc_seqno + 10000)
        assert response.status_code == 200
        assert response.json()["ok"] is False
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
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL,
                                   seqno=last_mc_seqno + 10000)
        assert response.status_code == 200
        assert response.json()["ok"] is False
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
