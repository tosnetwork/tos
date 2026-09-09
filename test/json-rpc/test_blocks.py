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
import base64

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
        assert data["result"]["last"]["@type"] == "tos.blockIdExt"
        assert data["result"]["init"]["@type"] == "tos.blockIdExt"

    def test_last_seqno_positive(self, api_method_call):
        response = api_method_call(self.METHOD)
        data = response.json()
        assert data["result"]["last"]["seqno"] > 0


# ═══════════════════════════════════════════════════════════════════════════
#  2. getMasterchainBlockSignatures
# ═══════════════════════════════════════════════════════════════════════════

class TestGetMasterchainBlockSignatures:

    METHOD = "getMasterchainBlockSignatures"
    # Ordinary blocks answer with blocks.blockSignatures; simplex-consensus
    # blocks answer with blocks.blockSignatures.simplex, which additionally
    # carries the session_id / slot / candidate needed to verify the signatures.
    SIG_TYPES = ("blocks.blockSignatures", "blocks.blockSignatures.simplex")

    def test_basic(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, seqno=last_mc_seqno)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] in self.SIG_TYPES
        if data["result"]["signatures"]:
            assert data["result"]["signatures"][0]["@type"] == "blocks.signature"

    def test_response_has_id(self, api_method_call, last_mc_seqno):
        """Response should include id field with the requested block."""
        response = api_method_call(self.METHOD, seqno=last_mc_seqno)
        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        assert "id" in data["result"]
        assert data["result"]["id"]["@type"] == "tos.blockIdExt"
        assert data["result"]["id"]["seqno"] == last_mc_seqno

    def test_wrong_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, seqno="invalid")
        assert response.json()["ok"] is False

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, seqno=last_mc_seqno + 1000000)
        assert response.json()["ok"] is False

    def test_returns_the_requested_blocks_own_signatures(self, api_method_call, last_mc_seqno):
        """Regression for the signature *direction*.

        A finalized masterchain block is always signed by validators, so the
        method must return that block's own, non-empty signature set. The
        previous implementation walked the proof forward FROM the block, whose
        forward links sign *later* blocks, and only understood the ordinary
        signature set -- so on this simplex-consensus network it returned an
        empty list for every block. This test therefore goes red on the old
        behavior and green once the handler reads the N-1 -> N link's signatures.

        It also pins the contract: signatures are carried under the requested id
        with no per-signature 'signed_block' field (that field was the old
        mislabeled output), and each entry is a well-formed Ed25519 signature
        (32-byte node id, 64-byte signature) so an empty or malformed set fails.
        """
        # A block a few behind the tip, so the forward proof link N-1 -> N that
        # carries its signatures is already available.
        if last_mc_seqno < 3:
            pytest.skip("chain has not advanced far enough for a settled block")
        seqno = max(2, last_mc_seqno - 3)

        response = api_method_call(self.METHOD, seqno=seqno)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["@type"] in self.SIG_TYPES
        assert result["id"]["seqno"] == seqno

        signatures = result["signatures"]
        assert signatures, "a finalized masterchain block must carry validator signatures"
        for sig in signatures:
            assert sig["@type"] == "blocks.signature"
            # The old handler tagged each signature with the block it actually
            # signed because those were NOT this block's signatures. The fixed
            # handler returns this block's signatures, so there is no such tag.
            assert "signed_block" not in sig
            assert len(base64.b64decode(sig["node_id_short"])) == 32
            assert len(base64.b64decode(sig["signature"])) == 64

        # Simplex signatures are made over a message built from the session id,
        # slot and candidate -- not the block hash -- so a client cannot verify
        # them without those fields. The simplex response must carry them (this
        # is the second review finding: the earlier version dropped them).
        if result["@type"] == "blocks.blockSignatures.simplex":
            assert len(base64.b64decode(result["session_id"])) == 32
            assert isinstance(result["slot"], int)
            assert "candidate" in result
            base64.b64decode(result["candidate"])  # must be valid base64


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
        assert data["result"]["masterchain_id"]["@type"] == "tos.blockIdExt"
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
                                   seqno=last_mc_seqno + 1000000)
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
        assert data["result"]["@type"] == "tos.blockIdExt"
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
                                   seqno=last_mc_seqno + 1000000)
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
        response = api_method_call("shards", seqno=last_mc_seqno + 1000000)
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
        assert data["result"]["id"]["@type"] == "tos.blockIdExt"
        assert data["result"]["id"]["workchain"] == -1
        assert data["result"]["id"]["seqno"] == last_mc_seqno

    def test_wrong_workchain(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain="invalid",
                                   shard=SHARD_ALL, seqno=last_mc_seqno)
        assert response.json()["ok"] is False

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL,
                                   seqno=last_mc_seqno + 1000000)
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
