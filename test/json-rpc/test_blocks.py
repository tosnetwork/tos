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
from rpc_contract import (
    SHARD_ALL,
    assert_error,
    assert_success,
    expect_error,
    expect_invalid_param,
    expect_result,
)


def assert_block_zero_or_refused(response, block_id_of):
    """seqno 0 is a valid selector for block 0, never the latest block.

    The masterchain zero state has no block record a node can look up, so a
    node may answer with block 0 or refuse; it must not reject the selector
    as malformed and must not answer with a later block.
    """
    body = response.json()
    assert response.status_code == 200, response.text
    if "result" in body:
        block_id = block_id_of(assert_success(body))
        assert block_id["seqno"] == 0, block_id
        assert block_id["shard"] == SHARD_ALL, block_id
    else:
        error = assert_error(body)
        assert error["code"] != -32602, error

# ═══════════════════════════════════════════════════════════════════════════
#  1. getMasterchainInfo
# ═══════════════════════════════════════════════════════════════════════════


class TestGetMasterchainInfo:
    METHOD = "getMasterchainInfo"

    def test_basic(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)
        assert data["result"]["@type"] == "blocks.masterchainInfo"
        assert data["result"]["last"]["@type"] == "tos.blockIdExt"
        assert data["result"]["init"]["@type"] == "tos.blockIdExt"
        assert data["result"]["last"]["shard"] == SHARD_ALL

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
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)
        assert data["result"]["@type"] in self.SIG_TYPES
        if data["result"]["signatures"]:
            assert data["result"]["signatures"][0]["@type"] == "blocks.signature"

    def test_response_has_id(self, api_method_call, last_mc_seqno):
        """Response should include id field with the requested block."""
        response = api_method_call(self.METHOD, seqno=last_mc_seqno)
        assert response.status_code == 200
        data = response.json()
        assert_success(data)
        assert "id" in data["result"]
        assert data["result"]["id"]["@type"] == "tos.blockIdExt"
        assert data["result"]["id"]["seqno"] == last_mc_seqno

    def test_wrong_seqno(self, api_method_call):
        # A verified view: its message is the reason string itself.
        response = api_method_call(self.METHOD, seqno="invalid")
        expect_error(response, -32602, "INVALID_ARGUMENT", retryable=False)

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, seqno=last_mc_seqno + 1000000)
        expect_error(response)

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
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)
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

    def test_simplex_context_is_present_and_not_skippable(self, api_method_call, last_mc_seqno):
        """Regression that the simplex verification context is returned.

        TOS runs simplex consensus, so a finalized masterchain block's
        signatures MUST come back as blocks.blockSignatures.simplex carrying the
        session_id / slot / candidate needed to reconstruct the signed
        finalize-vote message. Unlike the check in the direction test above, this
        asserts the simplex type *unconditionally* rather than behind an
        `if @type == simplex`: a regression that relabelled the response as the
        ordinary blocks.blockSignatures type (dropping the context, the way the
        pre-fix code did) would silently skip a guarded check but fails here.

        Full cryptographic verification of the signatures against the
        reconstructed message is a separate, larger follow-up; this test pins
        that the context is present and typed, not that it verifies.
        """
        if last_mc_seqno < 3:
            pytest.skip("chain has not advanced far enough for a settled block")
        seqno = max(2, last_mc_seqno - 3)
        response = api_method_call(self.METHOD, seqno=seqno)
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert result["@type"] == "blocks.blockSignatures.simplex", (
            "expected simplex signatures on a simplex-consensus network; a "
            "regression to the ordinary type would drop the verification context"
        )
        assert len(base64.b64decode(result["session_id"])) == 32
        assert isinstance(result["slot"], int)
        base64.b64decode(result["candidate"])  # must be valid base64
        assert result["signatures"], "simplex block must carry validator signatures"


# ═══════════════════════════════════════════════════════════════════════════
#  3. getShardBlockProof
# ═══════════════════════════════════════════════════════════════════════════


class TestGetShardBlockProof:
    METHOD = "getShardBlockProof"

    def test_basic(self, api_method_call, last_mc_seqno):
        response = api_method_call(
            self.METHOD,
            workchain=-1,
            shard=SHARD_ALL,
            seqno=1,
        )
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)
        assert data["result"]["@type"] == "blocks.shardBlockProof"
        assert data["result"]["masterchain_id"]["@type"] == "tos.blockIdExt"
        assert isinstance(data["result"]["links"], list)

    def test_wrong_workchain(self, api_method_call):
        response = api_method_call(self.METHOD, workchain="invalid", shard=SHARD_ALL, seqno=1)
        expect_error(response)

    def test_empty_workchain(self, api_method_call):
        response = api_method_call(self.METHOD, shard=SHARD_ALL, seqno=1)
        expect_error(response)

    def test_wrong_shard(self, api_method_call):
        response = api_method_call(self.METHOD, workchain=-1, shard="invalid", seqno=1)
        expect_invalid_param(response, "shard")

    def test_empty_shard(self, api_method_call):
        response = api_method_call(self.METHOD, workchain=-1, seqno=1)
        expect_invalid_param(response, "shard")

    def test_wrong_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL, seqno="invalid")
        expect_invalid_param(response, "seqno")

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(
            self.METHOD, workchain=-1, shard=SHARD_ALL, seqno=last_mc_seqno + 1000000
        )
        expect_error(response)

    def test_negative_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL, seqno=-1)
        expect_invalid_param(response, "seqno")

    def test_old_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL, seqno=1)
        expect_result(response)


# ═══════════════════════════════════════════════════════════════════════════
#  4. getConsensusBlock
# ═══════════════════════════════════════════════════════════════════════════


class TestGetConsensusBlock:
    METHOD = "getConsensusBlock"

    def test_basic(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)
        assert data["result"]["@type"] == "ext.blocks.consensusBlock"


# ═══════════════════════════════════════════════════════════════════════════
#  5. lookupBlock
# ═══════════════════════════════════════════════════════════════════════════


class TestLookupBlock:
    METHOD = "lookupBlock"

    def test_by_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL, seqno=last_mc_seqno)
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)
        assert data["result"]["@type"] == "tos.blockIdExt"
        assert data["result"]["workchain"] == -1
        assert data["result"]["seqno"] == last_mc_seqno

    def test_missing_workchain(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, shard=SHARD_ALL, seqno=last_mc_seqno)
        expect_invalid_param(response, "workchain")

    def test_wrong_seqno(self, api_method_call):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL, seqno="invalid")
        expect_invalid_param(response, "seqno")

    @pytest.mark.parametrize("shard", ["zz", "9223372036854775808", "0x8000000000000000", "+1"])
    def test_malformed_shard_is_refused(self, api_method_call, last_mc_seqno, shard):
        """Only the signed decimal spelling of the shard id is accepted; the
        unsigned spelling of the same 64 bits is refused, not reinterpreted."""
        response = api_method_call(self.METHOD, workchain=-1, shard=shard, seqno=last_mc_seqno)
        expect_invalid_param(response, "shard")

    def test_shard_as_json_number_is_refused(self, api_method_call_no_get, last_mc_seqno):
        response = api_method_call_no_get(
            self.METHOD, workchain=-1, shard=-9223372036854775808, seqno=last_mc_seqno
        )
        expect_invalid_param(response, "shard")

    def test_seqno_as_string_is_refused(self, api_method_call_no_get, last_mc_seqno):
        response = api_method_call_no_get(
            self.METHOD, workchain=-1, shard=SHARD_ALL, seqno=str(last_mc_seqno)
        )
        expect_invalid_param(response, "seqno")

    def test_workchain_as_string_is_refused(self, api_method_call_no_get, last_mc_seqno):
        response = api_method_call_no_get(
            self.METHOD, workchain="-1", shard=SHARD_ALL, seqno=last_mc_seqno
        )
        expect_invalid_param(response, "workchain")

    def test_requires_exactly_one_selector(self, api_method_call, last_mc_seqno):
        none = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL)
        expect_error(none, -32602, "INVALID_ARGUMENT")
        both = api_method_call(
            self.METHOD, workchain=-1, shard=SHARD_ALL, seqno=last_mc_seqno, unixtime=1
        )
        expect_error(both, -32602, "INVALID_ARGUMENT")

    def test_seqno_zero_is_block_zero(self, api_method_call):
        """seqno 0 names block 0; it is not a stand-in for the latest block."""
        assert_block_zero_or_refused(
            api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL, seqno=0),
            lambda result: result,
        )

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(
            self.METHOD, workchain=-1, shard=SHARD_ALL, seqno=last_mc_seqno + 1000000
        )
        expect_error(response)


# ═══════════════════════════════════════════════════════════════════════════
#  6. shards / getShards
# ═══════════════════════════════════════════════════════════════════════════


class TestGetShards:
    @pytest.mark.parametrize("method", ["shards", "getShards"])
    def test_basic(self, api_method_call, last_mc_seqno, method):
        response = api_method_call(method, seqno=last_mc_seqno)
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)
        assert data["result"]["@type"] == "blocks.shards"
        assert isinstance(data["result"]["shards"], list)

    @pytest.mark.parametrize("method", ["shards", "getShards"])
    def test_basechain_shard_is_written_signed(self, api_method_call, method):
        """The basechain full shard is written as the signed decimal string,
        the same spelling every other block id uses and the parser accepts."""
        result = expect_result(api_method_call(method))
        assert result["shards"], "a running chain has at least one basechain shard"
        basechain = [s for s in result["shards"] if s["workchain"] == 0]
        assert basechain, result
        for shard in result["shards"]:
            assert isinstance(shard["shard"], str), shard
            assert -(1 << 63) <= int(shard["shard"]) < (1 << 63), shard
        if len(basechain) == 1:
            assert basechain[0]["shard"] == SHARD_ALL

    @pytest.mark.parametrize("method", ["shards", "getShards"])
    @pytest.mark.parametrize("seqno", ["abc", -1, 1.5])
    def test_wrong_seqno(self, api_method_call, method, seqno):
        response = api_method_call(method, seqno=seqno)
        expect_invalid_param(response, "seqno")

    @pytest.mark.parametrize("method", ["shards", "getShards"])
    def test_seqno_as_string_is_refused(self, api_method_call_no_get, last_mc_seqno, method):
        response = api_method_call_no_get(method, seqno=str(last_mc_seqno))
        expect_invalid_param(response, "seqno")

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call("shards", seqno=last_mc_seqno + 1000000)
        expect_error(response)


# ═══════════════════════════════════════════════════════════════════════════
#  7. getBlockHeader
# ═══════════════════════════════════════════════════════════════════════════


class TestGetBlockHeader:
    METHOD = "getBlockHeader"

    def test_basic(self, api_method_call, last_mc_seqno):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL, seqno=last_mc_seqno)
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)
        assert data["result"]["@type"] == "blocks.header"
        assert data["result"]["id"]["@type"] == "tos.blockIdExt"
        assert data["result"]["id"]["workchain"] == -1
        assert data["result"]["id"]["seqno"] == last_mc_seqno
        assert data["result"]["prev_blocks"], "block header must expose exact parent IDs"
        for parent in data["result"]["prev_blocks"]:
            assert parent["workchain"] == -1
            assert -(1 << 63) <= int(parent["shard"]) < (1 << 63)
            assert parent["seqno"] < last_mc_seqno
            assert parent["root_hash"] and parent["file_hash"]

    def test_wrong_workchain(self, api_method_call, last_mc_seqno):
        response = api_method_call(
            self.METHOD, workchain="invalid", shard=SHARD_ALL, seqno=last_mc_seqno
        )
        expect_invalid_param(response, "workchain")

    @pytest.mark.parametrize("seqno", [-3, "abc", 2147483648])
    def test_out_of_range_seqno(self, api_method_call, seqno):
        response = api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL, seqno=seqno)
        expect_invalid_param(response, "seqno")

    def test_seqno_zero_is_block_zero(self, api_method_call):
        """seqno 0 names block 0; it is not a stand-in for the latest block."""
        assert_block_zero_or_refused(
            api_method_call(self.METHOD, workchain=-1, shard=SHARD_ALL, seqno=0),
            lambda result: result["id"],
        )

    def test_future_seqno(self, api_method_call, last_mc_seqno):
        response = api_method_call(
            self.METHOD, workchain=-1, shard=SHARD_ALL, seqno=last_mc_seqno + 1000000
        )
        expect_error(response)


# ═══════════════════════════════════════════════════════════════════════════
#  8. getOutMsgQueueSize
# ═══════════════════════════════════════════════════════════════════════════


class TestGetOutMsgQueueSize:
    METHOD = "getOutMsgQueueSize"

    def test_basic(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)
        # Result should contain a numeric size field
        assert "size" in data["result"] or isinstance(data["result"], (int, dict))
