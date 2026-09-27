from pathlib import Path

from pytosiq_core.tl.generator import TlGenerator


def test_pq_signature_tl_vectors_match_generated_schemas():
    root = Path(__file__).resolve().parents[4]
    fixture = root / "test/pq-native/pq-signature-tl-vectors.txt"
    schemas = TlGenerator.with_default_schemas().generate()
    rows = [
        line.split("\t")
        for line in fixture.read_text().splitlines()
        if line and not line.startswith("#")
    ]
    assert len(rows) == 6, "PYTHON_TL_VECTOR_ROW_COUNT"

    for row in rows:
        assert len(row) == 14, f"PYTHON_TL_VECTOR_BAD_COLUMNS case={row[0]}"
        (
            name,
            outcome,
            reason,
            carrier,
            role,
            cc_seqno,
            validator_set_hash,
            validator_id,
            algorithm_id,
            signature_hex,
            session_id,
            slot,
            candidate_hex,
            wire_hex,
        ) = row
        wire = bytes.fromhex(wire_hex)
        parsed, consumed = schemas.deserialize(wire)

        if reason == "wrong_constructor":
            assert (
                not isinstance(parsed, dict)
                or parsed.get("@type") != "liteServer.signatureSet.simplexPq"
            ), f"PYTHON_TL_VECTOR_UNEXPECTED_ACCEPT case={name} expected={reason}"
            continue

        assert consumed == len(wire), f"PYTHON_TL_VECTOR_TRAILING case={name}"
        expected_type = (
            "tosNode.signatureSet.simplexPq"
            if carrier == "node"
            else "liteServer.signatureSet.simplexPq"
        )
        assert parsed["@type"] == expected_type, f"PYTHON_TL_VECTOR_VARIANT case={name}"
        assert parsed["cc_seqno"] == int(cc_seqno)
        assert parsed["validator_set_hash"] == int(validator_set_hash)
        assert parsed["session_id"].upper() == session_id
        assert parsed["slot"] == int(slot)
        assert len(parsed["signatures"]) == 1
        pair = parsed["signatures"][0]
        assert pair["validator_id"].upper() == validator_id
        assert pair["algorithm_id"] == int(algorithm_id)
        assert pair["signature"] == bytes.fromhex(signature_hex)
        assert isinstance(parsed["candidate"], bytes), (
            f"PYTHON_TL_VECTOR_CANDIDATE_SHAPE case={name}"
        )
        assert parsed["candidate"] == bytes.fromhex(candidate_hex), (
            f"PYTHON_TL_VECTOR_CANDIDATE_MISMATCH case={name}"
        )

        checked_reason = None
        if pair["algorithm_id"] != 1:
            checked_reason = "unsupported_algorithm"
        elif len(pair["signature"]) != 2420:
            checked_reason = "signature_length"
        assert checked_reason == (None if outcome == "accept" else reason), (
            f"PYTHON_TL_VECTOR_REASON_MISMATCH case={name}"
        )
        if outcome == "accept":
            if carrier == "node":
                assert parsed["final"] == (role == "final")
            else:
                assert role == "final"
