"""Validate proposed wire shapes using synthetic, non-cryptographic test values.

Run with jsonschema 4.26.0. This does not execute or verify the proposed RPCs.
"""

import base64
import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA = json.loads(Path(__file__).with_name("explorer-pq-rpc-v1.schema.json").read_text())


def encoded(size):
    return base64.b64encode(bytes(size)).decode()


def validator(name, schema=SCHEMA):
    return Draft202012Validator({"$ref": f"#/$defs/{name}", "$defs": schema["$defs"]})


def check(name, value, valid, schema=SCHEMA):
    errors = list(validator(name, schema).iter_errors(value))
    if bool(errors) == valid:
        raise AssertionError(f"{name}: expected valid={valid}, errors={errors}")


def main():
    Draft202012Validator.check_schema(SCHEMA)
    block = dict(
        workchain=-1,
        shard="-9223372036854775808",
        seqno=12,
        root_hash=encoded(32),
        file_hash=encoded(32),
    )
    verification = dict(
        status="node_verified",
        scope="anchored_finality",
        trust_anchor=block,
        validator_set_source=block,
        expected_session_id=encoded(32),
        verified_weight="2",
        total_weight="3",
        quorum_threshold="2",
    )
    carrier = {
        "@type": "blocks.blockSignatures.simplexPq",
        "schema_version": 1,
        "id": block,
        "cc_seqno": 0,
        "validator_set_hash": 0,
        "session_id": encoded(32),
        "slot": 1,
        "candidate": encoded(4),
        "signature_context": "TOS-CONSENSUS-SIMPLEX-v1",
        "signing_payload": encoded(4),
        "verification": verification,
        "signatures": [
            {
                "@type": "blocks.signature.pq",
                "validator_id": encoded(32),
                "algorithm_id": 1,
                "signature": encoded(2420),
            }
        ],
    }
    unknown = dict(
        schema_version=1,
        recognition="unknown_code",
        code_hash=encoded(32),
        code_family=None,
        release_status="not_asserted",
        registry_revision="synthetic-v1",
        observed_masterchain_block=block,
        observed_shard_block=block,
        state_verified=True,
        state_schema=None,
        public_state=None,
    )
    cases = [
        ("SignatureRequest", {"seqno": 12}, True),
        ("SignatureRequest", {"block_id": block, "with_proof": True}, True),
        ("SignatureRequest", {}, False),
        ("SignatureRequest", {"seqno": 0}, False),
        ("SignatureRequest", {"seqno": True}, False),
        ("SignatureRequest", {"block_id": {**block, "seqno": 0}}, False),
        ("SignatureRequest", {"seqno": 12, "with_proof": "true"}, False),
        (
            "AccountRequest",
            {
                "address": "0:" + "00" * 32,
                "include_pq": True,
                "block_id": block,
                "with_proof": True,
            },
            True,
        ),
        ("AccountRequest", {"address": "0:" + "00" * 32, "with_proof": True}, False),
        ("ConfigRequest", {"param": 8, "include_decoded": True, "block_id": block}, True),
        ("ConfigRequest", {"param": 8, "block_id": block}, False),
        ("ProofRequest", {"query": encoded(4)}, True),
        ("ProofRequest", {"query": encoded(16385)}, False),
        ("ProofRequest", {"query": "%%%"}, False),
        ("PqSignaturesResult", carrier, True),
        ("PqSignaturesResult", {**carrier, "signatures": []}, False),
        ("PqSignaturesResult", {**carrier, "signatures": carrier["signatures"] * 401}, False),
        ("PqSignaturesResult", {**carrier, "candidate": encoded(1025)}, False),
        ("PqSignaturesResult", {**carrier, "signature_context": "other-domain"}, False),
        ("PublicAuthorization", unknown, True),
        ("PublicAuthorization", {**unknown, "recognition": "recognized"}, False),
        ("PublicAuthorization", {**unknown, "recognition": "no_active_code"}, False),
        (
            "AuthPolicy",
            dict(
                kind="auth_policy_v1",
                network_tag=encoded(32),
                policy_sequence="18446744073709551615",
                retired_flags=2,
                primary_deadline=None,
                policy_spec_hash=encoded(32),
                primary_status="retired",
            ),
            True,
        ),
        (
            "ControllerPolicy",
            {"kind": "validator_controller_policy_v1", "controller_codes": []},
            True,
        ),
        (
            "ControllerPolicy",
            {"kind": "validator_controller_policy_v1", "controller_codes": [encoded(32)] * 9},
            False,
        ),
        (
            "FeeMetadata",
            dict(
                schema_version=1,
                profile="hss-lms-sha256-h20-lmots-sha256-w4",
                algorithm_id=4,
                fee_tree_id=encoded(32),
                epoch0=0,
                epoch_seconds=3600,
                opening_horizon=4,
                public_key=encoded(60),
            ),
            True,
        ),
    ]
    malformed_signature = copy.deepcopy(carrier)
    malformed_signature["signatures"][0]["signature"] = encoded(2419)
    cases.append(("PqSignaturesResult", malformed_signature, False))
    primary = dict(algorithm_id=1, public_key=encoded(1312))
    rescue = dict(algorithm_id=3, public_key=encoded(32), policy="ready")
    module = dict(
        kind="quantum_module_v1",
        global_id=1,
        network_tag=encoded(32),
        primary=primary,
        rescue=rescue,
    )
    fee = dict(
        schema_version=1,
        profile="hss-lms-sha256-h20-lmots-sha256-w4",
        algorithm_id=4,
        fee_tree_id=encoded(32),
        epoch0=0,
        epoch_seconds=3600,
        opening_horizon=4,
        public_key=encoded(60),
    )
    states = [
        dict(
            kind="pq_highload_mldsa44_v1",
            algorithm_id=1,
            public_key=encoded(1312),
            consensus_key_id=encoded(32),
            subwallet_id=1,
            last_clean_time="0",
            timeout_seconds=3600,
        ),
        dict(kind="mldsa44_auth_module_v1", algorithm_id=1, global_id=1, public_key=encoded(1312)),
        dict(
            kind="falcon512_padded_auth_module_v1",
            algorithm_id=2,
            profile_version=1,
            global_id=1,
            public_key=encoded(897),
        ),
        module,
        dict(
            kind="quantum_wallet_v4",
            seqno=0,
            wallet_id=1,
            auth_mode=2,
            retired_flags=0,
            authority_epoch="0",
            primary_nonce="0",
            rescue_nonce="0",
            legacy_signature_enabled=False,
            module_state_init_hash=encoded(32),
            module=module,
            fee=fee,
        ),
        dict(
            kind="quantum_fee_vault_v3",
            next_leaf=0,
            configuration_hash=encoded(32),
            epoch0=0,
            module_address="0:" + "00" * 32,
            pop_parties_hash=encoded(32),
            fee_public_key=encoded(60),
            intent_prefix_hash=encoded(32),
            global_id=1,
            network_tag=encoded(32),
            wallet_address="0:" + "00" * 32,
            auth_mode=2,
        ),
    ]
    for state in states:
        view = {
            **unknown,
            "recognition": "recognized",
            "code_family": state["kind"],
            "state_schema": state["kind"],
            "public_state": state,
            "release_status": "review_candidate",
        }
        cases.append(("PublicAuthorization", view, True))
    cases.append(("PublicAuthorization", {**view, "code_family": "quantum_wallet_v4"}, False))
    bad_wallet = copy.deepcopy(states[4])
    bad_wallet["legacy_signature_enabled"] = True
    cases.append(("QuantumWalletState", bad_wallet, False))
    observation = dict(block_id=block, global_id=1, chain_time=100, vm_version=16)
    legacy_absence = dict(
        schema_version=1, param=48, presence="absent", observation=observation, value=None
    )
    cases.append(("DecodedConfig", legacy_absence, True))
    cases.append(
        (
            "DecodedConfig",
            {**legacy_absence, "observation": {**observation, "vm_version": 17}},
            False,
        )
    )
    cases.append(("DecodedConfig", {**legacy_absence, "param": 8}, False))
    global_config = dict(
        schema_version=1,
        param=8,
        presence="present",
        observation=observation,
        value=dict(kind="global_version", version=16, capabilities="18446744073709551615"),
    )
    cases.append(("DecodedConfig", global_config, True))
    cases.append(("DecodedConfig", {**global_config, "param": 47}, False))
    for name, value, valid in cases:
        check(name, value, valid)

    # Targeted sensitivity: remove only the nonempty-certificate rule. The empty
    # array vector must now pass, demonstrating that this rejection can go red.
    mutated = copy.deepcopy(SCHEMA)
    del mutated["$defs"]["PqSignaturesResult"]["properties"]["signatures"]["minItems"]
    empty_carrier = {**carrier, "signatures": []}
    if not validator("PqSignaturesResult", mutated).is_valid(empty_carrier):
        raise AssertionError("Empty-certificate sensitivity control did not exercise minItems")
    try:
        check("PqSignaturesResult", empty_carrier, False, mutated)
    except AssertionError as error:
        if str(error) != "PqSignaturesResult: expected valid=False, errors=[]":
            raise
    else:
        raise AssertionError("Removed certificate guard did not make its rejection test fail")
    positive = sum(valid for _, _, valid in cases)
    print(
        f"Schema checks: {len(cases)} passed ({positive} positive, {len(cases) - positive} negative)."
    )
    print(
        "Sensitivity: removing only minItems makes the empty-certificate rejection fail; original schema passes."
    )
    print("Scope: JSON shapes only; synthetic bytes are not signature/proof acceptance evidence.")


if __name__ == "__main__":
    main()
