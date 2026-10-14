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
            {
                "kind": "validator_controller_policy_v1",
                "controller_codes": [base64.b64encode(bytes([i]) * 32).decode() for i in range(9)],
            },
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
    # Independent wire-field inventory from block.tlb, not from the schema under test.
    fields_v1 = [
        "max_msg_bits",
        "max_msg_cells",
        "max_library_cells",
        "max_vm_data_depth",
        "max_ext_msg_size",
        "max_ext_msg_depth",
    ]
    fields_v2 = fields_v1 + [
        "max_acc_state_cells",
        "max_mc_acc_state_cells",
        "max_acc_public_libraries",
        "defer_out_queue_size_limit",
        "max_msg_extra_currencies",
        "max_acc_fixed_prefix_length",
        "acc_state_cells_for_storage_dict",
    ]
    fields_v3 = fields_v2 + [
        "max_transaction_library_loads",
        "max_total_msg_bits",
        "max_total_msg_cells",
    ]
    effective = dict.fromkeys(fields_v3, 1)
    limits = []
    for version, fields in [(None, []), (1, fields_v1), (2, fields_v2), (3, fields_v3)]:
        value = dict(
            kind="size_limits",
            wire_version=version,
            configured=dict.fromkeys(fields, 1) if version else None,
            effective=effective,
            defaulted_fields=[f for f in fields_v3 if f not in fields],
        )
        limits.append(value)
        cases.append(("SizeLimits", value, True))
        cases.append(
            (
                "SizeLimits",
                {**value, "defaulted_fields": list(reversed(value["defaulted_fields"]))},
                True,
            )
        )
        wrapped = dict(
            schema_version=1,
            param=43,
            presence="present" if version else "absent",
            observation=observation,
            value=value,
        )
        cases.append(("DecodedConfig", wrapped, True))
        cases.append(
            ("DecodedConfig", {**wrapped, "presence": "absent" if version else "present"}, False)
        )
        if version:
            for field in fields:
                bad = copy.deepcopy(value)
                del bad["configured"][field]
                cases.append(("SizeLimits", bad, False))
            for field in fields_v3:
                if field not in fields:
                    bad = copy.deepcopy(value)
                    bad["configured"][field] = 1
                    cases.append(("SizeLimits", bad, False))
            cases.append(("SizeLimits", {**value, "configured": None}, False))
            cases.append(("SizeLimits", {**value, "configured": {}}, False))
        else:
            cases.append(("SizeLimits", {**value, "configured": {}}, False))
        if value["defaulted_fields"]:
            cases.append(
                ("SizeLimits", {**value, "defaulted_fields": value["defaulted_fields"][1:]}, False)
            )
            cases.append(
                (
                    "SizeLimits",
                    {
                        **value,
                        "defaulted_fields": value["defaulted_fields"]
                        + [value["defaulted_fields"][0]],
                    },
                    False,
                )
            )
        else:
            cases.append(
                (
                    "SizeLimits",
                    {**value, "defaulted_fields": ["max_transaction_library_loads"]},
                    False,
                )
            )
    unlimited = copy.deepcopy(limits[3])
    unlimited["configured"]["max_transaction_library_loads"] = None
    unlimited["effective"] = {**effective, "max_transaction_library_loads": None}
    cases.append(("SizeLimits", unlimited, True))
    cases.append(
        ("SizeLimits", {**unlimited, "defaulted_fields": ["max_transaction_library_loads"]}, False)
    )
    for version in [0, 4, True, "1"]:
        cases.append(("SizeLimits", {**limits[1], "wire_version": version}, False))
    auth = dict(
        kind="auth_policy_v1",
        network_tag=encoded(32),
        policy_sequence="0",
        retired_flags=0,
        primary_deadline=None,
        policy_spec_hash=encoded(32),
        primary_status="not_retired",
    )
    for flags in [0, 2]:
        for deadline in [None, 1]:
            for status in ["not_retired", "retired"]:
                valid = (
                    (status == "retired")
                    if flags == 2
                    else (deadline is not None or status == "not_retired")
                )
                cases.append(
                    (
                        "AuthPolicy",
                        {
                            **auth,
                            "retired_flags": flags,
                            "primary_deadline": deadline,
                            "primary_status": status,
                        },
                        valid,
                    )
                )
    codes = [base64.b64encode(bytes([i]) * 32).decode() for i in range(9)]
    controller = dict(kind="validator_controller_policy_v1", controller_codes=codes[:8])
    cases.extend(
        [
            ("ControllerPolicy", controller, True),
            ("ControllerPolicy", {**controller, "controller_codes": codes}, False),
            ("ControllerPolicy", {**controller, "controller_codes": codes[:1] * 2}, False),
        ]
    )

    # Each mutation removes one guard and must make its particular negative
    # assertion fail. Other guards and the positive boundary remain untouched.
    controls = []

    def sensitivity(label, name, value, mutate):
        check(name, value, False)
        changed = copy.deepcopy(SCHEMA)
        mutate(changed["$defs"])
        try:
            check(name, value, False, changed)
        except AssertionError as error:
            if str(error) != f"{name}: expected valid=False, errors=[]":
                raise
        else:
            raise AssertionError(f"Sensitivity did not go red: {label}")
        controls.append(label)

    sensitivity(
        "controller count",
        "ControllerPolicy",
        {**controller, "controller_codes": codes},
        lambda d: d["ControllerPolicy"]["properties"]["controller_codes"].pop("maxItems"),
    )
    sensitivity(
        "controller uniqueness",
        "ControllerPolicy",
        {**controller, "controller_codes": codes[:1] * 2},
        lambda d: d["ControllerPolicy"]["properties"]["controller_codes"].pop("uniqueItems"),
    )
    incomplete = copy.deepcopy(limits[1])
    del incomplete["configured"]["max_msg_bits"]
    sensitivity(
        "complete v1 fields",
        "SizeLimits",
        incomplete,
        lambda d: d["SizeLimits"]["oneOf"][1]["properties"]["configured"]["required"].remove(
            "max_msg_bits"
        ),
    )
    extra = copy.deepcopy(limits[1])
    extra["configured"]["max_acc_state_cells"] = 1
    sensitivity(
        "version fields",
        "SizeLimits",
        extra,
        lambda d: d["SizeLimits"]["oneOf"][1]["properties"]["configured"].update(
            additionalProperties=True
        ),
    )
    sensitivity(
        "default provenance",
        "SizeLimits",
        {**limits[1], "defaulted_fields": []},
        lambda d: d["SizeLimits"]["oneOf"][1]["properties"]["defaulted_fields"].pop("minItems"),
    )
    sensitivity(
        "retired flag",
        "AuthPolicy",
        {**auth, "retired_flags": 2},
        lambda d: d["AuthPolicy"]["allOf"].pop(0),
    )
    sensitivity(
        "retired without cause",
        "AuthPolicy",
        {**auth, "primary_status": "retired"},
        lambda d: d["AuthPolicy"]["allOf"].pop(1),
    )
    print(f"Additional sensitivity controls: {len(controls)} passed.")

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
