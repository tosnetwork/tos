"""Validate proposed wire shapes using synthetic, non-cryptographic test values.

Run with jsonschema 4.26.0. This does not execute or verify the proposed RPCs.
"""

import argparse
import base64
import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA = json.loads(
    Path(__file__).with_name("explorer-pq-rpc-v1.schema.json").read_text(encoding="utf-8")
)


def encoded(size):
    return base64.b64encode(bytes(size)).decode()


def validator(name, schema=SCHEMA):
    return Draft202012Validator({"$ref": f"#/$defs/{name}", "$defs": schema["$defs"]})


def check(name, value, valid, schema=SCHEMA):
    errors = list(validator(name, schema).iter_errors(value))
    if bool(errors) == valid:
        summary = [f"{list(error.absolute_path)}: {error.validator}" for error in errors[:3]]
        raise AssertionError(f"{name}: expected valid={valid}, errors={summary}")


# Field sets are frozen independently from the schema under test, from
# SizeLimitsConfig v1/v2/v3. Values below are synthetic, not native defaults.
SIZE_V1 = (
    "max_msg_bits",
    "max_msg_cells",
    "max_library_cells",
    "max_vm_data_depth",
    "max_ext_msg_size",
    "max_ext_msg_depth",
)
SIZE_V2 = SIZE_V1 + (
    "max_acc_state_cells",
    "max_mc_acc_state_cells",
    "max_acc_public_libraries",
    "defer_out_queue_size_limit",
    "max_msg_extra_currencies",
    "max_acc_fixed_prefix_length",
    "acc_state_cells_for_storage_dict",
)
SIZE_V3 = SIZE_V2 + (
    "max_transaction_library_loads",
    "max_total_msg_bits",
    "max_total_msg_cells",
    "out_msg_queue_size_hard_limit",
    "out_msg_queue_size_soft_limit",
)


def size_limits(version):
    fields = {None: (), 1: SIZE_V1, 2: SIZE_V2, 3: SIZE_V3}[version]
    effective = dict.fromkeys(SIZE_V3, 1)
    effective["max_transaction_library_loads"] = None
    return dict(
        kind="size_limits",
        wire_version=version,
        configured=None if version is None else {name: effective[name] for name in fields},
        effective=effective,
        defaulted_fields=[name for name in SIZE_V3 if name not in fields],
    )


def decoded_sizes(value, block, presence=None):
    return dict(
        schema_version=1,
        param=43,
        presence=presence or ("absent" if value["wire_version"] is None else "present"),
        observation=dict(block_id=block, global_id=1, chain_time=100, vm_version=16),
        value=value,
    )


def size_limit_cases(block):
    cases = []
    for version, fields in [(None, ()), (1, SIZE_V1), (2, SIZE_V2), (3, SIZE_V3)]:
        value = size_limits(version)
        cases.extend(
            [
                ("SizeLimits", value, True),
                ("DecodedConfig", decoded_sizes(value, block), True),
            ]
        )
        if version is None:
            continue
        # Delete each required field in isolation; never change another guard.
        for name in fields:
            bad = copy.deepcopy(value)
            del bad["configured"][name]
            cases.append(("SizeLimits", bad, False))
        for name in (name for name in SIZE_V3 if name not in fields):
            bad = copy.deepcopy(value)
            bad["configured"][name] = bad["effective"][name]
            cases.append(("SizeLimits", bad, False))
        cases.append(("SizeLimits", {**value, "configured": None}, False))
        cases.append(
            (
                "SizeLimits",
                {**value, "defaulted_fields": value["defaulted_fields"] + [fields[0]]},
                False,
            )
        )
        if value["defaulted_fields"]:
            cases.append(("SizeLimits", {**value, "defaulted_fields": []}, False))
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
    cases.extend(
        [
            ("SizeLimits", {**size_limits(1), "configured": {}}, False),
            ("SizeLimits", {**size_limits(1), "wire_version": 2}, False),
            ("SizeLimits", {**size_limits(2), "wire_version": 3}, False),
            ("SizeLimits", {**size_limits(None), "defaulted_fields": []}, False),
            ("DecodedConfig", decoded_sizes(size_limits(None), block, "present"), False),
            ("DecodedConfig", decoded_sizes(size_limits(1), block, "absent"), False),
        ]
    )
    # A configured Maybe-none is explicit unlimited, not an absent/defaulted field.
    explicit_unlimited = size_limits(3)
    cases.append(
        (
            "SizeLimits",
            {**explicit_unlimited, "defaulted_fields": ["max_transaction_library_loads"]},
            False,
        )
    )
    explicit_limit = copy.deepcopy(explicit_unlimited)
    explicit_limit["configured"]["max_transaction_library_loads"] = 10
    explicit_limit["effective"]["max_transaction_library_loads"] = 10
    cases.append(("SizeLimits", explicit_limit, True))
    for name, maximum in [
        ("max_msg_bits", 4294967295),
        ("max_vm_data_depth", 65535),
        ("max_acc_fixed_prefix_length", 255),
    ]:
        value = size_limits(3)
        value["configured"][name] = maximum
        value["effective"][name] = maximum
        cases.append(("SizeLimits", value, True))
        bad = copy.deepcopy(value)
        bad["configured"][name] = maximum + 1
        cases.append(("SizeLimits", bad, False))
        bad = copy.deepcopy(value)
        bad["effective"][name] = maximum + 1
        cases.append(("SizeLimits", bad, False))
    return cases


def sensitivity(schema, name, invalid, path, label):
    """Remove one guard and require its actual rejection assertion to fail."""
    check(name, invalid, False, schema)
    mutated = copy.deepcopy(schema)
    parent = mutated
    for key in path[:-1]:
        parent = parent[key]
    del parent[path[-1]]
    Draft202012Validator.check_schema(mutated)
    check(name, invalid, True, mutated)
    try:
        check(name, invalid, False, mutated)
    except AssertionError as error:
        if str(error) != f"{name}: expected valid=False, errors=[]":
            raise
    else:
        raise AssertionError(f"{label}: removing the guard did not fail its rejection test")
    check(name, invalid, False, schema)
    print(f"Sensitivity {label}: rejection fails without guard; passes restored.")


def main(schema=SCHEMA):
    Draft202012Validator.check_schema(schema)
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
        trust_anchor={**block, "seqno": 11},
        validator_set_source={**block, "seqno": 8},
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
    cases.append(("DecodedConfig", {**global_config, "param": 43}, False))
    cases.extend(size_limit_cases(block))
    policy = dict(
        kind="auth_policy_v1",
        network_tag=encoded(32),
        policy_sequence="1",
        retired_flags=0,
        primary_deadline=None,
        policy_spec_hash=encoded(32),
        primary_status="not_retired",
    )
    bad_flag_policy = {**policy, "retired_flags": 2}
    bad_inert_policy = {**policy, "primary_status": "retired"}
    cases.extend(
        [
            ("AuthPolicy", policy, True),
            ("AuthPolicy", bad_flag_policy, False),
            ("AuthPolicy", bad_inert_policy, False),
            ("AuthPolicy", {**policy, "primary_deadline": 101}, True),
            ("AuthPolicy", {**policy, "primary_deadline": 100, "primary_status": "retired"}, True),
        ]
    )
    # Deadline/time comparison remains a native semantic check, not a schema claim.
    for name, value, valid in cases:
        check(name, value, valid, schema)

    controls = [
        (
            "PqSignaturesResult",
            {**carrier, "signatures": []},
            ["$defs", "PqSignaturesResult", "properties", "signatures", "minItems"],
            "nonempty-certificate",
        ),
        (
            "SizeLimits",
            {**size_limits(1), "configured": {}},
            ["$defs", "ConfiguredSizeLimitsV1", "allOf", 1, "required"],
            "size-v1-completeness",
        ),
        (
            "SizeLimits",
            {**size_limits(1), "defaulted_fields": []},
            ["$defs", "SizeLimits", "allOf", 1, "then", "properties", "defaulted_fields"],
            "size-default-provenance",
        ),
        (
            "DecodedConfig",
            decoded_sizes(size_limits(None), block, "present"),
            ["$defs", "DecodedConfig", "allOf", 6],
            "size-present-wire-version",
        ),
        (
            "AuthPolicy",
            bad_flag_policy,
            ["$defs", "AuthPolicy", "allOf", 0],
            "retired-flag-status",
        ),
        (
            "AuthPolicy",
            bad_inert_policy,
            ["$defs", "AuthPolicy", "allOf", 1],
            "no-retirement-source-status",
        ),
    ]
    for name, invalid, path, label in controls:
        sensitivity(schema, name, invalid, path, label)
    positive = sum(valid for _, _, valid in cases)
    print(
        f"Schema checks: {len(cases)} passed ({positive} positive, {len(cases) - positive} negative)."
    )
    print(f"Sensitivity controls: {len(controls)} passed.")
    print("Scope: JSON shapes only; synthetic bytes are not signature/proof acceptance evidence.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--schema",
        type=Path,
        help="Validate an alternate schema, e.g. a pinned regression baseline",
    )
    args = parser.parse_args()
    selected_schema = (
        SCHEMA if args.schema is None else json.loads(args.schema.read_text(encoding="utf-8"))
    )
    main(selected_schema)
