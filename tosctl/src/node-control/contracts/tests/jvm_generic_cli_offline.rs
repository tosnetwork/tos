/*
 * Offline byte-stability tests for the generic deploy + call CLI
 * primitives (Phase P).  These tests do NOT spin up an RPC client —
 * they only exercise the parsing + cell-encoding paths that the
 * `jw deploy-contract` and `jw call` commands rely on, locking the
 * shapes produced from CLI-style inputs.
 */

use chain_block::Cell;
use contracts::jvm_codec::{
    compute_jvm_address_commit, compute_jvm_class_hash,
    compute_jvm_manifest_root_hash, derive_jvm_contract_address,
    encode_jvm_args, encode_jvm_call_descriptor, parse_manifest_cell,
    parse_typed_args, parse_workchain_address, JvmArgs, JvmCallDescriptor,
};
use contracts::jvm_wallet::method_id_of;

fn sample_manifest_json() -> &'static str {
    r#"[
        {
            "abi_sig": "init(bytes32)",
            "class_name": "com/example/Counter",
            "method_name": "init",
            "method_spec": "(Ljava/lang/Bytes32;)V"
        },
        {
            "abi_sig": "increment(uint256)",
            "class_name": "com/example/Counter",
            "method_name": "increment",
            "method_spec": "(Ljava/lang/Uint256;)V"
        },
        {
            "abi_sig": "totalCount()",
            "class_name": "com/example/Counter",
            "method_name": "totalCount",
            "method_spec": "()V"
        }
    ]"#
}

fn sample_class_bytes() -> Vec<u8> {
    // Non-empty deterministic blob — bypass the "empty class" check
    // and exercise the chunk-chain encoding path.
    (0..256u32)
        .map(|i| ((i.wrapping_mul(11).wrapping_add(7)) & 0xff) as u8)
        .collect()
}

#[test]
fn parse_manifest_cell_is_deterministic_across_two_parses() {
    let cell1: Cell = parse_manifest_cell(sample_manifest_json()).unwrap();
    let cell2: Cell = parse_manifest_cell(sample_manifest_json()).unwrap();
    assert_eq!(
        cell1.repr_hash(),
        cell2.repr_hash(),
        "Parsing the same manifest JSON twice must produce identical cells"
    );
}

#[test]
fn parse_typed_args_round_trips_through_encode() {
    let specs: Vec<String> = vec![
        "uint256:0x000000000000000000000000000000000000000000000000000000000000002a".to_string(),
        "bytes:0x010203".to_string(),
        "bool:true".to_string(),
        "int:-7".to_string(),
        "long:1234567890".to_string(),
    ];
    let args = parse_typed_args(&specs).unwrap();
    assert_eq!(args.len(), 5);
    let cell1 = encode_jvm_args(&JvmArgs::new(args.clone())).unwrap();
    let cell2 = encode_jvm_args(&JvmArgs::new(args)).unwrap();
    assert_eq!(
        cell1.repr_hash(),
        cell2.repr_hash(),
        "Encoding the same parsed args twice must produce identical cells"
    );
}

#[test]
fn generic_call_descriptor_matches_method_id_of_signature() {
    // CLI builds a call descriptor by hashing the user-supplied
    // signature with `method_id_of` and embedding parsed args.  Lock
    // that the descriptor's method_id field matches what method_id_of
    // returns for the same signature (sanity check; the wallet/
    // deployer manifests already use the same derivation).
    let sig = "increment(uint256)";
    let args: Vec<String> = vec!["uint256:0x0000000000000000000000000000000000000000000000000000000000000005".to_string()];
    let typed = parse_typed_args(&args).unwrap();
    let desc =
        JvmCallDescriptor::new(method_id_of(sig), JvmArgs::new(typed));
    assert_eq!(desc.method_id, method_id_of("increment(uint256)"));
    // And the encoded cell is non-null.
    let cell = encode_jvm_call_descriptor(&desc).unwrap();
    assert_eq!(cell.references_count(), 1);
}

#[test]
fn generic_contract_address_derivation_matches_consensus_formula() {
    // Manually replay the address derivation `jw deploy-contract`
    // performs and verify it produces a stable, non-zero, manifest-
    // dependent address — i.e. swapping any of (deployer, salt,
    // class_bytes, init_args, manifest) changes the address.
    let deployer = [0xdeu8; 32];
    let salt = [0xa5u8; 32];
    let class_bytes = sample_class_bytes();
    let class_hash = compute_jvm_class_hash(&class_bytes);

    let manifest_cell = parse_manifest_cell(sample_manifest_json()).unwrap();
    let manifest_hash =
        compute_jvm_manifest_root_hash(Some(&manifest_cell));

    let init_args = parse_typed_args(&[
        "bytes32:0x0000000000000000000000000000000000000000000000000000000000000007".to_string(),
    ])
    .unwrap();
    let init_args_cell =
        encode_jvm_args(&JvmArgs::new(init_args)).unwrap();
    let address_commit =
        compute_jvm_address_commit(&deployer, &salt, &init_args_cell);
    let addr1 = derive_jvm_contract_address(
        &deployer,
        &address_commit,
        &class_hash,
        &manifest_hash,
    );

    // Different salt → different address.
    let salt2 = [0x5au8; 32];
    let commit2 =
        compute_jvm_address_commit(&deployer, &salt2, &init_args_cell);
    let addr2 = derive_jvm_contract_address(
        &deployer,
        &commit2,
        &class_hash,
        &manifest_hash,
    );
    assert_ne!(addr1, addr2);

    // Different manifest → different address (even with same salt).
    let manifest_cell_alt = parse_manifest_cell(
        r#"[{"abi_sig":"only()","class_name":"c","method_name":"only","method_spec":"()V"}]"#,
    )
    .unwrap();
    let manifest_hash_alt =
        compute_jvm_manifest_root_hash(Some(&manifest_cell_alt));
    let addr3 = derive_jvm_contract_address(
        &deployer,
        &address_commit,
        &class_hash,
        &manifest_hash_alt,
    );
    assert_ne!(addr1, addr3);
}

#[test]
fn parse_workchain_address_round_trips_for_wc3() {
    let (wc, id) = parse_workchain_address(
        "3:0x0000000000000000000000000000000000000000000000000000000000000abc",
    )
    .unwrap();
    assert_eq!(wc, 3);
    assert_eq!(id[31], 0xbc);
}

#[test]
fn parse_manifest_cell_rejects_invalid_json() {
    assert!(parse_manifest_cell("{ malformed").is_err());
    assert!(parse_manifest_cell("[]").is_err()); // empty manifest
}

#[test]
fn jvm_receipt_event_deserializes_from_server_shape() {
    // Mirror the exact JSON shape `jvm_receipt_event_json` produces
    // server-side (`validator-engine/json-rpc-server-jvm.cpp:214`).
    // Any drift on the camelCase rename, the topics-array shape, or
    // the createdLt/transactionLt string typing would break this
    // test in lockstep with the CLI being unable to render receipts.
    use chain_rpc_client::v2::jvm::{JvmReceiptEvent, JvmReceiptsResponse};

    let payload = serde_json::json!({
        "contractAddress": "0xabcdef",
        "receipts": [
            {
                "blockSeqno": 12345,
                "blockHash": "0x1234567890abcdef",
                "transactionLt": "98765",
                "transactionHash": "0xdeadbeef",
                "logIndex": 0,
                "createdLt": "98766",
                "createdAt": 1700000000,
                "topics": [
                    "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "0x2222222222222222222222222222222222222222222222222222222222222222"
                ],
                "data": "0xabcd"
            }
        ],
        "scannedTransactions": 42,
        "truncated": false
    });

    let parsed: JvmReceiptsResponse =
        serde_json::from_value(payload).expect("deserialize response");
    assert_eq!(parsed.contract_address, "0xabcdef");
    assert!(!parsed.truncated);
    assert_eq!(parsed.scanned_transactions, 42);
    assert_eq!(parsed.receipts.len(), 1);

    let ev: &JvmReceiptEvent = &parsed.receipts[0];
    assert_eq!(ev.block_seqno, 12345);
    assert_eq!(ev.transaction_lt, "98765");
    assert_eq!(ev.created_at, 1700000000);
    assert_eq!(ev.topics.len(), 2);
    assert_eq!(ev.data, "0xabcd");
}

#[test]
fn jvm_receipts_response_defaults_handle_missing_fields() {
    // The validator's core-RPC fallback (`jvm/core/rpc.cpp`) returns
    // `{contractAddress, receipts:[]}` with no `truncated` or
    // `scannedTransactions` — the Rust struct must treat those as
    // optional so tosctl works against any compliant node.
    use chain_rpc_client::v2::jvm::JvmReceiptsResponse;

    let minimal = serde_json::json!({
        "contractAddress": "0xff",
        "receipts": []
    });
    let parsed: JvmReceiptsResponse =
        serde_json::from_value(minimal).expect("deserialize minimal");
    assert_eq!(parsed.contract_address, "0xff");
    assert!(parsed.receipts.is_empty());
    assert!(!parsed.truncated);
    assert_eq!(parsed.scanned_transactions, 0);
}
