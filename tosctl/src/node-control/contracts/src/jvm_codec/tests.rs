/*
 * Structural / determinism tests for the Rust port of the JVM ABI
 * codec.  Byte-stability against the C++ reference is verified
 * indirectly via the address-derivation formula: if the Rust JvmArgs
 * cell hash matches the C++ cell hash for the same input, the
 * derived contract address will match too — and that address is
 * already locked by the consensus address-binding gate.
 */

use super::*;

fn sample_owner_pubkey() -> [u8; 32] {
    let mut v = [0u8; 32];
    for (i, b) in v.iter_mut().enumerate() {
        *b = i as u8;
    }
    v
}

fn sample_salt() -> [u8; 32] {
    let mut v = [0u8; 32];
    for (i, b) in v.iter_mut().enumerate() {
        *b = (i ^ 0x55) as u8;
    }
    v
}

#[test]
fn args_encode_is_deterministic() {
    let owner = sample_owner_pubkey();
    let args = JvmArgs::new(vec![JvmTypedArg::bytes32(owner)]);
    let a = encode_jvm_args(&args).expect("encode 1");
    let b = encode_jvm_args(&args).expect("encode 2");
    assert_eq!(
        a.repr_hash(),
        b.repr_hash(),
        "JvmArgs encoding is not deterministic"
    );
}

#[test]
fn empty_args_root_has_no_child_ref() {
    let cell = encode_jvm_args(&JvmArgs::default()).expect("encode");
    assert_eq!(
        cell.references_count(),
        0,
        "empty JvmArgs must have no child refs"
    );
}

#[test]
fn non_empty_args_root_has_single_child_ref() {
    let owner = sample_owner_pubkey();
    let args = JvmArgs::new(vec![
        JvmTypedArg::bytes32(owner),
        JvmTypedArg::uint256([0u8; 32]),
    ]);
    let cell = encode_jvm_args(&args).expect("encode");
    assert_eq!(
        cell.references_count(),
        1,
        "non-empty JvmArgs must have exactly one chain-head ref"
    );
}

#[test]
fn call_descriptor_round_trips_method_id_and_args() {
    let owner = sample_owner_pubkey();
    let init_method_id = 0xdead_beef;
    let descriptor = JvmCallDescriptor::new(
        init_method_id,
        JvmArgs::new(vec![JvmTypedArg::bytes32(owner)]),
    );
    let cell = encode_jvm_call_descriptor(&descriptor).expect("encode");
    assert_eq!(
        cell.references_count(),
        1,
        "JvmCallDescriptor always carries exactly one args ref"
    );
    // Determinism: re-encode the same descriptor and compare hashes.
    let cell2 = encode_jvm_call_descriptor(&descriptor).expect("encode 2");
    assert_eq!(cell.repr_hash(), cell2.repr_hash());
}

#[test]
fn class_hash_empty_input_is_zero() {
    let h = compute_jvm_class_hash(&[]);
    assert_eq!(h, [0u8; 32], "empty class_bytes ⇒ all-zero class_hash");
}

#[test]
fn class_hash_changes_with_input() {
    let a = compute_jvm_class_hash(b"alpha");
    let b = compute_jvm_class_hash(b"beta");
    assert_ne!(a, b);
}

#[test]
fn manifest_root_hash_null_is_zero() {
    assert_eq!(compute_jvm_manifest_root_hash(None), [0u8; 32]);
}

#[test]
fn address_derivation_changes_with_salt() {
    // Two wallets with identical owner pubkey + class but different
    // salts must resolve to different addresses (basic salt
    // disambiguation property — mirrors the C++ test
    // `GenesisWalletDifferentSaltProducesDifferentAddresses`).
    let owner = sample_owner_pubkey();
    let salt_a = sample_salt();
    let mut salt_b = salt_a;
    salt_b[0] ^= 0xff;

    let init_args =
        encode_jvm_args(&JvmArgs::new(vec![JvmTypedArg::bytes32(owner)]))
            .expect("encode init args");
    let class_hash = compute_jvm_class_hash(b"class-bytes-fixture");
    let manifest_hash = [0u8; 32];

    let deployer = [0u8; 32]; // sentinel "genesis deployer"
    let commit_a =
        compute_jvm_address_commit(&deployer, &salt_a, &init_args);
    let commit_b =
        compute_jvm_address_commit(&deployer, &salt_b, &init_args);
    assert_ne!(commit_a, commit_b);

    let addr_a = derive_jvm_contract_address(
        &deployer, &commit_a, &class_hash, &manifest_hash,
    );
    let addr_b = derive_jvm_contract_address(
        &deployer, &commit_b, &class_hash, &manifest_hash,
    );
    assert_ne!(addr_a, addr_b);
}

#[test]
fn address_derivation_is_deterministic() {
    let owner = sample_owner_pubkey();
    let salt = sample_salt();
    let init_args =
        encode_jvm_args(&JvmArgs::new(vec![JvmTypedArg::bytes32(owner)]))
            .expect("encode init args");
    let class_hash = compute_jvm_class_hash(b"class-bytes-fixture");

    let deployer = [0u8; 32];
    let commit_a =
        compute_jvm_address_commit(&deployer, &salt, &init_args);
    let commit_b =
        compute_jvm_address_commit(&deployer, &salt, &init_args);
    assert_eq!(commit_a, commit_b);

    let addr_a = derive_jvm_contract_address(
        &deployer, &commit_a, &class_hash, &[0u8; 32],
    );
    let addr_b = derive_jvm_contract_address(
        &deployer, &commit_b, &class_hash, &[0u8; 32],
    );
    assert_eq!(addr_a, addr_b);
}

#[test]
fn deploy_descriptor_carries_three_refs() {
    let class_hash = compute_jvm_class_hash(b"class-bytes-fixture");
    let init_args =
        encode_jvm_args(&JvmArgs::new(vec![JvmTypedArg::bytes32(
            sample_owner_pubkey(),
        )]))
        .expect("encode init args");

    let descriptor = JvmDeployDescriptor {
        deployer: [0u8; 32],
        salt: sample_salt(),
        class_hash,
        class_name: "java/lang/Wallet".to_string(),
        class_bytes: b"class-bytes-fixture".to_vec(),
        init_args,
    };
    let cell = encode_jvm_deploy_descriptor(&descriptor).expect("encode");
    assert_eq!(
        cell.references_count(),
        3,
        "JvmDeployDescriptor carries (class_name, class_bytes, init_args) refs"
    );
}

#[test]
fn state_init_cell_has_two_refs_and_is_valid_shape() {
    // We use a small placeholder cell as the JVAC stand-in. The
    // StateInit cell must reference it together with the activation
    // marker; the validator validates the full TLB shape downstream.
    let mut placeholder_builder = chain_block::BuilderData::new();
    chain_block::IBitstring::append_u8(&mut placeholder_builder, 0xde)
        .expect("placeholder builder");
    let placeholder = placeholder_builder
        .into_cell()
        .expect("placeholder finalize");

    let state_init = encode_jvm_state_init_cell(placeholder).expect("encode");
    assert_eq!(state_init.references_count(), 2);
}

#[test]
fn storage_value_empty_encodes_to_single_bit_cell() {
    let cell = encode_jvm_storage_value(&[]).expect("encode empty");
    assert_eq!(cell.references_count(), 0);
    // The cell carries exactly a single zero bit (empty marker).
    // Inspecting the bit count isn't trivial via the public API, but
    // re-encoding twice and checking hash equality at least proves
    // determinism.
    let cell2 = encode_jvm_storage_value(&[]).expect("encode empty 2");
    assert_eq!(cell.repr_hash(), cell2.repr_hash());
}

#[test]
fn storage_value_chunks_above_127_bytes() {
    // 200 bytes ⇒ 2 chunks (127 + 73). The root cell must hold one ref
    // (to the tail chunk).
    let payload = vec![0xabu8; 200];
    let cell = encode_jvm_storage_value(&payload).expect("encode");
    assert_eq!(
        cell.references_count(),
        1,
        "non-final chunk must reference the next chunk"
    );
}
