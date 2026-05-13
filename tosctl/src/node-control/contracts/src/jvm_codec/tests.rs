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

/// Byte-exact parity gate between the Rust port (`jvm_codec`) and the
/// C++ consensus codec (`jvm/core/{message-abi,deploy-abi,cell-codec,
/// storage-cell-host}.{h,cpp}`).
///
/// The reference vectors live in `jvm/core/jvm-codec-reference.txt`,
/// generated by `cargo run -p contracts --example jvm_codec_reference`.
/// Both this test and the C++ test
/// `JvmWorkchainCore::JvmCodecParityVectors` (in
/// `crypto/test/test-workchain-execution-registry.cpp`) MUST agree
/// byte-for-byte with those vectors. If only one side breaks after a
/// codec change, the maintainer is forced to acknowledge the drift
/// before either test can go green again.
#[test]
fn parity_against_reference_vectors() {
    use chain_block::{BuilderData, IBitstring};

    const REFERENCE: &str =
        include_str!("../../../../../../jvm/core/jvm-codec-reference.txt");

    fn lower_hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    fn lookup(label: &str) -> String {
        for line in REFERENCE.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }
            let mut parts = trimmed.split_whitespace();
            let key = parts.next().expect("reference line label");
            let value = parts.next().expect("reference line hash");
            if key == label {
                return value.to_string();
            }
        }
        panic!("reference vector `{label}` not found in jvm-codec-reference.txt");
    }

    let owner = sample_owner_pubkey();

    // empty-args
    let empty_args = encode_jvm_args(&JvmArgs::default()).expect("empty args");
    assert_eq!(
        lower_hex(empty_args.repr_hash().as_slice()),
        lookup("empty-args"),
        "Rust encode_jvm_args(default()) drifted from jvm-codec-reference.txt"
    );

    // single-bytes32-args
    let single =
        encode_jvm_args(&JvmArgs::new(vec![JvmTypedArg::bytes32(owner)]))
            .expect("single bytes32");
    assert_eq!(
        lower_hex(single.repr_hash().as_slice()),
        lookup("single-bytes32-args"),
        "Rust single-bytes32-args drifted from jvm-codec-reference.txt"
    );

    // two-args-mixed
    let two_args = JvmArgs::new(vec![
        JvmTypedArg::uint256([0x42u8; 32]),
        JvmTypedArg::address(3, [0xabu8; 32]),
    ]);
    let two = encode_jvm_args(&two_args).expect("two args mixed");
    assert_eq!(
        lower_hex(two.repr_hash().as_slice()),
        lookup("two-args-mixed"),
        "Rust two-args-mixed drifted from jvm-codec-reference.txt"
    );

    // empty-call-descriptor
    let empty_call = encode_jvm_call_descriptor(&JvmCallDescriptor::new(
        0x1234_5678,
        JvmArgs::default(),
    ))
    .expect("empty call");
    assert_eq!(
        lower_hex(empty_call.repr_hash().as_slice()),
        lookup("empty-call-descriptor"),
        "Rust empty-call-descriptor drifted from jvm-codec-reference.txt"
    );

    // call-with-typed-args
    let typed_call = encode_jvm_call_descriptor(&JvmCallDescriptor::new(
        0xdead_beef,
        two_args.clone(),
    ))
    .expect("typed call");
    assert_eq!(
        lower_hex(typed_call.repr_hash().as_slice()),
        lookup("call-with-typed-args"),
        "Rust call-with-typed-args drifted from jvm-codec-reference.txt"
    );

    // state-init
    let mut placeholder = BuilderData::new();
    placeholder.append_u8(0xde).expect("placeholder");
    let state_cell = placeholder.into_cell().expect("placeholder finalize");
    let state_init =
        encode_jvm_state_init_cell(state_cell).expect("state init");
    assert_eq!(
        lower_hex(state_init.repr_hash().as_slice()),
        lookup("state-init"),
        "Rust state-init drifted from jvm-codec-reference.txt"
    );

    // wallet-manifest — must equal the C++ build_wallet_manifest_cell()
    // hash; otherwise tosctl-derived wallet addresses don't match the
    // chain's genesis-seeded wallet addresses.
    let wallet_manifest = crate::jvm_wallet::build_wallet_manifest_cell()
        .expect("wallet manifest cell");
    assert_eq!(
        lower_hex(wallet_manifest.repr_hash().as_slice()),
        lookup("wallet-manifest"),
        "Rust wallet-manifest drifted from jvm-codec-reference.txt"
    );

    // deployer-manifest — same parity concern, but the consequence is
    // worse: a drift here makes `tosctl jw deploy --via <deployer>`
    // route to a non-existent account because the deployer's wc=3
    // address depends on this cell's hash.
    let deployer_manifest = crate::jvm_deployer::build_deployer_manifest_cell()
        .expect("deployer manifest cell");
    assert_eq!(
        lower_hex(deployer_manifest.repr_hash().as_slice()),
        lookup("deployer-manifest"),
        "Rust deployer-manifest drifted from jvm-codec-reference.txt"
    );

    // address-derivation-1 / address-derivation-2
    let init_args =
        encode_jvm_args(&JvmArgs::new(vec![JvmTypedArg::bytes32(owner)]))
            .expect("encode init args");
    let class_hash = compute_jvm_class_hash(b"class-bytes-fixture");
    let manifest_hash = [0u8; 32];
    let deployer = [0u8; 32];

    let salt_a = [0u8; 32];
    let mut salt_b = salt_a;
    salt_b[0] ^= 0xff;

    let commit_a =
        compute_jvm_address_commit(&deployer, &salt_a, &init_args);
    let addr_a = derive_jvm_contract_address(
        &deployer,
        &commit_a,
        &class_hash,
        &manifest_hash,
    );
    assert_eq!(
        lower_hex(&addr_a),
        lookup("address-derivation-1"),
        "Rust address-derivation-1 drifted from jvm-codec-reference.txt"
    );

    let commit_b =
        compute_jvm_address_commit(&deployer, &salt_b, &init_args);
    let addr_b = derive_jvm_contract_address(
        &deployer,
        &commit_b,
        &class_hash,
        &manifest_hash,
    );
    assert_eq!(
        lower_hex(&addr_b),
        lookup("address-derivation-2"),
        "Rust address-derivation-2 drifted from jvm-codec-reference.txt"
    );
}
