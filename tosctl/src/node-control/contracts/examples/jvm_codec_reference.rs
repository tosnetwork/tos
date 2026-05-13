// Reference-vector generator for the wc=3 JVM ABI codec.
//
// Prints exactly 8 lines of canonical hex hashes for fixed test inputs.
// Both the Rust parity test (`cargo test -p contracts jvm_codec_parity`)
// and the C++ test (`Test_JvmWorkchainCore_JvmCodecParityVectors` in
// `crypto/test/test-workchain-execution-registry.cpp`) MUST agree
// byte-for-byte with the hashes printed here.  The reference text file
// `jvm/core/jvm-codec-reference.txt` is the committed expected output
// of running this binary; it locks the Rust port (tosctl) and the C++
// consensus codec against silent drift.
//
// To regenerate after an intentional wire-format change:
//   1. Update both the Rust and C++ encoders.
//   2. cargo run -p contracts --example jvm_codec_reference \
//          > jvm/core/jvm-codec-reference.txt
//   3. Copy the new hex hashes into the C++ test inline expectations.
//   4. Verify `cargo test -p contracts jvm_codec` and
//      `./test-workchain-execution-registry` both pass.

use chain_block::{BuilderData, Cell, IBitstring};
use contracts::jvm_codec::{
    compute_jvm_address_commit, compute_jvm_class_hash,
    derive_jvm_contract_address, encode_jvm_args, encode_jvm_call_descriptor,
    encode_jvm_contract_account_state, encode_jvm_state_init_cell,
    encode_jvm_storage_value, JvmArgs, JvmCallDescriptor,
    JvmContractAccountState, JvmTypedArg,
};
use contracts::jvm_deployer::build_deployer_manifest_cell;
use contracts::jvm_wallet::build_wallet_manifest_cell;

fn owner_pubkey_fixture() -> [u8; 32] {
    // 0x00, 0x01, .., 0x1f — same as the existing
    // `jvm_codec::tests::sample_owner_pubkey` helper.
    let mut v = [0u8; 32];
    for (i, b) in v.iter_mut().enumerate() {
        *b = i as u8;
    }
    v
}

fn empty_args_fixture() -> JvmArgs {
    JvmArgs::default()
}

fn single_bytes32_args_fixture() -> JvmArgs {
    JvmArgs::new(vec![JvmTypedArg::bytes32(owner_pubkey_fixture())])
}

fn two_args_mixed_fixture() -> JvmArgs {
    JvmArgs::new(vec![
        JvmTypedArg::uint256([0x42u8; 32]),
        JvmTypedArg::address(3, [0xabu8; 32]),
    ])
}

// Mirrors the exact argument shape `Wallet.execute(uint256 nonce,
// bytes payload, bytes signature)` takes on the wire.  Locks the
// variable-length `Bytes` arg encoding path against silent drift —
// every signed Wallet call rides on this shape.
fn execute_args_fixture() -> JvmArgs {
    let mut nonce = [0u8; 32];
    nonce[31] = 0x07;
    let payload: Vec<u8> = (0..200u32)
        .map(|i| ((i.wrapping_mul(31).wrapping_add(11)) & 0xff) as u8)
        .collect();
    let signature: Vec<u8> = (0..64u32)
        .map(|i| ((i.wrapping_mul(17).wrapping_add(3)) & 0xff) as u8)
        .collect();
    JvmArgs::new(vec![
        JvmTypedArg::uint256(nonce),
        JvmTypedArg::raw_bytes(payload),
        JvmTypedArg::raw_bytes(signature),
    ])
}

fn placeholder_state_cell() -> Cell {
    // Same one-byte 0xde placeholder used by the existing
    // `state_init_cell_has_two_refs_and_is_valid_shape` test fixture.
    let mut cb = BuilderData::new();
    cb.append_u8(0xde).expect("placeholder builder");
    cb.into_cell().expect("placeholder finalize")
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

fn args_hash(args: &JvmArgs) -> String {
    let cell = encode_jvm_args(args).expect("encode_jvm_args");
    lower_hex(cell.repr_hash().as_slice())
}

fn call_descriptor_hash(method_id: u32, args: JvmArgs) -> String {
    let descriptor = JvmCallDescriptor::new(method_id, args);
    let cell = encode_jvm_call_descriptor(&descriptor)
        .expect("encode_jvm_call_descriptor");
    lower_hex(cell.repr_hash().as_slice())
}

fn state_init_hash() -> String {
    let cell = encode_jvm_state_init_cell(placeholder_state_cell())
        .expect("encode_jvm_state_init_cell");
    lower_hex(cell.repr_hash().as_slice())
}

fn wallet_manifest_hash() -> String {
    let cell = build_wallet_manifest_cell().expect("wallet manifest cell");
    lower_hex(cell.repr_hash().as_slice())
}

fn deployer_manifest_hash() -> String {
    let cell = build_deployer_manifest_cell().expect("deployer manifest cell");
    lower_hex(cell.repr_hash().as_slice())
}

// 300-byte fixture chosen so chunking actually fires: 127 + 127 + 46
// = 3 chunks.  Pattern is i * 7 + 3 mod 256 — non-repeating so a
// chunk-boundary off-by-one would change the hash.
fn class_bytes_fixture() -> Vec<u8> {
    (0..300u32)
        .map(|i| ((i.wrapping_mul(7).wrapping_add(3)) & 0xff) as u8)
        .collect()
}

fn storage_value_multi_chunk_hash() -> String {
    let cell = encode_jvm_storage_value(&class_bytes_fixture())
        .expect("storage value chunked");
    lower_hex(cell.repr_hash().as_slice())
}

fn jvac_canonical_hash() -> String {
    // Deterministic JVAC fixture: same owner_pubkey pattern as the
    // other vectors, all-zero genesis deployer, fixed address_commit,
    // chunked class_bytes from class_bytes_fixture(), no storage_root,
    // wallet manifest cell as manifest_root.  This single fixture
    // exercises: JVAC envelope, chunked class_bytes ref, Maybe(None)
    // bit for storage_root, Maybe(Just) bit for manifest_root.
    let mut address_commit = [0u8; 32];
    for (i, b) in address_commit.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(11).wrapping_add(7);
    }
    let mut stdlib_hash = [0u8; 32];
    for (i, b) in stdlib_hash.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13).wrapping_add(2);
    }
    let manifest = build_wallet_manifest_cell().expect("wallet manifest cell");
    let state = JvmContractAccountState {
        stdlib_hash,
        deployer: [0u8; 32],
        address_commit,
        class_bytes: class_bytes_fixture(),
        storage_root: None,
        manifest_root: Some(manifest),
    };
    let cell = encode_jvm_contract_account_state(&state)
        .expect("encode_jvm_contract_account_state");
    lower_hex(cell.repr_hash().as_slice())
}

fn address_fixture(salt: [u8; 32]) -> String {
    let deployer = [0u8; 32];
    let owner = owner_pubkey_fixture();
    let init_args = encode_jvm_args(&JvmArgs::new(vec![
        JvmTypedArg::bytes32(owner),
    ]))
    .expect("encode init args");
    let class_hash = compute_jvm_class_hash(b"class-bytes-fixture");
    let manifest_hash = [0u8; 32];
    let commit = compute_jvm_address_commit(&deployer, &salt, &init_args);
    let address = derive_jvm_contract_address(
        &deployer,
        &commit,
        &class_hash,
        &manifest_hash,
    );
    lower_hex(&address)
}

fn print_line(name: &str, hex: &str) {
    // Pad name to 26 cols so the hex column lines up; matches the
    // committed jvm-codec-reference.txt layout.
    println!("{:<26}{}", name, hex);
}

fn main() {
    println!("# jvm-codec-reference v1");
    println!("# Generated from contracts::jvm_codec — see jvm_codec_reference.rs.");
    println!("# Do not edit by hand.  Both Rust (cargo test -p contracts jvm_codec_parity)");
    println!("# and C++ (test-workchain-execution-registry JvmCodecParityVectors) MUST");
    println!("# produce these exact hashes.");

    print_line("empty-args", &args_hash(&empty_args_fixture()));
    print_line(
        "single-bytes32-args",
        &args_hash(&single_bytes32_args_fixture()),
    );
    print_line("two-args-mixed", &args_hash(&two_args_mixed_fixture()));
    print_line("execute-args", &args_hash(&execute_args_fixture()));
    print_line(
        "empty-call-descriptor",
        &call_descriptor_hash(0x1234_5678, empty_args_fixture()),
    );
    print_line(
        "call-with-typed-args",
        &call_descriptor_hash(0xdead_beef, two_args_mixed_fixture()),
    );
    print_line("state-init", &state_init_hash());
    print_line("wallet-manifest", &wallet_manifest_hash());
    print_line("deployer-manifest", &deployer_manifest_hash());
    print_line(
        "storage-value-multi-chunk",
        &storage_value_multi_chunk_hash(),
    );
    print_line("jvac-canonical", &jvac_canonical_hash());

    let salt_a = [0u8; 32];
    let mut salt_b = salt_a;
    salt_b[0] ^= 0xff;
    print_line("address-derivation-1", &address_fixture(salt_a));
    print_line("address-derivation-2", &address_fixture(salt_b));
}
