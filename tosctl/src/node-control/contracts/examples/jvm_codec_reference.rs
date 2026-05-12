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
    encode_jvm_state_init_cell, JvmArgs, JvmCallDescriptor, JvmTypedArg,
};

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
    print_line(
        "empty-call-descriptor",
        &call_descriptor_hash(0x1234_5678, empty_args_fixture()),
    );
    print_line(
        "call-with-typed-args",
        &call_descriptor_hash(0xdead_beef, two_args_mixed_fixture()),
    );
    print_line("state-init", &state_init_hash());

    let salt_a = [0u8; 32];
    let mut salt_b = salt_a;
    salt_b[0] ^= 0xff;
    print_line("address-derivation-1", &address_fixture(salt_a));
    print_line("address-derivation-2", &address_fixture(salt_b));
}
