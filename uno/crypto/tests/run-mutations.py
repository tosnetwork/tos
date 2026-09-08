"""Run destructive controls only in an isolated source copy; retain evidence."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

# These controls run on an isolated copy, not in the ordinary CTest job.
# The underlying Rust regression tests do run in CTest.
SYSTEM_MUTATIONS = [
    [
        "domain",
        "src/system_encryption.rs",
        "    transcript.append_message(b\"protocol-domain\", domain);",
        "",
        "system_encryption_binds"
    ],
    [
        "id",
        "src/system_encryption.rs",
        "    transcript.append_message(b\"deposit-id\", id);",
        "",
        "system_encryption_binds"
    ],
    [
        "recipient",
        "src/system_encryption.rs",
        "    transcript.append_message(b\"recipient-P\", recipient);",
        "",
        "system_encryption_binds"
    ],
    [
        "amount",
        "src/system_encryption.rs",
        "    transcript.append_message(b\"amount\", &amount.to_le_bytes());",
        "",
        "system_encryption_binds"
    ],
    [
        "zero-amount",
        "src/system_encryption.rs",
        "    if amount == 0 { return Err(Error::UNO_CRYPTO_DECODE); }",
        "",
        "system_encryption_rejects"
    ],
    [
        "identity",
        "src/system_encryption.rs",
        "    if p.is_identity() { return Err(Error::UNO_CRYPTO_DECODE); }",
        "",
        "system_encryption_rejects"
    ],
    [
        "zero-scalar",
        "src/system_encryption.rs",
        "    if r == Scalar::ZERO { return Err(Error::UNO_CRYPTO_DECODE); }",
        "",
        "system_encryption_rejects"
    ],
    [
        "domain-label",
        "src/system_encryption.rs",
        "    let mut transcript = Transcript::new(b\"uno-v2/system-encryption\");",
        "    let mut transcript = Transcript::new(b\"uno-v2/system-encryption-wrong\");",
        "system_ciphertext_decrypts"
    ],
    [
        "wide-high-half",
        "src/system_encryption.rs",
        "    let r = Scalar::from_bytes_mod_order_wide(wide);",
        "    let mut narrow = *wide; narrow[32..].fill(0);\n    let r = Scalar::from_bytes_mod_order_wide(&narrow);",
        "system_ciphertext_decrypts"
    ],
    [
        "omit-handle-comparison",
        "src/ffi.rs",
        "        if expected != unsafe { *supplied } { return Err(AbiStatus::UNO_CRYPTO_VERIFY); }",
        "        if expected.commitment != unsafe { (*supplied).commitment } { return Err(AbiStatus::UNO_CRYPTO_VERIFY); }",
        "system_abi_checks"
    ],
    [
        "omit-commitment-comparison",
        "src/ffi.rs",
        "        if expected != unsafe { *supplied } { return Err(AbiStatus::UNO_CRYPTO_VERIFY); }",
        "        if expected.handle != unsafe { (*supplied).handle } { return Err(AbiStatus::UNO_CRYPTO_VERIFY); }",
        "system_abi_checks"
    ],
    [
        "abi-version",
        "src/ffi.rs",
        "    if r.abi_version != UNO_CRYPTO_ABI_VERSION { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }",
        "",
        "system_abi_checks"
    ],
    [
        "failure-atomicity",
        "src/ffi.rs",
        "        let ciphertext = unsafe { system_ciphertext(request)? };",
        "        unsafe { output.write(SystemCiphertext { commitment: [0;32], handle: [0;32] }); }\n        let ciphertext = unsafe { system_ciphertext(request)? };",
        "system_abi_checks"
    ],
    [
        "invent-deposit-limit",
        "src/system_encryption.rs",
        "    if amount == 0 { return Err(Error::UNO_CRYPTO_DECODE); }",
        "    if amount == 0 || amount > 1000 { return Err(Error::UNO_CRYPTO_DECODE); }",
        "system_encryption_rejects"
    ],
    [
        "verify-abi-version",
        "src/ffi.rs",
        "    if r.abi_version != UNO_CRYPTO_ABI_VERSION { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }",
        "",
        "system_verify_checks_request_version_independently"
    ]
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target-dir", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    fixture = Path(tempfile.mkdtemp(prefix="uno-kernel-mutations-")) / "crypto"
    shutil.copytree(ROOT, fixture, ignore=shutil.ignore_patterns("target", "__pycache__"))
    environment = dict(os.environ, CARGO_NET_OFFLINE="true", CARGO_TARGET_DIR=str(args.target_dir))
    results = []

    def command(label, test, should_pass):
        result = subprocess.run(["cargo", "test", "--locked", "--offline", "--release", "-j48", "--lib", test,
                                 "--", "--nocapture"], cwd=fixture, env=environment, capture_output=True, text=True)
        log = result.stdout + result.stderr
        (args.output / (label + ".log")).write_text(log)
        executed = "running " in log and "test result:" in log
        if not executed or (result.returncode == 0) != should_pass:
            raise RuntimeError(f"{label}: expected an executed {'passing' if should_pass else 'failing'} test; fixture={fixture}")
        results.append({"label": label, "test": test, "exit": result.returncode})

    def mutation(label, path, before, after, test):
        file = fixture / path
        original = file.read_text()
        if original.count(before) != 1:
            raise RuntimeError(f"mutation anchor not unique: {label}")
        file.write_text(original.replace(before, after))
        try:
            command(label, test, False)
        finally:
            file.write_text(original)

    command("baseline", "", True)
    for label, path, before, after, test in SYSTEM_MUTATIONS:
        mutation("system-" + label, path, before, after, test)
    mutation("drop-internal-collect-ceiling", "src/relation.rs", "limits.max_collect > 64", "false",
             "internal_collect_ceiling_rejects_unsupported_policy_before_input")
    path = "vendor/bulletproofs/src/range_proof/deterministic.rs"
    for name, replacement in (("drop-ip", "poly.is_identity()"), ("drop-poly", "ip.is_identity()"),
                              ("allow-cancellation", "(ip + poly).is_identity()")):
        mutation(name, path, "ip.is_identity() && poly.is_identity()", replacement, "range_residuals_cannot_cancel")
    for index in range(21):
        mutation(f"drop-sigma-{index}", "src/relation.rs",
                 "for ((row, target), t) in rows.iter().zip(targets).zip(ts) {",
                 f"for (index, ((row, target), t)) in rows.iter().zip(targets).zip(ts).enumerate() {{ if index == {index} {{ continue; }}",
                 "each_sigma_equation_has_an_independent_negative_witness")
    mutation("drop-context", "src/relation.rs",
             'transcript.append_message(b"authenticated-context", context);',
             'let _ = context;', "every_public_field_and_proof_component_is_bound")
    mutation("drop-and-commitment-binding", "src/relation.rs",
             'for commitment in commitments { t.append_message(b"T", commitment); }',
             'for commitment in commitments { let _ = commitment; }', "cross_language_vectors_are_frozen")
    mutation("drop-collect-limit", "src/relation.rs", "ids.len() > limits.max_collect ||", "false ||",
             "policy_and_encoding_boundaries")
    mutation("wrong-shared-response-index", "src/relation.rs",
             "Point::vartime_multiscalar_mul(zs, row)", "Point::vartime_multiscalar_mul(zs.iter().rev(), row)",
             "full_send_and_collect_all_candidate_sizes")
    mutation("unrelated-range-commitments", "src/relation.rs", "ranges.resize(m, zero);",
             "ranges.clear(); ranges.resize(m, zero);", "full_send_and_collect_all_candidate_sizes")
    mutation("drop-kat-event", "src/tests.rs", 't.append_u64(b"counter",0x0102030405060708);',
             't.append_u64(b"counter",0x0807060504030201);', "transcript_matches_independent_c_reference")
    for name, before in (
        ("send-identities", "[p[0], p[1], p[5], p[7], p[8]].iter().any(Point::is_identity)"),
        ("collect-identities", "p[0].is_identity() || p[4].is_identity()"),
        ("receipt-identity", "receipt[1].is_identity()"),
    ):
        mutation("drop-" + name, "src/relation.rs", before, "false",
                 "nonidentity_handles_are_checked_before_proof_verification")
    for name, before in (
        ("value-zero", "limits.max_value == 0"),
        ("value-order", "limits.max_value > limits.max_balance"),
        ("collect-zero", "limits.max_collect == 0"),
        ("context-zero", "limits.max_context_bytes == 0"),
        ("proof-zero", "limits.max_proof_bytes == 0"),
        ("empty-context", "context.is_empty()"),
        ("context-ceiling", "context.len() > limits.max_context_bytes"),
        ("proof-ceiling", "range_size(m)? > limits.max_proof_bytes"),
    ):
        mutation("drop-" + name, "src/relation.rs", before, "false",
                 "admission_predicates_have_independent_witnesses")
    mutation("drop-unknown-kind", "src/relation.rs", "kind != UNO_RELATION_COLLECT", "false",
             "unknown_relation_kind_is_not_collect")
    mutation("send-with-receipts", "src/relation.rs", "kind == UNO_RELATION_SEND && k == 0",
             "kind == UNO_RELATION_SEND", "admission_predicates_have_independent_witnesses")
    mutation("empty-collect", "src/relation.rs", "kind != UNO_RELATION_COLLECT || k == 0",
             "kind != UNO_RELATION_COLLECT", "admission_predicates_have_independent_witnesses")
    mutation("drop-alignment", "src/ffi.rs", "(pointer as usize) % mem::align_of::<T>() == 0",
             "true", "admission_predicates_have_independent_witnesses")
    command("restored", "", True)
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    shutil.rmtree(fixture.parent)
    print(f"PASS: {len(results)} executed controls, evidence at {args.output}")


if __name__ == "__main__":
    main()
