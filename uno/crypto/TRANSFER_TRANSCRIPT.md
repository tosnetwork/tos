# Private-transfer transcript candidate v0

Unactivated Rust prototype, not the frozen TL-B wire or a production scheme.
The C++ verifier still accepts a supplied digest; this module is not yet exposed
through the generated ABI or connected to host admission. The expected domain
and resource limits must come from authenticated, supported configuration.

Hash: BLAKE3-256. `B(x)` means `u64be(len(x)) || x`. Fixed-width integers are
big-endian, including two's-complement signed values. Each digest begins with
`B("tos-uno-privacy-v1/experimental-transfer-v0") || B(label)`.
This experimental domain is deliberately distinct from an activation transcript.

For label `txid`, append in this exact order:

| Fields | Encoding |
|---|---|
| wire version, scheme, engine selector, engine version, encryption profile | five u32 |
| network ID | B(bytes32) |
| global ID, workchain ID | two i32 |
| chain ID | B(bytes32) |
| private-transfer kind | one zero byte |
| expiry height, nonce | u64, B(bytes32) |
| fee, public input, public output | three u128; input/output fixed zero |
| external reference, destination, refund plan | three zero absence bytes |
| fixed bundle-profile marker, flags | zero byte, one flags byte |
| value balance, anchor, Action count | i64, B(bytes32), u64 |
| each Action in order | B(cv_net), B(nf), B(rk), B(cmx), B(epk), B(enc_ciphertext), B(out_ciphertext), B(KEM ciphertext) |

Other action kinds require separate definitions, not changing the marker in
this transfer-only type. Bundle profile must equal the locked orchard_v2 profile.
For label `sighash`, append `B(txid)`. For label `authorization`, append `B(txid)`,
`B(proof)`, each `B(spend_signature)` in Action order, then `B(binding_signature)`.
Proofs/signatures never enter their own signing preimage. Blocks must separately
retain and commit authorization bytes; this is not the block data archive.

`transfer_digests` streams bounded fields and may run before authorization is
populated. `verify_transfer` compares the expected domain, derives the digest
from the same encoded object used by primitive decoding, and verifies the full
bundle in Transfer context. It takes no externally supplied sighash. Shape,
decode and verification errors remain distinguishable. Expiry, fee-policy,
state and canonical Cell checks remain the enclosing host's responsibility.

KEM fields must match the caller-profile's nonzero exact size, one per Action.
Tests use **four-byte opaque fixtures**, not ML-KEM ciphertexts. Their hashing
tests binding only, not encryption, outgoing recovery or backup correctness.

## Dependency and evidence

Pinned `blake3 = 1.8.7`, checksum
`6d9e454fc11f76977dc803893aff6304ed33d6a26efae8696573bea74baa27ae`;
crate VCS metadata identifies `f3149ec5bb5449af877ba20377a11008ff499fa2`.
See the [upstream release](https://github.com/BLAKE3-team/BLAKE3/releases/tag/1.8.7).
License: CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception.
New transitive packages cc 1.4.5, cpufeatures 0.3.1, find-msvc-tools 0.1.12 and
shlex 2.0.1 are each MIT OR Apache-2.0; checksums are locked. Existing dependency
versions were not bumped. This is not an activation-time dependency audit.

Primitive empty/three-byte known answers use the first 32 bytes of the
[tagged upstream vectors](https://github.com/BLAKE3-team/BLAKE3/blob/1.8.7/test_vectors/test_vectors.json).
Local transcript snapshots freeze a synthetic candidate fixture, not an
independently specified production wire. Tests vary every semantic field,
Action/KEM order, proof and signatures, and distinguish length-prefixed
`("ab", "c")` from `("a", "bc")`.

The real proof test authorizes the same proven spend using the derived digest.
It checks acceptance, nonce/KEM mutation rejection at spend-signature validation,
and domain mismatch rejection. Deliberately omitting nonce breaks that real
verification test; omitting byte-string lengths breaks field separation. Both
mutations were restored. The primitive, transcript and fixed-VK tests pass with
the new lockfile; neither that result nor the KEM fixture freezes a scheme.
