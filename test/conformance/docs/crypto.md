# crypto harness

One call of a cryptographic or consensus-identity function the node uses, on the node's own C++
function (`ref/harness-crypto.cpp`, `runner/harnesses/crypto.py`, `schema/harness/crypto-v1.schema.json`).

## Context and effects

`{"scheme", "operation", "inputs", "edits"?}`. `inputs` must match
`$defs.operations["<scheme>/<operation>"]` of the schema. Variable-length bytes are base64 (or a blob
reference, so a signature shared by many fixtures is stored once), 32-byte identifiers are 64
lowercase hex digits, and integers that may exceed 2^53 are decimal strings. `edits` (1..16) change
named byte inputs before the call: `xor` one byte with a non-zero value, `resize` (truncate or pad
with a byte), `fill`. An edit naming an input the operation does not read is refused.

Effects, by `outcome`: `verdict` (`valid`, `invalid`, `malformed_input`, `backend_error`), `bytes`
(`output`, lowercase hex), `integer` (`value`, decimal string), `boolean`, `record` (`fields`: name to
string; lists are comma-joined, `-` when empty, hashes lowercase hex), `rejected` (`reason`, a stable
code; a refusal of the node that the harness cannot classify is a harness error, so a new failure
path fails the run instead of being folded into an old code).

| Operation | C++ behind it | Effect |
|---|---|---|
| `ed25519/verify` | `td::Ed25519::PublicKey::verify_signature` (CHKSIGN*, classical block signatures) | verdict valid/invalid |
| `mldsa44/verify` | `tos::pq::verify_mldsa44` | verdict |
| `mldsa44/verify_consensus` | `verify_mldsa44` under the frozen surface context of `pq-consensus.h` (`simplex`, `validator_election`, `validator_config_vote`, `config_admin`) | verdict |
| `mldsa44/derive_key_id` | `tos::pq::derive_key_id` | bytes, or rejected `refused` |
| `falcon512/verify_padded` | `tos::pq::verify_falcon512_padded` | verdict |
| `slhdsa128s/verify` | `tos::pq::verify_slhdsa128s` | verdict |
| `lms_fee/verify`, `lms_fee/worst_compressions` | `tos::pq::verify_lms_fee`, `lms_fee_worst_compressions` | verdict; integer or rejected `unsupported` |
| `sha256/digest` | `td::sha256` | bytes |
| `poseidon2/permute`, `poseidon2/manifest_digest` | `vm::poseidon2::permute` (canonical elements only), SHA-256 of `manifest_bytes()` | bytes |
| `quorum/threshold`, `quorum/has_quorum` | `tos::quorum_threshold`, `tos::has_quorum` | integer, boolean |
| `validator_session/members` | `block::validator_session_members` (TL encoding of each member) | record |
| `validator_session/identity`, `config_hash`, `options_hash` | `block::derive_validator_session_identity`, `validator_session_config_hash`, `validator_session_options_hash` | record, bytes |
| `pq_bytes/pack`, `pq_bytes/unpack` | `tos::pq::pack_pq_bytes`, `unpack_pq_bytes` | record (root hash, BOC) / bytes, or rejected |
| `consensus/simplex_data_to_sign` | `block::BlockSignatureSet::build_simplex_data_to_sign` | bytes, or rejected `block_id_mismatch` / `candidate_tl` |
| `block_signatures/fetch` | `BlockSignatureSet::fetch` (cell; with a trusted validator set when given) | record (signers, session, slot, candidate digest, reserialization), or rejected reason |
| `block_signatures/fetch_tl` | TL decode, then `fetch_pq_node_checked` / `fetch_pq_lite_checked` | record, or rejected reason / `tl_parse` |
| `config43/parse` | `block::Config::do_get_size_limits_config` | record of the 18 limits, or rejected |
| `validator_set/unpack` | `block::Config::unpack_validator_set` (a set BOC, or descriptors the harness wraps in a set header) | record, or rejected |
| `elector/{stake,config_vote,complaint_vote}_preimage` | `tos::pq::*_preimage` (`pq-elector.h`) | bytes |

## Families

| Family | Fixtures | Context source | Cross-check |
|---|---|---|---|
| `pq-bytes` | 16 | `test/pq-mldsa44/pq-bytes-vectors.txt` | `migrate/crypto_generators.py`: equal to the frozen file row for row; frozen file equal to `pq-bytes-vectors-gen` output |
| `config43` | 9 | `test/pq-native/config43-vectors.tsv` | same, `config43-vectors-gen` |
| `authorisation-preimage` | 10 | `test/pq-native/authorisation-preimage-vectors.tsv` | same, `authorisation-preimage-vectors-gen` |
| `descriptor-verdict` | 10 | `test/pq-native/descriptor-verdict-vectors.tsv` | same, `descriptor-verdict-vectors-gen` |
| `validator-session-members` | 3 | `test/pq-native/validator-session-vectors.txt` | member id and bytes equal; `validator-session-vectors-gen` |
| `validator-session-derivation` | 3 | `test/pq-native/validator-session-derivation-vectors.tsv` | session config hash, session id, default Param29 options hash equal |
| `pq-block-signatures` | 23 | `test/pq-native/pq-block-signature-vectors.txt` | outcome, reason code and every parsed column equal |
| `pq-signature-tl` | 6 | `test/pq-native/pq-signature-tl-vectors.txt` | same |
| `slhdsa128s-openssl` | 4 | `test/pq-slhdsa/slh-verify-vectors.txt` | every signature verifies, as the file states |
| `rtos-lms-fee` | 332 | Rust tree `pq-crypto/tests/data/lms-fee.tsv` (166 rows: verify + worst-case cost) | `migrate/crypto_rtos.py compare` |
| `rtos-falcon512` | 228 | Rust tree `pq-crypto/tests/data/falcon512.tsv` | same |
| `rtos-mldsa44-verification` | 198 | Rust tree `pq-crypto/tests/data/verification-vectors.tsv` (ACVP, OpenSSL, Wycheproof inputs) | same |
| `rtos-simplex-context` | 6 | Rust tree `pq-crypto/tests/data/simplex-context.json` | same |
| `rtos-slhdsa128s-boundaries` | 8,334 | Rust tree `slhdsa128s-boundaries.tsv` and its ACVP/CIRCL/profile bases; mutations as `edits` | same, plus the ACVP/CIRCL upstream answers |
| `rtos-quorum` | 16 | Rust tree `block/tests/data/quorum-vectors.txt` | same |
| `wycheproof-ed25519` | 145 | `third-party/openssl/wycheproof/testvectors/eddsa_test.json` | `migrate/crypto_authored.py check`: equal to the Wycheproof result |
| `poseidon2-kat` | 22 | `crypto/vm/poseidon2-kat.h` perm8 vectors, manifest digest of `crypto/poseidon2/PROVENANCE.md` | equal to the pinned upstream outputs |
| `mldsa44-openssl` | 3 | `test/pq-mldsa44/fixtures.json` | all verify |
| `falcon512-vectors` | 28 | `test/pq-falcon512/vectors.json` | equal to the stated verdict |
| `crypto-negatives` | 112 | authored in `migrate/crypto_authored.py` | 96 with an authored expectation, 16 filled only |

The Rust tree's validator-session vector files are byte-identical to the C++ ones above, so they are
covered by the two `validator-session-*` families rather than duplicated.

## Commands

```
# contexts (the Rust files flat in <rtos-data>, taken with git show <commit>:<path>)
python3 test/conformance/migrate/crypto_generators.py contexts . <dir>
python3 test/conformance/migrate/crypto_authored.py contexts . <dir>
python3 test/conformance/migrate/crypto_rtos.py contexts <rtos-data> <dir>
# fill, one family at a time
python3 test/conformance/runner/conformance.py create --reference build/test/conformance/conformance-ref-cli \
    --harness crypto --family <family> --source <source> --blob-threshold 1024 \
    <dir>/<family>.contexts.jsonl test/conformance/vectors/crypto/fixtures/<family>.jsonl
# cross-checks
python3 test/conformance/migrate/crypto_generators.py check --source-dir . --vectors test/conformance/vectors/crypto/fixtures
python3 test/conformance/migrate/crypto_authored.py check . test/conformance/vectors/crypto/fixtures
python3 test/conformance/migrate/crypto_rtos.py compare <rtos-data> test/conformance/vectors/crypto/fixtures
```

ctest: `conformance-vectors` runs every family against the reference; `conformance-crypto-generators`
reruns the generator cross-check with the generator binaries; `runner/test_crypto.py` (in
`conformance-runner`) runs the generator and authored cross-checks and their tamper controls.
