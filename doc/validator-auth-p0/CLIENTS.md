# Native API, clients and implementation acceptance

## Typed native API

C++ owning buffers/spans and Result types, and Rust Vec/slices and Result types,
expose the same operations. Integer widths and bytes are WIRE.md, never a compiler's
in-memory struct layout. Actor/future scheduling is an adapter concern.

```text
decode_envelope(bytes, ParseBudget) -> Decoded<Envelope> | DecodeError
decode_certificate(bytes, ParseBudget) -> Decoded<Certificate> | DecodeError
compile_registry(AuthenticatedRegistry, SessionContext, Policy) -> RegistrySnapshot | RegistryError
make_statement(RegistrySnapshot, Policy, ExpectedDuty, ValidatorId) -> CanonicalStatement | AuthError
verify_envelope(Decoded<Envelope>, RegistrySnapshot, Policy, ExpectedDuty, ProviderSet) -> VerifiedSigner | AuthError
verify_certificate(Decoded<Certificate>, RegistrySnapshot, Policy, ExpectedDuty, ProviderSet) -> VerifiedCertificate | AuthError
encode_envelope(Envelope) -> bytes | EncodeError
encode_certificate(Certificate) -> bytes | EncodeError
select_policy(AuthenticatedPolicyHistory, SessionBirthCoordinate) -> Policy | PolicyError
```

Decoded/Verified are distinct types; authenticated-result constructors are private
to verifiers. VerifiedCertificate contains duty/policy/committee IDs, unique signer
identities and authenticated weight. It does not apply a block. Verification is
read-only; state changes occur only in validated apply paths.
ProviderSet is an installed exact-profile allowlist, not peer callbacks.
validate_key, validate_signature_encoding and verify(CanonicalStatement,key,signature)
produce VALID/INVALID/UNSUPPORTED/BACKEND_ERROR; unsupported/backend failures never
fall back. Signing providers sit behind SIGNER.md, not peer certificate execution.

Snapshots own admitted key bytes and cached key/committee hashes. Validate costly
key/subgroup properties once per immutable snapshot. C0 should directly dispatch
Ed25519 without PQ work, rebuilding registries or unbounded copies. Check canonical
order; do not silently sort a malformed message. Cached verdicts bind policy,
committee, key and exact statement. Old signatures_checked flags cannot cross eras.

## RPC/SDK

New methods are validatorAuth.v1.getProfile/getPolicy/getRegistry/getKey/
getCertificate/verifyCertificate. The method table and every request/result/error field are fixed by
[canonical-schema.json](canonical-schema.json) and [API-CONTRACT.md](API-CONTRACT.md).
Requests pin a masterchain block seqno/root/file/resulting-state ID,
not floating latest state for historical verification. Binary objects are canonical
lowercase hex; the thin envelope and strict JSON field rules follow API-CONTRACT.md.
Profile exposes installed and active suites separately. Key/registry responses
include state-root/Merkle proofs anchored to that pinned block; the client verifies
the anchor independently. Registry pages contain 1..limit identities (limit <=128) in increasing
order, or an explicitly proved empty terminal page. Cursors bind the entire
anchor and query; range proofs establish completeness, and pages cannot mix snapshots.
Certificate responses include era/profile, canonical bytes and committee/policy
proof references. can_parse is not can_verify, and can_verify is not active.
Unsupported clients return UNSUPPORTED_PROFILE, not a legacy weaker-proof retry.
Old SDK methods may return historically typed records, never truncate or drop new
components. Wallet-level PQ support does not imply validator-certificate support.

## Concrete implementation and evidence map

| Existing boundary | Required implementation/gate |
| --- | --- |
| crypto/block/block.tlb, mc-config.cpp, validator-set.cpp, zerostate | Reviewed Config46/capability; authenticated stake/key/policy references; malformed config rejection and full genesis vectors |
| crypto/smartcont/elector-code.fc and config-code.fc | Current-policy registration/rotation/votes/privileged paths; regenerate compiled artifacts and execute action-phase tests |
| keyring/, keys/, validator-engine/ | Typed service/opaque handles; close raw sign/export bypass; actual durability, multi-writer, fencing and restore tests |
| validator/consensus/types.cpp, block-producer.cpp, simplex/votes.cpp, pool.cpp, certificate.cpp | VAS1 for proposals/all votes; preserve real quorum/conflict rules; mutations on actual call sites |
| validator/manager.cpp and consensus/bridge.cpp | Trusted session/committee/policy derivation; boundary/split/merge/stale-cache tests |
| crypto/block/signature-set.cpp, check-proof.cpp and consumers | Separate historical/P0 eras; parse is not authentication; invalid surplus signer and historical proofs |
| tos_api.tl, lite_api.tl and TL-B generators | New constructors alongside old IDs; native full TL/TL-B/BOC round trips |
| tosctl/src/block/src/signature.rs and Rust clients | Variable-length typed API alongside historical type; independent C++/Rust golden/negative/provider equality |
| RPC/JS SDK, explorer/indexer/archive | Pinned proofs, pagination, era/type distinction, unsupported errors |
| Light clients and embedded bridges | Full policy/committee proof chain and checkpoint trust; coordinated client-specific upgrade |

These actual production integrations remain open. Listing them or passing a
reference codec is not evidence that they have been implemented.

## Acceptance and performance

Reference tests cover the concrete wire contract and distinguish real C0 signatures
from shape/model tests. Native BOC codecs, cross-language edge cases, real registration/
rotation, active/active signing, power-loss before/after writes, restore against an
independent witness, and full multi-node transitions are production release gates.
Stateful PoP/exhaustion/fencing tests additionally gate a later stateful suite.

Proposed integrated-C0 budget: <=5% median and <=10% p95 extra already-admitted
certificate verification time, no PQ operation and no unbounded allocation, with
no statistically supported block/finality regression. Compare base/candidate on
the same minimum supported validator, compiler and flags using at least 30 paired
post-warmup samples. Record source/binary hashes, governor, p50/p95/p99, allocations,
RSS, certificate size and propagation; report registry creation separately. A noisy
interval is inconclusive. These are reviewable acceptance budgets, not results or
claims of zero cost for future activated PQ.

Profile review finishes after grammar/semantics/allocations/service/client owners
agree and candidate tests pass. Production P0 finishes only after every mapped
boundary runs on testnet with Ed25519 alone. Later PQ approval chooses a reviewed
suite and completes its separate security/resource/operational activation gates.

## Frozen capacity and carriers

Clients implement all 15 schema methods, VAOv/VAOr chunk resolution and the strict
JSON parser in API-CONTRACT.md. Check 400-member bounds without limiting historical
archive size. Resolve and authenticate a pinned object before reporting success;
partial upload/download is never a proof or receipt. The C++/Rust structural
codec differential harness covers every tagged and untagged type and malformed
framing. Native TL-B/BOC maximum-size tests cover storage, not chain inclusion
or authenticated range-proof production integration.

## P0-era finality proof consumers (revision 6)

`block_signatures_validator_auth#13` (WIRE.md section 7) is verified per the
separate historical/P0 eras rule: parse is not authentication. A P0-era finality
proof is verified by reconstructing the authenticated committee, session and Duty
from trusted chain history and checking the canonical VAC1 against them, with quorum
from the verified certificate weight — never from a claimed `sig_weight`. The
full-node `validator/impl/check-proof.cpp` verifier semantics are part of this
revision; the light-client `crypto/block/check-proof.cpp` proof era, its 2-root
source-context proof and `liteServer.signatureSet.validatorAuth` are a separate
later amendment. `tosctl/src/block/src/signature.rs` and other consumers either fully
verify the P0 era or return an explicit unsupported-era result; silent truncation of
VAC1 to the 64-byte leaf is forbidden.
