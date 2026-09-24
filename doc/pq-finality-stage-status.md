# Post-quantum finality stage status

This document records the implementation evidence for sections 3 through 10 of
`N5-EXECUTION-ORDER.md`.  It is an implementation status, not an activation
decision, an independent audit, or a claim beyond the boundaries stated for each
gate.  Test names below are the names registered in CTest unless explicitly
identified as Rust or workflow-only tests.

The design document uses stage-prefixed gate names.  Source and test names use
subject names instead; the mappings below are normative for finding the evidence
in this tree.

## Section 3: measured and frozen carrier

Commits:

- `c4fabb76445ccf3a008b9f026857553e47eb8d0a` — route-limit inventory and gate.
- `c4acd8914926172383fd5e837aaf1e7622fa0981` — prescribed verdict rows and explicit projections.
- `5d02341d37f8fe661c682591a002bad6840ce984` — measurement switched from a hand-built `#13` value to the production serializer.
- `b11a4d9c8c65a1f4b98e8e11e5ebc9a69c1b8781` — generated node/lite sizes replaced the incorrect projections.

| Design gate | Registered subject test | Proves | Does not prove |
|---|---|---|---|
| `n5-0-block-signature-measure` | `block-signature-carrier-measure` | Deterministic production serialization at 1/21/32/64/100/400 signers; the 400-signer BOC is 1,020,996 bytes with SHA-256 `0C05E72DD2095B0B3497CEF3422DFBC65B42891BB011C75E769AC245FA0B9B63`. | Network admission, proof verification, or block acceptance. |
| `n5-0-block-signature-limits` | `block-signature-carrier-bound` | The frozen one-MiB persisted envelope admits the canonical 400-signer object and the production serializer refuses 401 signers. | A 400-member live committee, transport throughput, or cryptographic quorum. |
| Static route inventory required by §3.3 | `block-signature-carrier-routes` | Every named production limit still equals the recorded value and every route minimum and measured headroom recomputes. | This static inventory does not exercise transport. Sections 6 and 10 add serializer/admission and live framed-TCP gates, but no gate in this stage stands up a live overlay peer graph. |

Mutations observed:

- Lowering the production ADNL external packet constant by 4096 produced exactly
  `ROUTE_CONSTANT_MISMATCH: adnl::adnl_ext_max_packet_bytes recorded=16777216 actual=16773120`.
- Changing the recorded one-signer node projection by one byte produced exactly
  `ROUTE_PROJECTION_SIZE_MISMATCH: object=projected-tosNode.signatureSet.simplexPq signers=1 recorded=2645 measurement=2644`.

The generated TL codec later established that the projection had invented
`4 * signer_count + 4` bytes of vector/element framing.  The authoritative node
and lite sizes are 2,636 / 51,836 / 78,896 / 157,616 / 246,176 / 984,176 bytes
at 1 / 21 / 32 / 64 / 100 / 400 signers.  The persisted BOC and its frozen
envelope did not move.  These numbers are the generated-code measurements in
`test/pq-native/block-signature-carrier-measurements.tsv`, consumed by
`block-signature-carrier-measure` and `block-signature-carrier-routes`.

## Section 4: canonical C++ and Rust `#13` codec

Commits:

- `5d02341d37f8fe661c682591a002bad6840ce984` — C++ `#13` schema, checked codec, shared fixture, and C++ mutations.
- `af3c1334d20b52a4a426e9a8739d5a35b47f6459` — Rust codec and byte-identical shared-fixture round trip.
- `65b8a65dfd567cd07e937908460c409f698b1c76` — cross-language unknown-signer and algorithm-mismatch parity.

| Design gate | Registered subject test | Proves | Does not prove |
|---|---|---|---|
| `n5-pq-block-signature-codec-cpp` | `pq-block-signature-vectors` | C++ accepts and rejects the shared canonical BOCs for the recorded structural rule and reserializes accepted rows byte-for-byte. | ML-DSA validity, trusted session derivation, or quorum. |
| `n5-pq-block-signature-codec-rust` | Rust `shared_pq_block_signature_codec_parity_does_not_verify_finality` | Rust consumes the same fixture, applies the same structural reason code, and reserializes accepted rows byte-for-byte. | Rust finality verification; Rust is a codec/tooling consumer here. |
| `n5-pq-block-signature-parity` | The preceding C++ and Rust tests over `test/pq-native/pq-block-signature-vectors.txt` | The two languages accept the same structural language and emit the same BOC bytes. | Semantic proof acceptance by a node or lite client. |

Mutations observed:

- Removing C++ tag discrimination produced `VECTOR_REASON_MISMATCH`; the input
  remained rejected by a later rule, so this guard is reason-sensitive rather
  than the only refusal.
- Removing the C++ signer-count bound produced
  `VECTOR_UNEXPECTED_ACCEPT case=401-signers expected=signer_count`.
- Removing the C++ exact-signature-length check produced
  `VECTOR_UNEXPECTED_ACCEPT case=wrong-signature-length-short expected=signature_length`.
- Removing C++ PQBytes canonicality produced
  `VECTOR_UNEXPECTED_ACCEPT case=noncanonical-pqbytes expected=noncanonical_pqbytes`.
- Removing the C++ duplicate-validator check produced
  `VECTOR_UNEXPECTED_ACCEPT case=duplicate-validator-id expected=duplicate_validator_id`.
- Removing the C++ dictionary index/count check produced
  `VECTOR_UNEXPECTED_ACCEPT case=dictionary-gap expected=dictionary_index`.
- Removing the C++ candidate bound produced `VECTOR_REASON_MISMATCH`; a later
  candidate check still refused the row for a different reason.
- The corresponding Rust removals produced, exactly:
  `RUST_VECTOR_UNEXPECTED_ACCEPT case=401-signers expected=signer_count`,
  `RUST_VECTOR_UNEXPECTED_ACCEPT case=wrong-signature-length-short expected=signature_length`,
  `RUST_VECTOR_UNEXPECTED_ACCEPT case=duplicate-validator-id expected=duplicate_validator_id`, and
  `RUST_VECTOR_UNEXPECTED_ACCEPT case=dictionary-gap expected=dictionary_index`.
- Restoring Rust's former “skip unknown signer” behavior produced
  `RUST_VECTOR_UNEXPECTED_ACCEPT case=unknown-validator-id expected=unknown_validator_id`.

For the two reason-shadowed C++ mutations, the retained review transcript records
the exact emitted marker but not the dynamic `actual=` suffix.  That is a
mutation-evidence retention limitation; it is not relabeled here as a complete
raw transcript.

## Section 5: trusted-set, signature, quorum, and session binding

Commits:

- `da478ed3edb44a7982e92f1799945112e5eafe40` — authoritative weight and ML-DSA verification.
- `65b8a65dfd567cd07e937908460c409f698b1c76` — unknown signer and descriptor-algorithm refusal.
- `b199f068243c56f81d5c9391365dc0a73805aff6` — one shared session derivation, exact Param30-cell commitment, and governing-snapshot vectors.
- `ab4e32f743db8e8e300cc03010f2f775c4c03753` — trusted expected-session verification boundary and production caller source guard.
- `1347c91435908902296e61b3a76470723baba2c9` — bidirectional classical-carrier inventory and removal of the dead, misleading disk-manager session helper.
- `1897d48329ca80d21d11f0005c7b4684a1aca50b` — admission-path carrier markers classified by their actual classical-only or PQ-reachable branches.
- `fe0896df8c8604ca6f4572e3f284bb0b0a7105e6` — session-options hashing moved below consensus to preserve link boundaries.
- `8c3981f63d7791b7203fceb7311ceb5d17ee8714` — governing header `global_id` checked against ConfigParam 19 at both proof-context entry points.
- `bf3f7a912941fd64f6fc72a63cc6c3a67f9dd339` — manager session-input assembly made directly testable, with a real serialized-state accessor gate.

The bidirectional classical-carrier inventory contains 50 rows covering 44
Git-tracked paths, 85 distinct marker entries and 279 source sites.  These
counts are produced by `scripts/check-classical-carrier-sites.py` from
`test/pq-native/classical-carrier-sites.tsv`; at this head the checker reports
`entries=85 sites=279`.  Its earlier
408-site figure included 130 occurrences in eight untracked
`tl/generate/auto/tl/*` build outputs.  Those derived copies are now excluded;
their two authoritative tracked schema inputs remain inventoried.

| Design gate | Registered subject test | Proves | Does not prove |
|---|---|---|---|
| `n5-pq-block-signature-conformance` | `pq-block-signature-conformance` | Stable validator ID, descriptor type/algorithm/key, signed preimage, role, every included signature, checked weight, and quorum are enforced. | That every production proof consumer supplies the right trusted context. |
| `n5-pq-block-signature-no-legacy` | `pq-block-signature-no-legacy` | Cell, node-TL, and lite-TL `#11/#12` carriers are refused before classical verification under a PQ set. | Removal of historical classical codecs. |
| `n5-pq-session-binding` | `validator-session-derivation`, `validator-session-param30`, `validator-session-global-id`, `validator-session-local-override`, `validator-session-governing-snapshot`, `validator-session-session-path`, `validator-session-constructor-selection`, `validator-session-manager-assembly`, `validator-session-state-global-id`, `validator-session-assembly-source`, `pq-block-signature-conformance`, `pq-finality-boundary-source` | The shared formula commits governing-state `global_id`, Param29 hash, exact selected Param30 cell hash and group coordinates; the manager's named production input assembly reproduces the frozen vector and binds every coordinate; a bidirectional source gate pins all three manager group paths to it; `ShardStateQ::get_global_id()` is exercised from a real serialized state BOC; a proof must match a separately trusted expected session. | Actor-scheduler creation and lifecycle of a live `ValidatorManagerImpl`; the focused gates exercise and source-pin the exact pure assembly used by its validator, future-validator and observer paths, not manager initialization. |

Mutations observed:

- Omitting Param30 from the derivation produced `PARAM30_CHANGE_DID_NOT_CHANGE_SESSION`.
- Omitting `global_id` produced `GLOBAL_ID_CHANGE_DID_NOT_CHANGE_SESSION`.
- Letting a node-local noncritical override enter the commitment produced
  `LOCAL_NONCRITICAL_OVERRIDE_CHANGED_SESSION`.
- Reusing a session path across Param30 changes produced
  `PARAM30_CHANGE_REUSED_SESSION_PATH`.
- Removing expected-session comparison produced
  `PQ_BLOCK_SIGNATURE_UNEXPECTED_ACCEPT case=wrong-workchain-shard-session expected=carried session_id does not match trusted expected session_id`.
- Returning after quorum instead of checking surplus signatures produced
  `PQ_BLOCK_SIGNATURE_UNEXPECTED_ACCEPT case=invalid-surplus-signature expected=pq signatures: invalid signature`.
- Allowing a legacy cell carrier under a PQ set produced
  `PQ_BLOCK_SIGNATURE_UNEXPECTED_ACCEPT case=cell-ordinary-under-pq-set expected=unsupported carrier for post-quantum validator set`.
- Bypassing the manager's frozen input assembly produced
  `MANAGER_SESSION_ASSEMBLY_FROZEN_VECTOR_MISMATCH`.
- Bypassing the serialized-state `global_id` accessor produced
  `SHARD_STATE_GLOBAL_ID_MISMATCH header=-17 accessor=0 expected=-17`.
- Removing one manager group path from the assembly source contract produced
  `VALIDATOR_SESSION_ASSEMBLY_SOURCE_FAILURE: manager global_id wiring changed count=2 expected=3`.

The Simplex end-to-end and vote-journal tests coexist with the new formula but do
not exercise it: their bus session ID is a fixture constant.

## Section 6: generated network carriers, checked parsing, and capacity

Commits:

- `b11a4d9c8c65a1f4b98e8e11e5ebc9a69c1b8781` — generated node/lite PQ TL variants and shared TL fixture.
- `cadd24c26be58950d10fa3dcc25274c93505d72c` — checked untrusted parsers, pre-decompression ordering, crypto counters, and true signature-volume accounting.
- `51f865505b83745c871b8b28fc3e785481ec7fb6` — production-predicate node/lite carrier capacity gates.

| Design gate | Registered subject test | Proves | Does not prove |
|---|---|---|---|
| `n5-pq-node-tl-checked` | `pq-signature-tl-vectors`, `test-pq-network-parser-resource` | Generated node/lite TL round trips preserve authority fields and structural rejects happen before crypto; compressed-V2 rejects signatures before decompression. | Cryptographic finality or transport delivery. |
| `n5-pq-node-carrier-capacity` | `pq-node-finality-carrier-capacity` | Complete 21/100/400 signer finality broadcasts match recorded sizes, pass the exact production Plumtree admission predicate, and reach the checked receiver parser. | A live overlay peer graph, FEC propagation, block acceptance, or throughput. |
| `n5-pq-lite-carrier-capacity` | `pq-lite-forward-proof-carrier-capacity` | Complete 21/100/400 signer lite answer fixtures match recorded sizes, pass the exact ADNL external framed-TCP send/receive predicates, and reach the checked lite parser. | This capacity-only gate does not run a live encrypted TCP actor pair or advance a trusted chain; section 10's forward-proof gate supplies those two later claims. Neither gate proves public-network deployment, loss behavior, latency, or throughput. |

The design's RLDP wording does not match this tree: production lite queries use
`AdnlExtClient`/`AdnlExtServer` over framed TCP.  The gate follows that actual
route.  All complete-object rows in
`test/pq-native/block-signature-carrier-routes.tsv`, including compressed V2,
now have measured `STATIC FIT` verdicts; no `UNKNOWN` row remains.

Mutations observed:

- Changing one C++ TL authority field produced
  `TL_VECTOR_CONTENT_MISMATCH case=node-final`; the equivalent Rust-side field
  change produced `RUST_TL_VECTOR_ALGORITHM_MISMATCH case=node-final`.
- Removing the node/lite exact-signature check produced
  `RESOURCE_GATE_UNEXPECTED_ACCEPT case=node-signature-2419` and the analogous
  `lite-signature-2419` failure.
- Inserting an ML-DSA call into structural parsing produced
  `RESOURCE_GATE_CRYPTO_CALLS case=node-401-signers expected=0 actual=1`.
- Moving compressed-V2 signature parsing after decompression produced
  `COMPRESSED_ORDER_DECOMPRESSION expected=0 actual=1`.
- Lowering Plumtree admission to one byte below the otherwise-valid node payload
  produced `CARRIER_LIMIT_NEGATIVE route=node` when the production refusal was
  disabled; the intact gate reports `reason=payload_limit crypto_calls=0`.
- Lowering the ADNL framed-packet allowance to one byte below the otherwise-valid
  lite answer produced `CARRIER_LIMIT_NEGATIVE route=lite` when the production
  refusal was disabled; the intact gate reports `reason=packet_limit crypto_calls=0`.
- Changing the recorded node size produced
  `CARRIER_RECORDED_SIZE_GATE_FAILED route=node`; changing the recorded lite size
  produced `CARRIER_RECORDED_SIZE_GATE_FAILED route=lite`.
- Removing the 401-signer checked-parse refusal produced
  `CARRIER_401_UNEXPECTED_ACCEPT route=node` and
  `CARRIER_401_UNEXPECTED_ACCEPT route=lite`.

## Section 7: exact FinalCert-to-`#13` conversion

Commits:

- `488f885a5c868fff0c8f010922ee59daff692132` — fail-soft certificate conversion and removal of the normal carrier-missing seam.
- `1f1192fceaaa94bf0030806a947a74ba15c7a9cd` — local accepted finality bound to the trusted session.
- `4137595e2d610dd18f647635e02db22d3350bdb8` — three-consecutive-block progress and independent trusted-context verification of every accepted proof.

| Design gate | Registered subject test | Proves | Does not prove |
|---|---|---|---|
| `n5-pq-exact-certificate-carry` | `test-consensus-simplex2-pq-finality-e2e-single`, `test-consensus-simplex2-pq-finality-e2e-multi`, `test-consensus-simplex2-pq-finality-e2e-21`, `test-consensus-simplex2-pq-finality-e2e-100` | For every signer in one selected proof, journal, FinalCert, `#13`, DB-loaded set, and BlockProof-loaded set carry identical randomized ML-DSA bytes; every accepted proof in the run is independently checked at the trusted-context verifier; at least three unique consecutive blocks are accepted; normal PQ finality emits no carrier-missing event. | The five restart cuts or five-way byte comparison of every proof (the independent verifier, rather than the five-way comparison, covers every accepted proof). |

Mutation observed:

- Re-signing during conversion produced
  `EXACT_SIGNATURE_BYTES_MISMATCH signer=0 journal/final-cert/carrier/db/block-proof are not byte-identical`.
- Restoring the old conversion refusal made the accepted-chain scenarios fail
  with `finalized only 0 blocks, expected at least 40`.

## Section 8: persistence, proof consumers, and broadcasts

Commits:

- `d20860dfa6fdf2844f8e54d3c5e183710d81932a` — 21/100 archive and database round trip plus nine-field corruption matrix.
- `6c0df3a85a4386bc0a5413f619d5f3d966df6d38` — CheckProof and serialized TopBlockDescr consumers.
- `d270017f83da57eab61dbfde1cee5e3fee029b2e` — AcceptBlock trusted-session boundary.
- `40141c9a94b1c8fe4e555701d90f3cbebcb04285` — persistence gate inventory.
- `890875a5dc236a23e646fe7ddf2260ad13bfec52` — persisted BlockProof fixture.
- `62d5c48a3f1d5c5cbb314bf942964dabfef00422` — semantic compressed-V2 and finality broadcast round trips.
- `659a717df7c0209f10fe55fd50834679051ce9b7` — restored PQ catch-up and empty-chain restart scenarios.
- `a8d3baa063ac3de3250867602c168aecd8e81c88` — JSON-RPC refuses the unsupported PQ signature carrier instead of emitting an empty classical list.
- `cce69caf023cf087c67134a028a31da1fff028b7` — bounded arrival-order cache for finality evidence that cannot yet be verified.
- `3de7316c83b14678d6b2620f706daf335bb92706` — TopBlockDescr authority comes from the masterchain snapshot named by its shard proof, not the node's current state.
- `4b801892ef542f3148a358590a1e9ce450bcb0eb` — focused TopBlockDescr coverage now drives the production `prevalidate` consumer and its governing-state guard.
- `b64af02c37f01a5f9543385c6adba130298bd156` — evidence-aware Plumtree identity and authenticated-sender, byte-bounded pending finality admission.
- `30b68d257b4b69a030b4ea2eaa4b6f4e740467aa` — remote pending evidence charged by its exact received payload bytes without pre-admission reserialization.
- `1175bc561` — transient pending finality failures retain evidence for bounded delayed retries; permanent coordinate mismatches fail immediately.
- `b37e5c7c1` — pending finality retention is bounded by a 60-second admission deadline with exponential backoff and independent expiry.
- `ccbd2e59a0096957c3dd280cda9acd2a3637a5a1` — retry deadline and expiry evidence recorded in the status gate.
- `937be43d5fc5b9ef3d15a444c5b4fb665b5f86f2` — initial per-validator capacity reservation.
- `48127da2a27e126d983ba25886919da0cedd2e57` — public and committee evidence separated into disjoint byte pools.
- `0ba0dcd1e928247dc31dd216c6fbdc5bfe1fa330` — validator-authority classification memoized against trusted state.
- `65452101e667c97d1ecd42cd924bbeb3d1e3787d` — claimed hashes removed from the computation key and catchain coordinates bounded cheaply.
- `be7a83ba2fd18a9c1429c30afccea7cf22cc1a90` — authority memo capped globally with an eight-entry LRU.
- `89e9170976ad2b42c9b30e9a5dc121ce0b2c1f54` — sender accounting made per block and pool sizes derived from the measured carrier.
- `6206f5401def4aface646789706b664ff45e5672` — the same memoized trusted sets supplied to classical verification.
- `6bfe0a581b5d32b7ee57990543b6d47850264f9e` — production rejection logs changed from unstable integers to named reasons.

| Design gate | Registered subject test | Proves | Does not prove |
|---|---|---|---|
| `n5-pq-db-roundtrip` | `test-pq-signature-persistence` | Real RootDb/archive store/get/fetch returns 21/100 signer `#13` bytes unchanged and the result verifies. | Process-crash atomicity at every persistence cut. |
| `n5-pq-block-proof` | `test-pq-signature-persistence` plus the PQ Simplex end-to-end tests | AcceptBlock's extracted PQ boundary, serialized/persisted BlockProof signature-envelope extraction, and a low-level proof-verifier reject/accept matrix preserve and verify `#13`. | A production `CheckProof` actor invocation. Deleting `CheckProof::check_signatures`' rejection of verifier errors leaves this focused test green. |
| `n5-pq-top-shard-descr` | `test-pq-signature-persistence` | A production `ShardTopBlockDescrQ::fetch` parses a real shard proof link, then production `prevalidate` accepts session A using the named governing state after the current state advances to B, rejects using B as the governing state, and rejects a valid session-B signature at the pre-change position. | The actor that asynchronously obtains the current and governing states from `ValidatorManager`; the focused test supplies purpose-built state objects directly to the production consumer. |
| `n5-pq-broadcast-roundtrip` | `pq-broadcast-semantic-roundtrip` | The same 21/100 fixtures traverse compressed-V2 and simple-Plumtree TL, are checked against trusted PQ context, and call ML-DSA exactly once per included signer; 400 is structurally measured. | A live overlay peer graph, block-acceptance actor scheduling, or FEC behavior. |
| Accepted-chain regressions restored by §10.5.3 | `test-consensus-simplex2-pq-state-resolver-catch-up`, `test-consensus-simplex2-pq-empty-chain-restart` | A lagging node recovers an evicted finalized ID through live DB lookup; a chain longer than 4096 empty candidates resumes after a cold resolver restart and reuses its completed-ancestor cache. | The five crash cuts required by §10.5.4. |
| JSON-RPC unsupported-carrier behavior | `test-json-rpc-parse` | A PQ lite signature set produces error `-32603` with an explicit unsupported-carrier message, while genuine absence remains the only path to an empty classical list. | Rendering PQ signatures in the public JSON model. |
| Unverified finality admission | `test-pending-finality-cache`, `finality-evidence-admission-source` | Public and fast-sync Plumtree IDs commit to the block and canonical signature set; authenticated sender identity and the exact received boxed-TL byte count reach the manager without reserialization; the manager rejects missing accounting and classifies a remote sender against the exact current/next validator set named by the evidence. An implausible claimed catchain sequence or a shard absent from the exact trusted shard configuration is rejected before set computation. A real split-shard fixture confirms that `get_shard_cc_seqno` alone would let a nonexistent descendant inherit its containing shard's coordinate, while the exact-shard check blocks it. The trusted-state-scoped memo keys computation by `(shard, cc_seqno)`, compares a claimed set hash with the locally computed hash stored inside the entry, and supplies the same computed sets to classical signature verification. Cycling 64 different claimed hash/sequence triples therefore performs only the two current/next computations. Its global eight-entry LRU also bounds the memo while real shard coordinates are cycled beyond the cap; current/next coordinates per shard explain the honest hit rate, not the memory bound. The 400-validator shard-set benchmark measured 390 us and 524,800 copied PQ-key bytes per set on the development host. One sender gets one unverified candidate per block, each capped at the measured 984,260-byte maximum boxed carrier, and at most four maximum carriers across all blocks. Four is the three-consecutive-block recovery window exercised by the accepted-chain gate plus one in-flight successor; it limits one public peer to 1/4 of the shared pool and one committee authority to 1/100 of the reserved pool. Non-validator public-overlay peers share exactly 16 maximum carriers (15,748,160 bytes); a disjoint 393,704,000-byte pool holds exactly one maximum carrier for each of 400 committee authorities, so rounded MiB shares cannot admit a 401st authority and filling the public pool cannot displace valid validator evidence. The 4096-byte minimum charge and the two pools cap retained unverified finality evidence at exactly 409,452,160 bytes (about 390.48 MiB). Retry/expiry APIs require callers to pass both `now` and `expires_at` explicitly, so omitting the clock is a compile error. | A live Plumtree peer graph or the actor-scheduled `ValidatorManagerImpl` coroutine. The behavioural gate drives the production transport-ID helper, authority memo/classifier, ingress decision, exact-shard/coordinate rule and pending-store implementation; the source gate pins their composition in the manager and transport ingress, including the memo-fed classical verifier. It cannot distinguish a legitimately local manager call from an upstream remote path that incorrectly omits its authenticated peer; that handoff remains source-pinned. Classification uses only a validator set whose hash and catchain sequence match the evidence; evidence naming unavailable historical coordinates uses the public pool until its trusted context is available. The validator-reserved pool does not promise two independent full-committee reservations during a validator-set rotation. Locally originated evidence has no received payload and uses reserved capacity charged by intrinsic signature bytes. Block IDs are not range-gated here: masterchain and shardchain sequence numbers are not comparable, and valid finality may precede local block data. |
| Pending-finality transient recovery | `test-pending-finality-cache`, `pending-finality-retry-policy-source` | `notready`/`timeout` retains evidence for exponential-backoff retries within a 60-second admission-to-expiry deadline, a later success consumes it, the independent expiry timer frees its sender slot even without another event, and permanent protocol errors discard immediately; production verification, proof creation and apply failures use this decision. Every asynchronous attempt carries `{queue_generation, attempt_generation}` through verification and apply. The store assigns a new queue generation when the same block entry is destroyed and recreated, so an old queue's late failure or success cannot pop, verify, or complete the replacement queue's front; the replacement's own identity still processes normally. The three same-object validator-coordinate mismatches are created as `protoviolation`. | Actor timing and successful delayed callback delivery under a stopped/restarted manager. The behavioural gate drives the production state transition, destroys and recreates a block queue during the stale-callback interleaving, and checks deterministic deadline/backoff arithmetic; the source gate pins the manager's token propagation, scheduling composition and error classifications. |

Number provenance for the admission rows is explicit in the tree: 984,260 bytes
is the measured 400-signer boxed finality carrier in
`test/pq-native/block-signature-carrier-routes.tsv`; the 16-carrier public pool,
400-authority reserved pool, four-carrier cross-block sender share, 4096-byte
minimum charge, eight-entry memo cap and
derived 15,748,160 / 393,704,000 / 409,452,160-byte ceilings are production
constants asserted by `test-pending-finality-cache`; the 60-second deadline is
tied in `validator/finality-cache-policy.h` to the manager's existing
60-second block-data wait; and 390 us plus 524,800 copied PQ-key bytes is the
20-run, 400-validator development-host measurement recorded beside the
production authority-memo lookup in `validator/manager.cpp`.

The post-quantum refusal inside the detached classical-only
`check_finality_signatures` helper is defence-in-depth.  Its sole caller already
branches on `!sig_set->is_pq()`, so that inner refusal has no killable mutation
and is not counted as independent coverage.

The nine persisted corruption rows and their asserted reasons are: constructor →
`unsupported carrier for post-quantum validator set`; validator ID →
`pq signatures: unknown validator_id`; algorithm →
`pq signatures: unsupported algorithm`; PQBytes length →
`pq signatures: signature length 2419, expected 2420`; signature chunk →
`pq signatures: invalid signature`; session ID →
`carried session_id does not match trusted expected session_id`; slot →
`pq signatures: invalid signature`; candidate data →
`pq signatures: invalid signature`; claimed weight → `signature weight mismatch`.

Mutations observed:

- Corrupting the stored/reloaded 21-signer bytes produced
  `PQ_SIGNATURE_PERSISTENCE_BYTES_MISMATCH signers=21`.
- Bypassing the AcceptBlock expected-session check produced
  `PQ_BLOCK_SIGNATURE_UNEXPECTED_ACCEPT case=accept_block_wrong_session expected=carried session_id does not match trusted expected session_id`.
- Bypassing the extracted low-level proof-verifier matrix produced
  `PQ_BLOCK_SIGNATURE_UNEXPECTED_ACCEPT case=invalid_signature expected=pq signatures: invalid signature`.
- Deleting the governing-state check from production `ShardTopBlockDescrQ::validate_internal`
  produced
  `PQ_BLOCK_SIGNATURE_REASON_MISMATCH case=top_descr_current_state_is_not_governing expected=top block description governing state mismatch actual=ShardTopBlockDescr for (0,8000000000000000,42):3CA07AC18F14A3D906CC28AA6FD6AB0F5438703611BD8B998E0D4B1AB7320AC7:0E768FA97910A760F489744EC9AEAF5637282B2270BBC17E034670D73FA76BFB does not have valid signatures: [Error : 0 : pq finality: carried session_id does not match trusted expected session_id]`.
- Deleting production `CheckProof::check_signatures`' `result.is_error()` rejection left
  `test-pq-signature-persistence` green (`1/1 ... Passed`).  This is retained as
  evidence that the focused BlockProof gate does not exercise the production actor.
- Dropping the serialized BlockProof signature reference produced
  `PQ_BLOCK_PROOF_ENVELOPE_ID_OR_SIGNATURES_MISMATCH`.
- Dropping TopBlockDescr PQ metadata preservation produced
  `PQ_TOP_BLOCK_DESCR_ENVELOPE_METADATA_MISMATCH`.
- Skipping broadcast verification produced
  `PQ_BROADCAST_CRYPTO_CALLS route=compressed-v2 expected=21 actual=0`.
- Accepting a tampered broadcast pair produced
  `PQ_BROADCAST_TAMPER_UNEXPECTED_ACCEPT case=invalid-signature`.
- Disabling the catch-up lookup produced
  `catch-up test never recovered an evicted finalized ID through live DB lookup`.
- Dropping the persisted finalized anchor across the empty-chain restart produced
  `missing-manager-anchor fallback was not exercised`.
- Stopping after the first invalid unverified final, without changing the
  candidate bound, produced
  `PENDING_FINALITY_ORDER_FAILURE: bad final displaced the later valid final`.
- Reversing unverified candidate processing, without changing the candidate
  bound, produced
  `PENDING_FINALITY_ORDER_FAILURE: later bad final ran before the earlier valid final`.
- Allowing the current post-key-block masterchain state to stand in for the
  snapshot named by the shard proof produced
  `PQ_TOP_BLOCK_DESCR_CURRENT_STATE_ACCEPTED_AS_GOVERNING`.
- Restoring the block-only transport identity produced
  `PENDING_FINALITY_TRANSPORT_DEDUP_FAILURE: invalid finality occupied the honest finality transport id`.
- Removing the one-unverified-candidate-per-sender guard produced
  `PENDING_FINALITY_SENDER_ISOLATION_FAILURE: one sender occupied more than one block candidate`.
- Reverting sender accounting to sum across blocks produced
  `PENDING_FINALITY_PER_BLOCK_SENDER_FAILURE: one sender could not retain maximum-size evidence for two blocks`.
- Removing the four-carrier cross-block sender guard admitted one public peer to
  all 16 shared slots and one committee authority to all 400 reserved slots,
  producing
  `PENDING_FINALITY_GLOBAL_SENDER_BUDGET_FAILURE: validator sender admitted=400 rejection=validator_reserved_budget held=393704000 expected_slots=4` and
  `PENDING_FINALITY_POOL_MONOPOLY_FAILURE: validator sender prevented honest sender after reaching its global share; rejection=validator_reserved_budget`.
- Changing the frozen maximum carrier size by one byte produced
  `CARRIER_PENDING_BUDGET_SIZE_MISMATCH recorded=984259 actual=984260`.
- Removing the total byte guard produced
  `PENDING_FINALITY_TOTAL_BUDGET_FAILURE: store exceeded its 16777216-byte budget`.
- Replacing the public Plumtree route's evidence-aware helper with the old
  block-only ID produced
  `FINALITY_ADMISSION_SOURCE_FAILURE: public Plumtree finality route lost its evidence-aware transport id (validator/full-node-shard.cpp)`.
- Restoring manager-side canonical reserialization in place of received-byte
  charging produced
  `FINALITY_ADMISSION_SOURCE_FAILURE: manager admission no longer charges the received payload bytes (validator/manager.cpp)` and
  `FINALITY_ADMISSION_SOURCE_FAILURE: manager reserializes remote finality before admission`.
- Treating proof/state `notready` as permanent produced
  `PENDING_FINALITY_RETRY_FAILURE: valid evidence was discarded while required state was not ready`.
- Ignoring the processing generation while A expired and B became the front
  produced
  `PENDING_FINALITY_STALE_ATTEMPT_PERMANENT_FAILURE: A's late permanent error removed candidate B` and
  `PENDING_FINALITY_STALE_ATTEMPT_SUCCESS_FAILURE: A's late success mutated candidate B`.
- Replacing one production callback's token match with a bare `processing()`
  check produced
  `PENDING_FINALITY_RETRY_SOURCE_FAILURE: expected 3 callback attempt-token guards, found 2 (validator/manager.cpp)`.
- Reusing queue generation 1 after the store erased and recreated the same
  block entry produced
  `PENDING_FINALITY_QUEUE_REUSE_PERMANENT_FAILURE: Q1's late permanent error removed Q2 candidate B` and
  `PENDING_FINALITY_QUEUE_REUSE_SUCCESS_FAILURE: Q1's late success mutated Q2 candidate B`.
- Treating a verification timeout as permanent produced
  `PENDING_FINALITY_TIMEOUT_CLASSIFICATION_FAILURE: verification timeout was treated as permanent`.
- Retrying a protocol violation produced
  `PENDING_FINALITY_PERMANENT_FAILURE: inconsistent evidence was retained for retry`.
- Removing the retention-deadline expiry produced
  `PENDING_FINALITY_RETRY_DEADLINE_FAILURE: expired candidate retained its sender slot`.
- Removing the checked-subtraction precondition and exercising a corruption-shaped
  `removed = SIZE_MAX` produced
  `PENDING_FINALITY_BUDGET_ARITHMETIC_FAILURE: removed bytes exceeded current accounting without rejection`.
- Removing delayed rescheduling after a retained transient failure produced
  `PENDING_FINALITY_RETRY_SOURCE_FAILURE: manager no longer schedules another attempt after retaining transient evidence (validator/manager.cpp)`.
- Reclassifying each of the three permanent coordinate mismatches back to
  `notready` independently produced, respectively,
  `PENDING_FINALITY_RETRY_SOURCE_FAILURE: catchain-seqno mismatch is no longer a permanent protocol violation (validator/validate-broadcast.cpp)`,
  `PENDING_FINALITY_RETRY_SOURCE_FAILURE: header/signature validator-set mismatch is no longer a permanent protocol violation (validator/validate-broadcast.cpp)`, and
  `PENDING_FINALITY_RETRY_SOURCE_FAILURE: validator-set mismatch with an exact key block is no longer a permanent protocol violation (validator/validate-broadcast.cpp)`.

## Section 9: transport authority

Commit:

- `81ef38f8644653483900ff55cb9123072c3190a2` — ADNL transport-root authority, local reference-counted signer registry, engine lifecycle wiring, and inventory closure.

| Design gate | Registered subject test | Proves | Does not prove |
|---|---|---|---|
| `n5-pq-transport-authority` | `test-validator-transport-authority` | A PQ descriptor authorizes its explicit Ed25519 ADNL ID; a held matching key issues a certificate; `validator_id` and unrelated permanent-key roots cannot authorize or issue it on the fast-sync path; consensus rotation preserves and ADNL rotation changes authority; startup/add/delete/expiry/overlap/no-key registry behavior holds. | A live fast-sync overlay graph. |
| `n5-no-classical-finality-fallback` | `consensus-no-fallback` plus workflow `.github/workflows/classical-key-inventory.yml` | Consensus source has no keyring-signing fallback, and every `classical_key()` use is inventoried with no `aborts-on-pq` row. | Arbitrary wrong-source substitutions that do not spell `classical_key()`. |

Mutations observed:

- Reverting signer selection to the legacy permanent-key registry produced
  `TRANSPORT_AUTHORITY_FAILURE: matching validator ADNL key did not issue a certificate`.
- Reintroducing `classical_key()` in `validator/full-node.cpp` produced
  `classical-key check failed: validator/full-node.cpp reads a classical key (1 sites) and is not in the inventory`.
- Reintroducing it in `validator/full-node-fast-sync-overlays.cpp` produced
  `classical-key check failed: validator/full-node-fast-sync-overlays.cpp reads a classical key (1 sites) and is not in the inventory`.

The focused behavior test covers the full-node authority helper.  Fast-sync uses
the production `fast_sync_validator_transport_authority` extraction used by the
overlay update path.  Its positive proves the matching ADNL key can issue an
authorized certificate; separate negatives prove that sourcing roots from
`validator_id` or an unrelated permanent Ed25519 key cannot authorize that
certificate or select the held ADNL signer.

## Section 10: lite proof chain and accepted-chain checklist

Commits:

- `468ceccb0c3d333f5a2eb6c6a709129b19e46b20` — liteserver `#13` generation and two-step production lite proof-chain verification over framed TCP.
- `a601b54398da07bcf1037e793475cac054ae75db` — Rust codec-only boundary made explicit in the test name and CI filter.
- `659a717df7c0209f10fe55fd50834679051ce9b7` — the two formerly blocked accepted-chain scenarios restored.

| Design gate | Registered subject test | Proves | Does not prove |
|---|---|---|---|
| `n5-pq-lite-forward-proof` | `test-pq-lite-forward-proof` | Two consecutive 21-signer proof steps traverse the production ADNL external client/server framed-TCP harness, derive step two's trusted set from step one's destination key block, call ML-DSA exactly 42 times, and advance; a 100-signer step calls it exactly 100 times. | Rust finality verification, a public-network deployment, arbitrary latency/loss, or performance. |
| `n5-pq-block-signature-parity` tooling part | Rust `shared_pq_block_signature_codec_parity_does_not_verify_finality` in `.github/workflows/pq-mldsa44.yml` | C++ and Rust parse and reserialize the same persisted `#13` BOC. | Rust proof validation or trusted-chain advancement. |
| §10.5.3 restored scenarios | `test-consensus-simplex2-pq-state-resolver-catch-up`, `test-consensus-simplex2-pq-empty-chain-restart` | The two accepted-chain scenarios disabled at the old carrier seam run with PQ finality without weakening their original assertions. | The complete §10.5.2/§10.5.4 matrix below. |

The lite negative matrix asserts: classical carrier, wrong validator ID, wrong
algorithm, wrong signature, wrong session, wrong slot, wrong candidate, sub-quorum,
wrong validator-set hash, wrong catchain seqno, invalid surplus signature, and a
previous-set signature on the next step.  The `previous-set-on-next-step` row fails
with `unknown validator_id`, which is the observable proof that step two did not use
a test-global copy of step one's set.

Mutations observed:

- Skipping lite signature verification produced
  `PQ_LITE_FORWARD_PROOF_FAILURE: two-step verifier calls expected=42 actual=0`.
- Reusing the previous set for the next step produced
  `PQ_LITE_FORWARD_PROOF_FAILURE: negative previous-set-on-next-step expected=unknown validator_id actual=accepted`.
- Removing the framed-TCP answer-size refusal produced
  `PQ_LITE_FORWARD_PROOF_FAILURE: lite answer limit below required bytes did not refuse`.

The eight migrated adversarial scenarios were audited against their disabled
classical registrations.  Each PQ registration retains the same attack flag(s),
and the shared final assertions still check malicious-observer injection,
adaptive membership rotation, relay exercise and deduplication, query-rate
limits, and resolver-state non-growth.  Packet loss, node restart, and network
partition additionally have to increment their injection counters before the PQ
gate can complete.  The classical registrations required five accepted heights;
their PQ counterparts now require three *consecutive unique* accepted heights,
the explicit section 10.5 criterion.  This is a deliberate change: it is stronger
evidence of continuity, because three adjacent unique heights must advance, and
weaker evidence of volume, because three is fewer than five.  No attack-specific
assertion was dropped.

The finalization-backpressure scenario is deliberately exempt from that general
three-block progress bar.  Its premise is that an over-limit finalization backlog
stops production.  It instead requires the over-limit transition, zero candidates
while throttled, the cleared transition, and at least one accepted block after
recovery.  Loss and partition still require their injected adversity followed by
three consecutive unique accepted heights.  Transient finalization failure must
exhaust its finite injected failures and then meet the same three-height bar.
Permanent finalization failure does not use the progress gate: its contract is to
retain the certificate, stop retrying it, and stop production.

### Source-guard execution integrity

The quorum-arithmetic source guard requires `ripgrep` and now fails closed when
that executable or a configured scan root is absent.  Branch/PR CI selects all
pure-source guards through their per-test `source-guard` label with
`--no-tests=error`; full CTest and focused validator-auth workflows explicitly
install the same search dependency.  Before these checks were made fail-closed,
the validator-auth workflow had repeatedly printed `quorum static check passed`
without searching anything because `rg` was missing.  The retained mutation
evidence is: removing `rg` fails with `ripgrep is required but not installed`, a
missing scan root fails naming that root, and a real `signed_weight += weight`
probe still fails naming its file and line.  This is execution-integrity evidence
for the guard, not evidence about paths outside its declared scan roots.

## Registered gaps and explicit non-claims

Correction to the former wording, “Both are parked by owner decision, with
implementation work not started”: that description predates the N02–N07
controlled actor/DB cuts and the N01 cold seq2 continuation. Those cuts are
implemented; the encompassing N01 remains open pending fixed-tree CI and
aggregate review. They do not establish power-loss or cross-node recovery.
The other entries below record resolved rows, deliberate naming
choices, harness boundaries, evidence-retention limits, or separately scoped
API/tooling debt; none is silently promoted to a green claim.

1. **Manager actor integration is exercised by a real zerostate startup.**
   `validator/manager.cpp` now passes a named
   `ValidatorSessionIdentityInput` to the shared derivation in each of its current,
   future and observer group paths.  The registered manager-assembly gate calls that
   exact production overload, reproduces the frozen vector and changes every input
   independently; the state-global-id gate obtains the remaining state input through
   `ShardStateQ::fetch` from a real serialized state BOC.  The workflow test
   `test/integration/test_manager_session_identity.py` additionally provisions a
   real ML-DSA-44 consensus seed, writes the matching `validator_pq#b3` descriptor
   into a generated zerostate, starts the production DHT and validator-engine actors,
   and observes the masterchain group ID logged by `ValidatorManagerImpl`.  Three
   startups make the attribution explicit: changing the node-local data directory
   and port while restoring the first zerostate `global_id` preserves the observed
   session ID, while changing `global_id` with those launch coordinates held fixed
   changes it.  Replacing the manager's
   production `.global_id = global_id` assembly with zero makes the gate fail with
   `MANAGER_SESSION_IDENTITY_FAILURE: changing zerostate global_id did not change the manager-created group session`.
   This actor gate varies exactly one of the derivation's seven input categories;
   it does not vary the validator list or the selected Simplex configuration cell.
   Those inputs and the complete formula remain pinned by the frozen-vector and
   manager-assembly gates, not by this end-to-end actor observation.
   The older consensus end-to-end harness still pins `bus->session_id`; it coexists
   with this integration evidence but does not supply it.

2. **Three API/tooling consumers remain incomplete.**

   - `toslib/toslib/ToslibClient.cpp` explicitly returns
     `post-quantum block signatures are not supported by toslib yet`; this is a
     loud refusal, not support.
   - JSON-RPC now returns error `-32603` with
     `post-quantum block signatures are not supported by JSON-RPC yet`; it is a
     loud refusal, not support.  The former empty-classical-list response was a
     defect and was fixed in `a8d3baa063ac3de3250867602c168aecd8e81c88`.
   - `sdk/js/packages/client/src/types.ts` models only ordinary and classical
     Simplex block signatures; it has no PQ response type.  The generic
     `rawCall<T>` performs no runtime decoding, coercion, or field stripping, so
     it cannot itself turn a PQ value into an empty classical list.  This is
     unfinished static type support, not a second silent downgrade.

3. **Carrier route rows are resolved.**
   No `UNKNOWN` row remains in `block-signature-carrier-routes.tsv`; compressed-V2
   complete objects are measured at 1/21/100/400 and marked `STATIC FIT`.

4. **A live overlay peer graph is not exercised by the carrier gates.**
   The capacity gate calls the production admission functions, and the semantic
   gate serializes, parses, and verifies complete objects, but neither stands up
   a live overlay peer graph.  This is a harness boundary, not an unresolved row
   in the route table.

5. **Section 10.5 is only partially met.**
   The old carrier-missing normal path is gone, accepted blocks and finalized
   markers continue, the two disabled accepted-chain scenarios are restored, and
   the PQ loss/restart/partition/byzantine/adversarial variants remain registered.
   The general gate now requires three consecutive accepted blocks and independently
   verifies every accepted proof observed during its run under the trusted context.
   The document's prescribed registered names
   `test-consensus-simplex2-pq-persisted-finality-single`,
   `test-consensus-simplex2-pq-persisted-finality-multi`, and
   `test-consensus-simplex2-pq-persisted-finality-21` are deliberately not added.
   The same coverage runs under the subject names mapped in section 7; aliases
   would duplicate CI runtime without adding evidence, and renaming would likewise
   add no evidence.  This is a documented naming deviation, not an unmet gate.

   Correction to the former “five restart cuts remain parked / implementation
   not started” statement: N02–N06 now exercise controlled write-after and
   cold-process recovery at the Simplex journal, `#13`, BlockProof, marker and
   DB/archive reconstruction boundaries; N07 exercises the retained PQ proof
   through a real CheckProof actor. Their individual scoped sign-offs do not by
   themselves prove continuation. [N01's seq2 fixture](pq-native/N5-COLD-SEQ2-CONTINUATION-FIXTURE.md)
   adds a cold-restored second FinalCert, real AcceptBlock/marker, a third cold
   read of both DB roots and a latest-finalized Pool anchor. N01 stays open until
   its committed/pushed-tree CI and aggregate review. Controlled orderly stops
   are not SIGKILL/power-loss atomicity; live overlay/Bridge and peer convergence
   require separate testnet fault evidence.

6. **Mutation transcripts are not repository artifacts.**
   This file records the exact failure lines retained in the implementation/review
   record.  Two early C++ reason-shadowing mutations retained only their exact
   `VECTOR_REASON_MISMATCH` marker, not the full dynamic suffix.  Reproducing raw
   transcripts is possible by rerunning those mutations, but the original complete
   output cannot be reconstructed from committed files alone.

7. **CheckProof actor coverage is now separate from the older direct matrix.**
   The former “implementation work has not started” statement described only
   `test-pq-signature-persistence`, which still calls a verifier directly.
   [N07's controlled Cut 6](pq-native/N5-CHECKPROOF-CUT6-REVALIDATION-FIXTURE.md)
   instead reads a persisted PQ BlockProof and the matching FinalCert from a
   cold source, then invokes the production CheckProof actor in a genesis-only
   consumer: the original proof is accepted and a tampered PQ signature is
   refused. This is actor-consumer coverage, not a full-node or remote-peer
   proof-ingress test. N01's overall persistence continuation is tracked above.

   TopBlockDescr no longer shares this gap at its decisive boundary: the focused
   fixture supplies two masterchain-state objects with configuration and shard
   topology to the real `ShardTopBlockDescrQ::prevalidate` method.  Removing the
   production governing-state guard makes that gate red.  The surrounding actor's
   asynchronous state-history lookup remains outside the focused test.

8. **Whole-project Python type checking is measured debt, not a gate.**
   `uv run basedpyright` at this branch head reports 736 errors and 4,310
   warnings across the configured `test/integration` and `test/tostester` trees.
   This is not a tidy-up-sized remainder of the CI-gates work.  The workflow's
   `python-types` job therefore remains manual and must not be presented as a
   closure gate; converting it into one requires a separately scoped type-debt
   project rather than suppressing or baseline-hiding the existing diagnostics.
