# TOS Simplex2 Selective Merge Guide

## 1. Purpose

This document defines how to selectively integrate the relevant Simplex2
features from the local TON reference checkout in `~/ton-c` into TOS.

The objective is not to replace the TOS consensus implementation wholesale.
TOS contains additional consensus hardening, recovery checks, a metric actor,
and misbehavior-reporting code. The merge must combine useful reference
networking and protocol-versioning work with the existing TOS safety
properties.

The upstream reference used for each merge must be recorded by an immutable Git
commit hash. Do not use a moving branch name as the review baseline.

### 1.1 Verification baseline

The current comparison was verified directly against these local commits:

| Repository | Commit |
|---|---|
| TOS (`~/tos`) | `94615dc6d` |
| TON reference (`~/ton-c`) | `bbc3bc6d52abbe3a7f852b22050708166fdaafbc` |

Statements in Section 2 describe only those revisions. Later upstream changes
must be reviewed again rather than assumed to have the same behavior.

Sections 3 through 10 are engineering recommendations and proposed acceptance
criteria. They do not claim that the described ports, tests, security
properties, soak runs, or Testnet readiness have already been implemented or
demonstrated.

This verification is a static source comparison. It confirms definitions,
feature gates, actor registration, and visible call paths; it does not by
itself prove runtime correctness, liveness, security, performance, or deployed
on-chain behavior.

### 1.2 Merge implementation status

Progress snapshot: 2026-07-24. The implementation is based on TOS commit
`94615dc6d`. The pinned TON comparison reference
remains `bbc3bc6d52abbe3a7f852b22050708166fdaafbc`.

Status definitions:

- **Completed ✅**: implemented and covered by the validation stated here.
- **Coding complete ✅ / pending validation**: the planned production code is
  merged, but the phase's adversarial, performance, or soak exit criteria are
  not yet satisfied.
- **Partial**: useful code is implemented, but phase exit criteria are not met.
- **Not started**: no production implementation has been merged.
- **Pending validation**: implementation exists, but the required adversarial,
  performance, or soak evidence is incomplete.

The `✅` marker applies only to the completed work named in its column or
section. It does not mean that a phase is complete unless the phase status
itself says **Completed ✅**.

| Phase | Status | Completed ✅ | Remaining work |
|---|---|---|---|
| 0. Baseline | Partial | ✅ Immutable source commits and static feature comparison are recorded | Archive golden ConfigParam cells and record CPU, memory, bandwidth, finality, and database-growth baselines |
| 1. ConfigParam30 | Coding complete ✅ | ✅ TON `#22` bit layout, first-testnet zerostate generation, protocol-v2 support, reserved-flag rejection, all four ConfigParam29 constructors, legacy `#21` decode coverage, and `#22` golden/truncated/invalid/future-version tests | Complete release validation |
| 2. Candidate codec | Coding complete ✅ / pending validation | ✅ Consensus-layer payload API, combined BOC/LZ4/improved codec, negative-size and integer/size hardening, malformed-input rejection, high-compression-ratio coverage, and configured-maximum coverage | Expand the compression-abuse corpus and collect repeatable peak-memory evidence |
| 3. Block-sync overlay | Coding complete ✅ / pending validation | ✅ Protocol-v1 private overlay, validator authorization, expected-collator precheck, payload bounds, and misbehavior reporting | Run recovery, restart, duplicate/reorder, partition, flood, queue-pressure, and bandwidth validation |
| 4. Observer and relay | Coding complete ✅ / pending validation | ✅ Protocol-v2 candidate relay, manager/full-node broadcast API adaptation, optional validator/ADNL message identity, validator-only authority gates, protocol-v1 block-sync observers, independently keyed manager observer-group lifecycle, read-only observer Pool/CandidateResolver operation, arbitrary-member candidate queries, and bounded candidate caching | Run authorization, eviction, removal/liveness, query-abuse, and relay-loop validation |
| 5. Plumtree | Coding complete ✅ / pending validation | ✅ Overlay core, TL messages, eager/lazy peers, FEC trees, repair, AnySender authorization, statistics, public, fast-sync, and custom-overlay candidate/finality paths, bounded candidate/finality reconciliation with tested finality-cache precedence, proof generation, validator-side shard-block-description generation, cryptographic finality-signature mutation checks, deduplicated CandidateReceived/FinalizeBlock fallback relay, the upstream graph simulator with deterministic packet loss, temporary and rotating node isolation, and a selective data-forwarding fault, and fault-injected Simplex consensus tests are adapted to TOS | Run end-to-end manager-ingress error propagation, eviction, relay-loop, actual membership churn, Byzantine selective-forwarding, and release-scale packet-loss and partition validation |
| 6. Structural refactoring | Optional; no activation blocker | ✅ Consensus payload boundary and collator-schedule file separation are aligned; BusRuntime conditionally spawns actors through `should_be_spawned` as required by the Simplex2 actor topology; TOS session-specific database paths were reviewed at a high level | Perform further semantic DB/network-state refactoring only if later evidence requires it |
| Activation | Coding complete ✅ / pending release validation | ✅ The first-testnet zerostate writes `#22` with protocol v2 and QUIC enabled; validator startup supports versions 0–2 and rejects version 3 | Complete phases 1–5 exit criteria, define rollback procedure, and run a 72-hour multi-region soak |

**Coding conclusion:** the planned production implementation for phases 1–5
and first-testnet activation is coding complete ✅ at this snapshot. The
overall Simplex2 release still requires the validation and release gates below.

Coding checklist:

- [x] ✅ Phase 1 configuration schema, parsing, and version gates
- [x] ✅ Phase 2 consensus payload API and bounded candidate codec
- [x] ✅ Phase 3 block-sync overlay
- [x] ✅ Phase 4 observer cache and candidate relay
- [x] ✅ Phase 5 Plumtree candidate/finality and validator-side shard-block-description integration
- [x] ✅ Required payload and collator-schedule structural separation
- [x] ✅ BusRuntime conditional actor spawning and provider registration
- [x] ✅ First-testnet `#22` zerostate and protocol-v2 activation
- [ ] Adversarial, performance, multi-region soak, and release evidence

Completed targeted validation:

- [x] ✅ Finality-cache duplicate, upgrade, and downgrade precedence
- [x] ✅ Finality signature mutation and validator-set-hash rejection
- [x] ✅ FEC and simple Plumtree packet-loss simulations
- [x] ✅ FEC and simple Plumtree temporary and rotating outage simulations
- [x] ✅ FEC and simple Plumtree static selective-forwarding simulations
- [x] ✅ Overlay privacy-rule authorization and AnySender rejection cases
- [x] ✅ FEC and simple 20-broadcast 256 KiB performance stress runs
- [x] ✅ Manager-ingress tasks now use observable detached completion logging
- [ ] End-to-end manager-ingress, authorization, eviction, relay-loop,
  membership-churn, Byzantine, performance, and multi-region validation

### Completed implementation work ✅

- `simplex_config_v2#22` uses the reference five-bit flags, two-bit
  `protocol_version`, and `use_quic` layout.
- The legacy `simplex_config#21` layout remains decodable for tooling and
  regression coverage, but the first-testnet zerostate now emits only `#22`.
- TON's `simplex_config_v2#22` is the sole authoritative `#22` layout. The
  pre-merge TOS draft layout has never been deployed and is not decoded.
  Non-zero reserved flags are rejected.
- Protocol version 1 has a dedicated block-sync overlay.
- The TON consensus-layer payload boundary is present as
  `validator/consensus/payload.{h,cpp}`. Simplex candidate parsing and
  serialization now use this API, which delegates to the single hardened TOS
  candidate codec instead of duplicating its implementation.
- The pre-existing TOS candidate codec in
  `validator-session/candidate-serializer.cpp` has additional negative-size,
  integer-width, compressed-input, and decompression-bound checks.
- The default Simplex collator schedule is isolated in
  `simplex/collator-schedule.cpp`, matching TON's source-level separation while
  retaining TOS's existing bus initialization interface.
- The protocol-version-2 candidate relay actor has been adapted to the
  existing TOS manager and full-node broadcast APIs and is selected by the
  first-testnet protocol-v2 configuration.
- The consensus bus now represents the local validator identity as optional,
  and validator-authority actors have explicit validator-only spawn gates.
  A non-voting `BlockSyncObserver` actor can cache candidates delivered by the
  authenticated protocol-v1 block-sync overlay. The manager derives local
  observer ADNL identities from the previous, current, and next total
  validator sets and reconciles observer groups independently by session and
  ADNL identity. Observer databases have identity-specific suffixes, and the
  block-sync and protocol-v2 private-overlay memberships use the deduplicated
  total-validator ADNL set. Private-overlay candidate-broadcast authorization
  remains restricted to the session validator set. Protocol messages carry
  both an ADNL source and an optional validator identity: observer votes are
  rejected, while certificates still require their validator quorum
  signatures and may be relayed by observers. Member queries are rate-limited
  by ADNL identity, and CandidateResolver may query an arbitrary non-local
  member. Authenticated non-empty candidates are cached through the manager's
  128-entry in-memory LRU and may enter the separately gated candidate-relay
  path.
- The TON Plumtree overlay core, including eager/lazy peer management, FEC
  trees, repair queries, source authorization, AnySender restrictions, and
  statistics exchange, has been adapted to TOS and builds as part of the
  overlay library.
- Public shard and fast-sync overlays derive the Plumtree candidate setting
  from ConfigParam30, create QUIC-backed Plumtree overlays, and send candidate
  FEC payloads through Plumtree when enabled.
- Finality broadcasts have a dedicated TL type and deterministic broadcast ID.
  Public and fast-sync overlays send them through Plumtree; custom overlays use
  their existing authorized FEC path. The manager retains candidates and
  finality sets in bounded LRU caches, reconciles either arrival order, builds
  a proof or proof link, and then reuses the existing `ValidateBroadcast` path.
  Before caching, the manager verifies final or approve signatures against the
  current or next validator set selected for the advertised catchain sequence.
  Invalid signatures cannot occupy the pending-finality cache, and a final
  signature set can upgrade a cached approve set while duplicates and
  downgrades are ignored.
- Candidate, finality, and complete-block network ingress now preserves
  whether a message came from the public, fast-sync, or custom overlay.
  Locally emitted finality is tagged as consensus-overlay ingress before it is
  sent. Public-overlay ingress is not reflected into custom overlays;
  fast-sync ingress may bridge into them; custom-overlay ingress is bridged
  only when the local identity is not configured as a block sender for that
  overlay. The existing per-block relay caches remain the final duplicate-loop
  guard.
- Candidate relay deduplicates block IDs, tracks the latest finalized
  masterchain sequence, and re-broadcasts a recent non-empty candidate when a
  `FinalizeBlock` event arrives without a prior `CandidateReceived` event.
- Full-node candidate and finality ingress starts manager tasks with labeled
  detached completion logging, so actor/task failures are visible while the
  broadcast path remains best-effort.
- Candidate relay actor lifetime follows the consensus baseline: validators
  and private-overlay observers host the actor, while each event still checks
  the Plumtree ConfigParam30 gate before forwarding.
- Simplex state resolution is likewise scoped to validators and configured
  private-overlay observers; public block-sync observers do not start the
  state-resolver actor.
- Legacy Simplex performance records now tolerate manager-acknowledgement
  lag, using finality observation as the completion timestamp instead of
  dereferencing an absent manager-acceptance value.
- The upstream Plumtree graph simulator is adapted to TOS. It exercises the
  real overlay actor, Plumtree implementation, TL messages, signatures, repair
  query transport, deterministic graph topology, geographic latency/jitter,
  bandwidth limits, deterministic per-message packet loss, sequential
  broadcasts, delivery latency, traffic, and duplicate accounting. Its
  current transport model can temporarily isolate one node, but does not model
  multi-component partitions, churn, or general Byzantine behavior. It can
  suppress outbound Plumtree data messages from one node while retaining
  control and repair traffic, and can rotate a temporary outage across nodes
  between broadcasts.
- The downloader can construct a masterchain `BlockProof` from a final
  signature set and the matching masterchain state. The shared proof-root
  builder validates the block root hash, header identity and shard flags,
  Merkle update shape, and key-block configuration before serializing either a
  full proof or proof link. Candidate/finality reconciliation now consumes
  this helper before invoking the existing broadcast validator.
- Validator startup supports protocol versions 0–2 and rejects version 3.
  Observer and transport-specific finality security/runtime validation remains
  incomplete.

The production and first-testnet activation coding tranches are complete ✅.
Release validation is intentionally still staged.

### Completed validation evidence ✅

- The `overlay` target builds with the Plumtree core.
- The `plumtree-graph-sim` target builds.
- The `validator` target builds with the masterchain-proof generation helper.
- The complete `validator-engine` executable links with the candidate/finality
  transport and manager reconciliation paths.
- The validator state exposes current and next validator-set selection by
  catchain sequence for early finality signature validation.
- Finalized signatures are round-tripped through the new finality TL envelope
  during the consensus simulation, including block ID, finality flag, catchain
  sequence number, validator-set hash, cryptographic signature verification,
  and rejection against a tampered block ID.
- ✅ Real finality signature sets produced by the consensus simulation reject a
  bit-flipped signature and a mismatched validator-set hash through the
  production `BlockSignatureSet` verifier. The negative copies use independent
  buffers and do not mutate the live consensus certificate.
- ✅ Overlay privacy rules reject unauthorized AnySender broadcasts, enforce
  authorized-key size limits, and distinguish authenticated `NeedCheck` traffic
  from trusted and forbidden traffic.
- ✅ The manager's finality-cache policy is exercised for empty-cache
  insertion, duplicate approve/final sets, approve-to-final upgrade, and
  final-to-approve downgrade rejection. The production manager calls the same
  tested policy function. End-to-end candidate/finality ordering with real
  block proof construction remains a separate integration test.
- The CTest FEC and simple-mode Plumtree smoke simulations pass on a 12-node,
  four-validator topology.
- ✅ Deterministic short CTests exercise the same topology with 10 percent
  per-message loss in FEC mode and 8 percent per-message loss in simple mode;
  five sequential broadcasts in each case reach all 12 expected nodes. These
  simulator checks are not substitutes for release-scale or multi-region
  packet-loss validation.
- ✅ A deterministic partition-recovery CTest isolates one node for the first two
  broadcasts, verifies propagation to the other 11 nodes, heals the link, and
  requires the third broadcast to reach all 12 nodes. This is a short
  single-node isolation check, not multi-component or multi-region partition
  evidence.
- ✅ A deterministic selective-forwarding CTest suppresses outbound Plumtree data
  messages from one non-validator while leaving its control and repair traffic
  intact. Five sequential broadcasts in both FEC and simple mode still reach
  all 12 nodes. This covers one static omission fault, not adaptive or general
  Byzantine forwarding.
- ✅ A deterministic rotating-outage CTest isolates a different non-validator
  during each of four broadcasts in both FEC and simple mode, requires
  delivery to the other 11 nodes in every affected round, then heals all nodes
  and requires 12-of-12 delivery. This tests repeated availability changes,
  not overlay membership churn.
- A 20-broadcast stress run in both FEC and simple modes, using 256 KiB
  payloads, 0.5 relative latency jitter, and a 1 MB/s per-message bandwidth
  model, delivered every broadcast to all 12 expected nodes.
- ✅ The same 20-broadcast FEC and simple stress profiles run as CTests and
  complete successfully. They provide a deterministic local performance
  regression gate, not production capacity or multi-region evidence.
- The complete `test-consensus` target builds.
- The `test-runtime` suite passes all eight cases, including the upstream
  provider-order test used by the default collator-schedule injection path.
- The `validator` library and complete `validator-engine` executable build
  after the consensus payload and collator-schedule separation.
- A ten-second multi-node consensus simulation at a 100 ms test target
  completes successfully.
- CTest runs short five-node Simplex liveness scenarios with 15 percent
  protocol-message loss, repeated process restarts, and repeated temporary
  single-node network isolation. Each scenario enforces a minimum finalized
  height, so lack of progress is a test failure.
- Those five-node scenarios now set protocol version 2 explicitly and assert
  that finalized blocks suppress the legacy shard-block-description broadcast,
  covering the consensus-to-accept-block feature gate.
- ConfigParam30 tests pin the protocol-v2 `#22` cell hash, decode it through
  the production configuration loader, reject reserved flags, truncation and
  zero leader-window size, and confirm that a future version is unsupported.
- The first-testnet Fift encoding constructs a valid `#22` cell with
  `flags=0`, `protocol_version=2`, `use_quic=true`, four slots per leader, and
  explicit 400/1000/250 noncritical parameters. The validator accepts v2 and
  continues to reject protocol version 3.
- The dedicated `test-consensus-simplex2-genesis-config` CTest pins that Fift
  cell to hash
  `6ADBFE8D74E95D62C7E2FC6F4615C7C628B476E1D06142F8A532F619BDD28814`.
- The isolated tostester zerostate regression passes both cases: it generates
  and deserializes the complete masterchain/shard zerostate through the dynamic
  `#22` path and confirms the canonical 5,000,000,000 TOS total supply.
- The real `test/integration/test_basic.py` topology passes with two initial
  validators and their observer groups. It starts from a freshly generated
  protocol-v2 zerostate, produces masterchain and base-workchain blocks,
  returns validator actor statistics, deploys and funds a workchain wallet,
  and shuts down cleanly.
- That integration run also exercises BusRuntime's `should_be_spawned`
  filtering. In particular, the Simplex Pool and block-sync observer remain
  mutually exclusive providers of candidate-broadcast prechecks instead of
  being instantiated together.
- The same two-validator integration topology passes after enabling
  validator-side shard-block-description generation and retaining TOS's
  `gen_utime`-sensitive validator-set selection.
- ConfigParam29 tests cover constructors `#d6`, `#d7`, `#d8`, and `#d9`
  through the production loader, including catchain IDs, protocol version,
  QUIC selection, and the maximum-block-height coefficient.
- Candidate-codec tests round-trip raw, legacy LZ4, and improved-structure
  payloads and reject mode mismatch, undersized limits, inconsistent declared
  size, truncation, trailing compressed bytes, and corrupted improved payloads.
- A 0.5 MiB multi-cell BOC with greater than 8:1 compression verifies that the
  exact configured limit succeeds, a one-byte-smaller limit fails, and an
  oversized declared output is rejected before decompression.
- A separate codec-boundary test uses valid block and collated-data BOCs within
  384 KiB of their respective 4 MiB production limits. Their combined
  7.66 MiB decompressed envelope succeeds under the production
  `8 MiB + 1024 bytes` budget and fails when that budget is one byte too small.
- Deterministic abuse cases reject a maximal declared legacy size, compressed
  input larger than its configured budget, invalid LZ4, empty and unknown V2
  codecs, and the stateful V2 codec when no state is supplied. The V2 baseline
  LZ4 algorithm is also covered by a successful round trip.
- `git diff --check` passes.

These fault-injected tests exercise the Simplex consensus simulator, not the
full-node Plumtree transport or manager reconciliation. They therefore do not
satisfy the transport-specific impairment, adversarial, performance, fuzzing,
or soak requirements listed later in this guide.

## 2. Current Architectural Differences

### 2.1 ConfigParam30 wire format

TOS uses the pinned TON `simplex_config_v2#22` layout:

```tlb
simplex_config_v2#22
  flags:(## 5)
  protocol_version:(## 2)
  use_quic:Bool ...
```

The five-bit flags, two-bit protocol version, and one-bit QUIC layout is the
only supported `#22` interpretation.

The pinned TON reference uses `protocol_version` to gate features:

| Protocol version | Upstream behavior |
|---:|---|
| 0 | None of the version-gated methods below returns true |
| 1 | Block-sync overlay |
| 2 or later | New database names, observers in the private overlay, and Plumtree broadcast; `enable_block_sync()` is false |

The first-testnet zerostate and validator binaries must use this same layout.

### 2.2 Reference features and current TOS status

- Candidate payload encoding was already present in TOS under
  `validator-session/candidate-serializer.cpp`. It combines block and
  collated-data BOCs, uses LZ4 for the legacy compressed form, and accepts the
  improved BOC-compression form. The first merge tranche added checks for
  negative size values, integer conversion, compressed input, and configured
  decompression bounds.
- A dedicated block-candidate synchronization overlay is now present for
  protocol version 1.
- Candidate caching through `ManagerFacade::cache_block_candidate` by a
  non-validator `BlockSyncObserver` is implemented for protocol version 1.
- Candidate relay through `ManagerFacade::send_block_candidate_broadcast`
  with custom, fast-sync, and public broadcast mode bits is now present behind
  the protocol-version-2 feature gate. Its downstream public-shard and
  fast-sync candidate paths now use Plumtree when selected by ConfigParam30.
- Protocol-version-gated Plumtree overlay support and its TL messages are now
  present. Public and fast-sync candidate propagation plus public, fast-sync,
  and custom-overlay finality propagation are integrated. Observer support is
  implemented; the required focused security, impairment, and soak tests
  remain incomplete, so Plumtree is not yet an activatable TOS protocol
  feature.
- TOS already uses session-specific consensus database paths. Reference v2
  database naming must be compared semantically before any further DB-path
  change.

The block-sync overlay creates a private overlay whose authorized-key map is
built from the validator set. Its broadcast precheck rejects a source that is
not in that set or is not the expected collator for the advertised slot.

### 2.3 Verified TOS additions and divergences to preserve

- Early rejection of certificates that are too far ahead of the local slot.
- Database replay checks that bind a saved vote key hash to the serialized vote
  or certificate value before replay.
- Candidate-resolver database checks that skip malformed keys and reject a
  stored candidate whose ID does not match the requested database key.
- A TOS `MisbehaviorReporter` actor and manager-facade delivery path. Its
  existence is verified here; end-to-end acceptance and punishment by the
  deployed elector contract must be validated separately.
- A TOS metric-collector actor wired into the consensus runtime.
- TOS-specific manager, peer-identifier, quorum-threshold, validator-group
  query, and transport integration differences visible in the consensus diff.

Every merge review must explicitly demonstrate that these properties remain
intact.

Certificate gossip (`certificate_gossip_neighbors` and random-neighbor
broadcast) and the underlying consensus statistics types exist in both
revisions. They are shared behavior, not TOS-only additions. Both TL-B trees
also contain `use_quic`; this guide does not claim that QUIC itself is unique to
TOS.

## 3. Merge Principles

1. **Merge by feature, not by directory.** Do not copy or replace the complete
   `validator/consensus` tree.
2. **Preserve consensus safety.** An upstream behavior must not remove a
   stricter TOS validation rule without a written safety analysis.
3. **Gate network-visible behavior.** New wire formats, overlay behavior, and
   broadcast algorithms must be activated through an on-chain version or an
   equally deterministic network-wide mechanism.
4. **Keep the first deployment deterministic.** The zerostate generator,
   validator, and public tooling must encode and decode exactly the same
   protocol version and configuration.
5. **Bound all untrusted inputs.** Candidate payload sizes, decompression
   output, queue sizes, slot gaps, and cache retention must have explicit
   limits.
6. **Keep changes reviewable.** Schema definition, payload codec, block sync,
   observer support, and Plumtree must be separate changes.
7. **Keep the 400 ms target controlled by on-chain configuration.** The
   verified TOS repository zerostate generator writes 400 ms for both
   masterchain and shard Simplex parameters, and the TOS C++
   `NewConsensusConfig` fallback is also 400 ms. Do not import the reference
   implementation's 2,400 ms fallback in a way that silently changes TOS
   pacing.

## 4. Recommended Merge Phases

### Phase 0: Freeze the baseline

**Current status: Partial.** Source revisions and the static comparison are
recorded. Performance baselines and archived configuration fixtures are still
missing.

- Record the TOS and upstream TON commit hashes.
- Produce a file-level and symbol-level consensus diff.
- List all TOS-only safety changes and assign an owner to each one.
- Capture a performance baseline for block interval, finality, CPU, memory,
  network traffic, and database growth.
- Archive representative ConfigParam29 and ConfigParam30 cells.

**Exit criteria**

- The baseline is reproducible from clean checkouts.
- Existing TOS consensus and local-network tests pass.
- A fresh local network sustains the configured block interval.

### Phase 1: ConfigParam30 format and protocol versioning ✅

**Current status: Coding complete ✅.** Schema parsing, reserved-flag
rejection, runtime version rejection, a `#22` golden hash, and malformed,
reserved-flag, zero-slot, future-version, and all four ConfigParam29
constructor tests are implemented. The first-testnet zerostate writes `#22`
with protocol version 2 and QUIC enabled, and validator startup accepts v2.

The pre-testnet format design must answer:

- What value is returned when ConfigParam30 is absent?
- Which protocol version is written into the first testnet zerostate?
- How do validators reject unsupported future versions?
- Can tooling round-trip every currently supported cell without changing bits?

TON's current `#22` layout is authoritative and the first testnet starts
directly from it.

Implement:

- Explicit protocol-version parsing and validation.
- Strict rejection of unknown active versions.
- Parsing tests for all supported ConfigParam29 constructors.
- Golden serialized-cell tests for every supported ConfigParam30 layout.

Do not enable block sync or Plumtree in this phase.

**Exit criteria**

- Golden vectors decode identically on all supported platforms.
- The first-testnet zerostate and validator decode the same ConfigParam30.
- Invalid, truncated, reserved-flag, and future-version cells are rejected.

### Phase 2: Candidate payload codec ✅

**Current status: Coding complete ✅ / pending validation.** The codec and additional resource-bound checks are
implemented. Deterministic tests cover raw, legacy LZ4, improved-structure
compression, exact configured limits, wrong declared size, truncation,
trailing bytes, corruption, compression-mode mismatch, and a valid 0.5 MiB
high-compression-ratio candidate. A dedicated CTest also covers valid block and
collated-data BOCs close to their respective configured 4 MiB maxima under the
combined production decompression budget. An initial deterministic abuse corpus
covers extreme size declarations and malformed legacy and V2 codec inputs.
Coverage-guided fuzzing, further corpus expansion, and repeatable peak-memory
evidence are not complete.

Port the reference combined candidate payload design:

- Serialize the block and collated data into a well-defined combined BOC.
- Preserve the exact versioned codec semantics selected for TOS. The verified
  legacy reference serializer uses LZ4; the improved form is decoded through
  the BOC compression API.
- Carry and validate the declared decompressed size.
- Enforce maximum compressed and decompressed sizes before allocation.
- Reject negative legacy size fields and unsafe integer conversions.
- Reject malformed BOCs, trailing data, compression bombs, and inconsistent
  size declarations.
- Accept the raw payload form only when selected by the active protocol
  version.

The codec must be independent of transport so that the same validation applies
to QUIC, overlay, relay, and test inputs.

**Required tests**

- Golden encode/decode vectors.
- Round-trip tests for boundary-sized blocks and collated data.
- Truncated and corrupted payload tests.
- Oversized declared and actual output tests.
- Compression-ratio abuse tests.
- Fuzzing of both the envelope and decompressor entry points.
- Peak-memory measurement under maximum permitted input.

**Exit criteria**

- No unbounded allocation is reachable from network data.
- Corpus fuzzing completes without crash, timeout, or excessive allocation.
- Candidate propagation bandwidth improves or remains within the agreed limit.

### Phase 3: Block-sync overlay ✅

**Current status: Coding complete ✅ / pending validation.** The protocol-v1 overlay and its primary
authorization and collator checks are implemented. Recovery, impairment,
restart, saturation, and resource-pressure exit tests remain open.

Port the block-sync overlay behind a disabled protocol-version gate.

The implementation must:

- Admit only authorized validator identities.
- Authenticate the source of every candidate.
- Verify that the source is the expected collator for the slot.
- Apply payload bounds before expensive parsing.
- Deduplicate candidates and bound cache lifetime.
- Avoid allowing block-sync traffic to starve votes or certificates.
- Preserve the intended TOS transport behavior and provide explicit fallback
  semantics, if any.

Do not assume that upstream manager, overlay, and full-node interfaces can be
cherry-picked independently. Adapt the feature to the TOS actor and network
interfaces, keeping integration changes small.

**Required tests**

- Catch-up after a validator misses candidates.
- Candidate retrieval after process restart.
- Unauthorized sender and wrong-collator rejection.
- Duplicate, delayed, reordered, and conflicting candidate delivery.
- Packet loss, latency, partition, and reconnect scenarios.
- Bandwidth and queue pressure from a malicious authorized peer.

**Exit criteria**

- Block sync cannot alter voting or certificate validity rules.
- Recovery time improves in the target impairment scenarios.
- Consensus traffic remains live under block-sync saturation tests.

### Phase 4: Observer cache and candidate relay ✅

**Current status: Coding complete ✅ / pending validation.** Candidate relay, observer creation,
optional validator identity, private-overlay membership, read-only Pool and
CandidateResolver operation, arbitrary-member candidate queries, and bounded
in-memory candidate retention are implemented behind their protocol gates.
Authorization, eviction, removal/liveness, query-abuse, and relay-loop tests
remain open.

Add non-voting observers only after the block-sync overlay is stable.

Observers must:

- Have no ability to vote, certify, or influence collator selection.
- Cache only authenticated and validated candidate envelopes.
- Use bounded memory and disk retention.
- Be removable without affecting validator liveness.
- Be distinguishable from validators in authorization and metrics.

Candidate relay must not turn untrusted public traffic into trusted private
overlay traffic. Trust must be re-established at every boundary.

**Exit criteria**

- A process possessing only observer credentials cannot produce a consensus
  message accepted as validator-authorized.
- Validator recovery works with multiple observers and with no observers.
- Cache eviction and relay loops are tested.

### Phase 5: Plumtree broadcast ✅

**Current status: Coding complete ✅ / pending validation.** The planned Phase
5 production coding is complete. The overlay protocol core and TL schema are
implemented and build successfully. Public-overlay and fast-sync candidate
paths are integrated and the complete validator engine links. The graph
simulator and its FEC/simple smoke tests are ported. Finality and downloader
transport, bounded manager reconciliation, proof construction, and existing
broadcast validation integration are ported. Short fault-injected Simplex
consensus tests cover protocol-message loss, process restart, and temporary
single-node isolation with explicit liveness thresholds. Transport-specific
runtime coverage for end-to-end candidate/finality arrival ordering,
manager-ingress invalid signatures, eviction, relay loops, actual membership
churn, and adaptive Byzantine selective forwarding remains open. Overlay
privacy-rule authorization and local performance regression are covered
directly; production capacity and multi-region soak evidence remain open.
Deterministic short simulator tests now cover packet loss, temporary
single-node isolation, rotating temporary outages, and one static selective
data-forwarding omission. Actual membership churn, release-scale packet-loss
and partition, security, and performance evidence remain open.

TON commit `208c0ded`'s end-to-end shard-block-description path is adapted:
Plumtree suppresses the legacy accept-block broadcast, validators generate the
description locally from validated finality signatures, proof links are
rebuilt from validated block data when a legacy proof omits `BlockExtra`, and
the generated chain is bounded to eight proof roots. Header catchain sequence
and validator-set hash must match the signature set even when signatures were
checked earlier. Unlike current TON, TOS retains its time-sensitive
validator-set API and selects the set using the proved block's `gen_utime`;
this preserves TOS semantics instead of importing the unrelated API
refactoring.

Integrate Plumtree as an independently gated feature. Test it against the
existing TOS certificate and candidate propagation mechanisms.

Measure:

- Propagation latency at p50, p95, p99, and maximum.
- Duplicate bytes per delivered message.
- Recovery after eager-peer failure.
- Behavior under asymmetric latency and packet loss.
- Resistance to peer churn and selective forwarding.

Activation should require evidence that finality and propagation tails are not
worse than the existing mechanism under the test matrix.

### Phase 6: Optional structural refactoring

**Current status: Optional; no activation blocker.** The consensus payload
boundary and collator-schedule source separation are complete ✅. No additional
structural refactor is required for the currently completed tranches.

Only after the feature ports are stable should TOS consider upstream structural
changes such as network-state management, database naming, or collator-schedule
file separation.

These are not prerequisites for protocol parity. Avoid mixing them with
consensus-visible changes.

## 5. Changes That Must Not Be Regressed

The following TOS properties require dedicated regression tests:

### Too-new certificate rejection

A peer or Byzantine quorum must not be able to advance a node's accepted
future-slot window merely by sending a validly signed certificate far ahead of
the local state.

Tests must cover:

- A single malicious validator.
- A Byzantine quorum.
- Repeated future certificates.
- A node that later catches up normally.

### Vote and certificate database consistency

Database replay must verify that the stored key, vote hash, certificate
payload, and certificate hash refer to the same object. Corrupt or mismatched
records must fail safely and produce actionable diagnostics.

### Misbehavior reporting

Evidence serialization and reporting must remain deterministic. Any upstream
message-type changes must be mapped into TOS evidence types or explicitly
declared unsupported.

### Metrics

New actors and network paths must expose enough metrics to diagnose:

- Candidate creation, compression, transfer, validation, and cache time.
- Block-sync requests, hits, misses, rejection reasons, and bytes.
- Observer cache size and eviction.
- Broadcast fanout, duplicates, and propagation time.
- Votes, certificates, commits, slot lag, and recovery duration.

## 6. Test Matrix

| Area | Scenario | Expected result |
|---|---|---|
| Configuration | First-testnet ConfigParam30 | Decodes exactly according to TON's current `#22` definition |
| Configuration | New supported protocol version | Decodes deterministically and gates only documented features |
| Configuration | Unknown future version | Rejected before joining consensus |
| Payload | Maximum valid candidate | Accepted within CPU and memory budgets |
| Payload | Compression bomb | Rejected before excessive allocation |
| Payload | Corrupt BOC or compressed stream | Rejected without crash |
| Block sync | Missed candidate | Retrieved and validated from an authorized source |
| Block sync | Wrong collator | Rejected and recorded |
| Block sync | Traffic flood | Votes and certificates continue to make progress |
| Observer | Honest observer | Improves candidate availability |
| Observer | Malicious observer | Cannot forge or authorize consensus data |
| Broadcast | Peer churn | Propagation recovers without consensus stall |
| Safety | Too-new certificate | Dropped without advancing the local window |
| Recovery | Corrupt DB binding | Detected; no inconsistent state is replayed |
| Timing | 400 ms target | Sustained within the agreed tolerance |

Run the matrix with at least:

- 1, 4, and 7 validators.
- Zero, one, and multiple observers.
- Same-region and multi-region latency profiles.
- Clean start, rolling restart, crash restart, and network partition.
- Honest operation, one Byzantine validator, and the maximum tolerated
  Byzantine population.

## 7. Testnet Release Gates

### Testnet-0

Completion of every Simplex2 port is not proposed as a Testnet-0 prerequisite.
This statement is a scope recommendation, not a conclusion that the current TOS
revision is otherwise ready for Testnet-0. Overall readiness still depends on
the wider consensus, networking, genesis, operations, and security release
criteria outside this guide.

Testnet-0 should establish baseline behavior and exercise new code with feature
gates disabled.

Recommended Testnet-0 goals:

- Validate the 400 ms configured pacing under sustained load.
- Measure database growth and network use.
- Exercise validator restart and database recovery.
- Validate TOS certificate-window hardening.
- Deploy payload and block-sync code in disabled or limited-canary mode.

### Testnet-1

Before public Testnet-1, the following should be complete:

- A single ConfigParam30 protocol-version format shared by the zerostate,
  validators, and tooling.
- Candidate payload compression with strict resource bounds.
- A feature-gated block-sync overlay.
- Observer cache support, if observers are part of Testnet-1 operations.
- Regression coverage for all TOS-specific safety changes.
- A multi-region soak test of at least 72 hours without unexplained consensus
  stalls, divergence, or unbounded resource growth.

Plumtree may be activated later during Testnet-1 through an on-chain upgrade
after its own release gates are satisfied.

## 8. Pull Request Structure

Use small, ordered pull requests:

1. Baseline documentation and golden configuration fixtures.
2. ConfigParam30 parser and validation tests.
3. Protocol-version feature-gate plumbing.
4. Candidate payload codec and fuzz tests.
5. Block-sync overlay core.
6. TOS manager, QUIC, and overlay integration.
7. Observer cache and candidate relay.
8. Plumtree broadcast.
9. Optional structural refactoring.

Each pull request must include:

- The upstream commit hash and source files used.
- A description of adapted versus copied behavior.
- Consensus and wire-format impact.
- Resource limits introduced or changed.
- Tests added and their results.
- Metrics added.
- Rollback behavior.
- A checklist confirming that TOS-only safety logic was preserved.

## 9. Activation and Rollback

Consensus-visible features must not depend on local command-line flags alone.
Activation must be deterministic from finalized chain state.

Before activation:

- Confirm that the required validator stake has upgraded.
- Confirm that all public tooling supports the new configuration.
- Publish the activation block or configuration condition.
- Take recoverable database backups.
- Verify dashboards and alerts for the new paths.

Rollback is safe only before a consensus-visible activation or through another
agreed on-chain transition. After activation, operators must not independently
downgrade to binaries that interpret the same configuration differently.

Emergency controls may disable optional relaying or observer services if doing
so does not change consensus interpretation. They must not reinterpret payloads,
votes, certificates, or protocol versions.

## 10. Completion Criteria

The selective Simplex2 merge is complete when:

- ConfigParam30 has one documented interpretation in the first-testnet
  zerostate, validator, and tooling.
- Candidate payload processing is bounded and fuzz-tested.
- Block sync improves recovery without weakening authentication or liveness.
- Observer and broadcast features cannot influence consensus authority.
- TOS-specific certificate and recovery checks, misbehavior reporting,
  metric-actor integration, and transport behavior are preserved.
- The full test matrix and 72-hour multi-region soak pass.
- Operators have documented deployment, monitoring, and rollback procedures.

## 11. Source Evidence Map

The following locations support the implementation statements in Section 2 at
the pinned commits. Line numbers are navigation aids and may move after edits.

| Statement | TOS evidence | TON reference evidence |
|---|---|---|
| ConfigParam30 v2 bit layout | `crypto/block/block.tlb:806` | `crypto/block/block.tlb:793` |
| Generated TOS v2 decoder layout | `crypto/block/block-auto.cpp:18085` | N/A |
| TOS ConfigParam30 loader | `crypto/block/mc-config.cpp:417` | `crypto/block/mc-config.cpp:376` |
| Protocol-version feature gates | N/A | `ton/ton-types.h:504` |
| Payload codec and size checks | `validator-session/candidate-serializer.cpp:32` | `validator/consensus/payload.cpp:25` |
| Block-sync private overlay and precheck | `validator/consensus/block-sync-overlay.cpp:28` | `validator/consensus/block-sync-overlay.cpp:29` |
| Observer caching and candidate relay | `validator/consensus/bridge.cpp`, `validator/consensus/private-overlay.cpp` | `validator/consensus/bridge.cpp:155` |
| Database-name and observer identity gates | `validator/manager.cpp`, `validator/consensus/bridge.cpp` | `validator/validator-group.cpp:90` |
| Too-new certificate rejection | `validator/consensus/simplex/pool.cpp:438` | Comparison target: `validator/consensus/simplex/pool.cpp:459` |
| Vote/certificate DB hash binding | `validator/consensus/simplex/db.cpp:129` | Comparison target: `validator/consensus/simplex/db.cpp:131` |
| Candidate-resolver DB hardening | `validator/consensus/simplex/candidate-resolver.cpp:255` | Comparison target: `validator/consensus/simplex/candidate-resolver.cpp:259` |
| Misbehavior reporter actor | `validator/consensus/misbehavior-reporter.cpp:152` | No matching actor |
| Metric-collector actor | `validator/consensus/simplex/metric-collector.cpp:23` | No matching actor |
| Shared certificate gossip setting | `tos/tos-types.h:562` | `ton/ton-types.h:545` |
| TOS zerostate 400 ms values | `crypto/smartcont/gen-zerostate.fif:178` | N/A |
| Default target-rate fallback | TOS: 400 ms at `tos/tos-types.h:546` | TON reference: 2,400 ms at `ton/ton-types.h:529` |

“No matching module” or “No matching actor” means no file or symbol with the
corresponding consensus role was found in the pinned comparison revision. It
does not prove that no equivalent behavior exists elsewhere in the entire
codebase. A feature owner must repeat repository-wide symbol and call-path
searches during the actual port.
