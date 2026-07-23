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
| TOS (`~/tos`) | `51e810a935328fe7c3490d8cff02f2849d83c4e4` |
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

Progress snapshot: 2026-07-23. The implementation is based on TOS commit
`38d50d663dcaaa8ad911d5d219fc9a7e9ad29e89` plus the uncommitted Plumtree
overlay work described below. The pinned TON comparison reference remains
`bbc3bc6d52abbe3a7f852b22050708166fdaafbc`.

Status definitions:

- **Completed**: implemented and covered by the validation stated here.
- **Partial**: useful code is implemented, but phase exit criteria are not met.
- **Not started**: no production implementation has been merged.
- **Pending validation**: implementation exists, but the required adversarial,
  performance, soak, or mixed-version evidence is incomplete.

| Phase | Status | Implemented | Remaining work |
|---|---|---|---|
| 0. Baseline | Partial | Immutable source commits and static feature comparison are recorded | Archive golden ConfigParam cells and record CPU, memory, bandwidth, finality, and database-growth baselines |
| 1. ConfigParam30 | Partial | TON `#22` bit layout, protocol parsing, supported-version gate, and `#21` round-trip test | Resolve historical old-`#22` ambiguity; add golden, truncated, invalid, and mixed-version activation tests |
| 2. Candidate codec | Partial | Existing combined BOC/LZ4/improved codec verified; negative-size and integer/size bounds hardened | Add boundary vectors, corruption/compression-bomb corpus, fuzzing, and peak-memory measurements |
| 3. Block-sync overlay | Partial | Protocol-v1 private overlay, validator authorization, expected-collator precheck, payload bounds, and misbehavior reporting | Add recovery, restart, duplicate/reorder, partition, flood, queue-pressure, and bandwidth tests |
| 4. Observer and relay | Partial | Protocol-v2 candidate relay actor and existing manager/full-node broadcast API adaptation | Port non-validator group reconciliation, optional validator identity, observer cache/retention, authorization, eviction, and relay-loop tests |
| 5. Plumtree | Partial | Overlay core, TL messages, eager/lazy peers, FEC trees, repair, AnySender authorization, statistics, and public plus fast-sync candidate paths compile in TOS | Port finality/downloader paths; add simulation, churn, loss, latency, duplicate-byte, and security tests |
| 6. Structural refactoring | Not started | TOS session-specific database paths were reviewed at a high level | Perform semantic DB-name comparison only if required after protocol features stabilize |
| Activation | Not started | Protocol v2 is parsed but validator startup rejects it explicitly | Complete phases 1–5 exit criteria, define proposal/rollback procedure, and run mixed-version plus 72-hour multi-region soak |

Implemented work to date:

- `simplex_config_v2#22` uses the reference five-bit flags, two-bit
  `protocol_version`, and `use_quic` layout.
- The legacy `simplex_config#21` layout remains supported and is still emitted
  by the repository zerostate generator.
- Protocol version 1 has a dedicated block-sync overlay.
- The pre-existing TOS candidate codec in
  `validator-session/candidate-serializer.cpp` has additional negative-size,
  integer-width, compressed-input, and decompression-bound checks.
- The protocol-version-2 candidate relay actor has been adapted to the
  existing TOS manager and full-node broadcast APIs. It remains unreachable
  while protocol version 2 is startup-gated and must not be treated as
  Plumtree support.
- The TON Plumtree overlay core, including eager/lazy peer management, FEC
  trees, repair queries, source authorization, AnySender restrictions, and
  statistics exchange, has been adapted to TOS and builds as part of the
  overlay library.
- Public shard and fast-sync overlays derive the Plumtree candidate setting
  from ConfigParam30, create QUIC-backed Plumtree overlays, and send candidate
  FEC payloads through Plumtree when enabled. Finality/downloader integration
  and observer group creation remain unported.
- Protocol version 2 remains deliberately unsupported at validator startup.
  Its observer and finality/downloader integration dependencies have not been
  fully ported and tested.

This is a staged implementation, not completion of all phases in this guide.

Validation completed for the current working tree:

- The `overlay` target builds with the Plumtree core.
- The complete `test-consensus` target builds.
- A ten-second multi-node consensus simulation at a 100 ms test target
  completes successfully.
- `git diff --check` passes.

This validation does not satisfy the network impairment, adversarial,
performance, fuzzing, mixed-version, or soak requirements listed later in this
guide.

## 2. Current Architectural Differences

### 2.1 ConfigParam30 wire format

Before this merge, TOS defined `simplex_config_v2#22` with seven flag bits
followed by `use_quic`:

```tlb
simplex_config_v2#22 flags:(## 7) use_quic:Bool ...
```

The pinned TON reference, and TOS after the first merge tranche, assign two of
those bits to `protocol_version`:

```tlb
simplex_config_v2#22
  flags:(## 5)
  protocol_version:(## 2)
  use_quic:Bool ...
```

Both layouts consume the same eight bits after the constructor tag, but divide
them differently. The pre-merge generated TOS decoder read seven `flags` bits
and one Boolean; the new TOS and reference decoders read five `flags` bits, two
protocol-version bits, and one Boolean. Some cells can therefore parse under
both layouts while assigning different meanings to those bits.

Repository-wide search found production and test zerostate generation using
the unambiguous legacy `#21` constructor and found no TOS producer for the old
`#22` layout. Historical externally generated `#22` cells with non-zero flag
bits remain potentially ambiguous and must be inventoried before an on-chain
v2 configuration is proposed.

The pinned TON reference uses `protocol_version` to gate features:

| Protocol version | Upstream behavior |
|---:|---|
| 0 | None of the version-gated methods below returns true |
| 1 | Block-sync overlay |
| 2 or later | New database names, observers in the private overlay, and Plumtree broadcast; `enable_block_sync()` is false |

TOS must define an explicit migration and activation policy before adopting
this layout. A parser change alone is not sufficient.

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
  non-validator `BlockSyncObserver` when protocol version 1 is active remains
  unported because current TOS consensus groups require a validator identity.
- Candidate relay through `ManagerFacade::send_block_candidate_broadcast`
  with custom, fast-sync, and public broadcast mode bits is now present behind
  the protocol-version-2 feature gate. Its downstream public-shard and
  fast-sync candidate paths now use Plumtree when selected by ConfigParam30.
- Protocol-version-gated Plumtree overlay support and its TL messages are now
  present. Public and fast-sync candidate propagation is integrated. The
  reference finality/downloader and observer integrations remain unported, so
  Plumtree is not yet an activatable TOS protocol feature.
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
2. **Preserve consensus safety before compatibility.** An upstream behavior
   must not remove a stricter TOS validation rule without a written safety
   analysis.
3. **Gate network-visible behavior.** New wire formats, overlay behavior, and
   broadcast algorithms must be activated through an on-chain version or an
   equally deterministic network-wide mechanism.
4. **Maintain deterministic mixed-version behavior.** Before activation, old
   and new binaries must agree on the active rules. After activation,
   unsupported binaries must fail clearly rather than continue under a
   different interpretation.
5. **Bound all untrusted inputs.** Candidate payload sizes, decompression
   output, queue sizes, slot gaps, and cache retention must have explicit
   limits.
6. **Keep changes reviewable.** Schema migration, payload codec, block sync,
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

### Phase 1: ConfigParam30 compatibility and protocol versioning

**Current status: Partial.** Schema parsing and runtime version rejection are
implemented, but historical `#22` ambiguity, golden vectors, malformed-cell
coverage, and mixed-version activation tests remain open.

Design the ConfigParam30 migration before changing the TL-B schema. The design
must answer:

- How is the legacy TOS `#22` layout distinguished from the new layout?
- Is a new constructor required to avoid ambiguity?
- What value is returned when ConfigParam30 is absent?
- Which on-chain proposal activates each protocol version?
- How do validators reject unsupported future versions?
- Can tooling round-trip both legacy and new cells without changing bits?

Using a new constructor is preferable if the legacy and upstream layouts cannot
be distinguished unambiguously. Reusing `#22` must only be allowed after tests
prove that no legacy TOS cell can be silently decoded with shifted fields.

Implement:

- Explicit protocol-version parsing and validation.
- Legacy TOS config decoding for historical data and tooling.
- Strict rejection of unknown active versions.
- Parsing tests for all supported ConfigParam29 constructors.
- Golden serialized-cell tests for every supported ConfigParam30 layout.

Do not enable block sync or Plumtree in this phase.

**Exit criteria**

- Golden vectors decode identically on all supported platforms.
- Legacy TOS configurations remain readable.
- Invalid, truncated, ambiguous, and future-version cells are rejected.
- A mixed-binary network behaves identically before activation.

### Phase 2: Candidate payload codec

**Current status: Partial.** The codec and additional resource-bound checks are
implemented. The required boundary corpus, fuzzing, compression-abuse, and
peak-memory evidence is not complete.

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
- Keep raw payload compatibility only when explicitly required by the selected
  protocol version.

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

### Phase 3: Block-sync overlay

**Current status: Partial.** The protocol-v1 overlay and its primary
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

### Phase 4: Observer cache and candidate relay

**Current status: Partial.** Candidate relay is implemented behind the v2
gate. Observer creation, optional validator identity, bounded cache retention,
and observer security tests are not implemented.

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

### Phase 5: Plumtree broadcast

**Current status: Partial.** The overlay protocol core and TL schema are
implemented and build successfully. Public-overlay and fast-sync candidate
paths are integrated and the complete validator engine links. Finality and
downloader paths plus the required network simulation and performance evidence
remain open.

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

**Current status: Not started.** No structural refactor is required for the
currently completed tranches.

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
| Configuration | Legacy TOS ConfigParam30 | Decodes according to the legacy definition |
| Configuration | New supported protocol version | Decodes deterministically and gates only documented features |
| Configuration | Unknown future version | Rejected before joining consensus |
| Upgrade | Old and new binaries before activation | Same consensus behavior |
| Upgrade | Activation boundary | All upgraded validators switch at the same chain state |
| Upgrade | Unsupported validator after activation | Fails clearly and does not produce divergent messages |
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

- An unambiguous ConfigParam30 protocol-version migration.
- Candidate payload compression with strict resource bounds.
- A feature-gated block-sync overlay.
- Observer cache support, if observers are part of Testnet-1 operations.
- Mixed-version upgrade and activation tests.
- Regression coverage for all TOS-specific safety changes.
- A multi-region soak test of at least 72 hours without unexplained consensus
  stalls, divergence, or unbounded resource growth.

Plumtree may be activated later during Testnet-1 through an on-chain upgrade
after its own release gates are satisfied.

## 8. Pull Request Structure

Use small, ordered pull requests:

1. Baseline documentation and golden configuration fixtures.
2. ConfigParam30 parser and compatibility tests.
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
- Consensus and wire-compatibility impact.
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

- ConfigParam30 has one documented, unambiguous interpretation at every chain
  height.
- Candidate payload processing is bounded and fuzz-tested.
- Block sync improves recovery without weakening authentication or liveness.
- Observer and broadcast features cannot influence consensus authority.
- TOS-specific certificate and recovery checks, misbehavior reporting,
  metric-actor integration, and transport behavior are preserved.
- Mixed-version activation has been rehearsed successfully.
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
| Observer caching and candidate relay | No matching actors | `validator/consensus/bridge.cpp:155` |
| Database-name and observer identity gates | N/A | `validator/validator-group.cpp:90` |
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
