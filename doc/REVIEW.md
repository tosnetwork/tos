# Code review checklist

## Purpose

This document fixes the viewpoints from which every change to this repository is reviewed.
It has two jobs:

1. **Before a merge**, it tells the author and the reviewer which questions must have an
   answer, and what counts as an answer.
2. **After a bug escapes**, it tells us which viewpoint should have caught it, so that the
   checklist improves with every defect instead of the same class recurring.

The checklist is written for a post-quantum blockchain node and its surroundings: the
validator and consensus engine, the virtual machine and cell storage, the networking stack,
the JSON-RPC and lite-server interfaces, the Rust operator tooling, the smart contracts, the
genesis and configuration tooling, and the scripts and CI that build and test them.

[AGENTS.md](../AGENTS.md) remains the source of repository instructions. This checklist
provides review questions and evidence requirements; it does not replace those instructions.

## How to use it

- **Pick the areas the change touches.** Section headings name the code they apply to. A
  change usually touches three to six areas; *Upstream first*, *Tests and evidence* and
  *Documentation drift* apply to every change.
- **Answer each applicable item with evidence**, not with an opinion. Evidence is one of:
  a `file:line` reference on the reviewed commit, a test that fails without the change and
  passes with it, a command and its output, or a measurement with its method and host. "Looks
  fine" and "should be bounded" are not answers.
- **Mark an item `n/a` only with a one-line reason.** An item that does not apply to this
  change today is often the one that applies to the next change in the same file.
- **Review the exact commit.** State the commit hash the review covers. A review of an earlier
  head does not cover a later push.
- **Report findings with a severity (below), a location, the reachable scenario, and the
  checklist item that caught it.** A finding that cites no item is a signal that this document
  needs a new one (see *When a new bug is found*).

## Severity

| Level | Meaning | Examples of impact |
|---|---|---|
| **P0** | Breaks a safety property of the network or of funds. | Two honest nodes finalize different blocks or states; a signature or vote is accepted that the rules reject (or the reverse); funds can be stolen, created, destroyed or locked permanently; a validator or wallet key can be extracted or misused; a single cheap action halts block production or finality network-wide. |
| **P1** | Breaks availability or a funds-handling guarantee under realistic conditions, or makes a P0 likely. | A node crashes, stalls or exhausts memory or disk from remote input or normal load; a validator cannot recover after a restart; an operator tool can send, double-send or misreport a value transfer; a contract's solvency or replay protection depends on luck; a release or deployment artifact is not the reviewed one. |
| **P2** | Incorrect or fragile behaviour with bounded impact. | Wrong error codes or exit statuses; bounded resource waste; a limit that rejects a rare valid input; missing diagnostics; a test that cannot fail; documentation that contradicts the code. |
| P3 | Hygiene and clarity. | Naming, comments, log noise, small refactors. |

**What blocks a merge.** A finding blocks a merge when all three hold:

1. the change introduced it, including a newly introduced path to a pre-existing defect;
2. it can happen in the supported deployment (the platforms, topologies and operator
   workflows this repository supports);
3. a concrete test, reproduction or measurement can show it.

Every P0 or P1 that meets these conditions blocks. A P2 that meets them blocks unless the
owner accepts it in writing on the pull request. Anything else gets a reply with the reason
and becomes a tracked follow-up; it does not block. A finding that is identical in the
upstream implementation follows *Upstream first* below.

### Review and merge checks

- The author posts the self-check below before requesting review. A non-author agent reviews
  every pull request and names the checklist areas checked. In this repository, third-party
  review is also required; the author's or non-author agent's sign-off does not replace it.
  The operations repository, `tos-ops`, does not require third-party review; its local
  verification and non-author review remain applicable.
- Immediately before every merge, inspect the review bot's inline comments on the exact
  current head, not only its summary, the checks page or an earlier review. Reply to every
  finding with its resolution or the triage reason above, and record follow-ups. An unresolved
  blocking finding still blocks even when CI and the summary are green.
- Keep review fixes minimal and address the class across sibling paths. After at most two
  further bot rounds, track remaining P2 findings as follow-ups and escalate remaining
  blocking P0/P1 findings to the owner; do not start another round without a ruling.
- Map changed boundaries to the smallest sufficient checks under
  [the relevant-CI rule](../AGENTS.md#wait-for-relevant-ci-not-every-ci-job).
  A local replay of the workflow's exact commands in the repository builder image counts
  as CI evidence for supported Linux jobs. Publish the reviewed head, integrated main/base
  commit, image digest, commands and per-step results. Skipped or unreached steps are not
  passes. Before attributing a failure to the base, execute the remaining steps and compare
  with a full-step base run. Required checks still need evidence or an explicit owner ruling;
  a local receipt does not itself change branch protection or authorize a merge.

---

## 1. Upstream first

Most of the node is inherited from an upstream implementation, and a local clone of it is
kept for comparison. Code without an upstream counterpart (post-quantum consensus and
signatures, the Rust tooling, the JSON-RPC server, SDKs, scripts, contracts we wrote) follows
the normal rules.

- **UP-1** Was the same code path located in the current upstream implementation, with
  `file:line` and commit on both sides? Is it identical, changed or absent upstream?
- **UP-2** If the problem being fixed also exists upstream: has upstream fixed or mitigated
  it (newer commits, release notes)? If so, does the change port that fix as closely as
  possible rather than design a new one?
- **UP-3** If the problem exists upstream and is unfixed there: does the change justify
  diverging by a security defect or a consensus-fork risk in our own deployment? Otherwise
  leave inherited behaviour unchanged, reply with that reason and record the finding as a
  follow-up. An exception needs the owner's decision with deployment evidence.
- **UP-4** Where the change adds a mechanism of our own, is there a measurement showing the
  upstream strategy is insufficient for our deployment?
- **UP-5** Does the change keep inherited code recognisably close to upstream (layout,
  naming, structure), so that future upstream fixes can still be ported?
- **UP-6** When a protection is claimed to exist "as upstream does", has the claim been
  checked against upstream source, including whether upstream enables it by default?

## 2. Consensus safety and liveness

Applies to the consensus engine, block validation and acceptance, finality certificates,
validator-set installation, elections and session management.

- **CS-1** Does every decision that affects which block or state is final derive only from
  signed or chain-derived data that every honest node sees identically? Is any local
  observation (timeouts, skip judgements, cache contents, restart counters) used where a
  signed value exists?
- **CS-2** Can an honest node be made to sign two conflicting messages for the same slot,
  round or height — including across a crash, restart, rollback of local storage, or a
  database copied from another node?
- **CS-3** Are quorum and threshold computations exact (weights, rounding, duplicates,
  signers outside the set, a validator that appears twice)? Does verification reject a
  certificate that contains extra, duplicated or unknown signers?
- **CS-4** Late, early and out-of-order inputs: what happens to a candidate, vote or
  certificate that arrives after the decision it belongs to, before its parent, across a
  session or validator-set boundary, or for an observer rather than a participant? Is any
  valid input silently dropped so that a node stalls until restarted?
- **CS-5** Transient failure versus permanent failure: when a state resolution, download or
  verification fails transiently, does the node retry within a bound and still vote, or does
  it leave a pending marker that blocks the slot? When it fails permanently, does it fail
  closed?
- **CS-6** Error attribution: when verification of a block-plus-evidence bundle fails, is
  the failure attributed to the right component (block bytes, evidence, trusted context), so
  that valid data is never deleted because adjacent data is bad?
- **CS-7** Do the contract that installs a validator set, the governance path, and the node's
  decoder enforce the same validity rules (duplicates, weights, caps, key types)? Can a set be
  installed on chain that some node refuses to load?
- **CS-8** Griefing amplification: can one participant, for a small cost, cause the whole
  election, set installation or round to be refused or repeated? Is a bad entry isolated
  rather than voiding the batch?
- **CS-9** Does a stalled, lagging or minority node still converge without manual
  intervention, and is the condition visible (see *Observability*)?
- **CS-10** Are time-based rules (rounds, timeouts, election windows, expiries) evaluated
  against chain time where determinism matters, and do they tolerate realistic clock skew?
- **CS-11** Is every vote and consensus message checked against the key that the chain
  currently authorises for that validator *before* it is stored or counted, and do stored
  entries expire, so that forged or far-future messages cannot occupy a validator's slot?
- **CS-12** Can a cache or index keyed by height, slot, session or version enter a state
  where an entry is inserted under a key under which it is never looked up, so that replay or
  validation loops forever?

## 3. Determinism across nodes, implementations and architectures

Applies to the virtual machine, transaction execution, fee computation, serialization, and
any second implementation of the same rules (for example a Rust executor or emulator
alongside the native engine).

- **DT-1** Given the same inputs, does the code produce bit-identical results on every
  supported architecture, compiler and standard library? Watch iteration order of hash maps,
  floating point, uninitialised memory, pointer-derived ordering, locale, time zone and
  `sizeof`-dependent encodings.
- **DT-2** Where two implementations of the same rule exist (native and Rust executor,
  emulator and chain, getter environment and execution environment), does the change update
  both, and is there a differential test over a real corpus that compares them byte for
  byte?
- **DT-3** Do saturating or clamped counters, implicit conversions or overflow behaviour
  differ between implementations? A counter that saturates in one and errors in the other is
  a fork.
- **DT-4** Are version-gated behaviours keyed on the on-chain version or capability, with the
  activation boundary tested on both sides (one block before, at, and after)?
- **DT-5** Do special-case exemptions (special accounts, system contracts, masterchain-only
  paths) waive exactly the same components in every implementation?
- **DT-6** Is the build free of host-specific instruction sets or flags (`-march=native` and
  the like) for binaries that run on other hosts?
- **DT-7** Can contract-controlled input reach undefined behaviour in native code (signed
  overflow, shifts of negative values, unnormalised big integers, misaligned or uninitialised
  reads, invalid downcasts)? Does the code pass the test suite under address and
  undefined-behaviour sanitizers?
- **DT-8** When a version gate changes a protocol constant or list (reserved accounts, limits,
  exempt addresses), is every independent copy of that constant updated, with a test that
  compares the copies?

## 4. Resource bounds and unmetered work

Applies to every path that accepts work from a peer, a client or a contract: networking,
admission queues, caches, indexers, RPC, VM execution, storage.

For every C/C++ change, both the author and reviewer must answer
[the memory and resource growth review](../AGENTS.md#review-every-c-change-for-memory-and-resource-growth).
Keep its per-state answers and bound-test or RSS-soak evidence in the pull request. Review
the delta against the base and, for a port, the upstream bounds; review the questions below
alongside that required inventory.

- **RB-1** For each input source, what is the worst-case memory, CPU, disk and file
  descriptor cost of one message, and of the maximum concurrent number of them? Is that
  bound enforced *before* the resource is allocated (before buffering a body, decoding a
  payload, creating a per-source entry)?
- **RB-2** Is every queue, map, cache and buffer bounded by count *and* by bytes, and is the
  byte accounting the real retained size (allocator slabs, capacity, shared backing buffers)
  rather than the logical length?
- **RB-3** Are shared budgets allocated per source so that a few identities or one peer
  cannot consume the budget meant for all? Are untrusted and authenticated sources routed
  through different limiters?
- **RB-4** Do per-connection limits multiply into an acceptable aggregate (connections ×
  streams × buffer)? Is the aggregate stated and tested?
- **RB-5** Does every wait have a deadline, and does a deadline option have an upper bound so
  that configuration cannot disable it?
- **RB-6** Is any work done on behalf of an unauthenticated or unverified sender before
  verification (signature checks, decoding, VM execution, database lookups)? Is work that is
  not paid for by gas or fees bounded and measured, including work around execution
  (account loading, state init, storage phase, proof construction)?
- **RB-7** Does an optional or diagnostic feature (indexer, metrics, health instrumentation)
  add cost on the block-application or consensus path, even when disabled? Is it off the
  critical path and bounded when enabled?
- **RB-8** Do caps fail safe? When a cap is hit, is the input refused with a clear error,
  rather than silently dropped, permanently omitted, or marked as delivered?
- **RB-9** Do limits admit every valid input? Is the largest legitimate object (state piece,
  proof, block, message) measured and below the limit with margin?
- **RB-10** Disk growth: what is the growth rate of every directory the change writes, under
  load, and what deletes it? Is deletion guaranteed before the disk fills on the smallest
  supported host, including before the first event that normally triggers cleanup?
- **RB-11** Is there a full scan, full materialisation or quadratic loop over data that grows
  with chain history, peers or users (per block, per request, per key)?
- **RB-12** Are entries evicted on every exit path (error, timeout, cancellation), and are
  evicted entries reclaimable (no LRU entry that can never expire)?
- **RB-13** Has the resource claim been measured on the production hardware class, with the
  method recorded, rather than assumed from the code?
- **RB-14** Is every new or changed VM instruction or precompiled operation charged gas in
  proportion to its worst-case CPU and memory cost, benchmarked across its argument range?
  Can any opcode make cost grow faster than the gas charged?
- **RB-15** Are hash tables keyed by peer-controlled data protected against collision
  flooding (keyed or randomised hashing, bounded buckets)?
- **RB-16** Does any per-validator or per-peer structure scale with a quantity an attacker can
  inflate cheaply (registering many validators, opening many identities)?

## 5. Concurrency, actors, cancellation and shutdown

Applies to actor code, thread pools, async tasks, callbacks and shutdown paths.

- **CC-1** Is every completion delivered on a context that can receive it (for example a
  message posted from a plain worker thread into an actor scheduler)? Can a completion be
  silently dropped so that a waiter never wakes?
- **CC-2** After cancellation, can any path still start new work, resolve a promise twice,
  or assert on a cancelled result?
- **CC-3** Can a late completion arrive after its owner has moved on (stream closed, drain
  started, session rotated), and is it ignored safely?
- **CC-4** Are release, reclamation and reuse of shared resources serialised (no
  check-then-act race between a release and a reclamation check)?
- **CC-5** Shutdown: are tasks signalled before waiting on them, do all waits share one
  deadline, and are timeouts and errors during shutdown reported rather than reported as a
  clean drain?
- **CC-6** Are references held by timers and background cleanup protected so that cleanup
  cannot invalidate live entries?

## 6. State persistence, crash consistency and recovery

Applies to databases, journals, archives, state import/export, snapshots, and any operator
tool that writes node data.

- **PS-1** For every multi-step write, what is on disk if the process dies between any two
  steps? Is there a test that kills or stops the process at each cut point and checks the
  restart?
- **PS-2** Are writes durable before they are acted on (flush and fsync before a vote,
  broadcast, deletion, or acknowledgement), and are write and flush errors checked?
- **PS-3** No rollback after signing: can any recovery, restore, copy or reinitialisation
  path make a node reuse an earlier consensus or signing state after it has already signed
  later? Is the interlock durable across reboot?
- **PS-4** Is persistent identity or vote state (consensus databases, signing journals,
  session state) never copied, restored or shared between nodes?
- **PS-5** Is data imported from outside (snapshots, archives, dumps, remote downloads)
  verified under an explicit trust model before it reaches the live database, and imported
  into a staging location first? Are chain-derived roots checked where the protocol provides
  them, and any delegated trust in a publisher stated rather than described as trustless?
- **PS-6** Restart: does the node rebuild from the earliest state it still needs (not the
  newest local tip), with bounded retries on transient unavailability and a fail-closed exit
  on permanent loss?
- **PS-7** Does deletion run only after the thing that replaces it is durable (tombstones
  persisted before deleting, counts only of successful removals)?
- **PS-8** Are keys, indexes and records bound to the identity they belong to (session,
  shard, generation), so that a stale or foreign record cannot be loaded as current?
- **PS-9** Are schema or layout migrations ordered correctly (indexes created after
  migrations that change the rows they cover), and are partial migrations recoverable?
- **PS-10** Does a node that has fallen far behind still have a recovery path within the
  state and archive retention of its peers?
- **PS-11** Are every file and directory in the node's data root inventoried by any tool
  that copies or resets node data, with each one classed as copy, regenerate or never-copy?

## 7. Cryptography, signatures, domain separation and key custody

Applies to consensus signatures, wallet and contract signature checks, key management,
vaults, and every signed message format.

- **CK-1** Does every signed message carry a domain separator that binds it to its purpose,
  the network (global id), the contract or account, the session or epoch, and the protocol
  version? Could the same bytes be valid in another context?
- **CK-2** Is the signing preimage derived only from canonical chain state, identically by
  the signer and by every verifier, including an independent verifier that only has the
  chain? Is no local or runtime-only value mixed into it?
- **CK-3** Is the signer's authority checked against the right key type? Can a weaker or
  classical key change, replace or bypass a post-quantum key or policy?
- **CK-4** Are public keys validated on admission (weak, small-order, malformed,
  wrong-length, wrong-suite keys refused) in every contract, library and tool that accepts
  one?
- **CK-5** Stateful or one-time signature schemes: is the state (next leaf, counter)
  durable, never reused after restore or migration, and is exhaustion handled?
- **CK-6** Replay: is each signed action bound to a nonce, sequence or expiry, and does the
  replay record survive every lifecycle event (storage-fee freeze and deletion, redeploy of
  the same initial state, upgrade)?
- **CK-7** Key custody: are secret keys kept out of process arguments, environment dumps,
  logs, evidence files and published payloads? Are key files and backups created with
  restrictive permissions, through non-predictable paths, without following symlinks?
- **CK-8** Is the key that controls stake or funds separate from the hot key on the
  validator host, and is that separation enforced by the tooling rather than by convention?
- **CK-9** Key rotation: is a rotation staged across the validator-set transition so that no
  node needs the old and new key at the wrong time?
- **CK-10** Is every hash or proof that is checked computed over the exact bytes that the
  chain commits to (the actual configuration cell, the actual block identifier from a
  verified source), not over a re-serialisation or an unauthenticated RPC answer?
- **CK-11** Does the change claim a security property (post-quantum resistance, certified
  profile, completed ceremony) that the code or evidence does not support?
- **CK-12** For proof systems: does the challenge (Fiat–Shamir) hash include every public
  input and every proof component? Is any verification parameter (verifying key, setup
  output) from a trusted, recorded ceremony rather than a default?
- **CK-13** Is the signing component isolated so that compromise or exhaustion of another
  component cannot extract keys or make the signer sign arbitrary data?
- **CK-14** Do new cryptographic primitives follow the standard they name (encoding, bit
  order, error handling, edge cases), or document every divergence?

## 8. Input parsing and serialization

Applies to cells and BOC, TL schemas, network frames, RPC bodies, configuration files,
command lines and any decoder of untrusted bytes.

- **PA-1** Are size, depth, cell count, reference count and nesting bounded before decoding,
  and are the bounds pinned by a test with the exact limit and limit+1?
- **PA-2** Is every encoding canonical? Is a second encoding of the same value (non-minimal
  integers, alternative dictionary labels, padding, optional fields present but empty)
  refused wherever a hash, signature or deduplication key depends on the bytes?
- **PA-3** Does every decoder of untrusted data return an error instead of panicking,
  aborting or asserting? Is it fuzzed?
  Is there no `unwrap`, `expect`, unchecked index or assertion on a value derived from peer
  input?
- **PA-4** Do the encoder and every decoder of a format (contract, node, Rust tooling,
  SDK, off-chain service) agree on field order, widths and signedness? Is there a round-trip
  test across the implementations?
- **PA-5** Are type confusions refused (string where an integer is expected, unknown enum
  values, extra fields)?
- **PA-6** Are shard, workchain and address coordinates preserved exactly through every
  conversion?
- **PA-7** Does the admission of code or data to the chain enforce every invariant that a
  later consumer assumes (alignment, bounds, jump targets, library availability), so that the
  consumer never has to trust it?
- **PA-8** Is data read back with exactly the type and width it was written with, and are
  integers that must be non-negative typed as unsigned?

## 9. Smart contracts

Applies to FunC and other contract sources, their compiled artifacts, and the tests and
tooling that deploy them.

- **SC-1 Solvency invariant.** Is there a stated invariant such as `balance ≥ obligations +
  reserved fees + reserve`, and does every path that sends value preserve it *after* all
  fees of that transaction (compute, storage, forward, action) are paid, not against a
  pre-fee balance snapshot?
- **SC-2 Fees and the action phase.** Does the contract account for forwarding fees
  (including state init and payload walk), storage fees and the cost of each outgoing
  message before it accepts the message? Can the action phase fail after the compute phase
  succeeded, and what state is then committed?
- **SC-3 Send modes.** Is every send mode chosen deliberately? Is "ignore errors" never used
  on a payment whose failure must be noticed? Is "carry all balance" or "carry remaining
  value" used only where the accounting allows it? Are reserved flag bits refused?
- **SC-4 Bounce and asynchronous failure.** For every outgoing message whose receiver can
  reject it, is there a bounce handler that restores the sender's books, and is a
  multi-hop flow recoverable from a failure at each hop? Is there no state that can remain
  pending forever?
  Does the bounce handler work from the truncated body a bounce actually carries?
- **SC-5 Replay and accept ordering.** Is the signature, sequence and expiry checked, and the
  operation fully parsed and validated, *before* `accept_message` or raising the gas limit?
  Can a malformed but signed message be replayed to drain fees?
- **SC-6 Arithmetic.** Are all amount computations range-checked (no silent overflow,
  underflow or truncation into a narrower field)? Are sums over participants checked?
- **SC-7 Access control.** Is every privileged operation restricted to the right sender,
  and is the sender authenticated by address and code, not by a field in the message body?
  Can an unauthenticated message impersonate a trusted contract's receipt?
- **SC-8 Binding of terms.** When a caller acts on quoted terms (price, attestor, deadline,
  recipient), are those terms bound into the call so that the counterparty cannot change
  them in between?
- **SC-9 Bounded gas.** Are loops and data structures bounded (number of entries cleaned
  per transaction, chain walks, participant lists), and is the worst-case gas measured at
  the maximum size and at the oldest realistic storage age, not on a fresh deployment?
- **SC-10 Liveness of funds.** Can funds become permanently locked (quota deadlock,
  unreclaimable records, dispute without timeout, surplus that no path can withdraw)? Does
  every state have a timeout or exit?
- **SC-11 Time boundaries.** Are deadlines half-open and consistent between the contract and
  every client precheck?
- **SC-12 Unreachable guards.** Can each `throw` condition actually be triggered by a test?
  Does the compiler keep every check (for example calls whose result is unused must be
  declared impure)?
- **SC-13 Layout and getters.** Do getters, constructors and off-chain encoders match the
  current storage layout and ABI?
- **SC-14 Frozen artifacts.** Is the compiled artifact regenerated from the reviewed source,
  is its hash updated everywhere it is pinned, and does the test suite execute that artifact
  rather than a stale one?
- **SC-15 Configuration over time.** Does the contract keep working if fee, storage or
  forwarding prices change after deployment (margins, reserves, refusal rather than
  stranding)?
- **SC-16 Real execution.** Is the behaviour tested in a sandbox with real compute, action
  and storage phases and real bounces, not only by compute-phase unit tests?
- **SC-17 Asynchronous assumptions.** Does any handler rely on a condition checked earlier in
  the same message cascade that may no longer hold when this message arrives (concurrent
  chains, partial execution of a multi-message flow)?
- **SC-18 Notification senders.** Is every incoming notification of value (token transfer,
  refund, receipt) accepted only from the stored expected sender address?
- **SC-19 Results and exit codes.** Are success flags of dictionary and storage operations
  checked, and are exit codes distinct and outside the reserved range?
- **SC-20 Code updates.** Is the code-update path restricted to the right authority, and is
  the new code and data layout validated before it is set?
- **SC-21 Randomness.** Is on-chain randomness treated as predictable by block producers, with
  commit–reveal or equivalent for anything of value?
- **SC-22 Destruction and excess.** Is account destruction or full-balance transfer gated on
  an authenticated sender and a terminal state, and is excess value returned or withdrawable
  rather than accumulating?

## 10. Configuration, genesis and defaults

Applies to genesis generation, configuration parameters, default values in code, scripts,
templates and operator settings.

- **CF-1** Every layer that encodes a parameter: list each place the value lives (genesis
  template, config contract, node defaults, Rust tooling, test harness, deployment
  settings, documentation). Did the change update all of them, or derive them from one
  source?
- **CF-2** Is every default safe for production? Is any dangerous or test-only default
  (known test keys, fee-free special accounts, disabled limits, insecure listeners) refused
  outside an explicit test mode?
- **CF-3** Is a protection that the change relies on enabled by default and produced by
  genesis, rather than present only behind an opt-in flag?
- **CF-4** Does the parameter keep working when other configuration changes over time
  (validator-set rotation, price votes, version upgrades)? Is anything bound to the whole
  configuration root or to a value that changes routinely?
- **CF-5** Are parameter relationships consistent (election lead time versus term length,
  retention versus recovery needs, budgets versus the operations they fund, gas limits
  versus the most expensive legitimate transaction)? Are they derived rather than
  hard-coded, with a test that fails when one side moves?
- **CF-6** Are values that came from a different network, workchain or test template
  identified and justified?
- **CF-7** Are hashes, code identifiers and checksums pinned in scripts read from the release
  manifest rather than hard-coded?
- **CF-8** Are operator-tunable values validated and bounded (rates, intervals, timeouts,
  fractional state on change)?
- **CF-9** Is every new parameter documented with purpose, unit and valid range where
  operators and reviewers will look for it?

## 11. Upgrades and compatibility

Do not infer compatibility requirements from a pre-launch label: identify the running
deployment and its approved upgrade/reset procedure. Do not add compatibility shims for
retired formats; a change either supports a format fully or refuses it explicitly. Live
state and mixed-version operation require the checks below.

- **UG-1** Does the change remove retired code, formats and data paths outright, rather than
  keeping a compatibility layer?
- **UG-2** Where a live contract or node data must survive the change, is the old layout
  tested against the new code (deploy the previous artifact with its previous data, then
  upgrade)? Does code-in-place replacement decode live state correctly?
- **UG-3** Does new tooling refuse old contract instances and old data explicitly, rather
  than misdecoding them or producing signatures they will reject?
- **UG-4** Rolling upgrade: can old and new node versions run in the same network during the
  upgrade window (block production, validation, collation of future configurations)?
- **UG-5** Are version gates activated through the on-chain mechanism, and is the
  pre-activation behaviour unchanged byte for byte?
- **UG-6** Are external consumers (SDKs, wallets, explorers, other repositories) that pin
  code hashes, layouts or message formats updated or notified in the same change?
- **UG-7** Has a consensus-affecting change run on a test network, behind its version gate,
  before it is scheduled for production?

## 12. Networking and peers

Applies to transport, overlays, broadcast, DHT, peer management and proxies.

- **NW-1** Is a broadcast or relayed message verified before it is deduplicated, cached or
  relayed? Can an invalid message poison the dedup set for the valid one?
- **NW-2** Can a new or untrusted peer evict an established one, or occupy slots reserved for
  validators?
- **NW-3** Are listeners bound only to the interfaces the documentation promises?
- **NW-4** Are delivery and close semantics correct: no data truncated on close, no message
  marked delivered when it was evicted, reference counts changed only for active
  associations?
- **NW-5** Are reconnects, re-probes and capability detection retried after a peer changes,
  and torn down only for the matching connection generation?
- **NW-6** Are broadcast targets consistent with the receivers' roles?
- **NW-7** Are all transport paths (UDP, QUIC, TCP) covered by limits, firewall rules and
  fault-injection tests?

## 13. APIs, RPC and operator tooling

Applies to JSON-RPC, lite-server, HTTP endpoints, the operator CLI and services, and scripts.

- **AP-1** Argument parsing: are combined short options, attached values, negative numbers,
  relative paths and defaults handled, and can no option combination bypass a safety
  check?
- **AP-2** Error semantics: does every failure produce a non-zero exit status, a protocol
  error of the right class, and never a success response? Does the tool distinguish
  "rejected", "timed out", "unknown" and "succeeded"?
- **AP-3** Paths and privileges: are files opened through validated, pinned descriptors,
  without following attacker-controlled symlinks, without predictable temporary paths, and
  without running as root where not needed? Are paths derived from external keys or names
  sanitised against traversal? Does a root service execute only immutable, verified code?
- **AP-4** Authentication: is access control applied before the request body is buffered or
  parsed, are credentials never sent in plaintext, and are proxy and loopback hops handled
  explicitly?
- **AP-5** Do RPC and client-library answers that depend on chain state come with proofs that
  are checked on every path (including error paths, no blank result on error), and do readers
  fail over across nodes instead of trusting one?
- **AP-6** Batch and notification handling: are malformed batch elements answered with the
  correct error, and are limits applied to encoded size?
- **AP-7** Are long-running services restartable after a fatal error (exit status that the
  supervisor understands) and do they release locks that operator commands need?
- **AP-8** Every changed public function: are all callers updated, are argument orders and
  arities correct, and is there a test that exercises the real call (for example a real HTTP
  request) rather than a mock?

## 14. Value-moving tooling and off-chain settlement

Applies to any client, script, service or SDK that builds, signs, sends or confirms a
transaction that moves value (operator wallets, election and staking tasks, funding,
refunds, relayers, SDK send paths).

- **VM-1** Is each value-moving operation journaled durably before broadcast, so that a
  crash cannot cause a second signature or a second send?
- **VM-2** Does resubmission use the exact same signed bytes? Is any new signed attempt
  permitted only after the earlier attempt is proven terminal and accounted for, linked to
  that attempt, and explicitly requested under the journal lock with every gate rechecked?
  Can two attempts move the value twice?
- **VM-3** Is settlement confirmed by finding the specific transaction (by hash, on more
  than one independent source), decoding its outcome, and checking every phase — not by
  balance changes, sequence numbers or timeouts?
- **VM-4** Is a pre-broadcast balance check made against amount plus every fee the chain
  will actually charge, using the chain's own formulas?
- **VM-5** Is the destination verified (address derived or confirmed independently), and is
  the workchain and shard preserved exactly?
- **VM-6** Are all amount computations checked (no raw `+ - * /`, no saturating sums for
  money)?
- **VM-7** Do client prechecks mirror every refusal condition of the contract, and do they
  use chain time, not local time?
- **VM-8** Does the confirmation search scale with busy accounts and survive the node's
  state-retention window?
- **VM-9** Does the tool report "requested", "pending" and "settled" as distinct states to
  its user?

## 15. Observability and operability

- **OB-1** Is a stalled, lagging or degraded node visible at the default log level and in
  metrics, with how far it lags?
- **OB-2** Are logs retained long enough to diagnose a crash, rotated without losing the
  most recent data, and are rotation and pruning errors propagated?
- **OB-3** Are repeated errors rate-limited while the first non-routine failure is kept?
- **OB-4** Do health checks distinguish one node behind from the network stalled, and an
  unreachable host from a busy one?
- **OB-5** Is evidence (logs, core files) archived before a host is retired or reset?

## 16. Tests and evidence

- **TE-1** Does each new test fail when the change is reverted or the guarded line is
  removed? Is that red run recorded?
- **TE-2** Does each negative test fail for the specific reason claimed (the expected error
  code or refusal), not for any error?
- **TE-3** Are fixtures real (taken from the real caller, a real chain trace or a reference
  corpus), and do they exercise the production code path (the production response builder,
  the real bounce path, the real two-step receive) rather than a test double?
- **TE-4** Are measured numbers (gas, memory, latency, disk growth) measured on the reviewed
  commit, on the production hardware class, with the command and host recorded?
- **TE-5** Is the test deterministic (no single-sample races, no dependence on map order,
  platform allocator behaviour or scheduling)?
- **TE-6** Is the test registered with the test runner, built in every configuration that
  runs it, and triggered by CI for every path it depends on?
- **TE-7** Does each acceptance check verify the outcome on chain (the transaction exists,
  its phases succeeded, the value moved) rather than the tool's own report?
- **TE-8** For crash, restart and concurrency fixes: is there a test at each cut point or
  interleaving, including the one the fix targets?
- **TE-9** Do evidence files carry the commit, a reproducible command, and hashes that match
  the committed sources?
- **TE-10** Has a mutation of the fixed code been run to confirm the suite catches it?
- **TE-11** Are decoders and VM paths touched by the change covered by fuzz targets, and are
  fuzz corpora kept and re-run?
- **TE-12** For consensus, networking and recovery changes: has the change run in a
  multi-validator local network with real consensus, including stop, restart and partition?

## 17. Build, CI and release integrity

- **BC-1** Do the CI path filters include every source the changed tests and binaries
  depend on (schemas, templates, scripts, build files)?
- **BC-2** Does PR CI run the tests that cover the change, rather than only post-merge or
  scheduled jobs?
- **BC-3** Do release jobs publish exactly the artifacts built from the release commit, with
  pinned third-party actions and images, and runner selection not controlled by pull-request
  content?
- **BC-4** Is the compiled artifact checked for equivalence with its source in CI?
- **BC-5** Does the build work on every supported platform and configuration (feature flags
  off, library-only builds), and fail rather than silently skip?
- **BC-6** Do build scripts propagate errors and avoid host-specific tools?
- **BC-7** If the owner or a reviewer requested static analysis, does its receipt satisfy
  [the manual static-analysis rule](../AGENTS.md#static-analysis-is-run-manually), including
  proof that it analysed the change? Do not make that gate a prerequisite for every pull
  request.

## 18. Documentation drift

- **DC-1** Does every document, comment, changelog entry and help text touched by or
  describing the changed behaviour still match the code on this commit?
- **DC-2** Does the change claim a capability, completion, platform or performance that the
  code and evidence do not support?
- **DC-3** Are operator constraints introduced by the change written into the operator
  documentation (runbook steps, required order of operations)?
- **DC-4** Are numbers in documents (gas, sizes, rates) tied to the commit and method that
  measured them?

## 19. Repository hygiene

- **RH-1** Are comments, docs and commit messages free of external project names, issue
  tracker references and history narratives?
- **RH-2** Are personal paths, user names, host names and secrets absent from code,
  evidence and logs committed to the repository?
- **RH-3** Are bulk run logs and large archives kept out of Git, with only hashes and
  reproducible commands committed?
- **RH-4** Do scripts, harnesses and services clean up child processes, temporary files,
  locks and worktrees on every exit path, including interruption and timeout, and forward
  termination signals to their children?

---

## Author self-check before requesting review

Before asking for review, the author confirms each of these in the pull request description:

1. **Callers.** For every changed public function, type or message format, every caller and
   decoder was found (search, not memory) and updated; argument order, arity and defaults
   were checked at each call site.
2. **Order of operations.** For every changed sequence (validate → accept → act → persist →
   send), the order was checked against crash and failure at each step.
3. **The class, not the instance.** The same defect was searched for in every sibling code
   path (other contracts, other transports, other tools, the second implementation), and
   either fixed or listed.
4. **Every layer of a parameter.** Every place a changed value or format lives was updated.
5. **Upstream comparison.** One or two lines stating same / different / absent upstream and
   whether upstream has a fix.
6. **Red before green.** Each new test was seen to fail without the change.
7. **Stale documents.** Documents and comments describing the changed behaviour were found
   and updated.
8. **Current base.** The change was verified against the current main branch, not a stale
   checkout.
9. **Areas.** The checklist areas the change touches are listed, so the reviewer knows which
   sections to apply.
10. **Reviewable size.** Refactoring is in separate commits or pull requests from behaviour
    changes, and the change is small enough to review in one sitting.
11. **Measurements.** Performance- or resource-relevant changes carry before/after numbers
    from the production hardware class. Every C/C++ change also includes the per-state
    answers and bound-test or soak evidence required by
    [the memory and resource growth rule](../AGENTS.md#review-every-c-change-for-memory-and-resource-growth),
    or an explicit explanation that no state or resource lifetime changes.

## When a new bug is found

Every defect found after merge — in testing, on a network, by a scanner or by an external
reviewer — is classified against this checklist in the same change that fixes it:

1. **Classify.** Name the area and item that should have caught it.
2. **Record whether the item existed and was applied.** One of:
   - *existed and was applied, but the evidence was wrong* — sharpen the evidence the item
     demands;
   - *existed but was not applied* — record why (area not listed, item marked `n/a`, review
     skipped), and fix the process;
   - *did not exist* — add a new item, or sharpen an existing one, in the same change as the
     fix.
3. **Generalise.** Phrase the new or sharpened item as a question that would catch the whole
   class, without naming the incident.
4. **Search for siblings.** Apply the new item to the rest of the codebase and record the
   result.

The fix's pull request states the classification in one line, for example
`Checklist: RB-2 (existed, not applied: area not listed)`.

A defect that is exploitable on a running network is fixed under the security policy in
[SECURITY.md](../SECURITY.md) first; the checklist update follows in the same change once it is public.
