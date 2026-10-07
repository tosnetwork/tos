# Reading election participants and proposals for operator automation

- Opened: 2026-10-07. Status: **design for review — no code written.** Revision 2:
  the owner redirected the design from "harden the public RPC path" to "operator
  automation uses the node's authenticated control channel, not the public RPC".
  Revision 3: amendments from the design pre-review (off-actor execution with
  admission, exact VM context, honest capacity, TL optional fields, account and
  routing behaviour).
- Repository: `tosnetwork/tos`, base `main` at `6da705c8a` (includes PR #151).
- Branch / PR: `fix/elector-participant-list`, draft PR #152.
- Also kept in the team notes (`memo/elector-participant-list/`).

## 1. Symptom

`tosctl`'s election automation cannot read the current election once more than 38
participants have registered a stake.

- The elections runner reads the elector getter `participant_list_extended` on every
  tick through the node's public JSON-RPC method `runGetMethodStd`
  (`tosctl/src/node-control/contracts/src/elector/elector_impl.rs` ~85).
- With 39 or more registrations the read fails (`recursion limit exceeded`).
  `runner.rs:373` propagates the error, so the **whole tick aborts**: the node neither
  stakes, nor confirms acceptance, nor recovers returned stakes.
- The same read backs stake confirmation in `config_wallet_cmd`, `vote participants`
  and `vote cast`.

Registering a stake is permissionless. The elector admits up to 256 participants
(`pq_participant_limit = 256`, `elector-code.fc:235`; registration 257 refused at
`:536`; `conduct_elections` throws above 256 at `:1370`). Anyone can push the count
past 38 with minimum-stake registrations and stop every operator's automation for
that election. Only the number of *elected* validators is capped at 21 (`:1277`).

The same class of defect affects `vote offer ls` / `vote offer cast`
(`list_proposals`), which PR #151 moved to a hardened public-RPC path: the node stops
serving that getter at 49 proposals (§3.3).

## 2. Measurements

Real elector in the sandbox, rendered exactly as the node renders it; a native probe
linked to the node's VM libraries; read-only captures from the local development
network.

| Participants | Getter gas | Served JSON bytes | JSON nesting depth | Today |
| ---: | ---: | ---: | ---: | --- |
| 0 | 2,503 | 763 | 6 | ok |
| 21 | 30,175 | 21,415 | 74 | ok |
| 38 | 53,594 | 38,211 | 125 | ok |
| 39 | 54,926 | 39,199 | 128 | **fails** (client) |
| 77 | — | — | — | **node refuses** (serialization) |
| 214 | > 300,000 | — | — | **node refuses** (exit 13) |
| 256 | 368,795 | 254,122 | 779 | — |

Gas grows by about 1.33k and depth by exactly 3 per participant.
`list_proposals` (no voters): ~2,270 gas per proposal.

**Serialization budget accounting (measured, reproducible — Appendix A).** The lite
server serializes the result stack under a 1,000-operation budget (§3.3). Measured with
an instrumented `VmStateInterface` around the exact production calls
(`Stack::serialize`, `finalize_to`, `std_boc_serialize`): the stack root costs 1, every
scalar or null 1, and **every tuple 2** (the tuple itself plus one more operation per
tuple). Hence:

| Getter result | Operations | Largest that fits in 1,000 |
| --- | --- | --- |
| `participant_list_extended`, N participants | 13N + 8 (three tuples per entry) | N = 76 (77 → 1,009) |
| `list_proposals`, P proposals, V voter entries in total | 20P + 3V + 2 | P = 49 with no voters (50 → 1,002); P = 12 with 21 voters each |

`std_boc_serialize` adds no operations. With the budget raised to 10^9 the same probe
serializes 300 participants and 300 proposals, so the budget — not cell depth — is the
binding limit. An earlier source-only estimate (10N + 8) counted a tuple as one
operation and is superseded by these measurements.

## 3. Root cause

**Internal automation is built on an interface designed for the public.**
`runGetMethodStd` is the node's public query surface. Every limit we hit exists to
protect the node from anonymous callers, and none of them is a property of the data.

### 3.1 The answer is a linked list, rendered as nested JSON

`participant_list_extended` builds its result with `cons`
(`elector-code.fc:1667–1683`). The JSON-RPC renderer
(`validator-engine/json-rpc-server-runmethod.cpp`, `serialize_stack_entry_std`) emits
each cons cell as a two-element tuple, so a list of *n* entries becomes JSON nested
about 3·*n* levels deep.

### 3.2 Public-surface limit 1 — the client's JSON recursion limit (38)

`tosctl` parses with `serde_json` (recursion limit 128). Raising it is unsafe on a
public surface: a deep response from any endpoint could overflow the reader's stack.

### 3.3 Public-surface limit 2 — result serialization (76 participants, 49 proposals)

The lite server serializes a getter's result under `vm::FakeVmStateLimits
fstate(1000)` (`validator/impl/liteserver.cpp:1556`); larger stacks fail with
`cannot serialize resulting stack` (`:1580`, `:1587`), returned as HTTP 500 with a
generic `-32603` envelope.

### 3.4 Public-surface limit 3 — getter gas (≈ 212 participants)

`client_method_gas_limit = 300000` (`validator/impl/liteserver.hpp:83`) bounds every
anonymous getter call. The elector's own 256-member cap needs ≈ 369k.

## 4. Solution from first principles

### 4.1 What must be true

1. **The operator's automation talks to its own node.** It does not need, and should
   not inherit, limits whose purpose is to defend that node against strangers.
2. **The contract is the authority on its own data layout.** Run the contract's getter;
   do not re-implement its storage format in the client.
3. **Read capacity must cover the protocol's bound where one exists**, and state its
   limit honestly where none does: the elector caps participants at 256; the config
   contract has no proposal-count bound, so proposal reads are bounded all-or-nothing
   with explicit limits, and incremental reads remain future work.
4. **A list read is all or nothing**; a partial list never reaches a staking decision.
5. **Bounded cost even for an authenticated caller**: a bug in a client must not make
   the node do unbounded work.

### 4.2 Consequence

Add read-only queries to the validator engine's **control interface** — the
authenticated ADNL channel `tosctl` already uses for its node (`ControlClientAdnl`;
e.g. `getPqConsensusKeys`, `getStats`). The node runs the contract's getter in process
against its own masterchain state, with a budget sized for the protocol rather than
for anonymous traffic, and returns a **flat** TL structure. No JSON, no nesting, no
public serialization limit, no client-side stack-safety machinery, no stored-state
decoder.

The public RPC path stays as it is for the public (explorers, wallets), with its
documented limits. Operator workflows never fall back to it.

## 5. Design

### 5.1 New control queries (TL, `tl/generate/scheme/tos_api.tl`)

```
engine.validator.electionParticipant
    id:int256 stake:bytes max_factor:int adnl:int256 algorithm:int key_id:int256
    = engine.validator.ElectionParticipant;
engine.validator.electionParticipants
    block:tosNode.blockIdExt elect_at:int elect_close:int
    min_stake:bytes total_stake:bytes failed:Bool finished:Bool
    participants:(vector engine.validator.electionParticipant)
    = engine.validator.ElectionParticipants;
engine.validator.getElectionParticipants
    flags:# block:flags.0?tosNode.blockIdExt = engine.validator.ElectionParticipants;

engine.validator.configProposalMeta
    flags:# hash:int256 expires:int critical:Bool param_id:int
    param_hash:flags.0?int256 has_value:Bool
    vset_id:int256 voters:(vector int) weight_remaining:long
    rounds_remaining:int wins:int losses:int
    = engine.validator.ConfigProposalMeta;
engine.validator.configProposals
    block:tosNode.blockIdExt proposals:(vector engine.validator.configProposalMeta)
    = engine.validator.ConfigProposals;
engine.validator.getConfigProposals
    flags:# block:flags.0?tosNode.blockIdExt = engine.validator.ConfigProposals;

engine.validator.configProposalDetail
    flags:# block:tosNode.blockIdExt meta:flags.0?engine.validator.configProposalMeta
    value:flags.1?bytes
    = engine.validator.ConfigProposalDetail;
engine.validator.getConfigProposal
    flags:# block:flags.0?tosNode.blockIdExt hash:int256
    = engine.validator.ConfigProposalDetail;
```

`getConfigProposal` runs the config contract's `get_proposal`: `flags.0` absent means
no such proposal; when present, `value` (`flags.1`) is the proposed parameter cell as
a BOC exactly when `meta.has_value` is true, bounded by the reply bound. A full
`ConfigProposal` is built only from this detailed answer, never from metadata with the
value missing.

- Amounts are canonical big-endian unsigned bytes: zero is the empty string, no
  leading zero byte, at most 15 bytes — Coins is `VarUInteger 16`, whose length is
  less than 16, so the maximum is 2^120 − 1 (`crypto/block/block.tlb:116`,
  `tosctl/src/block/src/types.rs:855–864`); 2^120 − 1 is accepted and 2^120
  refused, tested separately from the Rust side's `u64` boundary; the Rust side converts with
  checked arithmetic and refuses explicitly what does not fit its existing types.
- TL `int` fields that carry times or ranges are interpreted as unsigned 32-bit and
  range-checked; unknown `flags` bits are refused.
- `param_hash` is optional (`flags.0`), so an absent hash is distinct from a
  legitimate all-ones hash; `has_value` says whether the proposal carries a value
  (absence means deletion to existing consumers). The metadata type is distinct from
  the existing `ConfigProposal`, whose `param.cell = None` means deletion — metadata
  must never be mapped into that type with the value dropped.
- `getConfigProposals` returns proposal metadata only (what `vote offer ls`/`cast`
  use), not parameter values, so its size is independent of proposal payloads.
- Without `flags.0` the query reads the latest masterchain state the node has applied;
  with it, the full block identity (root and file hash, not only seqno) must match a
  masterchain block whose state the node holds, else an explicit error. All reads of
  one query use one coherent applied snapshot, and the answer names that block.

### 5.2 Node implementation (`validator-engine/`)

- **Authorization first**: `vep_default` (read-only), checked before any state lookup,
  admission or allocation; unauthorized and insufficient-permission callers are tested.
- **Off the engine actor**: control callbacks are dispatched to the `ValidatorEngine`
  actor (`validator-engine.cpp:2962–2965`); a getter must not run there. A dedicated
  bounded executor runs getters: at most two active jobs and a small bounded queue,
  excess requests answered `busy`; admission is taken before retaining state or
  allocating results; workers receive an immutable snapshot; cancellation never
  releases admission while work continues; the result list is walked and destroyed
  iteratively; no VM state is persisted and returned actions are never executed.
- **Exact VM context**: reuse or extract the lite server's context construction
  (`liteserver.cpp:1416–1464`, `:1521–1547`) rather than `SmartContract` convenience
  defaults: the snapshot's global version, block time and logical time; full balance
  including extra currencies (set in c7 exactly — `Args::set_balance` takes `uint64`,
  so it is not used); address, code and data; config, previous-block information and
  version-dependent c7 fields; global and account libraries with the same rules; due
  payment and precompiled-contract context; signature checking enabled; randomness
  seeded by the same policy. Parity tests share the seed.
- **Named budgets**: `kElectorParticipantsGasLimit`, derived from the measured
  256-member worst case (≈ 369k) plus stated headroom; `kConfigProposalsGasLimit`
  (10,000,000) as an explicit operational ceiling, not a capacity claim. Gas
  exhaustion is an explicit error; no partial result.
- **Result conversion**: walk the cons list iteratively into the flat TL vector,
  validating exact tuple arities, integer ranges, strictly ascending ids, and for the
  elector at most 256 participants with the getter's exclusive `2^256 − 1` sentinel
  reproduced; any violation is an explicit error.
- **Reply bound**: a named maximum reply size well below the 16 MiB control packet
  (`adnl-ext-limits.h:15–18`) leaving protocol overhead; vector, count and byte bounds
  are applied before building the reply.
- **Accounts**: missing or frozen account → explicit error, never an empty election;
  active elector with no open election → the canonical empty result; upgraded code →
  run its getter and refuse incompatible output explicitly; missing libraries or
  context → explicit error. Account and state roots are unchanged after every
  execution, successful or not.
- **Exposure**: the control channel is authenticated but not inherently loopback-only
  (control ports carry no address restriction, `validator-engine.cpp:2980–2981`);
  deployment keeps it on loopback, as the production runbook requires.

### 5.3 tosctl

- `ElectorWrapperImpl::elections_info` and the config-proposal reads used by
  `vote offer ls` / `cast` call the new control queries over `ControlClientAdnl`.
- `ElectionsInfo` / `Participant` / `ConfigProposal` keep their shape, so every
  consumer's output is unchanged.
- If the node does not know the query (pre-upgrade engine), fail with an explicit
  "upgrade the node" error; TOS is pre-launch, so no compatibility path is kept.
- Every operator consumer is moved as listed in §5.5; operator commands never
  silently use the public path, and tests assert the public-RPC call count stays zero
  in each migrated workflow.
- The hardened public proposal path from #151 stays, explicitly separate, for public
  consumers; it is removed only after every remaining caller is inventoried and
  replaced.

### 5.4 One snapshot per election decision

Today three places read the election id and the participant list with two separate
getter calls and never check that both answers describe the same election:

| Pair of reads (on `main`) |
| --- |
| `elections/src/runner.rs:352` `get_active_election_id` then `:373` `elections_info` |
| `config_wallet_cmd.rs:492` then `:496` |
| `vote_cmd.rs:1748` then `:1761` |

`active_election_id` returns the stored `elect_at` even for a finished election
(`elector-code.fc:1617–1619`). Once the list moves to the control channel, the id would
come from one source and the list from another, so a public endpoint already showing a
new election E1 and a control node still on E0 (finished) would combine into a
snapshot that marks E1 finished with E0's participants, and the runner would skip E1.

Rule: each of these decisions takes the working election id, status and participants
from **one** `getElectionParticipants` response (its `elect_at` has the same meaning
as `active_election_id`); the separate id read is removed. The response's block
identity is kept; any other election-sensitive read in the same decision
(`past_elections`, `compute_returned_stake`) is pinned to that block, and an answer
for any other block is refused and the decision retried on the next tick, before the
snapshot or acceptance state is updated. Regression cases: public E1 / control E0
finished, and the reverse ordering; plus a block mismatch on a pinned follow-up read.

### 5.5 Routing of every consumer

| Consumer (call site on `main`) | Today | After |
| --- | --- | --- |
| Elections runner tick (`elections/src/runner.rs:373`) | public `participant_list_extended` | `getElectionParticipants` |
| Stake confirmation (`config_wallet_cmd.rs:496`, `:711`) | public | `getElectionParticipants` |
| `vote participants` / `vote cast` (`vote_cmd.rs:1651`, `:1761`) | public | `getElectionParticipants` |
| `vote offer ls` (`vote_cmd.rs:942`) | #151 bounded public path | `getConfigProposals` (metadata) |
| `vote offer cast` target selection (`vote_cmd.rs:1146`) | #151 bounded public path | `getConfigProposals` (metadata) |
| `vote offer create` read-back of the expiry (`vote_cmd.rs:749`) | #151 bounded public path | `getConfigProposal` (expiry from `meta`) |
| `vote offer diff --hash` details (`vote_cmd.rs:1077`) | #151 bounded public path | `getConfigProposal` (with `value`) |
| Service voting task (`service/src/voting/voting_task.rs:150`) | #151 bounded public path | `getConfigProposals` (metadata) |
| Explorer `/staking` (`service/src/http/explorer_query_api.rs:479`) | public | **unchanged — public consumer**, limits documented |

The zero-public-RPC assertion covers every "After" row except the explorer. The
explorer is a public service without a control key; it keeps the public path and
the #151 machinery for proposals.

### 5.6 Out of scope

- The explorer's public `/staking` endpoint and other public consumers keep the public
  path and its limits, documented: participants 13N + 8 ≤ 1,000 (76), proposals
  20P + 3V + 2 ≤ 1,000 (49 with no voters, 12 with 21 voters each), plus the client's
  separate JSON recursion limit (38 participants on the generic path); a paginated public
  query can be designed separately.
- A distinct JSON-RPC error code for result-serialization failures; the node's silent
  `"stack":[]` on result-parse failure (`json-rpc-server-runmethod.cpp:642–660`).

## 6. Capacity after the change

| Read | Bound |
| --- | --- |
| Election participants | the elector's own 256 cap, under a budget derived from the measured worst case |
| Config proposals | bounded all-or-nothing under an explicit 10M-gas operational ceiling and the reply bound; supported capacity stated only after measuring adversarial dictionary shapes and populated voter lists; incremental reads remain future work |
| Reply size | a named bound below the 16 MiB control packet |

## 7. Verification plan

- **Native**: a test that builds a masterchain state with the real elector holding
  0, 1, 21, 76, 77, 212, 256 participants (and the config contract with 0, 49, 50,
  several hundred proposals) and runs the new control-query handler: exact field
  equality with the getter's own result; 256 succeeds; a malformed result stack is
  refused; the iterative walk survives the deepest list; gas-budget exhaustion is an
  explicit error.
- **TL / client**: round-trip tests of the new TL types; tosctl decoding with checked
  conversions (amount overflow per field refused).
- **Command level**: runner snapshot, stake confirmation, `vote participants`,
  `vote offer ls`/`cast` produce byte-identical output to today for lists today's code
  can read, and succeed at 100 and 256 participants.
- **Live**: the local development network (7 nodes, elections running) answers the new
  queries over each node's control channel, read-only; results equal the public
  getter's for the current (small) election.
- **Executor**: queue saturation (`busy`), cancellation (admission held until work
  ends), shutdown, and another control query completing while an expensive getter
  runs.
- **Boundaries**: maximum-depth member dictionaries; 256 and 257 entries; amount
  overflow per field; the exclusive hash-max sentinel; frozen, missing, upgraded and
  library-coded accounts; wrong root/file hash at the same height; unavailable
  historical state; gas exhaustion and reply-size limits with no partial result;
  account/state roots unchanged after success and failure.
- **Mutation testing** per the project's rules (isolated worktrees, run in parallel).
- Full local gate: native build (no target) incl. `-Werror`; `ctest`; `cargo test
  --workspace --no-run`; touched crates; fmt; clippy.

## 8. Alternatives rejected

| Alternative | Why not |
| --- | --- |
| Harden the public RPC path and fall back to decoding stored state (revision 1) | Builds operator automation on anti-DoS limits; needs a Rust copy of the contract's storage layout that drifts on upgrade; much more machinery |
| Raise the lite server's gas / serialization limits | Weakens the public surface for everyone to serve one internal consumer |
| Read raw account state over the control channel and decode in Rust | Duplicates the contract's layout in the client; the getter already defines it |
| Cap or paginate in the elector | Contract change; the 256 cap already exists |

## 9. Reviewer rulings (design pre-review, 2026-10-07)

1. Control interface: yes; `vep_default` is appropriate, with authorization checked
   before state lookup and admission.
2. Separate named budgets: the elector's from the 256-member measurement plus
   headroom; 10M for proposals only as an explicit operational ceiling, off-actor.
3. Keep #151's public path separate for public consumers; operator commands never use
   it; remove it only after every caller is replaced.
4. Metadata suffices for `vote offer cast` selection and display, not for full details
   or diff; preserve optional-hash and value-presence semantics.

## Appendix A. Reproducing the serialization measurements

- Source revision: `main` at `6da705c8a`; `crypto/vm` and `validator/impl/liteserver.cpp`
  are identical to the revision the probe was linked against.
- Probe: `doc/evidence/getter-serialization-budget/probe.cpp` builds the getters'
  exact result shapes (`participant_list_extended`: 7-entry stack, entries
  `[id, [stake, max_factor, id, adnl, algorithm_id, key_id]]` in cons cells;
  `list_proposals`: cons of `[phash, 9-tuple]` with voter cons lists), then runs the
  production sequence `Stack::serialize` → `finalize_to` → `std_boc_serialize` under
  (a) `FakeVmStateLimits(1000)` as the lite server does and (b) a counting
  `VmStateInterface`.
- Build and run (from a configured tos build directory `build/`):
  see `doc/evidence/getter-serialization-budget/README.md`.
- Output: participants fit up to 76 (77 → 1,009 operations); proposals up to 49 with no
  voters (50 → 1,002), 12 with 21 voters each; with a 10^9 budget both reach the probe's
  300 cap.
- The implementation adds the equivalent as a committed native test through the
  production path (§7).
