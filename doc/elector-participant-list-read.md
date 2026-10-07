# Reading election participants and proposals for operator automation

- Opened: 2026-10-07. Status: **design approved; implementation in progress.** Revision 2:
  the owner redirected the design from "harden the public RPC path" to "operator
  automation uses the node's authenticated control channel, not the public RPC".
  Revision 3: amendments from the design pre-review (off-actor execution with
  admission, exact VM context, honest capacity, TL optional fields, account and
  routing behaviour). Revision 4: the serialization measurements are corrected
  (revision 3's probe built every tuple wrapped in a one-element tuple, §2) and checked
  against the real getters; the elector reads one decision needs come from one control
  query (§5.1, §5.4). Revision 5: per-getter elector budgets from measurements of all three
  getters, the combined query's total cost and native-work limits, and the extended
  combined-response tests (§5.2, §6, §7). Revision 6: the participant budget is
  raised to cover the deepest member dictionary (1.11M gas at 256), and the
  aggregate guard gets a test of its own.
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
serving that getter above 62 unvoted proposals, and above 17 when each carries 21
votes (§3.3).

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
| 100 | — | — | — | **node refuses** (serialization) |
| 214 | > 300,000 | — | — | **node refuses** (exit 13) |
| 256 | 368,795 | 254,122 | 779 | — |

Gas grows by about 1.33k and depth by exactly 3 per participant.
`list_proposals` (no voters): ~2,270 gas per proposal. The gas column is the Rust
sandbox with real registrations; the node's C++ VM running the elector code saved from
the local network, with its member book re-filled by cloned members, measures 131,621
gas at 99 members and 345,395 at 256 with hashed (random-like) keys, and 1,114,595 at
256 when the member keys form the deepest path a 256-bit-key dictionary allows
(Appendix A). Budgets are derived from that worst shape.

**Serialization budget accounting (measured, reproducible — Appendix A).** The lite
server serializes the result stack under a 1,000-operation budget (§3.3). Measured with
an instrumented `VmStateInterface` around the exact production calls
(`Stack::serialize`, `finalize_to`, `std_boc_serialize`): the stack root costs 1 and
every entry 1 — a scalar, a null, or a tuple, whose elements are then counted in turn.
A participant is a cons cell holding `[id, [6 fields]]`: 1 + 1 + 1 + 7 = 10. Hence:

| Getter result | Operations | Largest that fits in 1,000 |
| --- | --- | --- |
| `participant_list_extended`, N participants | 10N + 8 | N = 99 (100 → 1,008) |
| `list_proposals`, P proposals, V voter entries in total | 16P + 2V + 2 | P = 62 with no voters (63 → 1,010); P = 17 with 21 voters each (18 → 1,046) |

`std_boc_serialize` adds no operations. With the budget raised to 10^9 the same
sequence serializes 300 participants and 300 proposals with 21 voters each, so the
budget — not cell depth — is the binding limit.

The formulas hold for the real getters, not only for stacks built to their
description: the elector's code and an open election saved from the local network
(its member book re-filled to N members), and the genesis configuration contract with
proposal sets written by the sandbox, executed and measured through the same
sequence; the emulated elector result equals the lite server's own answer for the
saved block (Appendix A).

**Correction.** Revision 3 reported 13N + 8 and 20P + 3V + 2 (76 participants, 49
proposals). Its probe built each tuple with `make_tuple_ref(std::move(vector))`, which
brace-initializes a one-element vector and so wraps the intended tuple in a second
tuple (`crypto/vm/stack.hpp:63–64`); every tuple therefore cost one extra operation.
The source-derived 10N + 8 that revision 3 claimed to supersede was right.

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

### 3.3 Public-surface limit 2 — result serialization (99 participants, 62 proposals)

The lite server serializes a getter's result under `vm::FakeVmStateLimits
fstate(1000)` (`validator/impl/liteserver.cpp:1556`); larger stacks fail with
`cannot serialize resulting stack` (`:1580`, `:1587`), returned as HTTP 500 with a
generic `-32603` envelope.

### 3.4 Public-surface limit 3 — getter gas (≈ 212 participants)

`client_method_gas_limit = 300000` (`validator/impl/liteserver.hpp:83`) bounds every
anonymous getter call. The elector's own 256-member cap needs ≈ 369k with random-like keys and about 1.11M on the deepest dictionary shape.

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
engine.validator.frozenStake
    id:int256 owner:int256 weight:long stake:bytes banned:Bool
    = engine.validator.FrozenStake;
engine.validator.pastElection
    election_id:int unfreeze_at:int stake_held:int vset_hash:int256
    total_stake:bytes bonuses:bytes frozen:(vector engine.validator.frozenStake)
    = engine.validator.PastElection;
engine.validator.returnedStake
    wallet:int256 amount:bytes = engine.validator.ReturnedStake;
engine.validator.electorState
    block:tosNode.blockIdExt elect_at:int elect_close:int
    min_stake:bytes total_stake:bytes failed:Bool finished:Bool
    participants:(vector engine.validator.electionParticipant)
    past_elections:(vector engine.validator.pastElection)
    returned:(vector engine.validator.returnedStake)
    = engine.validator.ElectorState;
engine.validator.getElectorState
    flags:# block:flags.0?tosNode.blockIdExt wallets:(vector int256)
    = engine.validator.ElectorState;

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

`getElectorState` runs, on one state, the elector getters an election decision needs:
`participant_list_extended` (the open election; `elect_at = 0` with no participants
when none is open, as the getter returns), `past_elections` (each election's frozen
dictionary flattened into `frozen`, keyed by the stable validator id; complaints are
not returned — no consumer reads them), and `compute_returned_stake` once per requested
wallet. `wallets` holds at most `kMaxReturnedStakeWallets = 16` distinct addresses,
refused otherwise (duplicates included); `returned` has exactly one entry per wallet,
in request order, carrying the requested address, zero when nothing is owed. `weight` is the elector's unsigned 64-bit weight carried in
a TL `long` and interpreted as unsigned.

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

The shared context foundation is `crypto/block/get-method-context.{h,cpp}`.
The lite server calls it for both execution c7 and exported c7, and uses its library
lookup policy. The caller supplies the random seed; the lite server retains its
secure-random policy. VM flags, signature checks and gas limits remain unchanged.
`test/validator/getter-context-reference.h` retains the original construction as
an independent oracle; parity covers every c7 field and actual library resolution.
`getter-context-liteserver` runs the real lite-server handler on a fixture state and
compares exit codes and full result BOCs with the pre-extraction capture. Gas parity
is checked by executing the original VM path because the wire reply has no gas field.

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
- **Named budgets**, one per getter, each from a measurement of that getter
  (Appendix A, `elector-budget-result.txt`; the C++ VM on the saved elector, grown
  along each dimension the getter walks):

  | Getter (per run) | What its cost depends on | Measured worst case | Budget |
  | --- | --- | --- | --- |
  | `participant_list_extended` | members (protocol cap 256) and the member dictionary's path length | 1,114,595 at 256 on the deepest path (345,395 C++ / 368,795 Rust sandbox with random-like keys); a maximum-width stake (2^120 − 1, the record's only variable-width field) costs the same | `kElectorParticipantsGasLimit = 1,500,000` |
  | `past_elections` | retained past elections K (≈ 0.9k each; independent of frozen entries, returned as a cell) | 15,953 at K = 16 | `kPastElectionsGasLimit = 50,000` |
  | `compute_returned_stake` | credits dictionary path length | 2,896 at 65,536 random credits; 26,804 on the deepest path 256-bit keys allow | `kReturnedStakeGasLimit = 40,000` per wallet |
  | `list_proposals` / `get_proposal` | proposals, voters | — | `kConfigProposalsGasLimit = 10,000,000`, an operational ceiling, not a capacity claim |

  Gas exhaustion in any run is an explicit error; no partial result. The budgets are
  provisional until the implementation measures the same worst cases (the deepest
  256-member book included) in the production VM context of §5.2; each must keep at
  least the headroom stated here (about 35 % for participants) or be revised before
  merge.
- **Combined cost of `getElectorState`**: at most 2 + `kMaxReturnedStakeWallets` = 18
  getter runs; aggregate VM gas at most 1,500,000 + 50,000 + 16 × 40,000 = 2,190,000
  (`kElectorStateGasLimit`), each run also held to its own budget. Native work is
  bounded separately: `kMaxPastElections = 16` (an **operational** limit — the elector
  retains past elections until their stakes are unfrozen, about two at the local
  network's ConfigParam 15; the contract imposes no cap), at most 256 frozen entries
  per election (frozen entries are written only for elected members taken from that
  election's book, `elector-code.fc:1342`, and the book is capped at 256), and
  `kMaxFrozenEntriesTotal = 4,096`. The frozen-dictionary walk counts entries as it
  goes and stops at the first entry beyond a limit, without visiting the rest
  (measured: 4,096 entries flatten in about 2 ms). Any budget or limit exceeded —
  including a later getter after earlier ones succeeded — rejects the whole response;
  the client receives an error and changes no state.
- **Immutable snapshot**: every getter run starts from the same original snapshot's
  code and data cells; a run's VM-private changes (its c4, c5) are discarded and never
  seen by the next run.
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

- The elector reads (`elections_info`, `past_elections`, `compute_returned_stake`,
  `get_active_election_id`) and the config-proposal reads used by `vote offer ls` /
  `cast` call the new control queries over `ControlClientAdnl`; an elector decision
  makes one `getElectorState` call and takes everything it needs from that answer.
- `ElectionsInfo` / `Participant` / `PastElections` / `FrozenParticipant` /
  `ConfigProposal` keep their shape, so every consumer's output is unchanged.
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

Rule: each of these decisions takes every elector fact it uses — the working election
id, status and participants, the past elections' frozen stakes, and the stake owed to
each of its wallets — from **one** `getElectorState` response (its `elect_at` has the
same meaning as `active_election_id`). The separate id read is removed, and the runner
tick's later `past_elections` and `compute_returned_stake` calls (`runner.rs:418`,
`:862`) are replaced by the same answer's `past_elections` and `returned`, so there is
no follow-up elector read to pin and none can reach the public RPC. Regression cases:
public E1 / control E0 finished and the reverse ordering, each now unable to arise; a
tick whose returned stake and frozen stake come from different elections is
impossible by construction, and a test asserts the tick makes exactly one elector
query.

Not covered by this rule, and unchanged: the tick's reads of the operator's own pool
and wallet balances (`calc_stake`, `recover_stake`) are account reads of other
contracts at whatever block answers them. Combining them with frozen stakes from the
elector snapshot can over-count a stake that was returned to the pool in between; the
consequence is a stake message the pool refuses for insufficient funds, retried on
the next tick. This is pre-existing and recorded as follow-up, not fixed here.

### 5.5 Routing of every consumer

| Consumer (call site on `main`) | Today | After |
| --- | --- | --- |
| Elections runner tick (`elections/src/runner.rs:373`) | public `active_election_id`, `participant_list_extended`, `past_elections`, `compute_returned_stake` | one `getElectorState` per tick |
| Stake confirmation (`config_wallet_cmd.rs:496`, `:711`) | public | `getElectorState` |
| `vote participants` / `vote cast` (`vote_cmd.rs:1651`, `:1761`) | public | `getElectorState` |
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
  path and its limits, documented: participants 10N + 8 ≤ 1,000 (99), proposals
  16P + 2V + 2 ≤ 1,000 (62 with no voters, 17 with 21 voters each), plus the client's
  separate JSON recursion limit (38 participants on the generic path); a paginated public
  query can be designed separately.
- A distinct JSON-RPC error code for result-serialization failures; the node's silent
  `"stack":[]` on result-parse failure (`json-rpc-server-runmethod.cpp:642–660`).

## 6. Capacity after the change

| Read | Bound |
| --- | --- |
| Election participants | the elector's own 256 cap, under a budget derived from the measured worst case |
| Past elections | **operational** limit of 16 retained elections and 4,096 frozen entries (the contract has no cap on retained elections); exceeding it is an explicit error, not a truncated list |
| Returned stakes | up to 16 wallets per query, each lookup within its own measured budget |
| Config proposals | bounded all-or-nothing under an explicit 10M-gas operational ceiling and the reply bound; supported capacity stated only after measuring adversarial dictionary shapes and populated voter lists; incremental reads remain future work |
| Reply size | a named bound below the 16 MiB control packet |

## 7. Verification plan

- **Native**: a test that builds a masterchain state with the real elector holding
  0, 1, 21, 99, 100, 212, 256 participants (and the config contract with 0, 62, 63,
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
  getters' (`participant_list_extended`, `past_elections`, `compute_returned_stake`)
  for the current (small) election at the same block.
- **One snapshot**: `getElectorState` answers with past elections and returned stakes
  from the same state as the participants (a state where an election unfreezes between
  two blocks shows each block's answer internally consistent); wallet-list bounds,
  duplicates and the empty list; the runner tick makes one elector query and no
  public-RPC elector read. Also:
  - no open election, with non-empty past elections and non-zero returned credits;
  - 16 past elections and 4,096 frozen entries accepted, 17 elections or 4,097 entries
    refused;
  - `returned` matches the request in count, order and address; a reply with a
    missing, extra, reordered or wrong-address entry is refused by tosctl;
  - a frozen entry whose validator id differs from its owner is carried with both;
  - weight `2^63` and `2^64 − 1` round-trip as unsigned;
  - the aggregate guard on its own: the aggregate ceiling equals the sum of the
    per-run ceilings, so it cannot trip while every run stays within its own budget.
    The test injects an aggregate limit below the sum, lets the participant and
    past-election runs succeed, and asserts that a returned-stake run within its own
    budget fails on the aggregate and rejects the whole response; a per-getter gas
    failure does not count as coverage of the aggregate guard;
  - the deepest 256-member book (member keys on one 256-level path) and a maximum
    stake succeed within `kElectorParticipantsGasLimit`;
  - every run starts from the original snapshot, shown by a test getter that rewrites
    its own c4 before a second run reads it.
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

- Source revision: `main` at `6da705c8a`.
- Evidence: `doc/evidence/getter-serialization-budget/` — `probe.cpp`, the sandbox
  exporter `export_list_proposals_states.rs`, the elector state saved from the local
  development network at an open election (`elector-snapshot/`, with the lite client's
  answer at that block), `result.txt`, and a README with build commands, input hashes
  and sensitivity results.
- The probe measures, through the production sequence `Stack::serialize` →
  `finalize_to` → `std_boc_serialize`, both synthetic stacks of the documented shapes
  (tuples built directly, arities asserted) and the real getters executed on real code
  and data: the saved elector (member book re-filled to 1–256 members) and the genesis
  configuration contract with 0–63 proposals, with and without values, and with 21
  voters each. Every case must match `10N + 8` / `16P + 2V + 2` and the synthetic
  stack; the emulated elector result for the saved state must equal the lite client's
  answer.
- Output: participants fit up to 99 (100 → 1,008 operations); proposals up to 62 with
  no voters (63 → 1,010), 17 with 21 voters each (18 → 1,046); with a 10^9 budget,
  300 participants and 300 voted proposals serialize.
- Sensitivity: reintroducing revision 3's one-element tuple wrapper, or changing one
  digit of the saved lite-client answer, makes the probe exit 1.
- Scope of this evidence: the probes run the getters with `tos::SmartContract`'s
  convenience context. That validates these getters' result shapes, serialization
  cost and gas on real code and data; it does not establish the exact production c7
  parity §5.2 requires of the implementation, which the implementation's own parity
  tests must show.
- Elector budgets: `elector-budget.cpp` grows the saved elector's member book (0–256),
  past elections (1–16, each with 21 or 256 frozen entries) and credits (0–65,536
  random, plus the deepest 256-level path) and records each getter's gas and the
  native frozen-dictionary walk (`elector-budget-result.txt`).
- The implementation adds the equivalent as a committed native test through the
  production path (§7).
