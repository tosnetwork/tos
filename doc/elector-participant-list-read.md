# Reading election participants and proposals for operator automation

- Opened: 2026-10-07. Status: **design for review — no code written.** Revision 2:
  the owner redirected the design from "harden the public RPC path" to "operator
  automation uses the node's authenticated control channel, not the public RPC".
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
`list_proposals` (no voters): ~2,270 gas per proposal; the node stops serializing
at 49 proposals.

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
3. **Read capacity must cover the protocol's own bounds** (256 participants; every
   proposal the config contract can hold).
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
documented limits.

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

engine.validator.configProposal
    hash:int256 expires:int critical:Bool param_id:int param_hash:int256
    vset_id:int256 voters:(vector int) weight_remaining:long
    rounds_remaining:int wins:int losses:int
    = engine.validator.ConfigProposal;
engine.validator.configProposals
    block:tosNode.blockIdExt proposals:(vector engine.validator.configProposal)
    = engine.validator.ConfigProposals;
engine.validator.getConfigProposals
    flags:# block:flags.0?tosNode.blockIdExt = engine.validator.ConfigProposals;
```

- Amounts are carried as canonical big-endian bytes (Coins can exceed 64 bits); the
  Rust side converts with checked arithmetic into its existing types and refuses
  explicitly what does not fit.
- `getConfigProposals` returns proposal metadata only (what `vote offer ls`/`cast`
  use), not parameter values, so its size is independent of proposal payloads.
- Without `flags.0` the query reads the latest masterchain state the node has applied;
  the answer always names the block it was computed at.

### 5.2 Node implementation (`validator-engine/validator-engine.cpp`)

- Permission: `vep_default` (read-only), like `getStats`.
- Resolve the masterchain state (requested or latest) through the validator manager,
  as `getShardOutQueueSize` does; read the elector / config contract account from it.
- Run the getter in process with `SmartContract::run_get_method` and the same VM
  context the lite server builds (config, libraries, previous blocks, `now`), but with
  a **control-query gas budget** (`kControlGetterGasLimit`, proposed 10,000,000: ~27×
  the elector's 256-member worst case and ~4,400 proposals; a named constant with the
  rationale beside it).
- Walk the result cons list **iteratively** in C++ into the flat TL vector; validate
  every field (exact tuple arities, integer ranges, strictly ascending ids, at most
  256 participants for the elector); any violation is a control-query error.
- Bound the reply to the control channel's frame (16 MiB, `adnl-ext-limits.h`); the
  elector's worst case is a few tens of KB.
- Run in the engine's existing control-query actor context; the getter is CPU-bound and
  bounded by the gas budget.

### 5.3 tosctl

- `ElectorWrapperImpl::elections_info` and the config-proposal reads used by
  `vote offer ls` / `cast` call the new control queries over `ControlClientAdnl`.
- `ElectionsInfo` / `Participant` / `ConfigProposal` keep their shape, so every
  consumer's output is unchanged.
- If the node does not know the query (pre-upgrade engine), fail with an explicit
  "upgrade the node" error; TOS is pre-launch, so no compatibility path is kept.
- The hardened public-RPC proposal path from #151 is no longer used by operator
  commands; it is either kept for callers without a control key or removed — a
  review question (§9).

### 5.4 Out of scope

- The explorer's public `/staking` endpoint and other public consumers keep the public
  path and its limits (76 participants / 49 proposals), documented; a paginated public
  query can be designed separately.
- A distinct JSON-RPC error code for result-serialization failures; the node's silent
  `"stack":[]` on result-parse failure (`json-rpc-server-runmethod.cpp:642–660`).

## 6. Capacity after the change

| Read | Bound |
| --- | --- |
| Election participants | the elector's own 256 cap; gas ≈ 369k ≪ 10M |
| Config proposals | ≈ 4,400 at 10M gas; metadata only |
| Reply size | ≪ 16 MiB control frame |

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

## 9. Questions for the reviewer

1. Is the control interface (authenticated, loopback, `vep_default`) the right
   boundary for these reads, and is `vep_default` the right permission?
2. Is 10,000,000 gas an appropriate budget for an authenticated control query, or
   should each query get its own budget derived from the contract's cap?
3. Should #151's hardened public proposal path stay for callers without a control key,
   or be removed now that operator commands no longer use it?
4. Is returning metadata only from `getConfigProposals` sufficient for `vote offer
   cast` (which today shows the parameter id and voter count)?
