# Reading the elector's participant list beyond 38 entries

- Opened: 2026-10-07. Status: **design for review — no code written.**
- Repository: `tosnetwork/tos`, base `main` at `6da705c8a` (includes PR #151).
- Planned branch: `fix/elector-participant-list`.
- Also kept in the team notes (`memo/elector-participant-list/`).
- Purpose of this document: describe the symptom, the root cause and a solution
  derived from first principles, so an independent reviewer can judge the design
  before implementation.

## 1. Symptom

`tosctl`'s election automation cannot read the current election once more than 38
participants have registered a stake.

- The elections runner reads the elector getter `participant_list_extended` on every
  tick (`tosctl/src/node-control/contracts/src/elector/elector_impl.rs` ~85,
  `elections_info`).
- With 39 or more registrations the read fails with
  `recursion limit exceeded` while parsing the JSON-RPC response.
- `runner.rs:373` propagates that error (`elections_info().await?`), so the **whole
  tick aborts**: the node neither stakes, nor confirms acceptance, nor recovers
  returned stakes.
- The same read backs stake confirmation in `config_wallet_cmd`, `vote participants`
  and `vote cast`, and the explorer's `/staking` endpoint; all fail the same way.

Who is affected: every operator running `tosctl` automation, at once. The chain and
the elector contract are unaffected; elections still conclude correctly on chain.

Why it matters: registering a stake is permissionless. The elector admits up to 256
participants (`pq_participant_limit = 256`, `elector-code.fc:235`; registration 257 is
refused at `:536`; `conduct_elections` throws above 256 at `:1370`). Anyone can push
the count from 21 to 39 with minimum-stake registrations and blind every operator's
automation for that election. Only the number of *elected* validators is capped at
21 (`n = min(n, max_validators)` at election end, `:1277`).

## 2. Measurements

Taken with the real elector contract in the sandbox, rendered exactly as the node
renders it, plus a native probe linked to the node's VM libraries and read-only
captures from the local development network.

| Participants | Getter gas (limit 300,000) | Served JSON bytes | JSON nesting depth | `tosctl` today |
| ---: | ---: | ---: | ---: | --- |
| 0 | 2,503 | 763 | 6 | ok |
| 21 | 30,175 | 21,415 | 74 | ok |
| 38 | 53,594 | 38,211 | 125 | ok |
| 39 | 54,926 | 39,199 | 128 | **fails** |
| 76 | 106,735 | 75,778 | 239 | fails |
| 77 | — | — | — | node refuses (see below) |
| 212 | 299,987 | 210,512 | 647 | fails |
| 214 | exit 13 (out of gas) | — | — | fails |
| 256 | exit 13 | (254,122 with ample gas) | 779 | fails |

- Gas grows by about 1.33k and nesting depth by exactly 3 per participant.
- The elector **account** (code + data) at 256 participants is about 140 KB in base64.
- Response size is never the binding limit.

## 3. Root cause

Three independent ceilings sit below the protocol's own cap of 256. The client hits
the lowest one first.

### 3.1 The answer is a linked list, rendered as nested JSON

The getter builds its result with `cons`, walking the member dictionary downward from
`2^256 − 1` (`elector-code.fc:1667–1683`):

```
(elect_at, elect_close, min_stake, total_stake, l, failed, finished)
l = [id, [stake, max_factor, id, adnl_addr, algorithm_id, key_id]] :: … :: nil
```

The node's JSON-RPC renderer (`validator-engine/json-rpc-server-runmethod.cpp`,
`serialize_stack_entry_std`) tests for a tuple before a list, so every cons cell is
emitted as a two-element `tvm.stackEntryTuple` `[head, tail]`, and `nil` as an empty
`tvm.stackEntryList`. A list of *n* entries therefore becomes JSON nested about 3·*n*
levels deep. The list's **length** turns into the document's **depth**.

### 3.2 Ceiling 1 — the client's recursive JSON parser (38 participants)

The generic `tosctl` read path parses with `serde_json`, whose default recursion limit
is 128. At 39 participants the document is 128 levels deep and parsing stops. Simply
raising the limit is not safe: `serde_json`, the `Value` tree, the stack-entry
conversion and dropping the tree are all recursive, so a deep enough response from any
endpoint can overflow the thread's stack and abort the process.

### 3.3 Ceiling 2 — the node's result serialization limit (76 participants)

The lite server serializes a getter's result stack under
`vm::FakeVmStateLimits fstate(1000)` (`validator/impl/liteserver.cpp:1556`). A larger
stack fails with `cannot serialize resulting stack` (`:1580`, `:1587`). The JSON-RPC server returns it as HTTP 500 with a generic `-32603` error
envelope, observed as
`{"ok":false,…,"error":"runSmcMethod: [Error : -400 : cannot serialize resulting stack]","code":-32603}`
(the `-400` is the lite server's default `fatal_error` code, carried through
`validator/manager.cpp`; the `runSmcMethod: ` prefix and `-32603` come from
`validator-engine/json-rpc-server*.cpp`). No client change can make
the node serve more than 76 participants through this getter.

### 3.4 Ceiling 3 — the node's getter gas limit (about 212 participants)

Getters run in the node's TVM under `client_method_gas_limit = 300000`
(`validator/impl/liteserver.hpp:83`). At about 213 participants the getter runs out of
gas (exit 13). This is a per-query computation budget protecting the node from
denial of service, not a fee.

### 3.5 The same defect class exists in the code merged with PR #151

PR #151 made `vote offer ls` read the config contract's `list_proposals` through a
bounded, stack-safe path with a stored-state fallback for "answer too large" and
exit 13. Its capacity evidence checked gas only. Measured with the same native probe,
the node's serialization limit stops `list_proposals` at **49 proposals** (no voters).
Above that the node returns an error envelope; #151 classifies error envelopes as an
endpoint fault, tries the next endpoint, and finally fails — the stored-state fallback
is never reached. Practical risk is low (49 simultaneous configuration proposals), but
the documented capacity is wrong.

## 4. Solution from first principles

### 4.1 What must be true

1. **The authoritative data is the elector account's state at a known block.** The
   getter is a convenience that renders part of that state; it is not the source of
   truth.
2. **A client's read capacity must not be below the protocol's own bound.** The
   contract admits 256 participants, so every component on the read path must handle
   256. Anything less is a denial-of-service lever.
3. **A list read is all or nothing.** A partial participant list must never reach a
   staking decision; a failure must be explicit.
4. **Untrusted input must not be able to crash the reader.** Any endpoint, honest or
   not, can send arbitrarily deep or malformed data; the reader's memory, stack and
   time must be bounded independently of what it receives.
5. **Prefer the node's interpretation when it is available.** Decoding contract
   storage ourselves duplicates the contract's layout and can drift after an upgrade;
   use it only when the getter cannot answer.

### 4.2 Consequences

- From (4): parse responses on a dedicated worker thread with an explicit stack, a
  byte cap and a depth preflight; convert and drop the tree iteratively; let only flat
  domain results cross back. PR #151 already built exactly this for proposals.
- From (2) and (3.3/3.4): the getter alone can never reach 256. The client therefore
  needs a second path for large states — reading the elector account at the same
  pinned block and decoding the member dictionary itself.
- From (5): use the getter whenever it answers; fall back to stored state only when
  the node signals that it *cannot* render the answer (serialization limit, gas
  exhaustion, or an oversized response), never on other errors.
- From (1) and (5): the stored-state decoder must reproduce the getter's semantics
  exactly (including its omission of the key `2^256 − 1`), must check the account's
  code hash against the supported elector before interpreting storage, and must be
  cross-checked field for field against the getter where both can answer.
- From (3): strict decoding everywhere — exact tuple arities, canonical decimal
  numbers, checked integer conversions, strictly ascending ids, the 256 bound — and
  any violation rejects the whole answer.

## 5. Proposed design

### 5.1 Share PR #151's bounded reader

Move the machinery from `contracts/src/config_contract/proposal_transport.rs` into a
read-agnostic module (`contracts/src/bounded_read/`), behaviour-neutral, as its own
commit: depth preflight, strict JSON with iterative drop, envelope and answered-block
checks, iterative stack conversion and dismantling, admission (one global pool of two
workers, permit taken before buffering), endpoint failover, checkpoint pinning.

Supported reads become a closed set:

```
enum BoundedRead   { Proposals(ProposalRead), Elections }
enum BoundedAnswer { Proposals(ProposalAnswer), Elections(ElectionsInfo) }
```

Each variant fixes its method and arguments, its own depth limit (elections:
3 · 256 + 64 = 832; proposals unchanged), its fallback triggers and its stored-state
decoder. The generic `get_method` path and every other getter are unchanged.

### 5.2 Fallback triggers

For a read of the participant list (and, fixing §3.5, for `list_proposals`), fall back
to the stored-state path when, at the pinned checkpoint:

1. the getter answered with exit 13; or
2. the node returned its result-serialization error — recognized **only** as a valid
   error envelope with the matching request id, the server's error code and the known
   `runSmcMethod` message form; near matches and other errors stay ordinary retryable
   failures; or
3. the response exceeded the transport byte limit with a successful HTTP status.

Endpoint policy: try every configured endpoint once first; fall back only if a
trigger was observed and no endpoint produced a terminal answer. The stored-state
read must still match the pinned checkpoint and the supported code hash. The error
text is treated as a signal to try a checked path, not as proof of a limit.
`get_proposal` keeps no fallback for this trigger.

Implementation note: because this error arrives with HTTP 500, and the current raw
read path keeps only the status category of a non-2xx answer and discards its body
(`RawAttempt::Failed` in `chain-rpc-client/src/v2/client_json_rpc.rs`), recognizing it
requires keeping a bounded copy of non-success bodies for classification on the worker
(never logged or quoted).

### 5.3 Strict participant decoder

- Exactly seven stack entries; `elect_at`/`elect_close` as `u32`; stakes as canonical
  decimals converted with checked `u64` (the Rust API's width — amounts the contract
  admits but `u64` cannot hold are refused explicitly); `failed`/`finished` exactly
  `-1` or `0`; no election ⇒ all fields zero and an empty list.
- The list may end only in an empty `tvm.stackEntryList`; each cell is a 2-tuple, each
  head a 2-tuple holding a 6-tuple; ids, ADNL addresses and key ids are canonical
  decimal `u256`; the inner id must equal the head id; ids strictly ascending; at most
  256 entries.
- `ElectionsInfo`/`Participant` stay unchanged, so every consumer's output is
  byte-identical for lists the old code could read.

### 5.4 Stored-state decoder

Mirror `unpack_elect` and `pq::unpack_member`: the account root including its own
optional recovery reference and the election's optional `failed_inputs`; exact
consumption of bits and references; members walked in ascending order; the getter's
omission of `2^256 − 1` reproduced; the 256 bound enforced on the underlying book
including the omitted key; refusal on an unsupported code hash.

### 5.5 Capacity after the change

| Participants | Path |
| --- | --- |
| 0–76 | getter |
| 77–~212 | node serialization error → stored state |
| ~213–256 | exit 13 → stored state |

The stored account stays far below the 1 MiB transport cap; beyond it the error names
both limits. Proposals gain the same serialization fallback above 49.

## 6. Verification plan

- Unit table of accepted and refused shapes (terminators, arities, number forms, id
  equality and order, the 256 bound, amount overflow per field, no-election record).
- Sandbox with the real elector for 0, 1, 21, 38, 39, 76, 77, 100, 212, 214 and 256
  participants: getter decode equals stored-state decode field for field; above the
  getter's limits the stored state equals a high-gas getter run.
- A native test in `crypto/test/vm.cpp` that exercises the **production** serialization
  path and limit (no copied constant): 76 participants serialize, 77 do not; 49/50 for
  proposals.
- Read-only captures from the local development network (empty election and a live
  election) committed as fixtures with block, hash and command.
- Command-level tests over HTTP: snapshot and `vote participants --format json` are
  byte-identical to the old decoder for ≤ 38 participants; 100 participants fail on the
  old path and succeed on the new; the runner tick no longer aborts.
- Failover tests reusing #151's harness, including a transient serialization error on
  one endpoint followed by a healthy answer, mixed error orders, wrong request id or
  code on the serialization error, and supported vs unsupported code hash under every
  trigger.
- Mutation testing per the project's rules; each mutant must turn its suite red.
- Full local gate: native build including `test-vm`; `cargo test --workspace --no-run`;
  the `contracts`, `elections`, `commands` and `service` suites; `fmt`; `clippy`.

## 7. Alternatives rejected

| Alternative | Why not |
| --- | --- |
| Raise `serde_json`'s limit on the generic path | Every getter's depth becomes unbounded and the reader can overflow its stack; still stops at 76 on the node |
| Read stored state only | Every elector upgrade would break all operators until a client release |
| Raise the lite server's 1000-operation limit, or render lists without nesting | A fleet-wide node upgrade that changes every getter; the gas ceiling would remain |
| Cap or paginate in the elector | A contract change; the 256 cap already exists |
| A separate worker pool for elections | Doubles the worker-memory reservation without a measured benefit |
| Tighten the shared `list_or_empty` helper in place | Other callers depend on it and have not been audited |

## 8. Scope and follow-ups

In scope: the participant-list read; the #151 proposal ceiling and the correction of
its capacity evidence; the shared reader module; the native serialization test.

Out of scope, recorded:
- Other elector getters (`past_elections`, etc.) keep the generic path; their limits
  are to be measured and recorded separately.
- A distinct JSON-RPC error code for result-serialization failures, so clients need
  not match message text.
- The node serves `"stack":[]` when result-stack parsing fails
  (`json-rpc-server-runmethod.cpp:642–660`); it should be an explicit error.

## 9. Questions for the reviewer

1. Is reading the elector's stored state (with a code-hash gate) an acceptable second
   source of truth for operator automation, or should the fix instead change the node
   so the getter can always answer?
2. Is a tightly matched error message an acceptable fallback trigger until the node
   emits a distinct error code?
3. Should the #151 proposal ceiling be fixed in this PR or separately?
4. Is the 256 participant bound the right capacity target, or should the reader be
   designed for a future increase of `pq_participant_limit`?
