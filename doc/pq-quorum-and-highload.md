# Post-quantum quorum signatures and high-volume wallet: design

Status: design v4. Both deliverables are implemented and tested; reviews are recorded at
the end.
Two deliverables on one branch:

1. `pq-quorum-signatures`, a library:
   - FunC: `crypto/smartcont/pq-quorum-signatures.fc`;
   - Tol: `crypto/smartcont/tol-stdlib/pq-quorum-signatures.tol`.

   It gives strict M-of-N ML-DSA-44 authorization of a request, for long-lived committee
   authority such as bridge relayers and oracles.
2. `pq-highload-wallet-code.fc`, a deployable FunC wallet:
   - one ML-DSA-44 key;
   - any number of concurrent requests, with bounded replay protection;
   - one signature authorizes a batch of outbound messages.

The Ed25519 `quorum-signatures` library and `highload-wallet-v3-code.fc` stay as they
are, unchanged by this work. They keep working on chains below global version 16, and
they are not post-quantum.

## Constraints that shape everything

These come from `doc/tvm-mldsa44.md` and the C++ executor.

- **Version.** `PQCHECKSIG_MLDSA44` exists from global version 16 only, so both
  deliverables run only on a chain whose ConfigParam 8 names 16 or later. The canonical
  genesis now sets version 16 (`doc/validator-genesis-bootstrap.md`); a network
  configured below 16 cannot run them.
- **Operand sizes.**
  - signature: exactly 2420 bytes;
  - public key: exactly 1312 bytes;
  - message: 0..8192 bytes;
  - context: 0..255 bytes.
- **Operand shape.** Every operand is a canonical byte chain. A wrong length or encoding
  throws 9; an invalid signature returns 0.
- **Gas.** 50,000 per call before decoding, plus 1 per decoded byte, plus cell loads. One
  verification with a 32-byte message therefore costs on the order of 57,000 gas.
  - That exceeds the 10,000-gas external admission credit, so neither deliverable may
    verify before ACCEPT in an external message.
- **Gas limit of an internal message without ACCEPT.** It is the smaller of what the
  inbound value buys and what the account's balance buys, capped by the configured limit
  (`transaction.cpp` around the gas-limit computation). The basechain per-transaction
  limit in the fixture configuration is 1,000,000.

`crypto/smartcont/pq-bytes.fc` provides what both deliverables reuse:

- **Stored shapes.** `pq::stored_key` and `pq::stored_signature` handle the `len:uint32
  ^chain` shape:
  - they check the length and the canonical chain before any verification;
  - they refuse library and special cells;
  - the walk is bounded by the declared length.
- **`pq::key_id`.** It is the key's identity.
- **`pq::global_id`.**

## 1. `pq-quorum-signatures`

### API

It mirrors `quorum-signatures.fc`; the prefix is `pq_quorum::`.

| Function | Behaviour |
| --- | --- |
| `config(verifiers, quorum)` | Fully validates and returns `[verifiers, count, quorum]` (see Config validation). |
| `add_verifier(verifiers, stored_key)` | Validates the key, derives its id, and refuses a duplicate. |
| `with_verifiers(config, verifiers)` | Fully validates the new set against the current quorum. |
| `with_quorum(config, quorum)` | Keeps `1 ≤ quorum ≤ min(count, MAX_QUORUM)`. |
| `verifier?(config, key_id)` | Membership test. |
| `signing_hash(domain, target, nonce, valid_until, payload)` | The 256-bit commitment, same layout as the Ed25519 library: global id, domain, `addr_std` target, nonce, expiry, payload reference. |
| `require_not_expired(valid_until)` | Same as the Ed25519 library. |
| `require_quorum(config, hash, signatures)` | Verifies a request (see Verification rule). |

The caller keeps the responsibilities the Ed25519 library's header lists:

- use its own operation domain;
- build the commitment with the actual target contract's address;
- check expiry;
- consume the nonce in the same transaction as the verification.

### Data

- `verifiers`: `HashmapE 256`, key id → `^StoredKey`. The key id is
  `pq::key_id(mldsa44, StoredKey)`, the same identity consensus keys use (decision Q1).
- `signatures`: `HashmapE 256`, key id → `^StoredSignature`.

### Config validation

`config` and `with_verifiers` must not trust a dictionary built by the caller. For every
entry they check:

- the value is exactly one reference to a StoredKey, whose shape `pq::stored_key`
  accepts;
- the dictionary key equals `pq::key_id(mldsa44, StoredKey)`.

Otherwise one key K could be filed under two ids and satisfy a 2-of-2 alone.

They also check:

- `1 ≤ count ≤ MAX_VERIFIERS`;
- `1 ≤ quorum ≤ min(count, MAX_QUORUM)`.

Hashing every key costs gas in proportion to the set. That is paid when the
configuration changes, which is rare, never per request.

### Verification rule

- A request carries **exactly `quorum`** signatures (decision Q2). This changes the
  Ed25519 library's at-least-quorum behaviour. Requiring exactly quorum bounds the
  verifications a submitter can make the contract pay for.
- Order of checks:
  1. **Count.** Walk the signature dictionary, rejecting as soon as a `quorum + 1`th
     entry appears, so the walk is bounded. Reject a count below quorum.
  2. **Membership and wrapper.** For every entry, check its membership in the set, and
     check that its signature wrapper is exactly one reference to `len:uint32 ^chain` with
     `len = 2420`. These checks cost the same whatever the input.

     The chain is deliberately not walked here. `PQCHECKSIG_MLDSA44` itself refuses a
     non-canonical chain, a wrong length or a special cell, with cell underflow 9.
     Walking the chain beforehand only made a malformed request cheaper to refuse,
     saving gas its own submitter pays. The cost was about 20,000 gas per signature on
     every valid request: measured 86,000 gas per signature with the walk, 61,500
     without. Keys are walked once, when they enter a config, and taken as stored
     afterwards.
  3. **Verification.** Only then verify each signature.
- Any failure rejects the whole request.
- Message: the 32-byte commitment. Context: `"TOS-PQ-QUORUM-v1"`. Scheme: Pure
  ML-DSA-44.

### Limits

- **`MAX_QUORUM`: 12.** Measured on the C++ executor, a 12-of-64 `require_quorum`
  through a harness costs 745,000–747,000 gas (FunC and Tol). That leaves about 250,000 of
  the 1,000,000 limit for the calling contract.
  - Each further signature costs about 61,500 gas, so 13 would leave about 190,000.
  - The suite fails if 12 at a full set exceeds 850,000.
- **`MAX_VERIFIERS`.** The candidate is 64. Lookup cost depends on the dictionary's depth,
  so the measurement runs on a full set.

### Errors

- The range is 0x1b01–0x1b0f.
- The meanings follow the Ed25519 codes: invalid config, duplicate verifier, unknown
  signer, invalid signature, malformed signature, wrong signature count, invalid target,
  expired, key id mismatch.
- Shape errors from `pq-bytes.fc` (61–63) pass through.

## 2. `pq-highload-wallet-code.fc`

### Workchain

The wallet runs on workchain 0 only. `recv_internal` refuses any other `my_address()`
workchain. With the wallet and the relayer both on basechain:

- the refund's forwarding price is the basechain price;
- the state-size limits are the basechain ones.

### Entry and funding (the relayer model)

This follows `mldsa44-auth-module.fc`: verification is paid by whoever submits.

- **No external path.** The contract has no `recv_external`, so an external message finds no
  handler, and there is no ACCEPT anywhere. A `recv_external` that only threw would have
  been an untrippable guard: without ACCEPT an external message is never accepted
  anyway.
- **Submission.** A request arrives in an internal message from a relayer:

  ```
  submit#50514857 relayer_query_id:uint64 request:^Request signature:^StoredSignature
  ```

  - The relayer must be on workchain 0, so the refund's forwarding price is known in
    advance.
  - The relayer address and `relayer_query_id` are not signed. They only steer the
    refund of the relayer's own value.
- **Minimum value**, checked before verification. The message value must be at least
  `required_value(action_count)`, priced from the live configuration:
  - GETGASFEE for a measured compute upper bound (base plus per action, plus the replay
    dictionaries' worst case);
  - plus GETFORWARDFEE for the refund message, whose size is fixed.

  An underfunded request is refused before the expensive work and stays unused.
  Boundary tests separate a compute failure, a refund failure and success.
- **Refund.** It is best effort. The wallet builds it itself, as the first action:
  - destination: the sender;
  - mode 64 + 2, so it never fails the action phase;
  - value 0, carrying the inbound remainder;
  - non-bounceable;
  - body `excesses#d53276db relayer_query_id:uint64`.

  If the refund is skipped (+2), for instance because prices rose past the profile, the
  relayer's remainder stays in the wallet's balance. A later +128 sweep in the same batch
  can carry it to the signed destination. A relayer is not guaranteed a refund. It is
  guaranteed only that its value never pays for anything but its own transaction.
- **Bounce.** Relayers should submit bounceable messages. A failed non-bounceable
  submission leaves its remainder in the wallet, which costs only the relayer.

### Request

Every structure is consumed exactly: `submit`, `Request`, the stored signature, every
`OutList` node and its empty terminator, and every message body. `wallet` is a canonical
`addr_std` without anycast, compared bit for bit with `my_address()`. The signed message
is the request cell hash as 32 raw big-endian bytes.

```
Request = global_id:int32 wallet:MsgAddressInt subwallet_id:uint32 query_id:uint23
          created_at:uint64 timeout:uint22 actions:^OutList
```

- **Binding.** The request binds:
  - the network: `global_id` must equal GLOBALID;
  - the wallet instance: `wallet` must equal `my_address()`, including the workchain;
  - the subwallet and timeout: both must equal storage.
- **What is signed.** Pure ML-DSA-44 over the request's 32-byte cell hash, which covers
  the action list. The context is `"TOS-PQ-HIGHLOAD-v1"`.

### Order of work

No early COMMIT. The relayer pays for compute, so a compute failure has nothing to
protect; it rolls everything back and the request can be submitted again.

1. **Bounded parse and checks, cheap, before verification.**
   - The request: network, wallet, subwallet, timeout.
   - Replay: `replay_guard::check`, which covers freshness and the query id.
   - Every action, in full (see Batch). A malformed request is refused here, whole.
2. **Funding check.** The value must be at least `required_value(action_count)`.
3. **Verification.**
4. `replay_guard::record` and `save_data`.
5. **Queue the actions.** First the refund, then the batch messages in their signed order.
6. **Return normally.** The executor commits.

Failure classes:

| Where | Effect |
| --- | --- |
| Steps 1–3 | Contract data is not updated and no business message is sent. The query id stays unused. The relayer's remainder bounces only if the submission was bounceable and the remainder covers the bounce. |
| Step 5 runs out of gas | Rolls back to the state before the message: the id stays unused, nothing is sent. Step 2 makes this unreachable for a correctly funded request. |
| A batch message the action phase cannot deliver | Skipped (+2). The id is consumed and the other messages go out. |
| Refund | Mode +2, so a refund that cannot be paid is skipped rather than failing the action phase. |
| A message passes the action phase's total output limit (for example several messages sharing one large body) | That message alone is skipped (+2). The others go out and the id is consumed. Tested. |
| The whole action phase fails | New data and every queued message roll back; fees may still be charged. The id is unused and the request can be resubmitted. |

"The id is consumed and the messages go out" holds only when the whole action phase
succeeds.

For this wallet, under the default size limits, no input reaches a whole action-phase
failure:

- the refund and every batch message carry +2;
- the action list is built by the wallet itself;
- the largest state fits the basechain account limit of 65,536 cells. That state is two
  replay generations of 8,192 rows each, with their dictionary nodes, about 49,000 cells,
  plus an 11-cell key.

The table keeps the row because a configuration with smaller limits could reach it.

### Batch

`actions` is an `OutList` holding only `action_send_msg` (decision Q3), with at most
**254** entries: 255 action slots minus the refund. The 254 is provisional (decision Q4):
the measured profile must show that a full batch fits gas, message-size, total
output-size and cell-depth limits, or the ceiling is lowered.

Every entry is checked in step 1 and refused, whole request, unless all of these hold:

- the mode is built only from +1 (fees separately), +2 (ignore errors, forced anyway) and
  +128 (carry the balance, so an owner can sweep it): the allowed mask is `0x83`. That
  refuses:
  - +32, destroy if zero: a redeployed wallet would start with empty replay dictionaries;
  - +64, carry inbound value: the refund already took it;
  - +16, which the forced +2 makes meaningless;
  - +4 and +8, which the executor treats as invalid and would otherwise skip after the
    id was consumed;
- the message is a MessageRelaxed with `int_msg_info`, `src` = `addr_none`, not marked as
  bounced, and with no StateInit;
- an inline body or a referenced body is consumed exactly, as `highload-wallet-v3-code.fc`
  checks;
- no other action type appears;
- at least one action is present: an empty batch is refused.

254 is a limit on the number of actions. Gas, cell depth, per-message size and the
action phase's total output size apply separately. Several messages sharing one large
body are counted once per message by the total-output check, so even a short batch can
exceed it. The message that passes the limit is then skipped alone (+2), as the failure
table records.

Messages are re-emitted with `send_raw_message(message, mode | 2)` in the **signed order**.
An `OutList`'s head is its last action, so the wallet first collects the list, then emits
from the oldest entry.

### Storage and getters

- Storage:

  ```
  public_key:^StoredKey subwallet_id:uint32 old_queries:(HashmapE 13 ^Cell)
  queries:(HashmapE 13 ^Cell) last_clean_time:uint64 timeout:uint22
  ```

- Getters:
  - `get_key_id`, `get_subwallet_id`, `get_timeout`;
  - `processed?(query_id, need_clean)`;
  - `get_required_value(action_count)`;
  - `get_checked_config`, which applies the key-shape and positive-timeout checks to the
    stored state, for deployment tooling.

### Deployment

- The wallet runs only at global version 16 or later. A test shows that version 15
  refuses it; success at v16 does not show that a target chain is activated.
- `new-pq-highload-wallet.fif` builds the state and checks it with `get_checked_config`,
  run on the state itself; the getter needs only c4. The script prints the key id that
  check derives.

## Tests

ML-DSA tests run as Python suites on the real C++ executor at global version 16, in
`test/pq-contracts/`. They reuse:

- `test/auth-extensions/{cells,native}.py`;
- the TEST ONLY deterministic signer `test/mldsa-auth/signer.cpp`.

Every test asserts the final data, the action result, and whether the request can be
resubmitted, and checks outbound messages by destination, value and order. Emulator
success alone is not evidence.

- **Library**, through a harness contract compiled from FunC and from Tol, with identical
  vectors for both:
  - quorum met at exactly M; M − 1 and M + 1 refused, the latter before any
    verification;
  - an unknown key; a signature filed under another id;
  - a key filed under the wrong id, refused by `config`; one key under two ids;
  - a truncated signature, a non-canonical chain;
  - a wrong context or message;
  - the config invariants;
  - `MAX_QUORUM` verified within the gas limit at a full `MAX_VERIFIERS` set, with cold
    loads.
- **Wallet**, all as real transactions:
  - **batches:** a batch of 1 and of the ceiling; signed order kept (a payment, then a
    sweep);
  - **refunds and modes:** refund amount and order with batch modes 0, 1, 128 and 129;
    +64 and +32 refused;
  - **binding:** wrong wallet address (same network, both workchains), wrong network,
    wrong subwallet, wrong timeout;
  - **replay:** a replayed id; `created_at = now − timeout`; a future time; two
    generations of rotation; a query id whose low ten bits are 1023;
  - **signatures and funding:** a bad signature leaves the data unchanged; underfunding
    at the boundary, separating compute failure, refund failure and success;
  - **malformed requests:** a truncated header, a non-send action, a StateInit, a
    non-empty source; each refused whole before verification;
  - **undeliverable messages:** skipped, with the id consumed;
  - **entry and version:** external messages refused; v15 refused; a real StateInit
    deployment;
  - **worst cases:** sparse and dense replay dictionaries;
  - **profile:** measured against `get_required_value`, with
    `measured <= profile <= measured + 25%`.
- **Sensitivity.** A mutation script removes every guard in turn, and some test must fail.
  A guard no input can trip is removed rather than kept.
- **CI.** `.github/workflows/pq-contracts.yml`, modelled on `mldsa-auth-module.yml`, with
  no job time limit.

Not covered: special and library cells are refused by the verifier and by `pq-bytes.fc`'s
`XCTOS` parse, but the test codec cannot build an exotic cell, so no test sends one. The
mutation script names every guard it removes; a guard missing from that list is
untested by mutation.

## Review record

### Round 1, design v1 (`2c2cfacb7`)

Every finding was accepted.

- **High: the wallet request was not bound to the wallet address.** A request signed for
  one wallet ran on another with the same key, subwallet and timeout. The request now
  carries `wallet`, checked against `my_address()`.
- **High: batch mode +64 after the mode-64 refund.** The executor charges the compute fee
  against the message balance, which the refund has already zeroed, so the payment is
  reduced or skipped. Batch messages now refuse +64.
- **Medium: COMMIT does not protect against action-phase failure.** An early COMMIT could
  also consume the id while sending nothing. Early COMMIT is dropped and the work is
  reordered so that every compute failure rolls back completely.
- **Medium: the minimum value did not cover the refund's forwarding fee.** It now does,
  priced live, with the relayer restricted to workchain 0. The refund uses mode +2.
- **High (design gap): a caller-built verifier dictionary could file one key under two
  ids.** `config` and `with_verifiers` now check every id against the key's derived
  identity.
- **Low: overstated guarantees.** "A bad signature never touches the balance" and "always
  bounces" are corrected: storage fees still apply, and a bounce needs enough remaining
  value.
- **Also adopted:** keep the OutList order; the full v3 message checks; classify
  malformed requests (refused whole, before verification) apart from undeliverable
  messages (skipped); stop counting at quorum + 1; send-only batches; a provisional 254
  ceiling; replay-boundary, worst-state, v15 and deployment tests; and assertions on
  real-transaction outcomes.

### Round 2, design v2 (`088ad9c56`)

Conditional pass: the signed preimage, field order and contexts are frozen, and coding
may start. Every finding was accepted.

- **Medium: the failure table omitted whole action-phase failure.** That covers a state
  size or total output size over the limit, which rolls back data and messages. It is
  added, and "id consumed" is now conditional on the whole action phase succeeding.
- **Medium: a skipped refund leaves the relayer's remainder in the wallet.** The refund
  is now documented as best effort. The wallet is fixed to workchain 0, so its refund is
  priced at the basechain rate.
- **Low: the bounce promise.** It is conditional on a bounceable submission.
- **Low: 254 is an action-count limit only.** The other limits apply separately, and a
  shared-body test is planned.
- **Exact definitions added:** exact consumption, the address form, the 32 signed bytes,
  empty batches refused, and no reserved mode bits.
- **Untrusted config tuples.** A config tuple must come from validated, persisted state.
  This entry also claimed a fallback guarantee: that a key which skipped `config` could
  still authorize nothing. Round 3 showed the claim was false, and it was withdrawn.

### Implementation note, quorum library

Measurement changed one design point.

- **Signature chains are no longer walked before verification.** The walk cost about
  20,000 gas per signature on every valid request (86,000 against 61,500). The verifier
  refuses the same inputs itself.
- **Keys.** They are walked once, at configuration time.
- **`MAX_QUORUM = 12`.** Confirmed by measurement: 745,000–747,000 gas at a full
  64-verifier set.

### Round 3, quorum library code (`ab2cfd3d6`)

The reviewer accepted dropping the chain walk before verification: it found no input
the verifier accepts that the walk would have refused. Every other finding was accepted.

- **Medium: failed transactions were judged on a stale state.** The harness kept the
  account from before a failed transaction. Both suites now adopt the account the
  executor returns, whatever the outcome. A refusal must leave the data hash unchanged,
  and a success must complete both phases.
- **Medium: the claim that an unvalidated config "can still authorize nothing" was
  false.** The reviewer reproduced two counterexamples: an empty config with quorum 0
  passed, and one key under two ids made 2-of-2.
  - The claim is replaced by an explicit trusted-config precondition.
  - `require_quorum` now repeats the cheap range checks, so quorum 0 is refused.
  - A test shows the precondition is real: a set stored without `config()` with one key
    under two ids passes, and `config()` refuses that set.
- **Medium: the mutation verdict counted broken runs as kills.** Each suite now writes a
  structured result. A mutant is killed only if:
  - the baseline passed before and passes again after the sources are restored;
  - tests ran;
  - an assertion failed, with no errors.

  The killing tests are named.
- **Medium: rotating a full set did not fit one approved transaction.** Configuring 64
  keys costs about 850,000 gas, and 12-of-64 about 746,000, so the two do not fit
  together. `with_added_verifier` and `with_removed_verifier` change one key for about
  13,000 gas. A 12-of-64 approval plus removing one key and adding another costs about
  769,000–773,000 gas in one transaction, and is tested.
- **Low: overstated coverage.** Added tests for `verifier?`, for malformed keys through
  both entry points, and for the unconfigured state. Added mutations for the target
  check, the request-time range check, the single-key changes and the Tol key-chain
  checks. Special cells are listed as not covered.
- **The 250,000 gas margin.** It is now an assertion: `gas_limit − gas ≥ 250,000` at
  12-of-64.

### Implementation notes, wallet

Measured on the C++ executor at commit afb2e27f9 (the suite's `--report` output), with both
replay generations dense and the id needing a new row:

| Measurement | Value |
| --- | --- |
| Base gas | 79,546 |
| Gas per action | 2,708 |
| Full 254-action batch | 767,378 gas |
| Profile | 87,600 base and 2,930 per action |
| Minimum value, 1 action | 0.0915 TOS |
| Minimum value, 254 actions | 0.8328 TOS |

The suite finds the minimum value by bisection on real transactions. One nanoton less is
refused, with the id unused. Exactly that much runs the whole batch and its refund.

A 255-action request is refused before verification, but only after 254 entries have
been checked, at about 492,000 gas the relayer pays. Counting first would add a walk to
every valid request.

60 mutants, 37 in the library and 23 in the wallet, are each killed by an assertion.

### Round 4, quorum fixes and the wallet (`976ef3ff2`)

The reviewer confirmed that round 3 is closed. It found no forged-signature, relayer-
tampering or replay path in the wallet. Every finding was accepted.

- **Medium: reserved mode bits were not refused.** Modes 4 and 8 passed, and the executor
  then skipped the payment after the id was consumed. Batch modes are now restricted to
  the mask `0x83` (+1, +2, +128), checked before verification. Tests cover modes 4, 8,
  16, 1+4 and 1+16+128, and three mutations cover the mask.
- **Medium: the CI paths missed the executor core.** Added `crypto/block/**`,
  `crypto/common/**` and the test configuration BoC.
- **Low: the deployment test's code-hash comparison could pose as mutation evidence.** It
  is now a separate consistency test, and mutations.py does not count it as a kill.
  - The wallet getters are now checked through real get-method calls on the TVM
    emulator.
  - `get_required_value` equals the threshold the bisection finds, for 1 and for 254
    actions.
- **Low: contradictions and overclaims in v4.**
  - The total-output case is described as a single skip.
  - The withdrawn config guarantee is marked as withdrawn.
  - "Skipped count" and library-cell coverage are no longer claimed.
  - The deployment script now runs `get_checked_config`. It needs only c4, because the
    workchain check moved to submission time.

### Round 5, final acceptance (`afb2e27f9`)

The reviewer accepted the code. All four round-4 findings are closed, and no new
blocking issue was found. In an independent rerun, both quorum suites and the wallet
suite passed 20 of 20 each. All 61 mutants were killed by assertions, and the baselines
passed before and after.

- **Low: stale gas figures.** The source comment and the measurement table still quoted
  an earlier build. They now give the values this suite reports at `afb2e27f9`: 2,708 gas
  per action, 767,378 gas for a full batch and about 492,000 gas to refuse 255 actions.
  The funding profile of 87,600 base and 2,930 per action still covers them.

Merging still requires this workflow to pass in CI. It runs only on pull requests, so
the local acceptance does not count as that gate.
