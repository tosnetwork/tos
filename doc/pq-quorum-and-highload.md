# Post-quantum quorum signatures and high-volume wallet: design

Status: design v2, revised after review round 1 (recorded at the end), before any code.
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
are. They keep working on chains below global version 16, and their headers will say
they are not post-quantum.

## Constraints that shape everything

These come from `doc/tvm-mldsa44.md` and the C++ executor.

- **Version.** `PQCHECKSIG_MLDSA44` exists from global version 16 only. Genesis runs 14,
  so both deliverables run only on a chain whose ConfigParam 8 names 16. Activation is
  out of scope.
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
  2. **Shape.** For every entry, check its membership in the set and its signature's
     shape (`pq::stored_signature`). This is cheap.
  3. **Verification.** Only then verify each signature.
- Any failure rejects the whole request.
- Message: the 32-byte commitment. Context: `"TOS-PQ-QUORUM-v1"`. Scheme: Pure
  ML-DSA-44.

### Limits

- **`MAX_QUORUM`.** The candidate is 12. The final value is the largest quorum whose
  complete `require_quorum` fits the configured gas limit with room left for a calling
  contract. That room is not an estimate: it is measured, covering the stored-chain
  checks, the dictionary walk and lookups, and cold loads of every key and signature. A
  fixture checks the value against the configured gas limit.
- **`MAX_VERIFIERS`.** The candidate is 64. Lookup cost depends on the dictionary's depth,
  so the measurement runs on a full set.

### Errors

- The range is 0x1b01–0x1b0f.
- The meanings follow the Ed25519 codes: invalid config, duplicate verifier, unknown
  signer, invalid signature, malformed signature, wrong signature count, invalid target,
  expired, key id mismatch.
- Shape errors from `pq-bytes.fc` (61–63) pass through.

## 2. `pq-highload-wallet-code.fc`

### Entry and funding (the relayer model)

This follows `mldsa44-auth-module.fc`: verification is paid by whoever submits.

- **No external path.** `recv_external` always throws, and there is no ACCEPT anywhere.
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
- **Refund.** The wallet builds it itself, as the first action:
  - destination: the sender;
  - mode 64 + 2, so it never fails the action phase;
  - value 0, carrying the inbound remainder;
  - non-bounceable;
  - body `excesses#d53276db relayer_query_id:uint64`.

### Request

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
| Steps 1–3 | Nothing changes. The query id stays unused; the relayer's remainder bounces when it covers the bounce fee. |
| Step 5 runs out of gas | Rolls back to the state before the message: the id stays unused, nothing is sent. Step 2 makes this unreachable for a correctly funded request. |
| A batch message the action phase cannot deliver | Skipped (+2). The id is consumed and the other messages go out. |
| Refund | Mode +2, so it cannot fail the action phase. |

### Batch

`actions` is an `OutList` holding only `action_send_msg` (decision Q3), with at most
**254** entries: 255 action slots minus the refund. The 254 is provisional (decision Q4):
the measured profile must show that a full batch fits gas, message-size, total
output-size and cell-depth limits, or the ceiling is lowered.

Every entry is checked in step 1 and refused, whole request, unless all of these hold:

- the mode has neither +32 (destroy if zero; a redeployed wallet would start with empty
  replay dictionaries) nor +64 (carry inbound value; the refund already took it). Modes
  +128 and +1 are allowed, so an owner can sweep the balance;
- the message is a MessageRelaxed with `int_msg_info`, `src` = `addr_none`, not marked as
  bounced, and with no StateInit;
- an inline body or a referenced body is consumed exactly, as `highload-wallet-v3-code.fc`
  checks;
- no other action type appears.

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
- `new-pq-highload-wallet.fif` builds the state and checks it with `get_checked_config`.

## Tests

ML-DSA tests run as Python suites on the real C++ executor at global version 16, in
`test/pq-contracts/`. They reuse:

- `test/auth-extensions/{cells,native}.py`;
- the TEST ONLY deterministic signer `test/mldsa-auth/signer.cpp`.

Every test asserts the final data, every outbound amount, the action result, the skipped
count, and whether the request can be resubmitted. Emulator success alone is not
evidence.

- **Library**, through a harness contract compiled from FunC and from Tol, with identical
  vectors for both:
  - quorum met at exactly M; M − 1 and M + 1 refused, the latter before any
    verification;
  - an unknown key; a signature filed under another id;
  - a key filed under the wrong id, refused by `config`; one key under two ids;
  - a truncated signature, a non-canonical chain, a library cell;
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
- **CI.** A workflow modelled on `mldsa-auth-module.yml`, with no job time limit.

## Review record

### Round 1, design v1 (`31d982c2b`)

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
