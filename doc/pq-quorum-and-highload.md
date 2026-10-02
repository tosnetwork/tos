# Post-quantum quorum signatures and high-volume wallet: design

Status: design for review, before any code. Two deliverables on one branch:

1. `pq-quorum-signatures` — a library, FunC (`crypto/smartcont/pq-quorum-signatures.fc`)
   and Tol (`crypto/smartcont/tol-stdlib/pq-quorum-signatures.tol`): strict M-of-N
   ML-DSA-44 authorization of a request, for long-lived committee authority such as
   bridge relayers and oracles.
2. `pq-highload-wallet-code.fc` — a deployable FunC wallet: one ML-DSA-44 key, any
   number of concurrent requests with bounded replay protection, one signature per batch
   of outbound messages.

The Ed25519 `quorum-signatures` library and `highload-wallet-v3-code.fc` stay as they
are. They keep working on chains below global version 16; their headers will say they
are not post-quantum.

## Constraints that shape everything

From `doc/tvm-mldsa44.md`:

- `PQCHECKSIG_MLDSA44` exists from global version 16 only. Genesis runs 14, so both
  deliverables run only on a chain whose ConfigParam 8 names 16. Activation is out of
  scope.
- Operand sizes:
  - signature: exactly 2420 bytes;
  - public key: exactly 1312 bytes;
  - message: 0..8192 bytes;
  - context: 0..255 bytes.
- Every operand is a canonical byte chain: 127 bytes per non-final cell, one
  continuation. A wrong length or encoding throws 9; an invalid signature returns 0.
- Gas: 50,000 per call before decoding, plus 1 per decoded byte, plus cell loads. One
  verification with a 32-byte message therefore costs about 54,000 gas, plus about 3,100
  for loading roughly 31 cells.
  - This exceeds the 10,000-gas external admission credit, so neither deliverable may
    verify before ACCEPT in an external message.
  - The basechain per-transaction gas limit is 1,000,000. That bounds how many
    signatures one transaction can check.

`crypto/smartcont/pq-bytes.fc` already provides several things both deliverables reuse.

- The stored shape `len:uint32 ^chain` for a key (`pq::stored_key`) and for a signature
  (`pq::stored_signature`):
  - it checks the length and the canonical chain before any verification;
  - it refuses library or special cells, which the node itself cannot decode;
  - the walk is bounded by the declared length, not by the chain the sender attached.
- `pq::key_id`, SHA-256 over a domain, the algorithm and the key bytes.
- `pq::global_id` (GLOBALID).

## 1. `pq-quorum-signatures`

### API

It mirrors `quorum-signatures.fc`, so a contract can move from one to the other with
local changes. The prefix is `pq_quorum::`; the Tol names follow the same mapping as the
Ed25519 pair.

| Function | Behaviour |
| --- | --- |
| `config(verifiers, quorum)` | Validates and returns `[verifiers, count, quorum]`. |
| `add_verifier(verifiers, stored_key)` | Validates the key's stored shape, derives its key id, and refuses a duplicate. |
| `with_verifiers(config, verifiers)`, `with_quorum(config, quorum)` | Replacements that never leave `quorum > count`. |
| `verifier?(config, key_id)` | Membership test. |
| `signing_hash(domain, target, nonce, valid_until, payload)` | The 256-bit request commitment, identical in layout to the Ed25519 library: global id, domain, `addr_std` target, nonce, expiry, payload reference. |
| `require_not_expired(valid_until)` | Same as the Ed25519 library. |
| `require_quorum(config, hash, signatures)` | Verifies the request (see below). |

### Data

- `verifiers`: `HashmapE 256`, key id → `^StoredKey`.
- A key id is `pq::key_id(mldsa44, stored_key)`. Using the same identity as consensus keys
  lets tooling name a key once for every role. The domain string is the consensus one;
  see open question Q1.
- `signatures`: `HashmapE 256`, key id → `^StoredSignature`.

### Verification rule

- The request must carry **exactly `quorum`** signatures.
- Every one must:
  - be from a key in the set (the dictionary key makes signers distinct);
  - have a valid stored shape;
  - verify.
- Any failure rejects the whole request, as in the Ed25519 library.
- Requiring exactly `quorum` entries bounds the gas a request can make the contract spend
  to `quorum` verifications. Accepting extra entries would let a submitter raise the cost
  without adding authority.
- Order of checks, so that work is wasted as late as possible:
  1. the entry count;
  2. every entry's membership and shape, which is cheap;
  3. only then the verifications.
- The message passed to the verifier is the 32-byte commitment from `signing_hash`. The
  context is `"TOS-PQ-QUORUM-v1"`. The scheme is Pure ML-DSA-44, as in the auth module:
  no prehash mode.

### Limits

- `MAX_QUORUM` is the largest quorum whose verification fits the per-transaction gas
  limit with the caller's own work on top. It is about 1,000,000 / 57,000, so 17 at most.
  We propose **12**, which leaves about 300,000 gas for the calling contract. The exact
  figure comes from measurement (see Tests) and is checked against the configured gas
  limit by a fixture.
- `MAX_VERIFIERS` is **64**. Membership is a dictionary lookup, so the size of the set does
  not affect a request's gas. 64 keys at about 11 cells each are about 700 cells of
  state, which keeps the storage fee reasonable.

### Errors

- The range is 0x1b01–0x1b0f, unused today.
- The meanings mirror the Ed25519 codes: invalid config, duplicate verifier, unknown
  signer, invalid signature, malformed signature, insufficient signatures (the wrong
  count), invalid target, expired.
- A key whose shape `pq::stored_key` rejects surfaces as that library's code (61–63);
  this library does not remap it.

## 2. `pq-highload-wallet-code.fc`

### Entry and funding (the relayer model)

This follows the funding rules of `mldsa44-auth-module.fc` and `doc/mldsa44-auth-module.md`.

- `recv_external` always throws. No ACCEPT anywhere: verification is never paid from the
  wallet's balance or from a gas credit.
- A request arrives in a **bounceable internal message from any relayer**:

  ```
  submit#50514857 relayer_query_id:uint64 request:^Request signature:^StoredSignature
  ```

  - The relayer's message value buys the gas, because an internal message's gas limit is
    its value divided by the gas price.
  - A request with a bad signature fails in the compute phase and bounces the relayer's
    remainder back. The wallet's balance and state are untouched.
- **Minimum value before the expensive work.** Before verifying, the wallet requires the
  message value to be at least `required_value(action_count)`.
  - This is priced with GETGASFEE from a measured profile: base verification gas plus a
    per-action amount, like the existing fee profiles.
  - Without this check, a relayer could send a valid request with only enough value for
    verification. The transaction would run out of gas after the query id was committed
    but before the batch was sent, and the request would be lost.
  - With the check, an underfunded valid request is refused before verification and
    stays unused.
- **The relayer gets its remainder back.** The first action sends the inbound remainder
  back to the sender with mode 64. The batch actions follow, paid from the wallet's
  balance as the owner authorized.

### Request

```
Request = global_id:int32 subwallet_id:uint32 query_id:uint23 created_at:uint64
          timeout:uint22 actions:^OutList
```

- **Network binding.** `global_id` must equal GLOBALID. This fixes the cross-network
  replay noted in the Ed25519 wallet, whose requests are not network-bound.
- **Subwallet and timeout.** `subwallet_id` and `timeout` must equal storage, as in v3.
- **Replay.** `query_id` and `created_at` go through `replay-guard.fc`:
  1. `check` before verification;
  2. `record` after verification;
  3. then `save_data` and COMMIT, so a later failure cannot return the query id to
     circulation.
- **What is signed.** Pure ML-DSA-44 over the request's 32-byte cell hash, with the
  context `"TOS-PQ-HIGHLOAD-v1"`.

### Batch

`actions` is an action list, `OutList`, holding only `action_send_msg` entries, at most
**254**: the wallet's own refund action takes one of the action phase's 255 slots.

Each entry is re-emitted with `send_raw_message(message, mode | IGNORE_ERRORS)`:

- An undeliverable message is skipped, so the committed query id stands. This is the
  same rule as v3, and the reason the action-phase fixture exists.
- Mode +32 (destroy if zero) is refused, as in v3 since #124. A deleted wallet
  redeployed from its StateInit would start with empty replay dictionaries.
- Each message must be a MessageRelaxed with int_msg_info, as v3 checks, and must carry
  no StateInit.
- Any other action type in the list refuses the whole request.

### Storage and getters

- Storage:

  ```
  public_key:^StoredKey subwallet_id:uint32 old_queries:(HashmapE 13 ^Cell)
  queries:(HashmapE 13 ^Cell) last_clean_time:uint64 timeout:uint22
  ```

  The replay layout is unchanged from `replay-guard.fc`.
- Getters:
  - `get_key_id`, `get_subwallet_id`, `get_timeout`;
  - `processed?(query_id, need_clean)`, as in v3;
  - `get_required_value(action_count)`, the minimum value a relayer must attach.

### Deployment

The wallet runs only at global version 16 or later. The initial state is checked off-chain:

- key shape and identity through a getter;
- the timeout must be positive.

A `new-pq-highload-wallet.fif` script will build and check the state, like
`new-multisig-wallet.fif` does for the multisig.

## Tests

ML-DSA tests need signatures, so they run as Python suites on the real C++ executor at
global version 16. They reuse the existing infrastructure:

- `test/auth-extensions/{cells,native}.py`: a Cell codec and an emulator with a version
  argument;
- the TEST ONLY deterministic signer `test/mldsa-auth/signer.cpp`, built separately so
  that signing never enters the VM library.

The new suite lives in `test/pq-contracts/`.

- **Library**, through a small harness contract compiled once from the FunC library and
  once from the Tol library, with identical vectors for both:
  - quorum met at exactly M;
  - one fewer, and one more (both refused);
  - an unknown key;
  - a signature filed under another key id;
  - a truncated signature, a non-canonical chain, a library cell;
  - a wrong context or message;
  - the config invariants;
  - `MAX_QUORUM` verified within the gas limit, and `MAX_QUORUM + 1` refused before any
    verification.
- **Wallet**, all as real transactions:
  - a batch of 1 and of 254;
  - replay refused;
  - a bad signature leaves the wallet untouched and bounces to the relayer;
  - an underfunded valid request is refused before verification and can be resubmitted;
  - expired, wrong network, wrong subwallet, wrong timeout;
  - +32 refused, a non-send action refused, a malformed message skipped with the id
    consumed;
  - external messages refused;
  - the relayer refund amount;
  - the profile measured against `get_required_value`, with
    `measured <= profile <= measured + 25%`.
- **Sensitivity.** Every guard is removed in turn by a mutation script, and some test must
  fail. Following `CLAUDE.md`, a guard no input can trip is removed rather than kept.
- **CI.** A workflow modelled on `mldsa-auth-module.yml`, but with no job time limit: the
  result must come from the tests.

## Open questions for review

- **Q1.** Reuse the consensus key identity (`pq::key_id`, domain
  `"TOS-PQ-CONSENSUS-KEY-v1"`) for quorum verifiers, or define a quorum-specific domain?
  Reusing it gives one name per key across roles. A separate domain keeps roles
  unlinkable.
- **Q2.** Exactly-`quorum` signatures (proposed) or at-least-`quorum` with a cap? Exactly
  is simplest and bounds gas, but a submitter holding more than M signatures must choose
  which M to send.
- **Q3.** Should the wallet accept `action_reserve_currency` in a batch, so the owner can
  protect part of the balance from a mode-128 sweep, or only `action_send_msg`?
- **Q4.** Is a 254-message batch the right ceiling, given about 600 gas per re-emitted
  message on top of verification? The measured profile will tell, but the ceiling is a
  wire-visible rule.
