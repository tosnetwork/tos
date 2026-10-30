# Post-quantum multisig account

## Status

Implementation proposal, built as the cold administrator account of the Treasury Vault (`doc/treasury-vault-v1.md`). Do not fund a deployment before the native tests, the mutation controls and an independent review have passed on the exact reviewed commit, and before `get_checked_config` has been run against the deployed data.

## Purpose

`crypto/smartcont/pq-multisig-code.fc` turns a quorum of ML-DSA-44 signatures over one request into either a batch of outgoing internal messages or a change of the account's own membership. It is a low-volume governance signer. It is not a payout engine, not a replacement for the high-volume wallet, and it holds no business logic of its own: what a target contract accepts from it is that contract's rule.

The account relies on the quorum library `crypto/smartcont/pq-quorum-signatures.fc` for the trusted verifier set, the signing hash and the M-of-N verification. It requires TVM global version 16 and workchain 0.

## Storage

```
verifiers:(HashmapE 256 ^StoredKey) count:uint8 quorum:uint8 seqno:uint64
```

The first three fields are the library's trusted config and are persisted exactly as the library produced them. The sequence number is consumed by every accepted request.

## Request

```
submit#504d5353 relayer_query_id:uint64 request:^Request signatures:(HashmapE 256 ^StoredSignature)
Request = kind:uint8 valid_until:uint32 payload:^Cell
```

Signers sign `pq_quorum::signing_hash(domain, account, seqno, valid_until, payload)` under the library's context `TOS-PQ-QUORUM-v1`. The domain is `0x504d5331` for `kind` 1 (execute) and `0x504d5332` for `kind` 2 (configure). The hash therefore binds the network global ID, the purpose, this account's address, one sequence number, an expiry and the complete payload: a signature cannot be replayed, moved to another account or re-purposed. The signature dictionary is keyed by signer key ID and must hold exactly `quorum` entries, each from a distinct member.

- **Execute.** `payload` is an OutList of `send_msg` actions: 1 to 16 sends, modes within +1/+2/+128, each message an `int_msg_info` with source `addr_none`, no extra currencies, no StateInit, extra flags within 3. Sends run in signed order with +2 forced.
- **Configure.** `payload` is `change:uint8` followed by `1 add stored_key:^Cell`, `2 remove key_id:uint256` or `3 quorum:uint8`. Changes are applied through the library's `with_added_verifier`, `with_removed_verifier` and `with_quorum`, so every invariant (at most 64 members, `0 < quorum <= min(count, 12)`, IDs matching keys, no duplicates, no set smaller than its quorum) is the library's. A change is authenticated by the quorum that held before it and takes effect immediately. A full replacement of the set is deliberately not offered: validating a large set does not fit beside a quorum verification in one transaction, so membership moves one key at a time.

Unknown kinds, unknown changes, malformed or trailing data, an expired request, an exhausted sequence number and a request without enough relayed value are refused before any signature is verified, and a refused request leaves storage unchanged.

## Funding

There is no external handler and no `ACCEPT`: a relayer delivers the request as an internal message from workchain 0 and its value pays compute. The remainder is refunded to the relayer first (mode 64+2), then the batch is sent. `get_required_value(kind, action_count)` quotes the minimum value; the quote's constants are measured by `test/treasury-vault/test_pq_cold.py`, which asserts that every accepted request, including a 12-of-64 request carrying sixteen sends, stays under its quote.

## What is and is not proven

Sends are best effort: a consumed sequence number proves that the quorum authorized the batch, not that every message was delivered or accepted. Operators confirm the effect on the target contract, for example that the vault now holds the expected pending request, before treating a governance step as done.

The account verifies signatures and membership. It does not know what the messages mean; the Treasury Vault applies its own typed checks, 48-hour delay and role rules to whatever the multisig sends it.

## Deployment

Build the initial data with a verifier dictionary keyed by each key's ID, the member count, the quorum and `seqno` 0. Before deriving the address or funding, run `get_checked_config` on that data: it re-derives the trusted config from storage and refuses a key filed under a wrong ID, a duplicate, an out-of-range quorum or a wrong stored count. Verify the deployed code hash and the member set, rehearse a request below and at threshold, then install the address as the vault's cold administrator. The vault's cold address is immutable, so the multisig's membership rotation is the only key rotation the cold role will ever have.

## Tests

`test/treasury-vault/test_pq_cold.py` executes the compiled account on the native action-phase emulator with the test-only ML-DSA-44 signer: threshold and membership enforcement before verification, request binding (expiry, sequence number, target, domain) and replay, malformed requests, the exact funding quote, the largest supported quorum, sequence-number exhaustion, deposits and bounces, membership rotation, and the vault's cold leg: scheduling, the vault's own delay, veto, pause, the absence of an administrator payment path, and a full post-quantum lifecycle with post-quantum business and guardian wallets. `test/treasury-vault/mutations.py` removes the quorum requirement, the sequence-number increment, the expiry check and the deployment check in turn and requires the targeted test to fail.
