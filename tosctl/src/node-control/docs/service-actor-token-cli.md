# Token-rail Service Actor CLI (`tosctl agent service-token`)

The commands for the token-rail Service Actor (`crypto/smartcont/service-actor-token-code.fc`,
release `tos-service-actor-token-v1`, rail `tos.service.service-actor-token.v1`). Every message
body is built by the Rust SDK `contracts::service_actor_token`; this CLI adds the state read, the
refusals and the message envelope.

## Commands

| Command | What it sends | Value attached (nanoTOS) |
|---|---|---|
| `call` | a token `transfer` of exactly `price_per_call` from the sender's token wallet to the actor, forward payload `token_call` | forward + bridge wallet transfer cost |
| `send --operation respond` | `respond` (signed when the request snapshotted an attestor) | 0.01 TOS |
| `send --operation expire` | `expire` | 0.01 TOS |
| `send --operation claim-refund` | `claim_refund` | 2 × `payout_funding` |
| `send --operation sweep-expired-request` | `sweep_expired_request` | 2 × `payout_funding` |
| `send --operation update-policy` | `update_policy` | 0.01 TOS |
| `send --operation rotate-attestor-key` | `rotate_attestor_key` | 0.01 TOS |
| `send --operation revoke-attestor` | `revoke_attestor` | 0.01 TOS |
| `send --operation withdraw-revenue` | `withdraw_revenue(token_amount, tos_amount)` | 2 × `payout_funding` with a token part, else 2 × `PAYOUT_GAS_ALLOWANCE` |
| `send --operation claim-returned` | `claim_returned` | 2 × `payout_funding` |
| `send --operation sweep-returned` | `sweep_returned` | 2 × `payout_funding` |
| `send --operation recover-surplus` | `recover_surplus` | 2 × (`PAYOUT_GAS_ALLOWANCE` + `payout_funding`) |
| `send --operation abandon-payout` | `abandon_payout` | 0.01 TOS |
| `send --operation recheck-payout` | `recheck_payout` | 2 × `PAYOUT_GAS_ALLOWANCE` |
| `top-up --target actor` | an empty body to the actor | `--amount-nanotos` |
| `top-up --target wallet` | an empty body to the actor's own token wallet | `--amount-nanotos` |

`show`, `request-show`, `payout-show` and `returned-show` read and print state; they send
nothing.

A funded value defaults to twice its minimum at the state read, so that a gas price rise before
execution does not leave it short; the actor returns what it does not use to the sender. An
explicit `--amount-nanotos` (or `--forward-tos-nanotos` for `call`) below the minimum is refused.

## The state read

Every command reads the last masterchain block the endpoint reports and binds every further read
to that block: each get-method, account and ConfigParam read must report the same seqno and root
hash, or the command fails. The actor's code must be the pinned release code (`--code-profile
release`, the default) or the test build (`--code-profile test`, test networks only).

The command refuses, before signing, every message the actor would refuse for a reason visible in
that state, and names the actor's exit code in the error. For `call` these are the reasons that
would end in a funding return or leave the tokens as surplus:

- the sender is not canonical on workchain 0 (1934);
- the actor is inactive (1901), or admits only another caller (1923);
- `--expected-terms-hash` differs from `get_terms_hash` (1926);
- ConfigParam 84 does not list the master with status 1 and the route's wallet code hash (1933);
- the token liability plus the price exceeds the lesser of `max_token_liability` and the record's
  `max_liability_per_actor` (1937);
- the sender's token balance is below the price;
- `get_accepting_tokens` is false (the SDK's `funding_transfer` refuses);
- the forward is below `storage_fee + min_funding_value` (the SDK's `funding_transfer` refuses).

`claim-refund` and `claim-returned` refuse a destination that is not a canonical `addr_std` on
workchain 0 without anycast, or that is the actor itself (1934), with the SDK's
`check_destination`.

Checks that depend on the time of execution (the response window, the sweep and recheck ages, a
balance query younger than its TTL) are left to the actor, which bounces the message and returns
its value.

## `--build-only`

`--build-only` signs nothing. It prints one JSON document, followed by a newline, on stdout:

```json
{
  "version": "tosctl.service-actor-token.prepared-message.v1",
  "operation": "claim-returned",
  "rail": "tos.service.service-actor-token.v1",
  "code_profile": "release",
  "actor": "0:<64 hex>",
  "read_at": { "seqno": 4242, "root_hash": "<64 hex>" },
  "sender": "0:<64 hex>",
  "destination": "0:<64 hex>",
  "value_nanotos": "2400000000",
  "bounce": true,
  "body_boc": "<standard base64>",
  "body_hash": "<64 hex>",
  "details": { "...": "..." }
}
```

- The fields appear in this order, pretty-printed with two-space indentation (`serde_json`'s
  pretty printer).
- `operation` is the `--operation` name, or `call`, `top-up-actor` or `top-up-wallet`.
- `destination` is the message's recipient: the actor for every `send` and `top-up --target
  actor`, the sender's token wallet for `call`, and the actor's own token wallet for `top-up
  --target wallet`.
- Addresses are in raw form, `<workchain>:<64 lowercase hex>`.
- Amounts are decimal strings, so that no amount loses precision in a JSON number.
- `bounce` is always `true`.
- `body_boc` is the body cell serialized as a single-root BOC by `chain_block::write_boc`, in
  standard base64 with padding. `body_hash` is the body cell's representation hash in lowercase
  hex; a reproduction that serializes BOCs differently compares `body_hash`.
- `details` holds the operation's own fields, sorted by key; every value is a string. For `call`
  it records the token amount, the forward and its minimum, the storage fee, `min_funding_value`,
  `accepting_tokens`, the query id, both hashes, the asset master and decimals, the sender's token
  wallet and, when it was priced from the bridge parameter, `wallet_transfer_cost`.

The document is a function of the arguments and the state read at `read_at`: the same arguments
at the same block give the same bytes. To send it:

```text
tosctl wallet send --from <wallet> --to <destination> --amount-nanotos <value_nanotos> \
  --body-boc <body_boc> --bounce [--build-only]
```

`--sender <address>` names the sending wallet for `--build-only` without a local wallet;
otherwise `--from` names a configured wallet, and without `--build-only` the command signs the same
message with it, prints the wallet message line and broadcasts it.

### The `call` value

The wallet message to the sender's token wallet carries `forward_tos_amount` plus the bridge
wallet's transfer cost, read from the asset's bridge ConfigParam (ConfigParam 84's
`source_chain_id` names it: 79, 81, 82 or 83): `2 × wallet_gas_consumption +
wallet_min_tos_for_storage + 2 × 0.05 TOS` for the forwardings. The excess returns to the sender
as the transfer's response destination. When the bridge parameter is absent at the block,
`--wallet-value-nanotos` must be given.

## Golden fixtures

`tosctl/src/node-control/commands/src/commands/nodectl/fixtures/service_actor_token/` holds, for
every operation, `<name>.inputs.json` (the getter values, the extra reads, the sender and the
arguments) and `<name>.out.json` (the exact bytes `--build-only` prints for them, final newline
included). The test `build_only_documents_equal_their_golden_fixtures` plans each case and
requires the output to equal the fixture byte for byte; `every_document_carries_the_sdk_body`
requires each body to be the SDK builder's output. A reimplementation reproduces a document from
its inputs file and compares it with the out file.
