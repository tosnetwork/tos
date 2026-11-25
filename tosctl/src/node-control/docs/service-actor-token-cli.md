# Token-rail Service Actor CLI (`tosctl agent service-token`)

These are the commands for the token-rail Service Actor (`crypto/smartcont/service-actor-token-code.fc`,
release `tos-service-actor-token-v1`, rail `tos.service.service-actor-token.v1`).

- The Rust SDK `contracts::service_actor_token` builds every message body.
- This CLI adds three things: the state read, the refusals, and the message envelope.

## Commands

| Command | What it sends | Value attached by default (nanoTOS) | Unused value |
|---|---|---|---|
| `call` | A token `transfer` of exactly `price_per_call` from the sender's token wallet to the actor. Its forward payload is `token_call`. | The bridge wallet's need plus 0.05 TOS (below) | The wallet returns the excess to the sender. The actor returns the forward's change at admission. |
| `send --operation respond` | `respond`, signed when the request snapshotted an attestor | 0.01 TOS | Kept by the actor |
| `send --operation expire` | `expire` | 0.01 TOS | Kept by the actor |
| `send --operation claim-refund` | `claim_refund` | 2 × `payout_funding` | Returned to the sender |
| `send --operation sweep-expired-request` | `sweep_expired_request` | 2 × `payout_funding` | Returned to the sender, with the bounty |
| `send --operation update-policy` | `update_policy` | 0.01 TOS | Kept by the actor |
| `send --operation rotate-attestor-key` | `rotate_attestor_key` | 0.01 TOS | Kept by the actor |
| `send --operation revoke-attestor` | `revoke_attestor` | 0.01 TOS | Kept by the actor |
| `send --operation withdraw-revenue` | `withdraw_revenue(token_amount, tos_amount)` | 2 × `payout_funding` with a token part, else 2 × `PAYOUT_GAS_ALLOWANCE` | Returned to the sender |
| `send --operation claim-returned` | `claim_returned` | 2 × `payout_funding` | Returned to the sender |
| `send --operation sweep-returned` | `sweep_returned` | 2 × `payout_funding` | Returned to the sender |
| `send --operation recover-surplus` | `recover_surplus` | 2 × (`PAYOUT_GAS_ALLOWANCE` + `payout_funding`) | Returned to the sender |
| `send --operation abandon-payout` | `abandon_payout` | 0.01 TOS | Returned to the sender |
| `send --operation recheck-payout` | `recheck_payout` | 2 × `PAYOUT_GAS_ALLOWANCE` | Returned to the sender |
| `top-up --target actor` | An empty body to the actor | `--amount-nanotos` | Becomes the actor's balance |
| `top-up --target wallet` | An empty body to the actor's own token wallet | `--amount-nanotos` | Becomes the wallet's balance |

`show`, `request-show`, `payout-show` and `returned-show` read and print state. They send nothing.

**Default values.** A funded value defaults to twice its minimum at the state read. This protects against a gas price rise before the message executes.

**Explicit values.** An explicit `--amount-nanotos`, or `--forward-tos-nanotos` for `call`, below the minimum is refused. A value of zero is refused for every op.

**`update-policy` arguments.**

- Each field that is not given keeps its current value. `--open-access` takes `true` or `false`; `--clear-authorized-caller` removes the caller.
- The document's `details` show every field of the resulting policy.
- The command accepts exactly what the actor accepts, plus one more check: an `--authorized-caller` must be canonical on workchain 0, since the actor would never admit any other caller.

**An empty `withdraw-revenue` is refused.** The actor accepts a withdrawal of zero tokens and zero TOS, but it moves nothing, so the sender would only pay fees.

## The state read

Every command reads the last masterchain block the endpoint reports. That block's header gives the read's chain time, `gen_utime`.

Every further read is bound to the same block, or the command fails. The bound reads are:

- the get-methods;
- the account state;
- ConfigParams 19, 25 and 84;
- the asset's token bridge parameter.

A bound read must report the same seqno and root hash as the anchor block.

The actor's code must be one of:

- the pinned release code (`--code-profile release`, the default);
- the test build (`--code-profile test`, test networks only).

Before signing, the command refuses every message that the actor would refuse for a reason visible in that state. The error names the actor's exit code.

**Time-dependent conditions.** A condition that depends on the time of execution is decided as follows:

- **Already decided at `gen_utime`:** refused. Examples: a refund past its claim deadline (1916), a closed response window (1912), an expire past the refund window (1915). Time only moves forward, so these cannot become valid.
- **Not yet decided:** a warning on stderr. Examples: a sweep, recheck or abandon that is still too early.

### `call`

The checks follow the actor's admission order, so the reason given is the one the actor would log.

| Code | Refused when, at the read block |
|---|---|
| 1901 | the actor is inactive |
| 1944 | the policy names an attestor whose key is not yet in the actor's key store (read from its data) and 4 keys are live |
| 1932 | the route's master is not canonical on workchain 0, or `get_bridge_config_param` is not a token bridge slot (79, 81, 82, 83) |
| 1933 | ConfigParam 84 does not list the master with status 1 and the route's wallet code hash |
| 1934 | the sender is not canonical on workchain 0 |
| 1923 | the actor admits only another caller |
| — | `get_accepting_tokens` is false (the SDK's `funding_transfer`) |
| — | the forward is below `storage_fee + min_funding_value` (the SDK's `funding_transfer`) |
| 1927 | `pending_liability + price`, `locked_storage_fees + storage_fee` or the balance plus `storage_fee` reaches 2^120 |
| 1907 | `live_count` is at `MAX_LIVE_GLOBAL` |
| 1908 | `get_caller_live_count(sender)` is at 1,000 |
| 1909 | no request id is left |
| 1924 | the daily rate limit is reached for the read block's day (`gen_utime / 86400`), and that day has more than 600 seconds left. With less left, the command only warns. |
| 1935 | `returned_count` is at `MAX_RETURNED_GLOBAL`, or `get_caller_returned_count(sender)` is at 16 |
| 1937 | the token liability plus the price exceeds the lesser of `max_token_liability` and the record's `max_liability_per_actor` |
| 1926 | `--expected-terms-hash` differs from `get_terms_hash` |
| 1928 | the actor's balance is below `locked_storage_fees + locked_outcome_fees + 1 TOS` |
| — | the sender has no token wallet, or its balance is below the price |
| — | the bridge parameter and its negative slot are both absent (the bridge wallet would fail) |
| — | ConfigParam 25 is absent |

**Not prechecked.** Some admission refusals can arise only from deploy data that the SDK's `validate` and the actor's `update_policy` never write, so `call` does not check them:

- 1902 for a zero price or a zero `max_token_liability`;
- 1903–1906 for a response SLA, refund window, cleanup bounty or storage fee outside its bounds;
- 1925 for an attestor key that does not match its key id.

The actor still refuses these, and the tokens come back as a funding return.

**Warned, not refused.** These refusals depend on the time of execution, or on a state that has no getter:

- 1914 (`expire` too early), 1919 (a sweep too early), 1938 (`abandon-payout` too early) and 1942 (`recheck-payout` too early) are warned about on stderr when the read block's time is before the threshold;
- 1943, a balance query younger than its TTL, is neither checked nor warned about.

The actor refuses such a message, and the bounce returns its value.

**The value of the wallet message.** The wallet message to the sender's token wallet must exceed the bridge wallet's own need. That need is `send_tokens`' check:

```text
need = forward_tos_amount + fwd_count * fwd_fee
       + 2 * wallet_gas_consumption + wallet_min_tos_for_storage
```

Where:

- `fwd_count` is 2, since the forward is positive.
- `wallet_gas_consumption` and `wallet_min_tos_for_storage` are the third and fourth Coins of the prices reference. They are read from the route's bridge parameter or, when it is absent, from its negative slot, exactly as the wallet reads them. Anything after them is not read.
- `fwd_fee` is `floor(3 * remaining / 2)`, computed in three steps:
  1. `fee = lump_price + ceil((bit_price * bits + cell_price * cells) / 2^16)`, with ConfigParam 25. Here `bits` and `cells` count the transfer body and its `token_call` reference: the body counted as a referenced cell, the most a wallet message can cost.
  2. `first_part = floor(fee * first_frac / 2^16)`.
  3. `remaining = fee - first_part`.

The default value is `need + 0.05 TOS`. An explicit `--wallet-value-nanotos` must exceed `need`.

### `send`

| Operation | Refused when, at the read block |
|---|---|
| owner ops (`respond`, `update-policy`, `rotate-attestor-key`, `revoke-attestor`, `withdraw-revenue`, `recover-surplus`, `abandon-payout`) | the sender is not the owner (1900) |
| `respond` | the request is not pending (1913); its response window closed (1912). It is also refused when the request has an attestor but no signature is given, or when the signature does not verify under the key the request snapshotted (`get_request_attestor_key`, checked against its key id) for the domain bound to ConfigParam 19 (1911). A signature for a request without an attestor is refused too. |
| `expire` | not pending (1913); the refund window closed (1915) |
| `claim-refund` | the sender is off workchain 0 (1934); there is no refund (1917); the refund is another caller's (1918); it is expired (1916); the destination is invalid (1934) |
| `sweep-expired-request` | the request is neither pending nor refundable (1920) |
| `update-policy` | an SLA or window outside the build's bounds (1903, 1904); a bounty outside its bounds (1905); a storage fee below `MINIMUM_STORAGE_FEE + bounty` (1906); a zero price (1902); a zero liability cap (1937) |
| `rotate-attestor-key` | 4 keys are live (1944); the key is not 1,312 bytes |
| `withdraw-revenue` | the balance is below the locks plus the 1 TOS reserve, whatever the amounts (1922); the token part exceeds token revenue (1922); the TOS part exceeds the lesser of TOS revenue and the free balance (1922); 4 revenue payouts are in flight (1930); the owner is off workchain 0 (1934) |
| `claim-returned` | the sender is off workchain 0 (1934); the entry is missing (1931), in flight (1930) or another caller's (1918); the destination is invalid (1934) |
| `sweep-returned` | the entry is missing (1931) or in flight (1930) |
| `recover-surplus` | 4 surplus payouts are in flight (1930); the owner is off workchain 0 (1934); the amount exceeds the own wallet's balance minus the attributed ledger (1936) |
| `abandon-payout` | the payout is missing (1940); its kind is not 3 or 6 (1941) |
| `recheck-payout` | the payout is missing (1940); its kind is 3 or 6 (1941) |

**Destination check.** The destination of `claim-refund` and `claim-returned` is checked with the SDK's `check_destination`. It must be a canonical `addr_std` on workchain 0, without anycast, and must not be the actor.

**Left to the actor.** The command does not check a balance query younger than its TTL (1943). The actor refuses such a message, and the bounce returns its value.

## `--build-only`

`--build-only` signs nothing. It prints one JSON document on stdout, followed by a newline:

```json
{
  "version": "tosctl.service-actor-token.prepared-message.v1",
  "operation": "claim-returned",
  "rail": "tos.service.service-actor-token.v1",
  "code_profile": "release",
  "actor": "0:<64 hex>",
  "read_at": { "seqno": 4242, "root_hash": "<64 hex>", "gen_utime": 1800000000 },
  "sender": "0:<64 hex>",
  "destination": "0:<64 hex>",
  "value_nanotos": "2400000000",
  "bounce": true,
  "body_boc": "<standard base64>",
  "body_hash": "<64 hex>",
  "details": { "...": "..." }
}
```

**Layout.**

- The fields appear in this order.
- The printer is `serde_json`'s pretty printer: two-space indentation, `": "` after keys, no trailing spaces.

**Field values.**

- `operation` is the `--operation` name, or `call`, `top-up-actor` or `top-up-wallet`.
- `destination` is the message's recipient:
  - the actor, for every `send` and for `top-up --target actor`;
  - the sender's token wallet, for `call`;
  - the actor's own token wallet, for `top-up --target wallet`.
- Addresses are in raw form, `<workchain>:<64 lowercase hex>`.
- Amounts in `value_nanotos` and `details` are decimal strings, so no amount loses precision in a JSON number.
- `bounce` is always `true`.
- `body_hash` is the body cell's representation hash, in lowercase hex.
- `details` holds the operation's own fields, sorted by key; every value is a string.

**`body_boc`.** It is the body cell serialized by `chain_block::write_boc`, in standard base64 with padding. That is the single-root bag of cells, byte for byte:

1. The magic `b5 ee 9c 72`.
2. One flags byte: `has_idx` = 0, `has_crc32c` = 0, `has_cache_bits` = 0, `flags` = 0, then `size`. `size` is the number of bytes needed for the cell count (1 for these bodies), so the byte is `0x01`.
3. `off_bytes`: the number of bytes needed for the total size of the cell data, 1 for these bodies.
4. The cell count, the root count (1) and the absent count (0), each in `size` bytes.
5. The total cell data size, in `off_bytes` bytes.
6. The root's index, 0, in `size` bytes.
7. Each cell:
   - descriptor `d1 = references`;
   - descriptor `d2 = floor(bits / 8) + ceil(bits / 8)`;
   - the data bytes, an incomplete last byte completed by a 1 bit and then 0 bits;
   - each reference's index in `size` bytes.

**Cell order.** The cells come in the order of the reference implementation's bag-of-cells writer. For every body here, that is the root first and then its single reference, if any; only `call`'s transfer body has one (the `token_call`).

There is no index, no CRC32C and no trailing data.

**Determinism.** The document is a function of the arguments and the state read at `read_at`: the same arguments at the same block give the same bytes. There is one exception: `send --operation respond --attestor-controller`. Its ML-DSA signature is hedged (randomized), so its document is not byte-reproducible. `respond` is a provider operation that buyer tooling does not reproduce. Warnings go to stderr and are not part of the document.

**Sending the document:**

```text
tosctl wallet send --from <wallet> --to <destination> --amount-nanotos <value_nanotos> \
  --body-boc <body_boc> --bounce [--build-only]
```

**Choosing the sending wallet.**

- `--sender <address>` names the sending wallet for `--build-only` when there is no local wallet.
- Otherwise `--from` names a configured wallet.
- Without `--build-only`, the command signs the same message with that wallet, prints the wallet message line and broadcasts it.

## Golden fixtures

`tosctl/src/node-control/commands/src/commands/nodectl/fixtures/service_actor_token/` holds two files for every operation:

- `<name>.inputs.json`, with these fields:
  - `state`: the getter values the planner reads;
  - `reads`: the extra reads;
  - `sender`, `query_id` and `operation`;
  - `arguments`, keyed by the flag names, with amounts as decimal strings.
- `<name>.out.json`: the exact bytes `--build-only` prints, final newline included.

**Tests.**

- `build_only_documents_equal_their_golden_fixtures` plans every inputs file from its own bytes and requires the output to equal the out file, byte for byte.
- `every_document_carries_the_sdk_body` requires each body to be the SDK builder's output.

**Re-pinning.** After an intended change, regenerate the fixtures with:

```text
TOSCTL_UPDATE_GOLDEN=1 cargo test -p commands service_actor_token
```

The fixtures use a synthetic actor and wallet code, so a new actor code hash does not change them.
