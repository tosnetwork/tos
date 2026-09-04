# PredictionMarket V1 tosctl workflow

`tosctl agent prediction` is a fail-closed builder and inspection surface for
the frozen PredictionMarket V1 contract. Every online preparation re-derives
the market address from a strict definition, checks the connected chain's
`global_id` and ConfigParam 8, verifies the deployed code hash, then compares
the on-chain market ID and config hash with the definition.

The `prepare` commands never broadcast. They durably write the complete signed
external-message BOC before printing it. Re-running against the same output
path succeeds only if the bytes are identical; a different wallet seqno or
payload is never allowed to overwrite the prior evidence. For a manual relay,
base64-encode that file and use `tosctl wallet broadcast-prepared`, including
its explicit unpinned/manual acknowledgement. Autonomous OpenFox relays must
use their owner-pinned custody journal and multi-RPC resolver instead.

## Market definition

All quantities are integers and all monetary values are nanoTOS. Hash input is
64 lowercase hexadecimal characters; `rules_hash` and `metadata_hash` may use
the `sha256:` prefix. Unknown JSON fields are rejected.

```json
{
  "global_id": 42,
  "workchain_id": -1,
  "deployment_salt": "1111111111111111111111111111111111111111111111111111111111111111",
  "rules_hash": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  "metadata_hash": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
  "reserve_recipient": "-1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "trade_close": 1800000000,
  "resolve_not_before": 1800000100,
  "oracle_vote_deadline": 1800000300,
  "challenge_period": 3600,
  "appeal_review_delay": 3600,
  "appeal_period": 10800,
  "claim_deadline": 1810000000,
  "lot_value": 1000000000,
  "min_price_tick": 100,
  "min_fill_lots": 1,
  "max_order_lots": 100,
  "max_locked_collateral": 100000000000,
  "max_account_free_balance": 50000000000,
  "max_total_free_balance": 100000000000,
  "max_total_liability": 300000000000,
  "max_participants": 8,
  "max_orders_per_participant": 8,
  "max_live_order_records": 16,
  "participant_entry_fee": 1000000,
  "account_cleanup_bounty": 1000000,
  "order_entry_fee": 1000000,
  "order_cleanup_bounty": 1000000,
  "operating_reserve_floor": 1000000000,
  "terminal_tombstone_reserve": 100000000,
  "challenge_bond": 100000000,
  "challenge_processing_fee": 10000000,
  "normal_oracle_policy": {
    "threshold": 1,
    "reporters": ["-1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
  },
  "appellate_oracle_policy": {
    "threshold": 1,
    "reporters": ["-1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]
  }
}
```

Build and inspect deterministically:

```sh
tosctl agent prediction build-state --definition market.json --output-boc market-state-init.boc
tosctl agent prediction prepare-deploy --definition market.json --from master_wallet \
  --amount-nanotos 2000000000 --output-boc deploy-external-message.boc
tosctl agent prediction show --definition market.json
```

The deploy message carries StateInit and `activate` together and is bounceable,
as required by the contract. An already active or frozen address is rejected;
frozen-account recovery needs the exact retained dynamic state and is a
separate operational procedure.

## Operation request

`prepare --operation operation.json` accepts a tagged strict JSON object. The
supported tags and fields are:

```text
register_and_deposit: query_id, credited_amount, trading_pubkey
deposit: query_id, credited_amount
set_trading_key: query_id, new_pubkey
raise_nonce_floor: query_id, new_floor
cancel_exact: query_id, order
split | merge: query_id, quantity_lots
match_pair: query_id, quantity_lots, left_signed_order_boc, right_signed_order_boc
report_result: query_id, round, expected_round_context_hash, outcome,
               evidence_root, statement_created_at, statement_expiry
challenge_result: query_id, expected_proposed_statement_hash, counter_outcome,
                  counter_evidence_root
advance_phase | finalize_uncontested: query_id
finalize_review_timeout: query_id, expected_review_base_context_hash
claim: query_id, owner
withdraw: query_id, amount
withdraw_challenge_bond: query_id
force_refund_challenge_bond: query_id, challenger
prune_order: query_id, owner, epoch, nonce, accept_reward
prune_owner_orders | close_empty_account | force_close_account:
    query_id, owner, accept_reward
compact_terminal: query_id
withdraw_terminal_surplus: query_id, amount
top_up_reserve: query_id
```

`top_up_reserve` uses the explicit `pm_top_up_reserve#504d0019` body and a
minimum value of 1 TOS. This is the reserve-donation form that can pass Agent
Account V2 checked-call authorization; direct wallet transfers with an empty
body remain supported by the contract for compatibility.

Signed-order BOCs are standard base64 single-root cells. Outcomes are
`0=YES`, `1=NO`, `2=INVALID`; rounds are `0=NORMAL`, `1=APPEAL`.

Before an autonomous owner signs a custody effect, `build-operation` exposes
the exact canonical message body without reading chain state or any signing
key:

```sh
tosctl agent prediction build-operation \
  --definition /absolute/market.json \
  --operation /absolute/match.json \
  --output-boc /absolute/match-body.boc
```

Its `tos.prediction-operation-artifact.v1` JSON binds the operation and reviewed
custody action kind to the deterministic market address, market/config/code
hashes, exact body BOC/hash, and minimum value breakdown. OpenFox must authorize
that returned body hash and must still call `prepare-agent`, which independently
rebuilds the same body and checks the deployed source, market, network, value,
expiry, and owner signature. The pure builder is not evidence that a market is
deployed or live and never produces a bearer-executable external message.

Example deposit:

```json
{"operation":"deposit","query_id":7,"credited_amount":5000000000}
```

```sh
tosctl agent prediction prepare --definition market.json --operation deposit.json \
  --from trader --amount-nanotos 6000000000 --output-boc deposit-external-message.boc
```

The JSON result separately reports message value, credited amount, state
contribution, operation budget, and any excess reserve donation. First-time
`cancel_exact` and `match_pair` conservatively budget their maximum possible
order-record contribution; if records already exist, the disclosed excess is
a reserve donation.

## Agent Account V2 custody path

Autonomous OpenFox execution uses `prepare-agent`, not the direct-wallet
`prepare` output. The command accepts the dedicated
`PredictionCustodyEffectAuthorizationV1` JSON, checks its owner-pinned authority
signature in the shared controller custody journal, and requires the deployed
source to have the audited Agent Account V2 code hash. It also verifies the
full network domain, deployed market code, market ID/config hash, exact body
cell hash, value, action kind and expiry before reserving the controller seqno.

```sh
tosctl agent prediction prepare-agent \
  --definition /absolute/market.json \
  --operation /absolute/match.json \
  --wallet solver-agent \
  --amount-nanotos 1000000000 \
  --fee-reserve-nanotos 100000000 \
  --valid-until 1800000000 \
  --authorization-file /absolute/prediction-custody-authorization.json \
  --output-boc /absolute/prediction-action.boc \
  --yes
```

The signed payload is always `checked_contract_call_v2` (`0x41475007`) with
flags `3`, one exact body reference, and no StateInit. The exact external BOC is
persisted in custody before it is exposed. Prediction and Agreement actions use
the same journal and therefore cannot reserve the same Agent Account seqno.

The closed custody action mapping rejects pruning and account-force-close
operations because no corresponding V1 semantic action is frozen for them.
They remain permissionless/manual keeper operations; a future autonomous
mapping requires a reviewed additive semantic entry rather than prefix-based
acceptance.

## Order authorization

`build-order` requires the market definition, so the global ID, workchain,
deterministic address, config hash, trade close, quantity and price limits are
checked before a digest is emitted:

```sh
tosctl agent prediction build-order --definition market.json --order order.json \
  --output-boc unsigned-order.boc
```

Supplying both `--public-key` and `--signature` verifies the Ed25519 signature
and emits a signed-order cell. Key custody remains outside tosctl: an
owner-controlled signer/HSM must independently authorize the exact digest;
OpenFox must never treat an Intent publication signature as trading authority.
