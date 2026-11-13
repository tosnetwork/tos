# Migrated transaction families (`txn`)

The transaction-level families that used to carry their own formats and drivers are frozen as `txn`
fixtures under `vectors/txn/fixtures/`. Their contexts come from two places.

## Families run in this tree

`migrate/txnfam_capture.py` records every call an unchanged family makes into the C++ libemulator. It
is installed by putting `migrate/txnfam_site/` on `PYTHONPATH` (the families start supervised worker
processes, which inherit it) and replaces `ctypes.CDLL` with a subclass that forwards to the real
functions and remembers, per emulator object, exactly what the caller passed: the configuration given
to `transaction_emulator_create` (or `set_config`/`set_config_object`), unixtime, lt, rand seed,
libraries, previous blocks, `ignore_chksig` and the debug flag. At each `emulate_transaction` /
`emulate_tick_tock_transaction` call it writes the ShardAccount and message strings as passed and the raw
native response. Linked and carry families need nothing special: every step is its own call whose
ShardAccount is whatever the family passed, which is the previous native step's output. The Rust
executor exports the same C names; only the library at `TXNFAM_NATIVE` is recorded.

```
TXNFAM_CAPTURE_DIR=<dir> TXNFAM_NATIVE=build/emulator/libemulator.so \
PYTHONPATH=test/conformance/migrate/txnfam_site EMULATOR_PATH=build/emulator/libemulator.so \
    python3 test/executor-parity/tick_context.py --native ... --rust ... --output <out>
python3 test/conformance/migrate/txnfam_convert.py contexts <dir> <work> --family tick-context
python3 test/conformance/migrate/txnfam_convert.py check <work> build/test/conformance/conformance-ref-cli
python3 test/conformance/migrate/txnfam_artifacts.py <work> <out> [<committed report>...]
python3 test/conformance/runner/conformance.py create --reference build/test/conformance/conformance-ref-cli \
    --harness txn --family tick-context --source migrated:executor-parity/tick_context.py \
    --blob-threshold 512 <work>/create.jsonl test/conformance/vectors/txn/fixtures/tick-context.jsonl
python3 test/conformance/migrate/txnfam_convert.py fixtures <work> test/conformance/vectors/txn/fixtures/tick-context.jsonl
```

`contexts` turns each recorded call into a context. Settings the caller never made take the emulator's
own defaults: a zero rand seed, and (never needed by the migrated families) the first aligned lt after
the input ShardAccount's last transaction lt. A call with `ignore_chksig` set or without a unixtime
(the emulator would read the wall clock) is listed as not convertible. The expected effect of a call
is derived from its native response only (Transaction root, the ShardAccount's Account reference and
root, or the refused message's exit code). Three checks follow:

- `check`: the reference reproduces every recorded call;
- `txnfam_artifacts.py`: every per-row record the family retains — `*-roots.tsv` with
  `*-root-expected.tsv`, per-case dumps (`<case>.json` with its input BOCs), six-field scenario rows with
  native transcripts, JSON reports such as `tosctl/src/executor/tests/fixtures/storage-*-carry.json` —
  matches a converted context and carries the same outcome and hashes;
- `fixtures`: the frozen fixtures carry exactly those native effects.

Identical calls are frozen once. `ctest` runs `conformance-txnfam-selfcheck`, which re-runs the five
families needing only the C++ emulator (`storage-{cache,rollback,tick,option}-carry`, `deploy-state`)
under the recorder and requires all three checks plus identity of the frozen contexts.

## Rust-node executor exports

`migrate/txnfam_rtos.py` converts the rows a Rust-node executor test writes with its
`RTOS_<X>_EXPORT` variable (name, now, lt, ConfigParams wrapper, Account, message or `-`, libraries,
special flag, workchain, address). The C++ fillers of those families wrapped the Account in a
ShardAccount with zero last transaction hash and lt, used a zero seed and no previous blocks, and
passed now and lt to `emulate_transaction`; that is the context. Tick/tock rows follow the filler's
rule (`--tick-rule`). The emulator derives specialness from CP31 for masterchain accounts, so a row
whose special flag disagrees is not expressible. `check` and `fixtures` compare with the family's
frozen C++ result file (`name, transaction hash, account hash[, reason]`); `ERROR` rows of the earlier
fillers and `error … not-success` rows mean a refused message, other `error` reasons an emulation
error.

## Families

| Family | Fixtures | Blobs | Size | Global versions | Outcomes | Context source |
|---|---|---|---|---|---|---|
| `account-limit` | 12 | 5 | 23 KiB | 11,12,16 | accepted 12 | `pq-native/account-limit-parity.py` |
| `auth-factory-auth` | 252 | 190 | 9783 KiB | 6,14,16 | accepted 209 rejected 43 | `executor-parity/auth_factory_roots.py` |
| `auth-factory-mldsa` | 832 | 1028 | 4371 KiB | 15,16 | accepted 790 rejected 42 | `executor-parity/auth_factory_roots.py` |
| `bchk` | 3744 | 4 | 4575 KiB | 13,14 | accepted 3744 | `rust-node/executor/src/tests/data/bchk.tsv` |
| `bounce-size` | 42 | 4 | 466 KiB | 10,12,13,16 | accepted 42 | `rust-node/executor/src/tests/data/bounce-size.tsv` |
| `continuation-save` | 6132 | 10 | 8026 KiB | 3,4,12,13,14 | accepted 6132 | `rust-node/executor/src/tests/data/continuation-save.tsv` |
| `continuation-transactions` | 216 | 4 | 664 KiB | 8,9,12,16 | accepted 216 | `rust-node/executor/src/tests/data/continuation-transactions.tsv` |
| `credit-overflow` | 100 | 2 | 319 KiB | 11,16 | accepted 64 error 36 | `rust-node/executor/src/tests/data/credit-overflow.tsv` |
| `deploy-state` | 63 | 8 | 80 KiB | 16 | accepted 59 rejected 4 | `executor-parity/deploy_state.py` |
| `exotic-actions` | 376 | 29 | 3494 KiB | 11,12,14,15,19 | accepted 376 | `rust-node/executor/src/tests/data/exotic-actions.tsv` |
| `extra-currency-values` | 258 | 6 | 902 KiB | 11,12,16 | accepted 138 error 120 | `rust-node/executor/src/tests/data/extra-currency-values.tsv` |
| `fail-action-fine` | 12 | 3 | 19 KiB | 14,15,16 | accepted 12 | `executor-parity/fail_action_fine.py` |
| `falcon-module-roots` | 31 | 32 | 70 KiB | 16 | accepted 31 | `falcon-auth/tx_parity.py` |
| `falcon512` | 2520 | 509 | 5596 KiB | 15,16,18,19,20 | accepted 2520 | `rust-node/executor/src/tests/data/falcon512.tsv` |
| `frozen-prefix` | 1995 | 157 | 18525 KiB | 7,8,9,10,12,13,14,15,16,17,19 | accepted 1455 rejected 540 | `rust-node/executor/src/tests/data/frozen-prefix.tsv` |
| `gas-credit` | 26 | 17 | 42 KiB | 16 | accepted 2 error 6 rejected 18 | `executor-parity/gas_credit.py` |
| `gas-extreme` | 128 | 16 | 1795 KiB | 11,16 | accepted 60 error 60 rejected 8 | `rust-node/executor/src/tests/data/gas-extreme.tsv` |
| `gas-width` | 208 | 16 | 1885 KiB | 11,16 | accepted 132 error 60 rejected 16 | `rust-node/executor/src/tests/data/gas-width.tsv` |
| `generated-post-accept` | 5 | 1 | 15 KiB | 16 | accepted 3 rejected 2 | `wallet-quantum/post_accept_transactions.py` |
| `generated-release` | 10 | 11 | 74 KiB | 16 | accepted 10 | `wallet-quantum/release_config_transactions.py` |
| `historical-opcodes` | 2064 | 24 | 4844 KiB | 3,4,5,6,7,8,9,10,11,12,13,14 | accepted 2064 | `rust-node/executor/src/tests/data/historical-opcodes.tsv` |
| `historical-sendrawmsg` | 26262 | 49 | 35924 KiB | 0,1,3,4,7,8,12,13,14,15,17 | accepted 26262 | `rust-node/executor/src/tests/data/historical-sendrawmsg.tsv` |
| `ignored-executor` | 280 | 6 | 965 KiB | 4,12,13,14,15,17 | accepted 280 | `rust-node/executor/src/tests/data/ignored-executor.tsv` |
| `inbound-extra-flags` | 192 | 3 | 511 KiB | 11,12,16 | accepted 105 error 87 | `rust-node/executor/src/tests/data/inbound-extra-flags.tsv` |
| `incoming-storage` | 1440 | 25 | 4277 KiB | 14,16,17,18,19 | accepted 1440 | `rust-node/executor/src/tests/data/incoming-storage.tsv` |
| `library-budget-transactions` | 192 | 16 | 1904 KiB | 14,15,16,19 | accepted 48 error 144 | `rust-node/executor/src/tests/data/library-budget-transactions.tsv` |
| `linked-receipt` | 156 | 93 | 366 KiB | 16 | accepted 156 | `falcon-auth/receipt_e2e.py` |
| `linked-two-hop` | 1112 | 1340 | 4357 KiB | 15,16 | accepted 1070 rejected 42 | `falcon-auth/e2e.py` |
| `lms-fee` | 856 | 198 | 2262 KiB | 15,16,17,19 | accepted 856 | `rust-node/executor/src/tests/data/lms-fee.tsv` |
| `mldsa-module-roots` | 37 | 38 | 169 KiB | 16 | accepted 37 | `pq-readiness/tx_parity.py` |
| `nonminimal-coins` | 75 | 3 | 382 KiB | 11,12,16 | accepted 18 error 57 | `rust-node/executor/src/tests/data/nonminimal-coins.tsv` |
| `opcode-gates` | 120 | 26 | 2456 KiB | 0,3,4,5,13,14,15,16,18,19 | accepted 120 | `rust-node/executor/src/tests/data/opcode-gates.tsv` |
| `poseidon2-transactions` | 264 | 32 | 1307 KiB | 15,16,17,19 | accepted 264 | `rust-node/executor/src/tests/data/poseidon2-transactions.tsv` |
| `pq-suite` | 2016 | 314 | 4931 KiB | 15,16,17,18,19,20 | accepted 2016 | `rust-node/executor/src/tests/data/pq_suite.tsv` |
| `precompiled-external` | 12 | 11 | 26 KiB | 16 | accepted 6 error 1 rejected 5 | `executor-parity/precompiled_external.py` |
| `purchase-transactions` | 13 | 9 | 25 KiB | 16 | accepted 10 error 3 | `executor-parity/purchase_transactions.py` |
| `sdk-auth-pop-role1` | 40 | 44 | 220 KiB | 16 | accepted 17 rejected 23 | `wallet-quantum/sdk_auth_parity.py` |
| `sdk-auth-pop-role2` | 40 | 44 | 365 KiB | 16 | accepted 17 rejected 23 | `wallet-quantum/sdk_auth_parity.py` |
| `sendmsg` | 4368 | 148 | 20973 KiB | 9,10,13,14,15,19 | accepted 4368 | `rust-node/executor/src/tests/data/sendmsg.tsv` |
| `state-limits` | 2634 | 148 | 18808 KiB | 11,12,13,14,15,19 | accepted 2634 | `rust-node/executor/src/tests/data/state-limits.tsv` |
| `storage-cache-carry` | 2 | 1 | 3 KiB | 16 | accepted 2 | `executor-parity/storage_cache_carry.py` |
| `storage-option-carry` | 55 | 7 | 96 KiB | 9,10,12,13,16 | accepted 55 | `executor-parity/storage_option_carry.py` |
| `storage-rollback-carry` | 4 | 1 | 6 KiB | 16 | accepted 4 | `executor-parity/storage_rollback_carry.py` |
| `storage-tick-carry` | 3 | 1 | 4 KiB | 16 | accepted 3 | `executor-parity/storage_tick_carry.py` |
| `storage-transactions` | 14 | 1 | 121 KiB | 14 | accepted 14 | `rust-node/executor/src/tests/data/storage-transactions.tsv` |
| `tick-context` | 314 | 2 | 325 KiB | 16 | accepted 272 error 42 | `executor-parity/tick_context.py` |
| `ticktock-context` | 493 | 8 | 1329 KiB | 10,11,13,14,16,17,18,19 | accepted 493 | `rust-node/executor/src/tests/data/ticktock-context.tsv` |
| `ticktock-message-lt` | 108 | 6 | 748 KiB | 4,10,13,14,17,19 | accepted 108 | `rust-node/executor/src/tests/data/ticktock-message-lt.tsv` |
| `transaction-rejections` | 115 | 19 | 156 KiB | 9,10,16 | accepted 101 error 7 rejected 7 | `executor-parity/transaction_rejections.py` |
| `v15-libraries` | 1416 | 8 | 2522 KiB | 13,14,15,16,19 | accepted 1416 | `rust-node/executor/src/tests/data/v15-libraries.tsv` |
| `wallet-fee-transactions` | 42 | 45 | 378 KiB | 16 | accepted 18 rejected 24 | `wallet-quantum/fee_tx_parity.py` |
| `wallet-module-candidate` | 33 | 30 | 248 KiB | 16 | accepted 33 | `wallet-quantum/module_tx_parity.py` |
| `wallet-module-diagnostic` | 33 | 30 | 231 KiB | 16 | accepted 33 | `wallet-quantum/module_tx_parity.py` |
| `wallet-variant-preparation` | 24 | 29 | 413 KiB | 16 | accepted 24 | `executor-parity/wallet_variant_roots.py` |
| `wallet-variant-self-pay-recovery` | 33 | 46 | 387 KiB | 16 | accepted 29 rejected 4 | `executor-parity/wallet_variant_roots.py` |
| `wallet-variant-self-pay` | 230 | 170 | 990 KiB | 16 | accepted 96 error 21 rejected 113 | `executor-parity/wallet_variant_roots.py` |

Sources `rust-node/...` are Rust-node executor exports (commit `42b39d44`); the others are paths under
`test/`. Fixtures of every global version the source family used are kept; the target is version 16,
so rows of other versions are informational. Families without any version-16 row: `bchk`,
`continuation-save`, `historical-opcodes`, `historical-sendrawmsg`, `ignored-executor`, `state-limits`,
`storage-transactions`, `ticktock-message-lt`, `exotic-actions`, `sendmsg`.

Differences from the frozen Rust-node C++ results, all explained by C++ changes after those files were
filled (the fixtures hold the current C++ fill): `pq-suite` (820) and `opcode-gates` (12), ML-DSA-44
and SLH-DSA suite 3 rows at version 16 and later, repriced since; `library-budget-transactions` (144),
configurations whose ConfigParam 43 uses the `size_limits_config_v3` layout without the two outbound
queue limits added since, which the C++ now refuses. `v15-messages` is converted but not frozen: 2,262
of its 2,268 contexts carry that outdated ConfigParam 43 and only pin the refusal. `gas-threshold` and
`storage-fee-{vectors,synthetic}` are fee arithmetic, not transactions.
