# Local PQ performance bench

A local throughput and latency bench for TOS, derived from the upstream
benchmark design (pre-signed load at fixed offered rates, exact per-block
accounting) and adapted to post-quantum accounts. It runs a complete local
validator net in one process, so every number comes from one chain and one
clock.

Results are **local engineering evidence only**: co-located validators on one
host, no network latency and no adversarial load. They are not public or
release capacity numbers.

## Workload

Every account the bench creates is a **self-pay Quantum wallet**
(`crypto/smartcont/wallet-quantum-self-pay.fc`), the Quantum wallet the
mobile apps use. One transfer is one external message carrying a request
signed with the account's ML-DSA-44 PRIMARY key (context
`TOS-QSP-MLDSA44-v1`); the wallet verifies the 2,420-byte FIPS 204 proof on
chain, pays its own fees and executes the transfer to a sink. That is 2
transactions per transfer (wallet + sink) and no carrier, relayer or classical
key anywhere: the deployer wallets that create the load accounts are self-pay
Quantum wallets too, deploying up to 255 accounts per ML-DSA-44-signed external.
Only the genesis wallet's initial funding of the deployers is not PQ.

The account state and address layout is checked byte for byte against the
repository's public self-pay fixture generator
(`scripts/quantum_self_pay_fixture.py`).

Destinations are sink addresses outside every bench account set, so a
transaction on a load wallet is always one executed transfer.

## Build

```bash
# node, liteserver client library and contract compilers
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21
cmake --build build --target validator-engine create-state generate-random-id \
  tos-pq-consensus-key dht-server validator-engine-console lite-client toslibjson fift func

# batch ML-DSA-44 signer (same backend and parameters as crypto/pq/tools)
cmake -S bench/pq-signer -B build/bench-pq-signer -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21
cmake --build build/bench-pq-signer

uv sync && uv run test/tostester/generate_tl.py
```

## Run

```bash
# smoke (about 3 minutes)
uv run python bench/run_local_bench.py --out /tmp/bench-smoke \
  --wallets 1200 --rates 10,50 --duration 40 --warmup 10 --drain 20

# rate sweep to saturation
uv run python bench/run_local_bench.py --out /tmp/bench-sweep \
  --wallets 10000 --rates 10,50,100,250,500,1000 --duration 300 \
  --stop-on-saturation

# plot one stage
uv run python bench/plot_blocks.py /tmp/bench-sweep/stage-quantum-250
```

Main options: `--validators` (4..21),
`--wallets`, `--rates` (offered transfers/s per stage),
`--duration`/`--warmup`/`--drain` (seconds), `--deployers`, `--max-senders`,
`--block-limits production|dev` (default production: ConfigParams 22/23 exactly as
the canonical genesis, basechain bytes 256 KiB/1 MiB/2 MiB and gas 2M/10M/20M;
dev is the test-harness profile with half the block bytes), `--block-limit-mul`
(dev only, for deliberately unleashed comparisons), `--seed` (public run seed; every key is public test
material derived from it).

## How a stage is measured

1. Read every load wallet's PRIMARY nonce.
2. Pre-sign the whole stage: one ML-DSA-44-signed external per transfer.
   Wallets are reused round-robin, never faster than `--min-reuse` seconds.
3. Send at the offered rate through sender connections spread over every
   validator, while a scanner reads every basechain block.
4. Drain, then read every counter again: `transfers_executed` is exact, and
   `transfers_unaccounted` is what was planned but never executed (refused,
   expired or blocked behind a failed predecessor).

A stage is `below_offered_rate` when under 95% of planned transfers execute or
the steady-state transfer rate falls below 90% of the offered rate. It is
`saturated` only when that shortfall has no non-chain explanation: no node
admission refusals, no generator lag over 1 s and no observer lag
(`non_chain_bottlenecks` lists any that apply).

A thermal guard is optional. If one is attached to the run's process group,
pass its log with `--thermal-log`: every stage records the guard's
pause/resume events, and a stage that overlaps a pause is `valid: false` and
must be rerun, since a paused generator, observer or validator measures the
pause rather than the chain. Package temperatures are recorded per stage
either way.

## Outputs

* `results.json`: run parameters, deployment cost and one record per stage with
  `steady_transfer_tps`, `steady_total_tx_tps`, `completed_transfer_rate`,
  measured gas per transfer (`gas_sample`), inclusion latency
  percentiles, block counts, refusals and their reasons, and pre-signing time.
* `stage-<workload>-<rate>/blocks.csv`: every basechain block with its
  transaction count per account class.
* `stage-<workload>-<rate>/timeline.csv`: per-second sends, refusals and
  observed transactions.
* `bench.log`, `contracts/` (compiled code with hashes) and `network/` (node
  logs and configuration).

## Limits the bench respects

* Liteserver admission: each connection admits 64 queries/s with 32 in flight,
  and each node admits 512 medium-class queries/s (including `sendMessage`).
  Read connections stay at 48 queries/s.
* External admission: a node admits 30 external messages per 10 s from one
  client identity. The bench opens enough sender connections (each its own
  identity, paced at 2.5/s) for the highest offered rate, capped by
  `--max-senders`; on a public network the equivalent is many independent
  clients.
* Connections: a liteserver admits 64 connections per source IP. With every
  bench connection on one host, at most 56 senders per node are used, so one
  host can offer about 140 externals/s per validator (560/s with four). A
  higher rate is refused up front rather than measured as a chain shortfall. Sends are never
  retried, so a refusal at the node is reported as a result.
* External messages are capped at 64 KiB; deployment batches are sized under
  that.
* Requests are valid for at most 3,600 s, so `--duration + --drain` must leave
  room for pre-signing.

## Tests

```bash
uv run python bench/tests/test_workload.py \
  --signer build/bench-pq-signer/bench-pq-signer --key-tool build/pq-key-tool/tos-pq-key
```

The tests check the request, external and state layout (state and address
against the public self-pay fixture generator), that the batch signer is
deterministic, context-bound and fails whole batches on bad input, and that it
derives the same public key as `crypto/pq/tools` for the same seed (build
that tool with `cmake -S crypto/pq/tools -B build/pq-key-tool`).

## T4 transfer ramp (remote)

`bench/run_t4_ramp.py` runs a stepped transfer ramp against existing JSON-RPC
endpoints (see `bench/t4/ramp.py` and `--help`). It funds load wallets from
the bench wallet, journals every signed external before sending it, and binds
every transfer to its recipient transaction. `run_t4_ramp.py reconcile` reads
a run's journal back against the chain and sends nothing.

Funds are not swept back. Whatever the load wallets hold at the end stays in
them. `results.json` reports each load wallet's final balance under
`left_in_load_wallets`, and `wallet_balance` counts it in the run's cost. The
cost bound already counts all of the funding as spent. Moving the leftovers
back needs a separate tool that journals and reconciles its own sends.

Load-wallet keys come from the bench seed, the bench wallet's address and the
wallet index. Two bench configurations that share a seed but differ in wallet
id, AUTH tag or global id never share a load wallet.

## Not yet covered

* Genesis-generated large state (millions of accounts, state above RAM). Load
  accounts are deployed on chain, which keeps the code path production-like but
  bounds practical state size.
* The offline collation benchmark.
* Token transfers and RESCUE (SLH-DSA) spending.
