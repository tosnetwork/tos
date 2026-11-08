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

Every load account is a strict post-quantum account; there is no Ed25519 load.

`pq-relay`: a relayer external carries up to `--relay-batch` signed AUTH
submissions; each goes to the account's ML-DSA-44 module
(`mldsa44-auth-module.fc`), which verifies the 2,420-byte FIPS 204 proof on
chain and forwards the envelope; the strict-PQ Wallet V5 (authorization root
mode 2, classical signing disabled) executes the transfer to a sink. That is 3
transactions per transfer plus 1 relayer transaction per batch. It is the PQ
authorization path covered by the `test/pq-readiness` live regression, and the
messages are built with the same `contract` client types.

The relayer only carries messages onto the chain and pays their fees: neither
the PQ wallet nor the module accepts external messages, so the carrier's own
external is Ed25519-signed and authorizes nothing about the transfer. Every
transfer is authorized solely by its ML-DSA-44 proof.

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
# smoke (about 4 minutes)
uv run python bench/run_local_bench.py --out /tmp/bench-smoke \
  --wallets 200 --rates 5,10 --duration 30 --warmup 5 --drain 20

# rate sweep to saturation
uv run python bench/run_local_bench.py --out /tmp/bench-sweep \
  --wallets 10000 --rates 10,50,100,250,500,1000 --duration 300 \
  --connections-per-node 8 --stop-on-saturation

# plot one stage
uv run python bench/plot_blocks.py /tmp/bench-sweep/stage-pq-relay-250
```

Main options: `--validators` (4..21),
`--wallets` per workload, `--rates` (offered transfers/s per stage),
`--duration`/`--warmup`/`--drain` (seconds), `--relay-batch`,
`--block-limit-mul` (>1 only for deliberately unleashed runs; the default keeps
the genesis block limits), `--seed` (public run seed; every key is public test
material derived from it).

## How a stage is measured

1. Read every load wallet's counter (Wallet V5 seqno, or the AUTH nonce in
   strict PQ mode).
2. Pre-sign the whole stage: one ML-DSA-44 proof per transfer, then relayer externals carrying
   `--relay-batch` submissions each. Accounts are reused round-robin, never
   faster than `--min-reuse` seconds.
3. Send at the offered rate through a paced pool of liteserver connections
   spread over every validator, while a scanner reads every basechain block.
4. Drain, then read every counter again: `transfers_executed` is exact, and
   `transfers_unaccounted` is what was planned but never executed (refused,
   expired or blocked behind a failed predecessor).

A stage is `below_offered_rate` when under 95% of planned transfers execute or
the steady-state transfer rate falls below 90% of the offered rate. It is
`saturated` only when that shortfall has no non-chain explanation: no node
admission refusals, no generator lag over 1 s and no observer lag
(`non_chain_bottlenecks` lists any that apply).

Run the bench under a thermal guard on hosts that throttle, and pass its log
with `--thermal-log`. Every stage records the guard's pause/resume events; a
stage that overlaps a pause is `valid: false` and must be rerun, since a paused
generator, observer or validator measures the pause rather than the chain.

## Outputs

* `results.json`: run parameters, deployment cost and one record per stage with
  `steady_transfer_tps`, `steady_total_tx_tps`,
  `steady_pq_verifications_per_s`, `completed_transfer_rate`, inclusion latency
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
  The pool keeps each connection at 48 queries/s. Sends are never
  retried, so a refusal at the node is reported as a result.
* External messages are capped at 64 KiB; relayer batches and deployment
  batches are sized under that.
* AUTH requests are valid for at most 3,600 s, so `--duration + --drain` must
  leave room for pre-signing.

## Tests

```bash
uv run python bench/tests/test_workload.py \
  --signer build/bench-pq-signer/bench-pq-signer --key-tool build/pq-key-tool/tos-pq-key
```

The tests check that bench messages equal the reference client's, that the
batch signer is deterministic and fails whole batches on bad input, and that
it derives the same public key as `crypto/pq/tools` for the same seed (build
that tool with `cmake -S crypto/pq/tools -B build/pq-key-tool`).

## Not yet covered

* Genesis-generated large state (millions of accounts, state above RAM). Load
  accounts are deployed on chain, which keeps the code path production-like but
  bounds practical state size.
* The offline collation benchmark.
* Token transfers, and the Falcon-512 and SLH-DSA modules.
