# Shard-scaling bench

`bench/run_local_bench.py` measures what one user transfer costs: every
transfer is a signed external message, so client signing, ingress and PQ
signature verification are all in the measured path. This bench asks a
different question: **what does splitting the basechain buy?** It removes the
client from the loop entirely and lets the chain generate its own load, so
the only variable between runs is the number of shards.

## Method

1. tostester boots a local PQ validator net with the basechain fixed at
   `2^split` shards (`min_split = max_split = split`). The bench waits until
   the masterchain lists exactly those shards.
2. The genesis wallet sends one message that deploys `--accounts` copies of
   [`hop.fc`](hop.fc). The copies differ only in their id, so each address is
   derived from `(id, salt, code)`; addresses, and therefore copies, spread
   evenly over every shard. Deployment is a tree: copy `lo` deploys the start
   of each upper half of its range, so N copies need about 2N messages and
   no client round trips.
3. One start message launches `--chains` message chains. Each chain forks in
   two `--forks` times, so `chains × 2^forks` chains run concurrently. Each
   hop executes on the receiving copy and sends the next hop: with
   probability `--local` to a copy in the sender's own shard, otherwise to a
   uniformly random copy anywhere. A copy keeps its own balance; a hop spends
   only the value its message carries. Every chain stops at a deadline set
   past the measurement window.
4. A scanner walks every shard's blocks by header back-links. Each block is
   matched by root hash to its collator's `validatorStats.collatedBlock`
   record, which gives its transactions, serialized bytes, gas, the
   block-limit category each limit reached, messages imported from other
   shards, and the outbound queue left behind. A block with no record is
   counted through the liteserver instead.

The rate over the window `[start + warmup, start + warmup + duration)` is
reported per shard and in total. `load_tail_ratio` compares the rate in the
window's last 10 s with the whole window; a value well below 1 means the
chains thinned out, and the run understates capacity.

## Running

```
uv run python bench/tests/test_shard.py --build build
cargo test --manifest-path tosctl/src/Cargo.toml --locked -p contracts --test shard_bench_hop_sandbox
uv run python bench/shard/run_shard_bench.py --out /path/new-dir --split 2
```

The Python tests cover the wire format and the accounting. The sandbox suite
(`tosctl/src/node-control/contracts/tests/shard_bench_hop_sandbox.rs`) runs
`hop.fc` through the executor with a real action phase and checks what each
transaction emits. Every hop send ignores action errors, so it checks
skipped actions and emitted messages, not only success.

Run it once per `--split`, with everything else fixed. `--local 0.0` makes
most hops cross a shard boundary (all but `1/2^split` of them), which
measures the cost of cross-shard delivery against `--local 1.0`.

### Hop weight

By default a hop is as light as the contract allows: accounts are deployed
up front, so a hop carries no StateInit, and nothing checks who sent it.
Three switches add per-hop work, each on its own or together:

| Switch | Each hop then also |
|---|---|
| `--with-init` | carries the target's StateInit (code and data), so messages and blocks grow |
| `--verify-sender` | rebuilds the StateInit of the sender it names and checks the sender's address against it, which costs gas |
| `--payload N` | forwards N bytes unchanged in a cell chain, which adds message size only |

With `--with-init --verify-sender` a hop does what a self-deploying,
sender-checking contract does on every message. The light default isolates
the shard question; the heavier settings show how much of the per-shard rate
a message's own size and execution take. Every run records the switches in
`results.json`.

`--validators 1` runs a single validator, so one node, rather than four
nodes sharing the host, carries every shard.

Outputs under `--out`: `results.json` (parameters, chain config snapshot,
per-shard summary) and `blocks.csv` (one row per window block).

## T2 evidence: layout, continuity, conservation

`--t2-check` opens JSON-RPC on every node and, after the hop chains pass
their deadline and the outbound queue drains, checks the run window with
[`t2check.py`](t2check.py) over records read by
[`t2collect.py`](t2collect.py). Every read goes through
[`rpc.py`](rpc.py), which stays inside `--rpc-share` of the node's
per-source budget (600 requests per 10 s) and retries HTTP 429 and
`-32005`. The window opens at the first masterchain block with an empty
queue after deployment and closes at the first one with an empty queue
after the deadline.

- **Layout:** every masterchain block in the window is read, and each
  change of the basechain shard set is recorded with the masterchain
  seqno and time, as a split, a merge or both.
- **Continuity:** shard block headers are walked from the shard tops of
  every masterchain block in the window back to the opening tops,
  through both predecessors of a merge and across a split. Every block
  the scanner saw inside the window must be reached.
- **Conservation:** every internal message that a hop account emits in
  the window, and the funding wallet's start message, is imported
  exactly once by a transaction on its destination. Deployments and
  bounces are counted in their own classes, skipped actions on their own.

- **Finality:** the closing masterchain block, and so every shard top the
  walk starts from, must be at or below the finalized masterchain seqno
  (`getConsensusBlock`, the lowest over every node). The collector waits a
  bounded time for it and records it in `t2-records.json`.

`t2-records.json` also carries the run-owned emitted-minus-imported count
as a diagnostic; the verdict does not use it.

The verdict is PASS, FAIL with the offending blocks or messages, or
INCONCLUSIVE when a block was not read, the walk was cut short, the
window is above finality or the queue had not drained; a message is reported as dropped only from a
complete walk with an empty closing queue. Records and verdict go to
`t2/` under `--out`. Against an existing endpoint:

```
uv run python bench/shard/t2collect.py boundary --rpc http://127.0.0.1:PORT/jsonRPC
uv run python bench/shard/t2collect.py check --rpc http://127.0.0.1:PORT/jsonRPC \
    --from-mc A --to-mc B --opening-empty --closing-empty \
    --run-accounts accounts.json --entry-source ADDR --out DIR
```

The pure checks are tested in `bench/tests/test_t2.py`
(`uv run python bench/tests/test_t2.py`).

## Remote mode: one bounded burst over JSON-RPC

`run_shard_bench.py --remote` attaches to existing JSON-RPC endpoints
(`--rpc URL`, repeatable) instead of booting a net. It imports no
liteserver or local-net module, and every read and send goes through
[`rpc.py`](rpc.py) inside `--rpc-share` of each node's per-source budget.

Before anything is read or sent it checks the burst caps (`--chains`
1..255, `--forks` 0..12, `--hops` 1..1,000,000, `--accounts`
2..65,536, positive funding) and prints an upper bound on the run's
messages, transactions and attached value. It refuses to go on when the
bound exceeds `--max-messages` or `--max-cost`. The bound holds because
`hop.fc` enforces it: every hop decrements `remaining` and the chain
ends at 0, forks only while `forks` is positive, decrementing it, and
hop messages never bounce; the start message carries `--hops` and
`--forks`. A chain with `remaining = r` and `forks = f` executes
`2^(r+1) - 1` transactions when `f >= r`, otherwise
`2^f - 1 + 2^f (r - f + 1)`.

Cost is the value the bench wallet attaches plus a bound on the wallet's
own fees, derived before anything is written or sent from the live
configuration (the wallet must be on the basechain: ConfigParam 21 for
gas, 25 for forwarding, 18 for storage). For each of the two wallet
externals it adds the import fee of the external at its exact size, the
computation fee at the gas limit, and the forwarding fee of every message
it sends, at the size of its init and body; on top it adds the storage
the wallet can owe up to the run's fee horizon, at the highest storage
rate the network sets, plus any due payment. Requests are signed to
expire by that horizon. `results.json` records the bound and every input.
The run refuses when attached value plus fee bound exceeds `--max-cost`,
and stops before the start when the deployment's real fee exceeds its
bound.

`--local` must be 0 in remote mode: the start message carries shard
depth 0, and `hop.fc` keeps hops local only at a positive depth. If chain
time stops advancing after the start, the wait ends after the time left
to the deadline plus `--drain-wait`, and the run is recorded INCONCLUSIVE
(exit status 4) instead of hanging.

The bench wallet is a self-pay Quantum wallet. `--key-file` is a JSON
file, mode 0600, with `mldsa44_seed` and `rescue_public_key` (hex);
the seed goes to `--signer` over stdin only and is never logged or
recorded. The owner funds the wallet's address; its first request
deploys it.

The run counts by an RPC chain walk (`t2collect.check_window`) between
empty-queue boundaries, and `results.json` records the value left in
the hop accounts as stranded: nothing can withdraw it.

## Reading the numbers

Every validator on one host validates every shard: the shard committee is
the whole validator set whenever the set is no larger than ConfigParam 28's
`shard_validators_num`. So on one host the shards share the same CPUs and
disk, and the total stops scaling once the host saturates; a network of
separate machines spreads shards over machines instead. The scope string in
`results.json` says so. The workload has no per-transaction signature check,
so its rates are not comparable with the transfer bench's.
