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
uv run python bench/shard/run_shard_bench.py --out /path/new-dir --split 2
```

Run it once per `--split`, with everything else fixed. `--local 0.0` makes
most hops cross a shard boundary (all but `1/2^split` of them), which
measures the cost of cross-shard delivery against `--local 1.0`.

Outputs under `--out`: `results.json` (parameters, chain config snapshot,
per-shard summary) and `blocks.csv` (one row per window block).

## Reading the numbers

Every validator on one host validates every shard: the shard committee is
the whole validator set whenever the set is no larger than ConfigParam 28's
`shard_validators_num`. So on one host the shards share the same CPUs and
disk, and the total stops scaling once the host saturates; a network of
separate machines spreads shards over machines instead. The scope string in
`results.json` says so. The workload has no per-transaction signature check,
so its rates are not comparable with the transfer bench's.
