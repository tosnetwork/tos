# Local PQ bench results

Local engineering evidence only. Four validators share one host, so there is no network latency and no adversarial load. These are not public capacity numbers.

## 2026-11-08: self-pay Quantum wallet under the canonical genesis block limits

Evidence index: [evidence/20261108-production-sweep/INDEX.json](evidence/20261108-production-sweep/INDEX.json). It holds the command, the source commit `015ea5669`, the live ConfigParam 20–25 hashes and the full per-stage records in `results.json`. It also lists SHA-256 and size for each retained raw file: block and timeline CSVs, the bench log, and the validators' collation records.

Setup:
- **Block limits:** `--block-limits production`, i.e. ConfigParams 22/23 exactly as `gen-zerostate.fif` and the public testnet set them. Basechain: bytes 256 KiB / 1 MiB / 2 MiB, gas 2M / 10M / 20M, lt 1,000 / 5,000 / 10,000.
- **Chain:** Simplex at the 400 ms target, one basechain shard.
- **Host:** 192 CPUs, all used, no thermal guard.
- **Load:** 10,000 wallets, each transfer one ML-DSA-44 PRIMARY-signed external (2 transactions per transfer), 300 s per stage.
- **Accounting:** each transfer is counted from the value its sink received. Accepted requests (consumed nonces) are recorded separately.

| Offered/s | Delivered | Steady transfers/s | tx/s | Latency p50 / p99 | Blocks/s | External processing stopped on |
|---|---|---|---|---|---|---|
| 50 | 100% | 50.0 | 100.0 | 1.5 / 5.6 s | 2.50 | queue drained |
| 100 | 100% | 100.1 | 200.2 | 2.2 / 5.6 s | 2.50 | queue drained |
| 200 | 100% | 200.0 | 399.1 | 2.5 / 5.8 s | 2.50 | queue drained |
| 300 | 99.4% | 298.2 | 596.4 | 2.8 / 6.0 s | 2.50 | byte limit in 168 of 675 collations |
| 400 | 99.0% | 396.0 | 791.1 | 2.8 / 6.2 s | 2.50 | byte limit in 268 of 675 |
| 500 | 98.4% | 480.9 | 960.8 | 3.1 / 19.3 s | 2.42 | byte limit in 337 of 662 |

What the collators recorded for blocks that stopped on the byte limit (`block_full bytes`), medians at 400/s offered:
- block estimate 1.64 MB (the figure the byte limits apply to);
- serialized size 1.47 MB, about 5 KB per transfer including the recipient's transaction;
- 5.37M gas, about half the 10M soft limit;
- 0.19 s of collation CPU time.

At 500/s the median full block held 510 transactions, 1.40 MB and 4.31M gas.

Measured per transfer:
- 16,719 gas on the wallet transaction;
- 2,766 bytes for the external message, of which the ML-DSA-44 signature chain is 2,420.

Reading it:
- **The byte limit binds first.** From 300/s up, a growing share of blocks stop on it while gas stays near half its soft limit and lt delta stays small. At 500/s the block rate slips to 2.42/s and p99 latency rises to 19 s, so the chain is close to its byte-bound ceiling there. The full blocks imply about 280–290 transfers per block, roughly 700 transfers/s per shard at 2.5 blocks/s.
- **The 0.6–1.6% not delivered were refused at ingress.** At 300, 400 and 500/s, 59, 103 and 104 sends were refused by a node's external admission ("source rate limit exceeded"). Each refusal breaks that wallet's nonce chain for the rest of the stage, so its later transfers are refused with 1804.
  - Per-connection accounting shows the refusing connections sent at most 17–23 externals in any 10 s window, below the documented 30. So the admission window is tighter than one connection's own count, and the cascade is an artifact of one host sending everything, not of the chain.
  - No accepted request went undelivered (`requests_accepted_but_not_delivered` is 0 in every stage).
- **No observer or thermal confounders.** The scanner saw no late block except 7 at 500/s; no thermal guard was attached (validity n/a).

Comparisons (same host and workload, 120 s stages, earlier tooling):
- Test-harness profile with half the block bytes (512 KiB soft): blocks held at most 283–294 transactions and throughput plateaued at about 300–320 transfers/s.
- The same profile with four times the bytes (2 MiB soft): 391.5 transfers/s at 400/s offered, with blocks of up to 780 transactions.
