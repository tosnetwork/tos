# Local PQ bench results

Local engineering evidence only. Four validators share one host, so there is no network latency and no adversarial load. These are not public capacity numbers.

## 2026-11-08: self-pay Quantum wallet under the canonical genesis block limits

Evidence index: [evidence/20261108-production-sweep/INDEX.json](evidence/20261108-production-sweep/INDEX.json). It holds the command, the source commit `015ea5669`, the live ConfigParam 20–25 hashes and the full per-stage records in `results.json`. Later commits add ingress full nodes and chunked wallet derivation and change the stage classifier; they do not change what this run measured. The backlog attribution below is recomputed from the recorded refusal counts. It also lists SHA-256 and size for each retained raw file: block and timeline CSVs, the bench log, and the validators' collation records.

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

What the collators recorded for blocks that stopped on the byte limit (`block_full bytes`):
- The collator stops taking externals at the medium level, (soft + hard) / 2 = 1,572,864 bytes (`collator.cpp`, `ParamLimits::cl_soft`). It checks after each message, so the median full-block estimate of 1.64 MB is overshoot past that level.
- At 400/s the median full block holds 322 transactions, 1.47 MB serialized, about 4.55 KB per wallet transaction.
- At 500/s it holds 510 transactions (about 255 transfers), 1.40 MB serialized, about 5.4 KB per transfer including the recipient's transaction.
- Both are well under the 2 MiB hard limit. Gas runs 4.3–5.4M, about half the 10M soft limit, with 0.19–0.20 s of collation CPU time.

Measured per transfer:
- 16,719 gas on the wallet transaction;
- 2,766 bytes for the external message, of which the ML-DSA-44 signature chain is 2,420.

Reading it:
- **The byte limit binds first.** From 300/s up, a growing share of blocks stop on it while gas stays near half its soft limit and lt delta stays small. At about 5.4 KB per transfer the medium level holds about 290 transfers, so a shard tops out near **680/s** at the observed 2.4–2.5 blocks/s.
- **300 and 400/s: every shortfall is ingress.** The node's external admission refused 59 and 103 sends ("source rate limit exceeded"). Each refusal breaks its wallet's nonce chain for the rest of the stage. With 9 and 12 transfers per wallet, that explains at most 59 × 8 = 472 and 103 × 11 = 1,133 later stale-nonce (1804) refusals. Exactly that many were recorded, so none of them is chain backlog.
- **500/s: chain backlog begins.** With 15 transfers per wallet, 104 ingress refusals explain at most 1,456 stale refusals, but 2,323 were recorded. At least 867 are chain backlog: a wallet's next transfer arrived before its previous one executed, consistent with p99 latency of 19.3 s and a maximum of 36.5 s against the 20 s reuse interval. Blocks/s also slipped to 2.42. The stage classifier now counts stale refusals beyond the ingress cascade bound as saturation.
- **Per-connection accounting.** The refusing connections sent at most 17–23 externals in any 10 s window, below the documented 30, so the effective admission window is tighter than one connection's own count. No accepted request went undelivered (`requests_accepted_but_not_delivered` is 0 in every stage).
- **No observer or thermal confounders.** The scanner saw no late block except 7 at 500/s, and no thermal guard was attached (validity n/a).

Comparisons (same host and workload, 120 s stages, earlier tooling):
- Test-harness profile with half the block bytes (512 KiB soft): blocks held at most 283–294 transactions and throughput plateaued at about 300–320 transfers/s.
- The same profile with four times the bytes (2 MiB soft): 391.5 transfers/s at 400/s offered, with blocks of up to 780 transactions.
