# Local PQ bench results

Local engineering evidence only. Four validators run on one host, so there is no network latency and no adversarial load. These are not public capacity numbers.

## 2026-11-08: self-pay Quantum wallet under the canonical genesis block limits

Setup:
- Source: `feat/pq-benchmark` at 97cf3577d (bench) on main 080467e8c.
- Command: `run_local_bench.py --wallets 10000 --rates 50,100,200,300,400,500 --duration 300 --warmup 30 --drain 60 --max-senders 224`.
- Block limits: `--block-limits production`, i.e. ConfigParams 22/23 exactly as `gen-zerostate.fif` and the public testnet set them. Basechain is 256 KiB / 1 MiB / 2 MiB bytes, 2M / 10M / 20M gas, 1,000 / 5,000 / 10,000 lt.
- Chain: Simplex at a 400 ms target, one basechain shard.
- Host: 192 CPUs, all used, no thermal guard.
- Workload: one ML-DSA-44 PRIMARY-signed external per transfer, 2 transactions per transfer. 10,000 wallets were deployed in 66 s.

| Offered transfers/s | Executed | Steady transfers/s | Transactions/s | Latency p50 / p99 | Max tx per block | Valid |
|---|---|---|---|---|---|---|
| 50 | 100% | 49.8 | 99.6 | 1.4 s / 5.6 s | 158 | yes |
| 100 | 100% | 99.6 | 199.2 | 2.2 s / 5.6 s | 312 | yes |
| 200 | 100% | 200.1 | 400.3 | 2.6 s / 5.9 s | 420 | yes |
| 300 | 99.4% | 298.2 | 596.5 | 2.8 s / 6.0 s | 539 | yes |
| 400 | 99.0% | 394.6 | 790.3 | 2.8 s / 6.2 s | 560 | yes |
| 500 | 98.8% | 492.4 | 984.7 | 3.1 s / 11.1 s | 561 | yes |

Every transfer is accounted for from the wallets' PRIMARY nonces after each stage.

Measured gas is 16,719 per transfer. Package temperatures stayed between 65 and 85 °C.

Reading the table:
- **No stage saturated the chain.** The steady rate tracked the offered rate up to 500/s.
- The 0.6–1.2% of transfers that did not execute trace back to the host's own ingress. A node admits 30 externals per 10 s from one client identity: 60 to 104 sends per stage were refused that way, and each refused send broke its wallet's nonce chain, so later transfers of that wallet were refused with 1804.
- **500/s is close to the bench's ceiling on one host.** A liteserver admits 64 connections per source IP, which caps one host at about 560 externals/s to four nodes. The chain's own ceiling was not reached.
- **Block bytes are the binding chain limit.** At 500/s, blocks reached 561 transactions, about 280 transfers. That is the 1 MiB soft byte limit at about 3.6 KB per transfer (the 2,420-byte ML-DSA-44 signature dominates). Gas stays near 4.7M of the 10M soft limit, and the p99 latency begins to rise. The byte limit implies a per-shard ceiling of roughly 700 transfers/s at the 400 ms target.

Comparisons (same host and workload, 120 s stages):
- Test-harness profile, with half the block bytes (512 KiB soft): blocks held at most 283–294 transactions whatever the offered rate. Throughput plateaued at about 300–320 transfers/s, and at 400/s latency rose to tens of seconds.
- Test-harness bytes ×4 (2 MiB soft): 391.5 transfers/s at 400/s offered, with blocks up to 780 transactions.
