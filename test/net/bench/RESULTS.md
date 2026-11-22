# Transport benchmark results

Local engineering evidence only: one host, loopback, every process on the same 8 cores and their
hyper-threads, one thread per process, one repetition. Not a statement about a real network.

2026-11-22, `suite.sh` at the commit that added the suite, build with `-DTOS_USE_JEMALLOC=ON`,
`net.core.rmem_max = 33554432`, 5 s warm-up and a 20 s window. Every run was valid and the kernel
dropped no datagram.

## Throughput and cost

Each cell: rate, then CPU microseconds per message on the measured side.

| scenario | unit | ADNL | RLDP2 | QUIC |
| --- | --- | --- | --- | --- |
| `ihave-1x20` | messages/s delivered | 3,999; 41.2 µs | 4,000; 126.5 µs | 4,000; 98.0 µs |
| `ihave-40x20` | messages/s delivered | 6,002; 20.3 µs | 6,000; 112.2 µs | 6,000; 95.8 µs |
| `fanin` | messages/s delivered | 8,000; 18.9 µs | 7,998; 43.0 µs | 7,999; 53.9 µs |
| `bulk-common` | round trips/s | 18,662; 69.4 µs | 1,818; 252.0 µs | 29,763; 43.6 µs |
| `bulk-large` | round trips/s | not run | 323; 3880.2 µs | 4,832; 226.1 µs |
| `sat-1x1` | messages/s delivered (ceiling) | 168,229; 5.7 µs | 1,784; 73.9 µs | 24,743; 31.4 µs |
| `sat-20x400` | messages/s delivered (ceiling) | 155,618; 8.4 µs | 29,439; 38.4 µs | 29,807; 67.2 µs |

In the ceiling probes the sender offered far more than was delivered on RLDP2 and QUIC
(`sat-1x1`: ADNL 100.0%, RLDP2 1.3%, QUIC 4.9% of the offered messages delivered); see the README for why that does not invalidate a probe.

## Idle peers

| transport | peers | cores | server RSS, MiB | KiB per peer |
| --- | --- | --- | --- | --- |
| ADNL | 32 | 0.0000 | 22.0 | 29.4 |
| RLDP2 | 32 | 0.0000 | 22.9 | 54.1 |
| QUIC | 32 | 0.0015 | 28.4 | 176.9 |

## Two-node message ceiling, by payload size

`bench-adnl-quic-message --adnl --payload-size N --lag 16 --threads 8`, 2026-11-21, median of five
3-second runs, before `net.core.rmem_max` was raised (no datagram was dropped in these runs).
CPU is both ends together.

| payload | default allocator | jemalloc |
| --- | --- | --- |
| 240 B (`--lag 64`) | 188,941 messages/s; 27.3 µs | 225,030 messages/s; 13.9 µs |
| 2,800 B | 48,226 messages/s; 114.2 µs | 53,685 messages/s; 62.5 µs |
| 4,300 B | 34,652 messages/s; 167.1 µs | 39,223 messages/s; 91.3 µs |
