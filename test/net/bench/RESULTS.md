# Transport benchmark results

Local engineering evidence only: one host, loopback, one repetition. The whole suite ran under
`taskset` on 8 cores and their hyper-threads (pinning is not part of the scripts), one thread per
process. Not a statement about a real network.

2026-11-22, `suite.sh` as of the change that added this file, build with `-DTOS_USE_JEMALLOC=ON`,
`net.core.rmem_max = 33554432`, 5 s warm-up and a 20 s window. Every run was valid and the kernel
dropped no datagram.

## Throughput and cost

Each cell: rate, then CPU microseconds per message on the measured side.

| scenario | unit | ADNL | RLDP2 | QUIC |
| --- | --- | --- | --- | --- |
| `ihave-1x20` | messages/s delivered | 3,999; 40.1 µs | 4,000; 121.5 µs | 4,000; 92.0 µs |
| `ihave-40x20` | messages/s delivered | 6,001; 19.6 µs | 6,001; 109.4 µs | 6,001; 88.2 µs |
| `fanin` | messages/s delivered | 7,998; 19.4 µs | 7,999; 40.3 µs | 8,000; 52.4 µs |
| `bulk-common` | round trips/s | 19,865; 66.0 µs | 1,528; 260.2 µs | 30,620; 41.8 µs |
| `bulk-large` | round trips/s | not run | 342; 3645.4 µs | 4,888; 223.9 µs |
| `sat-1x1` | messages/s delivered (ceiling) | 184,539; 5.1 µs | 1,779; 72.2 µs | 23,410; 31.7 µs |
| `sat-20x400` | messages/s delivered (ceiling) | 165,570; 8.0 µs | 35,655; 32.0 µs | 31,149; 64.2 µs |

In the ceiling probes the sender offered far more than was delivered on RLDP2 and QUIC
(`sat-1x1`: ADNL 100.0%, RLDP2 1.3%, QUIC 5.3% of the offered messages delivered); see the README for why that does
not invalidate a probe.

## Idle peers

| transport | peers | cores | server RSS, MiB | KiB per peer |
| --- | --- | --- | --- | --- |
| ADNL | 32 | 0.0005 | 22.2 | 31.5 |
| RLDP2 | 32 | 0.0000 | 23.3 | 66.4 |
| QUIC | 32 | 0.0010 | 28.2 | 175.6 |

## Two-node message ceiling, by payload size

`bench-adnl-quic-message --adnl --payload-size N --lag 16 --threads 8` on 8 cores, 2026-11-21,
median of five 3-second runs, before `net.core.rmem_max` was raised (no datagram was dropped in
these runs). CPU is both ends together.

| payload | default allocator | jemalloc |
| --- | --- | --- |
| 240 B (`--lag 64`) | 188,941 messages/s; 27.3 µs | 225,030 messages/s; 13.9 µs |
| 2,800 B | 48,226 messages/s; 114.2 µs | 53,685 messages/s; 62.5 µs |
| 4,300 B | 34,652 messages/s; 167.1 µs | 39,223 messages/s; 91.3 µs |

With `--quic` (jemalloc, `--lag 16`, one 3-second run each, 2026-11-22): 20,033 messages/s at
240 bytes and 21,709 messages/s at 2,800 bytes.
