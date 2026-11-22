# Transport benchmarks

A suite that measures the node's three transports (ADNL, RLDP2, QUIC) on their own, without a
chain: paced gossip-shaped messages (fan-out and fan-in), query/response, idle peers and ceiling
probes. Server and client are separate processes with a readiness check, a warm-up and a fixed
measurement window.

It is ported from the upstream transport benchmark suite. Results are local engineering evidence
from one host over loopback; they say nothing about a real network.

## Run

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21 -DTOS_USE_JEMALLOC=ON
cmake --build build --target bench-rldp bench-adnl-quic-message

test/net/bench/suite.sh                  # every scenario on every transport, one repetition
REPETITIONS=3 test/net/bench/suite.sh    # medians of three
PROTOCOLS=adnl test/net/bench/suite.sh   # one transport
```

One workload: `test/net/bench/bench.sh -P adnl -T message -c 1 -n 20 -s 240 -m 4000 -B 20`.
`bench.sh -h` lists the options. `BENCH` names the binary (default `build/bench-rldp`).

Two-node ceiling in one process, one command: `build/bench-adnl-quic-message --adnl` (also
`--quic`; `--payload-size` works with both). `--payload-size N` sets the message size; above the ADNL MTU of 1024 bytes a message is
carried as several datagrams, so 2800 or 4300 measures the split path. With a large payload keep
`--lag` small (16), or raise the kernel limit below: the closed loop waits for every message, and
one dropped datagram loses a whole message.

Build with jemalloc, as release node binaries are: it roughly halves the CPU per message here.

Raise the kernel's UDP receive buffer limit first, or a run fails on drops:

```sh
sudo sysctl -w net.core.rmem_max=33554432
```

Harness tests: `python3 test/net/bench/test_bench.py`, and with the binary
`TOS_BENCH=build/bench-rldp python3 test/net/bench/test_bench.py`.

## Scenarios

| scenario | shape |
| --- | --- |
| `idle-small` | 32 established idle peers to one server; cores and memory are the result |
| `ihave-1x20` | one sender to 20 neighbours, one 240-byte message each, 4,000 messages/s |
| `ihave-40x20` | one sender to 20 neighbours, bursts of 800 messages, 6,000 messages/s |
| `fanin` | 8 senders to one server, 1,000 messages/s each |
| `bulk-common` | 2 clients to one server, 7,680-byte query and 1,024-byte answer |
| `bulk-large` | 2 clients to one server, 64-byte query and 256 KiB answer (RLDP2 and QUIC) |
| `sat-1x1` | ceiling probe, one sender to one server, 1,000,000 messages/s offered |
| `sat-20x400` | ceiling probe, one sender to 20 neighbours, 1,000,000 messages/s offered |

## What is measured, and what differs from upstream

- **Counts come from the benchmark.** The transports here export no metrics of their own, so
  `bench-rldp` counts what it sends and receives (messages, queries, completed and failed round
  trips, peers) and serves the counts on its `--prometheus-port` under the names the scripts
  expect of a transport. The node's metrics exporter is not used: it refreshes at most once in
  15 seconds, and the scripts read at the start and the end of a 20-second window.
- **A message is counted when it is handed to the transport.** In the paced scenarios a run is
  invalid unless at least 99% of what was submitted is delivered. In a ceiling probe the
  submitted figure is what was offered, not what the transport accepted; the delivered rate is
  the result and the delivery share is expected to be low.
- **No wire figures.** Datagrams, bytes and system calls per message, and per-layer drop
  counters, are not available and are reported as `-`.
- **Drops are the kernel's.** The change of `RcvbufErrors` on the `Udp:` line of
  `/proc/net/snmp` over the window is the drop evidence; any non-zero value invalidates a run.
  It is a host-wide counter, so other UDP traffic on the host is counted too.
- **A run is also invalid** when a query fails, or the peers that completed the readiness probe
  are not the expected number. That count does not fall when a peer is lost later: a session
  that dies during the window is seen only through its missing messages or failed queries, and
  in the idle scenario not at all.
- **Fewer failure signals than upstream.** There are no per-layer drop or message-failure
  counters, so a paced message run rests on the 99% rule and the kernel's drop count, and a
  ceiling probe on something being delivered with no kernel drops. In a probe the sender queues
  what is not delivered, so the rate is measured under a growing backlog.
- **QUIC caps connections from one address** at 1,024 by default, and every benchmark client is
  on 127.0.0.1: a QUIC run with more than 1,024 sessions to one server never becomes ready.
  `--no-admission-limits` does not lift that cap. The suite uses at most 32.
- **QUIC here has bidirectional streams only**; the options for unidirectional streams,
  datagram frames and acknowledgement tuning do not exist. The two external QUIC libraries the
  upstream suite compares against are not part of this tree; the scripts still accept
  `-I quic-go` and `-I quinn` and skip them when their drivers are not built.

Reference numbers: [RESULTS.md](RESULTS.md).
