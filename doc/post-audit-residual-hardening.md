# Post-Audit Residual Hardening

## Context

The pre-mainnet memory-leak and storage-growth audit (base commit `099ab990a`)
was remediated by PRs #71–#86. A line-by-line re-verification of the current
`main` (`a90d1f951`) confirms that all P0 findings (H1 broadcast rate limiter,
H4 QUIC streams/connections) and all Critical Rust findings except C1 are
genuinely fixed with reachable, non-zero bounds — no dead guards among them.
On-chain state-growth economics (storage rent enabled and non-zero, block/state
GC defaults) remain clean, and PR #86 did not regress them.

Re-verification did, however, leave **six residual items** — two never fixed,
four partially fixed. Two of the partial fixes are themselves the exact
"dead guard" pattern this repository's `CLAUDE.md` warns about: a bound that is
present in the source but never fires. This document specifies each residual,
its symptom, the source evidence on current `main`, and the proposed fix, so the
claims and solutions can be reviewed before any code is written.

Every fix below must ship with a **falsifiable** test: the guarded input must be
constructed, the guard must be shown to reject it, and removing the guard must
turn the test red (per `CLAUDE.md`, "A test that cannot fail is not evidence").

---

## Exposure note

- **In-line now (ships with `validator-engine`):** R1 (log disk cap), R2 (HTTP
  connection cap), R5 (shard-block-verifier).
- **Dormant ("潜伏雷"):** R3 and R4 are in the Rust `tosctl` ADNL/overlay stack,
  which has no production listening surface today; they become live the moment
  any Rust-side ADNL/overlay listener is deployed, and must be fixed before that.
  They are treated as blockers-before-listener, not live incidents.

---

## R1 — Log file has no on-disk size cap (F1 sub-item d) — HIGH, in-line

**Problem.** `validator-engine` runs at `INFO` by default and its log file has no
size ceiling. The three remotely-drivable INFO amplifiers named in the audit
were closed (adnl-proxy deleted; liteserver per-query lines demoted to `DEBUG`;
manager external-message lines demoted to `VLOG`/`DEBUG`; the VM log moved to a
fixed-capacity ring buffer). But the remediation substituted *volume reduction*
for a *disk cap*, and no disk cap exists.

**Symptom / failure scenario.** Any `INFO`-or-above line that can still be driven
remotely at high rate (or a future regression that re-introduces one, or an
operator raising verbosity) grows the log file without bound until the disk
fills — which takes the node (and, on a validator, consensus participation)
down.

**Evidence (dead guard).** `tdutils/td/utils/TsFileLog.cpp:87` initializes the
underlying `FileLog` rotation threshold with
`std::numeric_limits<int64>::max()`. The intended bound exists but is dead:
`DEFAULT_ROTATE_THRESHOLD = 10 MiB` (`TsFileLog.h:29`) and the `rotate_threshold_`
member are declared and assigned (`TsFileLog.cpp:37`, `:66`) but the member is
**never read** — nothing passes it to `log.init(...)`. `TsFileLog.cpp` is
unchanged since the initial import.

**Proposed fix.** Thread `rotate_threshold_` into the `FileLog::init(...)` call so
the file actually rotates at a finite size; keep `DEFAULT_ROTATE_THRESHOLD`
(10 MiB) as the default and allow it to be overridden (existing `TsFileLog`
constructor parameter). Confirm `FileLog`'s rotation actually caps the on-disk
footprint (rotate + bounded retained rotations), not merely renames unboundedly.

**Test.** Unit test that writes past the threshold and asserts the active file
was rotated / stays under the cap; assert that reverting to `INT64_MAX` makes it
fail.

---

## R2 — HttpServer connection count is unbounded for three services (M4) — MEDIUM, in-line

**Problem.** `HttpServer::Limits::max_connections` defaults to `0`, and the count
check is written `if (limits_.max_connections != 0 && ...)`, so `0` means
"unlimited". Three services construct `HttpServer` without setting `Limits`, so
they run with no concurrent-connection ceiling.

**Symptom / failure scenario.** An attacker (or misbehaving client) opens a large
number of concurrent connections to any of the three services and pins file
descriptors / per-connection memory until exhaustion. The recently added request
timeouts bound slow-trickle attacks but not the raw connection count.

**Evidence (dead guard).** Default `max_connections = 0` at
`http/http-server.h:50`; the no-op short-circuit at `http/http-server.cpp:62`.
Unset by `metrics/prometheus-exporter.cpp:29`,
`rldp-http-proxy/rldp-http-proxy.cpp:1007`, `http/http-proxy.cpp:177`. Only
`validator-engine/json-rpc-server.h:196` sets a real value (1024).

**Proposed fix.** Set an explicit, sane `max_connections` on each of the three
services (a conservative default appropriate to each, e.g. matching the
JSON-RPC server's order of magnitude, tunable via existing option plumbing where
present). Leaving the library default at `0` is acceptable *if* every in-tree
consumer sets a real value; the safer change is to also pick a non-zero library
default so a future consumer does not silently inherit "unlimited". Decision to
be confirmed in review.

**Test.** Extend `test/test-http-server-limits.cpp` to assert each service's
constructed limit is non-zero and that the count guard rejects the (limit+1)-th
connection; assert removing the limit makes it accept unboundedly.

---

## R3 — Two-step-simple broadcast leaks on verify failure (C6, second path) — CRITICAL when a Rust listener is live, dormant now

**Problem.** The audit's C6 (overlay broadcast entry inserted before signature
verification; verify-failure leaks the entry permanently) was fixed for the
simple-broadcast path but the sibling two-step-simple path has the same bug and
was missed.

**Symptom / failure scenario.** A forged-id / bad-signature `BroadcastTwostepSimple`
inserts a permanent entry into `owned_broadcasts`; there is no rollback and no
periodic sweep, so an unauthenticated remote peer grows the map without bound.
Network-reachable and not feature-gated.

**Evidence.** `tosctl/src/adnl/src/overlay/broadcast.rs`:
`BroadcastSimpleProtocol::check_broadcast` rolls back on failure via
`owned_broadcasts.remove(&bcast_id)` (~`:1400`), but
`BroadcastTwostepSimpleProtocol::check_broadcast` (~`:2043-2051`) calls
`src_key.verify(...)?` (~`:2047`) with no rollback on the `?` error path. Reached
via `overlay/mod.rs:2477`.

**Proposed fix.** Mirror the simple-path fix: on any verification/parse failure
after insertion, remove the just-inserted `owned_broadcasts` entry before
returning the error (RAII guard or explicit rollback on every early-return).
Prefer verify-before-insert if the surrounding code allows it.

**Test.** Feed a `BroadcastTwostepSimple` with a bad signature and assert
`owned_broadcasts` count is unchanged after the call; assert removing the
rollback makes the entry persist.

---

## R4 — Rust TCP connection table keyed on attacker address; idle fd not evicted (C1) — CRITICAL when a Rust listener is live, dormant now

**Problem.** C1 was only partially fixed. A teardown/removal path was added and
the receiver-side fd is freed on teardown, but (1) the connection maps are still
keyed on the peer's *self-reported* wire address rather than the kernel
`accept()` address, and (2) the sender-side `connections` entry (holding an
`Arc<Socket>` fd) is removed only when a *send* fails; an idle or receive-only
connection is never evicted and there is no TTL.

**Symptom / failure scenario.** An attacker opens many connections, each
self-reporting a distinct address, and either stays idle or only receives. Each
leaves a `Confirmed` map entry plus a live fd that is never reclaimed → fd /
memory exhaustion. The attacker-controlled key also lets one peer occupy many
logical slots.

**Evidence.** `tosctl/src/adnl/src/adnl/transport.rs`: the real accept address
captured at ~`:868` is overwritten by the packet-payload IP/port at ~`:924-925`
before it is used as the map key; sender-side removal is gated on
`TcpConnectionState::Disconnected` (~`:353-355`), which only fires on a failed
send; no idle/TTL sweep.

**Proposed fix.** Key the connection maps on the kernel `accept()` peer address
(the value captured before it is overwritten), and add an idle/last-activity TTL
sweep that evicts and closes connections (freeing the fd) after inactivity,
covering receive-only and never-sending connections. Keep the existing
send-failure teardown.

**Test.** Register connections that self-report colliding/false addresses and
assert they key distinctly by accept address and do not overwrite each other;
assert an idle connection past the TTL is evicted and its fd released.

---

## R5 — ShardBlockVerifier future-seqno BlockIds never pruned (M1) — MEDIUM (compromised-trusted-node), in-line

**Problem.** No fix landed. `ShardBlockVerifier::blocks_` is a
`std::map<BlockIdExt, BlockInfo>` with no count cap; entries are pruned only when
the real chain top seqno reaches the stored block's seqno. A BlockId with a
*future* seqno is inserted and persists until the chain catches up (which for a
far-future forged seqno is effectively never).

**Symptom / failure scenario.** A compromised or misbehaving **trusted** node
(the only source now admitted, since non-trusted sources are dropped) feeds
BlockIds with far-future seqnos; `blocks_` grows without bound. Threat surface is
narrower than an anonymous remote attacker, but the growth path is real.

**Evidence.** `validator/shard-block-verifier.cpp`: insertion at `get_block_info`
(~`:171`); pruning only via `is_block_outdated` (~`:59-62`, `:154-159`) which is
false while `top_block_id().seqno() < block_id.seqno()`; no size cap on `blocks_`
(`shard-block-verifier.hpp:78`); `git log 099ab990a..main` on these paths is
empty.

**Proposed fix.** Add (a) a future-seqno admission window — reject/refuse to
store BlockIds whose seqno is more than a bounded delta ahead of the current
chain top — and/or (b) a hard count cap on `blocks_` with eviction of the
furthest-future or oldest entries. Prefer the window bound as the primary guard;
add the count cap as a backstop.

**Test.** Insert a far-future-seqno BlockId and assert it is refused (window) or
that `blocks_` size stays bounded under a flood (cap); assert removing the guard
makes `blocks_` grow.

---

## R6 — Lower-priority residuals (document; fix only if review deems cheap and safe)

These are lower severity or already low-risk; listed for completeness and a
review decision on whether to include now or track separately.

- **H6 (Rust BOC deserialize):** depth is now bounded by the default
  `MAX_SAFE_DEPTH = 2048`, but there is no absolute cell-count cap on the
  deserialize path, and `max_ext_msg_size` / `max_ext_msg_depth` remain
  parsed-but-unused (`config_params.rs`, block-json serde — no enforcement call
  site). Proposed: add an absolute cell-count cap; wire the two config values to
  their enforcement points or delete them if superseded by the C++ side
  (`validator/impl/external-message.cpp:87/111` already enforces external-message
  size/depth).
- **Incinerator (Rust `lockfree/src/incin.rs`):** deferred reclamation grows
  per-thread garbage under sustained contention (non-blocking, so not a "stall");
  and `pause()` calls `panic!("Too many pauses")` (`:87`), which conflicts with
  the no-panic guidance even if effectively unreachable. Proposed: replace the
  panic with a `Result`/saturating path; document the reclamation behavior.
- **Telemetry / peer-table eviction (Rust):** the peer table is capped
  (`MAX_PEERS = 65536`) but has no LRU/idle eviction (explicitly deferred).
  Proposed: add idle eviction (shares mechanism with R4's TTL sweep).
- **TCP reconnect backoff (Rust, M2):** the send-queue length is bounded, but
  reconnect still retries with only the pre-existing connect timeout, no backoff
  or attempt cap. Proposed: add capped exponential backoff.

---

## Verified-clean (no action) — restated for the reviewer

- On-chain storage rent enabled and non-zero in both genesis generators
  (`bit_price_ps=1`, `cell_price_ps=500`; mc `1000/500000`); PR #86 changed only
  ConfigParam 14 block-create fees, not storage prices.
- Block/state GC defaults intact (`state_ttl=1d`, `archive_ttl=7d`).
- Contract layer: 0 high / 0 medium; hard caps + prepaid permissionless cleanup +
  reserve-before-send remain in force.
- All RESOLVED audit items (H1, H2, H3, H4, M2, M3, M5 C++; C2, C3, C4, C5, C7,
  H5, H8, M2-queue, M3, M4, M5 Rust; F2, F3, F4 storage) re-verified as real,
  reachable, non-dead bounds.
