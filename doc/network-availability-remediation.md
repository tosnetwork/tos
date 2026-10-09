# Network availability remediation

Base revision: `58872f3a3a8e847f8240eb80ba9666d205904a5e` (`main`).

## Problems and implementation plan

| Finding | Current failure | Planned correction | Required regression |
| --- | --- | --- | --- |
| Persistent health checks exhaust JSON-RPC slots (`68f3c16ed6648191b70240cf9dc35b9e`) | Keyless persistent requests can retain the entire global connection pool. | Bound live HTTP connections per TCP source, normalize IPv6 sources, release admission on every connection exit, and respect each request's persistence policy. Apply the source limit through the production JSON-RPC listener policy. | A source at its cap cannot evict another source; closing a connection restores admission; repeated health responses cannot take the global pool; `Connection: close` is honored. |
| Global ADNL output budget starves other clients (`06b84b6ba0a481919cb6d6a3c82d372d`) | Slow readers hold a shared output budget; a new honest response is the connection closed on exhaustion. | Charge unread output to a per-source share as well as the global budget, and impose a non-renewable deadline on undrained output, including while inbound keepalives continue. | Several connections of one source reach only their share; another source can answer; successful writes and every close release both charges; keepalives/trickle writes do not renew the output deadline. |
| Early HTTP proxy replies strand connection slots (`62761165fca88191ad7c4b7e4ec5d4ea`) | Response completion followed by request-body completion leaves next-request parsing disabled and the socket outside the request deadline. | Make connection reuse wait for both completion events, independent of their order, while preserving the close-after-early-answer option and CONNECT behavior. | Real sockets complete the answer before the last upload byte, then successfully issue a second request and expire normally when idle; reverse completion order and early close still work. |
| Global QUIC stream budget remains vulnerable to multiple sources (`7ee6d4d5c1448191a6dcf0e4952ecebe`) | Source shares isolate one address, but incomplete streams can renew their lifetime and multiple sources can fill the process budget. | Add a non-renewable incomplete-stream lifetime and admission that leaves capacity for new sources by reclaiming an incomplete stream from an overrepresented source when the global slot pool is full. Keep byte and source ceilings and preserve locally opened query deadlines. | Trickle data cannot extend an incomplete stream's total lifetime; a new source makes progress beside multiple saturating sources; displaced/expired streams return every reservation; outbound response deadlines are unchanged. |

The availability policy must not claim resistance to an unlimited number of
attacker-controlled identities or addresses. Source shares aggregate clients
behind the same NAT and IPv6 /64; deployments must account for that sharing.

## Validation and acceptance

Each regression must fail when its corresponding protection is removed and
pass when restored. Exercise production socket/QUIC callback paths, not only
counter helpers. Run the existing HTTP, ADNL output/refusal-close and QUIC
budget/source-share/deadline suites, and preserve their compatibility.

Record implementation and validation results here before marking the pull
request ready. A green test run is not a fresh security scan or production
acceptance. No scan status is changed by this remediation.

## Status

The four corrections are implemented. In addition to source connection
admission, JSON-RPC health, API-info and OPTIONS responses close even when the
request asks for persistence. Admission records that policy; it does not close
the socket before the asynchronous response is queued. Authenticated RPC
responses also honor `Connection: close`.

ADNL output is charged to the source and server before frame allocation;
partial writes and every teardown return both charges. The output backlog has
a 30-second total deadline, independent of incoming keepalives and partial
writes. A completely drained backlog may start a new deadline.

QUIC peer streams have a 120-second absolute lifetime alongside the existing
inactivity limit. Input FIN does not remove lifetime or reclamation protection:
the stream still holds a slot until its reply and transport closure complete.
Under global slot saturation, a source with less than its fair share can
request the oldest pending peer stream of the largest
holder to be reset. The budget coordinates at most one pending reset across
all its servers. The triggering stream is refused: the newcomer retries after
the owning callback returns the victim's slot. That slot is reserved for the
newcomer for two seconds after it is returned, so the displaced source cannot
immediately refill it; an abandoned retry temporarily withholds at most one
slot. If a reset remains unacknowledged for two seconds, the owner closes that
connection locally without awaiting the peer, releasing its slots and transport
state. This can interrupt sibling streams on that connection; their clients
must reconnect/retry; closing transport does not cancel already dispatched
application work. This is bounded recovery from
overrepresented sources, not guaranteed admission on the first attempt or
protection against an unlimited number of one-stream sources. Locally opened
query response deadlines are not extended or replaced.

The new regressions run in the existing network safety suites. The ADNL
output and refusal-close targets are also included in the AddressSanitizer
workflow, retaining their existing security regression labels.

## Initial implementation validation

The implementation at `292faf30b5476aa1253a1fa2fdfa9b15bb75f27c`
recorded Linux validation passing all 11 selected CTest groups: HTTP listener,
production JSON-RPC transport, ADNL output/refusal close, CONNECT tunnels, and
QUIC inbound/transport budgets, source shares, connection limits, inbound
expiry and outbound deadlines. A separate Debug build with Clang 21 and
AddressSanitizer also passed those 11 groups (`detect_leaks=0`, matching the
network workflow; this is not a leak-sanitizer claim).

All 12 removed-control cases failed for their named reason and passed after
restoration. The cases cover HTTP reuse, TCP source admission, keyless closure,
request persistence, ADNL source accounting/ceiling, output expiry and
non-renewal, QUIC total lifetime, source fairness, reserved retry capacity,
unacknowledged reset reclamation and input FIN. The output expiry regression
uses an independent watchdog so an expired actor alarm cannot spin until the
ordinary idle timeout and falsely pass.

Representative removed-control receipts (bounded excerpts):

| Case | Executed failure |
| --- | --- |
| HTTP reuse | `early.request_ok(3000)` fails after the delayed final upload byte. |
| HTTP source | `excess.drains_to_close(3000, received)` fails when source admission is disabled. |
| Keyless / request close | `client.drains_to_close(3000, rest)` fails when the corresponding persistence policy is removed. |
| ADNL source | `source overflow did not close` when source charging remains but its ceiling is disabled. |
| ADNL expiry | `keepalives renewed the output deadline` from the independent watchdog. |
| ADNL non-renewal | `partial writes moved the original output deadline`. |
| QUIC lifetime | `absolute lifetime expired before the renewed inactivity window` times out. |
| QUIC fairness | `overrepresented source was displaced on another server` times out. |
| QUIC reservation | `displaced source cannot take the reserved retry slot` times out. |
| QUIC reset | `unacknowledged reset released connection and slot` times out. |
| QUIC FIN | `input FIN did not remove the held slot lifetime` times out. |

The runner and named assertions above provide the reproducible evidence.
This initial receipt did not claim final-head GitHub CI or a fresh security
scan.

To reproduce sensitivity checks in an isolated checkout:

```sh
python3 scripts/test-network-availability-mutations.py \
  --build-dir /absolute/path/to/build \
  --log-dir /absolute/path/to/retained-results --jobs 4
```

Do not run mutations concurrently with builds or tests using the same source
tree. Each case restores its source even on failure, requires the named
executed failure, and rebuilds/reruns the restored regression.

## Review follow-up

Reviewed input: `292faf30b5476aa1253a1fa2fdfa9b15bb75f27c`.

The review found two remaining implementation defects, a test-registration
gap, and a synchronization defect in an existing ADNL regression:

- Completing an early-answered upload and then receiving input EOF could stop
  the HTTP connection with a serialized response still queued. The native
  regression reached EOF with 253,772 response bytes pending and failed at
  `body.has_value()`. Both completion orders now close only after output
  drains. HTTP also restores write readiness on each inbound EOF turn: the
  poll layer otherwise suppresses writes after a peer half-close, including
  later writable notifications. This covers responses still being serialized
  through a small output window, retains the configured response deadline,
  and adds no polling timer. The outbound constructor now identifies its
  client role correctly so this behavior remains confined to inbound HTTP.
- QUIC checked saturation before acquiring the reclamation lock. A requester
  delayed at that lock could use an obsolete full-pool observation to reclaim
  another stream and replace the previous newcomer's returned-slot
  reservation. The check now runs under the same lock as the handoff. The
  local reclaim token still outlives the lock guard, avoiding a token-deleter
  lock reentry during cleanup.
- The inbound-timeout CTest entry selected only
  `AbandonedInboundStreamIsReaped`, omitting the three new lifetime, reset and
  FIN cases. It now selects the entire `QuicInboundStreamTimeout` suite. The
  ASAN registration check also requires all 15 network-safety groups; five
  already registered QUIC groups were previously absent from its expected
  inventory.
- The real-socket ADNL refusal test sampled discard totals as soon as the
  client saw EOF. The server shuts its write side first and can still have
  input-discard passes pending. The first full ASAN run passed 14 of 15 groups:
  this test received all 64 answers and clean EOF, then sampled only 458,752
  of 524,288 surplus bytes. It now keeps driving the scheduler until the
  input is discarded, bounded by the original absolute closing deadline.
  All response, EOF, byte-count and deadline assertions remain in place;
  this correction changes the test only.

ADNL coverage now checks rollback when the source reservation succeeds but
the global output reservation fails, and checks that complete output drain
clears the old deadline before a later backlog receives its own full lifetime.
JSON-RPC keyless checks now require the expected successful status and exact
health payload, valid API-info data, or empty OPTIONS response, plus closure
without surplus bytes. An arbitrary error followed by closure cannot pass.
In total, the follow-up adds eight regressions and strengthens the existing
JSON-RPC keyless and ADNL refusal-close cases.

The mutation runner now rebuilds and tests the restored source in `finally`.
A failed red build, timeout or wrong failure predicate triggers the same
restore/build/test cleanup before its error is propagated. Successful cleanup
leaves the executable matched to the restored source; a cleanup failure is
reported as an error. Successful cases report both exit codes.

| Changed boundary | Regression or execution check |
| --- | --- |
| Serialized HTTP response followed by upload EOF | `finishing_an_early_answered_upload_at_eof_drains_the_response` |
| HTTP EOF before asynchronous serialization | `an_answer_serialized_after_request_eof_drains_the_response` |
| HTTP EOF before a response larger than its output window | `an_answer_larger_than_the_window_after_request_eof_is_written_in_full` |
| Empty HTTP half-close releases the connection | `eof_without_a_request_releases_the_connection` |
| QUIC concurrent returned-slot handoff | `ConcurrentReclaimsPreserveTheReturnedRetrySlot` (eight requesters, 1,000 handoffs) |
| Abandoned QUIC retry reservation expires | `AbandonedReclaimReservationExpires` |
| ADNL rollback and complete-drain lifecycle | `source-rollback`; `drain-deadline` |
| ADNL write half-close precedes complete input drain | `half-close-after-surplus` waits within the original closing deadline and still requires all 64 answers and 512 KiB of discarded input. |
| JSON-RPC keyless response integrity | `keyless_endpoints_close_even_when_keepalive_is_requested` |
| Timeout cases execute under CTest/ASAN | All 15 groups and the full `QuicInboundStreamTimeout` filter are required; the old single-case filter fails the inventory check. |

### Follow-up validation

The follow-up used Linux x86-64, Clang 21.1.8, CMake 4.4.4 and a Debug
AddressSanitizer build with `-O0 -g1`. Leak detection was disabled, matching
the network workflow; no leak-sanitizer result is claimed.

All **23 removed-control cases** completed: each red run exited **1** for its
named reason, and each restored run exited **0** with its regression executed.
This includes all 12 initial controls and the eleven added controls below. The
four new HTTP EOF regressions also passed together before the mutation run.
The restored QUIC concurrency regression completed all 1,000 handoffs with
eight requesters and no extra reclamation. The reverted check failed with
one extra reclamation before completing those handoffs.

After rebuilding all target executables from restored source, the final
network-safety CTest run passed **15/15 groups** (exit **0**, 92.42 seconds).
Verbose output confirms execution of all four `QuicInboundStreamTimeout`
cases, all 41 HTTP server-limit cases, all 16 JSON-RPC transport cases, and
the complete ADNL output and refusal-close suites. The real-socket ADNL
surplus case delivered all 64 answers with clean EOF and discarded all
524,288 bytes. No AddressSanitizer error was reported.

The ASAN workflow's actual inventory script passed with all 15 registered
groups (exit 0). Giving it the old single-case timeout filter failed with
`network-safety gate must run the full QuicInboundStreamTimeout suite`
(exit 1). Changed-line Clang 21 formatting, Ruff 0.15.2 lint and format checks,
and the QUIC CTest isolation source guard also passed.

All temporary production mutations were restored after the controls finished;
the twelve final non-documentation files matched the last source manifest,
with no extra source modifications remaining. Their
alphabetically ordered `sha256sum` listing has SHA-256:

```text
f22fba38f795e5d33293ecb34295c2457291a1596cba5ac581f7deb4246e33b8
```

From the commit containing this receipt, reproduce that fingerprint with:

```sh
git diff --name-only -z 292faf30b5476aa1253a1fa2fdfa9b15bb75f27c HEAD -- . \
  ':(exclude)doc/network-availability-remediation.md' |
  LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum
```

Additional bounded failure receipts (all red exits 1; all restored exits 0):

| Control | Executed failure |
| --- | --- |
| `http-eof-drain` | `Expectation failed: body.has_value()!` |
| `http-eof-empty` | `Expectation failed: fetched.clean_eof!` |
| `http-eof-write` | `Expectation failed: body.has_value()!` |
| `http-eof-answer` | `Expectation failed: body.has_value()!` |
| `http-eof-window` | `Expectation failed: body.has_value()!` |
| `keyless-success` | Expected `HTTP/1.1 200 OK`, received `HTTP/1.1 401 Unauthorized`. |
| `adnl-source-rollback` | `global refusal leaked the new source reservation` |
| `adnl-drain-deadline` | `drained output retained its old deadline` |
| `adnl-refusal-drain` | `the peer got 26 of the 64 answers queued before the refusal; the stream ended by reset after 34056 bytes of an unfinished frame` |
| `quic-concurrent-reclaim` | `extra_reclaims.load() is not equal to 0u (1 != 0)` |
| `quic-retry-expiry` | `Expectation failed: reservations[0].has_value()!` |

Reproduction commands (Linux, Bash, Clang 21):

```sh
cmake -S . -B build-review -G Ninja \
  -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21 \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS_DEBUG='-O0 -g1' -DCMAKE_CXX_FLAGS_DEBUG='-O0 -g1' \
  -DTOS_USE_ASAN=ON -DTOS_USE_LLD=ON
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:halt_on_error=1
export FUNC_BIN="$PWD/build-review/crypto/func"
export FIFT_BIN="$PWD/build-review/crypto/fift"
review_targets=(
  test-quic-sender test-adnl-peer-pair-cap test-overlay-broadcast-capacity
  test-http-server-limits test-json-rpc-transport
  test-adnl-ext-output-backpressure test-adnl-ext-refusal-close
  test-rldp-http-tunnel
)
cmake --build build-review --parallel 4 --target "${review_targets[@]}"
python3 scripts/test-network-availability-mutations.py \
  --build-dir "$PWD/build-review" \
  --log-dir "$PWD/review-mutation-results" --jobs 4
cmake --build build-review --parallel 4 --target "${review_targets[@]}"
ctest --test-dir build-review -L network-safety \
  --no-tests=error --output-on-failure --verbose
```

## Second review follow-up: withdrawing a reclaim when capacity returns

Reviewed input: `11b4d0fb892b2875f98164fb43b80398c11437d5`.

`request_reclaim` checked pool saturation under the reclamation lock, but
`release_stream` returned slots without it, and nothing ever withdrew a mark
once it was set. Two orders therefore reset a stream for capacity that was no
longer missing:

- A slot returned on another thread between the saturation check and the
  mark. This needs the budget to be used from more than one OS thread: every
  QUIC server is a poll actor on its scheduler's single I/O worker, and the
  validator engine runs one scheduler node, so the engine itself does not
  interleave these calls today. The budget is process-wide and documented as
  thread-safe, so the contract was still broken.
- An unrelated stream finished after the mark and before the victim's server
  acted on it (its reclaim check runs every 0.1 s). This needs no second
  thread. Every source but the newcomer is held one slot below the limit, so
  the newcomer took the returned slot, and the victim was still reset; if its
  peer did not acknowledge the reset, its connection was closed after the
  reset grace period.

`release_stream` now returns the slot under the reclamation lock and, if a
reclaim is pending, withdraws it: the victim's flag is cleared, the victim
stays reclaimable, and the returned slot becomes the newcomer's two-second
retry reservation, exactly as a slot returned by the victim itself does. The
victim's own release takes the same path. The withdrawal is keyed on the
global count actually dropping; the source-ledger release is still attempted
for every non-empty source, and the return value combines both results as
before. The pending victim's flag is kept as a non-owning pointer, valid while
the lock is held because the token's deleter clears it under that lock before
freeing it; an owning copy could become the last owner and run the deleter,
which takes the same lock, while the lock is held.

| Changed boundary | Regression or execution check |
| --- | --- |
| Natural release after the mark withdraws it | `NaturalReleaseWithdrawsAPendingReclaim` (single thread) |
| Release between saturation check and mark | `ReleaseInsideTheReclaimCheckCannotStrandAVictim` (test hook inside the locked check) |
| Concurrent requesters and natural release | `ReclaimRacingNaturalReleasesLeavesNoVictim` (eight requesters, 2,000 rounds, ThreadSanitizer target) |

All three are in the `QuicSourceShare` suite, so the existing
`quic-source-share` CTest entry and the network-safety ASAN gate run them.

### Second follow-up validation

Linux x86-64, Clang 21.1.8, CMake 3.22.1.

On `11b4d0fb8` with only the tests and the behavior-neutral test hook added,
each new regression exited **1** at its intended assertion:

| Regression | Executed failure on the reviewed input |
| --- | --- |
| `NaturalReleaseWithdrawsAPendingReclaim` | `Expectation failed: !pool.tokens[0]->load()!` |
| `ReleaseInsideTheReclaimCheckCannotStrandAVictim` | `Expectation failed: !pool.tokens[0]->load()!` |
| `ReclaimRacingNaturalReleasesLeavesNoVictim` | `Expectation failed: !pool.tokens[i]->load()!` |

Removed-control cases, run with the mutation runner on the strict Release
build (each red exit **1**, each restored run exit **0**):

| Control | Executed failure |
| --- | --- |
| `quic-reclaim-withdraw` (withdrawal removed) | `Expectation failed: !pool.tokens[0]->load()!` |
| `quic-release-lock` (release lock removed) | `Expectation failed: !pool.tokens[0]->load()!` |
| `quic-concurrent-reclaim` (existing) | `extra_reclaims.load() is not equal to 0u (1 != 0)` |
| `quic-retry-expiry` (existing) | `Expectation failed: reservations[0].has_value()!` |

With the release lock removed, the single-thread regression still passes and
only the hook-driven one fails, so the latter is the check for the lock.
Removing the withdrawal fails both.

ThreadSanitizer (`-DTOS_USE_TSAN=ON`, RelWithDebInfo, `-f Reclaim`, all five
reclaim regressions) exited **0** with no report; the stress regression had a
reclaim granted before the natural release in 1,991 of 2,000 rounds. With the
release lock removed it reported a data race on the pending reclaim between
`release_stream` and `request_reclaim` (exit 66), and was clean again after
restoring the source.

The strict build (`TOS_WERROR_BUILD`, Release, jemalloc, LLD, x86-64-v2)
passed. The network-safety label passed **15/15** on that build and **15/15**
under the AddressSanitizer configuration of the network workflow, whose
registration check also passed. Changed-line Clang 21 formatting and Ruff
0.15.2 lint and format checks passed.

`MultipleFullSourcesAllowANewSourceAcrossServers` intermittently times out at
`remaining streams reclaimed` with one stream slot still held three seconds
after the final time jump. It fails at comparable rates with and without
this change (for example 8 of 40 and 16 of 40 runs under four-way parallel
load, then 2 of 40 and 1 of 40 in a second sample, the original first), so it
is recorded here as a pre-existing timing margin, not addressed by this change.

Reproduction (in addition to the builds above):

```sh
./build/test-quic-sender -p 65000 -d tmp-reclaim -f Reclaim
TSAN_OPTIONS=halt_on_error=1 ./build-tsan/test-quic-sender -p 65000 -d tmp-tsan -f Reclaim
python3 scripts/test-network-availability-mutations.py --build-dir "$PWD/build" \
  --log-dir "$PWD/review-mutation-results" --jobs 4 \
  --case quic-reclaim-withdraw --case quic-release-lock \
  --case quic-concurrent-reclaim --case quic-retry-expiry
```
