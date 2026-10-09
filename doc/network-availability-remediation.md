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

Linux validation passed all 11 selected CTest groups: HTTP listener,
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

Full logs are retained outside Git in the isolated Linux PR test directory;
the runner and named assertions above provide the reproducible evidence.
Final-head GitHub CI and a fresh security scan have not been claimed.

To reproduce sensitivity checks in an isolated checkout:

```sh
python3 scripts/test-network-availability-mutations.py \
  --build-dir /absolute/path/to/build \
  --log-dir /absolute/path/to/retained-results --jobs 4
```

Do not run mutations concurrently with builds or tests using the same source
tree. Each case restores its source even on failure, requires the named
executed failure, and rebuilds/reruns the restored regression.
