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

Planning revision: implementation and validation are pending.
