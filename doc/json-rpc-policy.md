# JSON-RPC Server Design Policy

This document captures the design decisions for the embedded JSON-RPC HTTP
server in `validator-engine`.  Each policy has a short rationale; the
canonical source of truth is the code in `validator-engine/json-rpc-server.cpp`
and `validator-engine/json-rpc-server.h`.

## R6: Liteserver selection

All queries are routed through `ValidatorManagerInterface::run_ext_query`,
which executes them against the local validator's own liteserver state.  There
is no external liteserver pool, load balancing, or fallback.  This keeps the
server zero-dependency beyond the validator process itself and guarantees that
results reflect the node's current view of the chain, which is the only view
the operator should trust for staking operations.

## R8: Caching

There is no response caching.  Every request executes a fresh liteserver query
against the validator manager.  Caching was considered and explicitly scoped
out: the server runs co-located with a single validator node whose state
changes every block, making cache invalidation complexity unjustifiable for the
expected request volume.  Operators who need caching should front the server
with an external reverse proxy.

## R9: REST shape

`GET /healthcheck` and `GET /readyz` are the only GET endpoints; both are
read-only probes.  All data queries and mutations go through `POST /jsonRPC`
as standard JSON-RPC 2.0 requests.  `OPTIONS` on any path returns a CORS
preflight response.  Any other HTTP method returns 405.  This avoids the
combinatorial complexity of mapping every method to a RESTful path while
keeping health probes simple for load-balancer integration.

## R10: Parameter defaults

`getTransactions` defaults `limit` to 10 (clamped to a maximum of 100).
`getBlockTransactions` and `getBlockTransactionsExt` default `count` to 40.
These defaults mirror the tos-http-api conventions so that clients migrating
from that service see identical behavior without specifying explicit values.

## R11: Input normalization

The `address` parameter accepted by all address-bearing methods is parsed via
`block::StdAddress::parse_addr`, which accepts both raw form
(`workchain:hex_hash`) and user-friendly base64/base64url form.  This means
callers never need to pre-convert addresses.  The choice follows the same
normalization that tos-http-api provides, keeping client code portable.

## R12: Method-name stability

Public method names (`sendBoc`, `getAddressInformation`, `runGetMethod`, etc.)
follow the tos-http-api naming exactly.  No aliases or renames are introduced.
This allows existing client libraries (e.g. legacy web and API SDKs) to
target the embedded server with a URL change only, without code modifications.

## R13: Security

The server is only started when the operator explicitly passes
`--json-rpc-address <host:port>`, so it is off by default.
`--json-rpc-readonly` disables the three write methods (`sendBoc`,
`sendBocReturnHash`, `sendQuery`), making the server safe for public exposure
without risking unsolicited message injection.  There is no built-in
authentication or rate limiting; both are left to external infrastructure
(reverse proxy, firewall rules) because the server is designed for
single-operator use or placement behind an API gateway.

## R14: Versioning

There is no version header or version prefix in the URL.  Compatibility is
tracked implicitly through method names: new capabilities are added as new
methods, and existing method signatures are not changed.  If a breaking change
is ever required, it will be introduced as a new method name rather than
altering the semantics of an existing one.  This avoids the operational burden
of version negotiation in a system where the server and its primary clients
(tosctl, monitoring scripts) are typically co-deployed.
