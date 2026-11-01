# BR1 B1: bounded relay service and client

Status: **parallel engineering increment on PR #379, not production activation**.
The service implements real HTTP, quote allocation, capability-gated status,
SQLite-backed submission and recovery through the existing engine. Its authority
must provide native capabilities, descriptor generation and quote authentication.
B1 tests explicitly supply a fake authority; B1 supplies no production signer or
chain/finality verifier. A1's process adapter and C1's localnet entry point connect
these modules without claiming the missing native provider exists.

## Public boundary

The listener accepts IPv4 `127.0.0.1` only, for a separately reviewed transport
proxy. No public bind, operator-management route, key import, evidence upload,
admin recovery endpoint or arbitrary executable selection exists. The service
is disabled by default. Health always returns `production_approved: false`.
The receiver accepts one HTTP/1.1 request per connection, with a single canonical
Content-Length for POST, JSON media type, 8-KiB headers and at most 32 header fields.
Duplicate headers, chunking, compression, Upgrade, Expect, ambiguous framing and
buffered pipelining refuse. GET without Content-Length means an empty body.

| Endpoint | Request / response |
| --- | --- |
| `GET /v1/health` | Empty body; availability and exact release scope only. Readiness is not release approval. |
| `POST /v1/quote` | Exact `slot`, `lifetime`, `status_token`. The server chooses fee/funding cap, reserves the receiving index before signing, verifies the returned exact terms, and persists the envelope before publishing it. |
| `POST /v1/submit` | Exact `request` (the existing BR1 Request object) and `status_token`. Authenticate capability and match the local quote before proof work/signing. Return HTTP 202 with a status record, **not successful chain execution**. |
| `POST /v1/status` | Exact `request_id` and `status_token`. Read-only: it never runs reconciliation or accepts supplied evidence. Unknown and unauthorized requests return the same 404 shape. |

A status token is a random 32-byte lowercase hex capability. Its domain-separated
SHA-256 is signed into the quote; the clear token is never stored in the journal.
Use a fresh token for each quote and keep it client-side. It is passed in the JSON
body, not a URL. The service does not log request bodies or expose native stderr.
Transport/proxy logs require their own privacy review. The token protects receipt
access, not on-chain spending authorization; the user still signs the Shield body
locally and never sends a seed, note secret or witness to this API.

## Exact quote terms

`tos.br1.quote.terms.v1` has exactly:

```text
schema, release, nonce, note_index, issued_at, valid_until,
slot, amount, funding_cap, descriptor_b64, status_hash, success
```

`success` is always `pool_execution`: a later bounced public payout does not undo
an already successful pool transition/fee note. Amount and funding are positive
integers capped at 2^63-1 for this service policy; they are not floating point.
The lifetime is 1–300 seconds, slot 0–2, and index is durable and non-reusable.
The descriptor is the existing 2,573-byte Shield V1 descriptor. B1 checks its
encoding, width, version and allocated index; the native authority must verify
its execution domain, key derivation and recipient ownership.

A1's production envelope shape is `tos.br1.quote.v1` containing `terms`,
`public_key_b64` and `signature_b64`. The existing quote identity hashes canonical
terms, not the randomized signature. Repeated quotation is not on-chain
acceptance; acceptance is produced only after the exact candidate is admitted.

## Client

`relay_client.Client` accepts an operator-selected HTTPS origin, uses normal
certificate validation, follows no redirect, and requires a local pinned quote
verifier before constructing or submitting a request. HTTP is permitted only
with explicit `allow_loopback=True` and `127.0.0.1` for local tests. The client
reverifies the envelope again on submit, so mutating a Quote object's dictionary
cannot change the selected terms. DNS resolution remains an OS responsibility;
the socket I/O budget is cumulative, not an anonymity guarantee.

`SubmissionUnknown` carries the already-known request identity. No automatic
POST retry, fresh signature, relabelled fee or alternate-operator failover occurs.
Query the same request's status and authenticate chain evidence independently.
A returned status includes only identifiers, the acceptance, and a proof locator;
`requires_independent_verification` is always true. This client does not generate
Shield witnesses/transactions or verify finality itself. The user transaction
builder, fresh discovery verification and portable finality client remain B2 work.

## Resource and recovery contract

Four admitted connections and eight kernel backlog entries; admission occurs
before thread creation. One nonblocking service-work lock gives no unbounded
proof-work queue. A global token bucket bounds connection admission without an
attacker-keyed map. Read budgets are five cumulative seconds, replies two seconds;
JSON request bodies are bounded and responses at most 64 KiB. Native work has its
own per-call limits; a full multi-call request is not claimed to finish in five
seconds. The current policy favors safety and boundedness over throughput/fairness.

A private journal-specific flock excludes a second service process, including on
listener-bind failure. Shutdown joins owned workers before releasing the journal
and native executable. Recovery checks capabilities and visits at most 64 live
jobs, checking a shutdown signal between jobs. It cancels only expired unprepared
reservations, dispatches persisted prepared bytes, and reconciles UNKNOWN or
broadcast records from the authority. It never re-signs ambiguous work. A native
provider outage remains nonterminal; client status reads do not drive recovery.

The existing journal's storage/history limits still apply. Compaction preserves
request, slot and spent-input tombstones. At the lifetime history cap, drain and
retire the worker; do not delete replay-protection records to keep serving.

## Tests and remaining gates

```sh
python3 -m unittest discover -s test/bonded-relayer -p test_relay_service.py -v
python3 test/bonded-relayer/delivery_controls.py --lane service --out build/br1-service-controls.json
```

These execute actual socket framing, deadlines, connection bounds and SQLite,
with a deliberately fake quote/proof authority. They do not prove Shield execution,
fees received or production custody. Four actual guard-removal controls are
required, with specific assertion failures and restored-green runs. The common
control-runner file is identical in A1 and B1 so the branches can compose cleanly.

Still open: production native provider, complete funding/Bond lifecycle CLI,
user-side Shield builder, native acceptance verification on the client, authenticated
fresh discovery, privacy transport, distributed load/fault measurements, approved
economics, independent review and third-party audit. No main merge or activation
is requested by this increment; Energy remains unimplemented and unnecessary.
