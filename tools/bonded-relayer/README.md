# BR1 relay engine

`relay_core.py` is the durable, bounded submission engine. It is **not** an HTTP
server, a proof verifier, a production signer, or a public relayer network. It has
no automatic manual-CLI fallback. The production `Adapter` is an explicit open
integration gate, not replaced by the fake adapter in tests.

## Implemented

Strict request and full-release binding; canonical numeric/digest/body encoding;
private SQLite WAL journal with full synchronization; atomic acceptance-slot and
nullifier reservations; per-job and aggregate funding/queue limits; durable exact
prepared bytes; one broadcast claim across competing processes; crash-safe UNKNOWN
handling; destination-evidence binding; terminal-state monotonicity; spent-nullifier
tombstones. A prepared attempt can resume its persisted bytes. An ambiguous write
is never automatically re-signed or rebroadcast.

The journal also durably allocates receiving-note indices and quote identities,
retains the exact signed quote bytes, expires unclaimed quotes and enforces
quote/history limits. With `require_quotes=True`, reservation requires one matching
live local quote, and successful terminal evidence must bind the quoted fee credit.
Quote signature verification and finality authentication remain duties of the missing
production adapter; storing or parsing their bytes does not provide either.

Expired records still in `reserved` without a persisted prepared message or
broadcast claim can be cancelled without reusing their request identity or
acceptance slot. `Adapter.prepare` may already have signed before validation or
persistence failed; cancellation relies on preparation never broadcasting, not on
proof that signing never occurred. Prepared and unknown attempts cannot use that
recovery path. Post-window compaction drops eligible terminal
message/signature payloads and checkpoints the WAL while preserving requests,
slots and spent-input tombstones. It does not reset receiving indices or free
history-count capacity. A worker reaching its history cap must be drained and
retired with its records retained.

Storage admission checks the actual SQLite page ceiling and reclaimable pages,
combined database/WAL/SHM file usage, and completion headroom for admitted jobs
and allocated quote terms/signatures. It reserves temporary space for the largest
row update and remaining full-row WAL writes, including quote publication/claim/expiry cleanup
and terminal compaction. Serialized terminal evidence is capped at 16 KiB at
persistence. These are finite admission quotas, not a universal filesystem-size
guarantee under arbitrary external readers or writes.
The SQLite admission correction's exact sources and targeted validation are
recorded in `test/bonded-relayer/evidence/sqlite-admission-p2.json`.

The `body_sha256` field hashes **serialized bytes**, for local journal integrity.
It is not a TVM representation hash. `Prepared.message_hash` is the actual TVM
hash, independently recomputed by the adapter. The FC acceptance uses the TVM
body identity; an adapter must not substitute the serialized-byte digest.

## SDK and discovery integration

`tosctl/src/node-control/contracts/src/relayer_bond.rs` supplies canonical bond
configuration, StateInit/address derivation, decoding, message and signature-domain
encoders.
The frozen BOC and source-hashed candidate manifest are under `crypto/smartcont/`;
`python3 scripts/update-relayer-bond-code.py --check` reproduces their identity. This is
SDK/build tooling, not a funded deployment or lifecycle CLI. The manifest records
`activation_approved: false`.

The existing indexer now recognizes bond actors and exposes the public read-only
`GET /relayers` and `GET /relayers/{address}` routes. Records are untrusted
candidates and always carry `requires_live_verification: true`; current code,
configuration, network, worker status, backing and policy must be independently
verified before use. These directory endpoints do not accept relay submissions.

## Required adapter contract

`preflight` verifies the pinned full chain identity, approved code and policy,
canonical bond initial identity, current worker status and live backing, quote
signature/expiry/index, exact fee output and full native proof simulation. It
returns a positive funding reservation. `prepare` produces a real ML-DSA-44 FC
acceptance and exact funded wallet message without broadcasting, using the
journal-assigned slot/issue time and no more than the reserved funding.
`validate_prepared` independently checks those bindings; `recheck` reads current
state immediately before the single network write. `evidence` verifies portable
finality for the exact destination execution or a terminal refusal. Neither a
source wallet transaction nor RPC majority corroboration is automatically such
proof. Methods must refuse if the required verification capability is unavailable.

A release adapter must use production key management, never
`test/pq-contracts/test-pq-contracts-sign`. It must not use
`wallet broadcast-prepared --acknowledge-unpinned-manual-broadcast` as a purported
production custody boundary. JSON received from a network is not an `Evidence`
object merely because it has matching field names. `Journal.finish` is internal
trusted integration plumbing, never a public evidence-upload endpoint.

## Running local engine tests

```sh
python3 -m unittest discover -s test/bonded-relayer -p test_engine.py -v
python3 -m unittest discover -s test/bonded-relayer -p test_journal_limits.py -v
```

These exercise the real SQLite implementation with an explicitly fake adapter.
They prove durability/binding properties, **not cryptographic validity or live
network service readiness**. Native collateral tests live in `test_native.py` and
must run with the actual FunC/Fift/emulator and isolated test signer. Missing
native tools are errors, not skips. The workflow also runs wallet fee-output tests
with real note delivery encryption and ownership/body reconstruction.

`doc/bonded-relayer-implementation-status.md` separates the integrated baseline CI,
the subsequent source-hashed SQLite admission correction, and historical core
receipts. The `Relayer delivery integration` workflow prepares source, dependencies
and native binaries; it does not exercise a funded multi-operator relay network.

## Still required for activation

The [native local provider](provider/README.md) supplies real Bond/account proofs,
quote/descriptor generation, complete private-transfer simulation, funded V3
messages and positive destination finality/commission import for global id 3.
Its live local acceptance also exercises two operators, restart and spending
imported commissions. The requirements below still apply to production scope
and the complete C2 failure matrix.

A reviewed concrete production chain/signing/finality adapter; authenticated quote
and receiving-descriptor generation; full Shield proof validation and finalized
fee-note credit; deployment/lifecycle commands and a client relay workflow;
bounded quote/submission/status daemon, private transport, anti-DoS and service
observability; reviewed economic parameters and an approved code/policy release;
two independent funded operators on a distributed localnet, including restart and
failover; independent and third-party security review and existing Shield
activation gates. SDK, directory and journal components do not complete these
integrations. Energy remains unimplemented and is not a dependency.
