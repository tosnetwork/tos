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
is never automatically re-signed or rebroadcast. A signing/preparation failure
leaves a reserved record for investigation; it does not silently reuse a slot.

The `body_sha256` field hashes **serialized bytes**, for local journal integrity.
It is not a TVM representation hash. `Prepared.message_hash` is the actual TVM
hash, independently recomputed by the adapter. The FC acceptance uses the TVM
body identity; an adapter must not substitute the serialized-byte digest.

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
```

These exercise the real SQLite implementation with an explicitly fake adapter.
They prove durability/binding properties, **not cryptographic validity or live
network service readiness**. Native collateral tests live in `test_native.py` and
must run with the actual FunC/Fift/emulator and isolated test signer. Missing
native tools are errors, not skips. The workflow also runs wallet fee-output tests
with real note delivery encryption and ownership/body reconstruction.

## Still required for activation

A reviewed concrete production chain/signing/finality adapter; persistent quote
and receiving-descriptor index allocation; bounded public HTTP/private transport;
read-only discovery/indexer integration for the new code identity; release policy
and code-hash publication; two-independent-operator funded localnet and restart/
failover tests; independent security review. This directory must not be advertised
as completion of those remaining components. Shield and Energy status are unchanged.
