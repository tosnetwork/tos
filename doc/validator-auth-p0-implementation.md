# P0 production implementation

Implementation branch: `feat/validator-auth-p0`, based on main
`2004ce5e618c4a9d8ed5fe5ae51912d65bb524cd`.
The normative design remains v1 revision 3, fingerprint
`9b118505ab9a3f68118dc50b51f2742b3d29ca81c6be215cf54b28f4de83b568`.
This is an implementation in progress, not P0 acceptance. No network activation
or PQ suite allocation is authorized by this work.

## Execution boundaries and falsifiable checks

| Boundary | Implementation | Verification | Remaining integration |
| --- | --- | --- | --- |
| Ordered binary types | Production C++ library and Rust crate, generated typed bindings to all 70 schema types | Exact frozen bytes and 145 malformed binary inputs through both libraries | Production endpoint/caller wiring |
| C0 provider | Admitted public-key object; canonical, noncofactored verification using existing cryptographic libraries | 86 real signature/encoding cases, including valid R=identity; subgroup and equation guard removals | Keyring access restrictions and prepare/stage/retire integration |
| Committee and certificate verification | Owned immutable admitted snapshots, expected-duty binding, complete roster and all signatures | 40 cases across five roles; exact quorum, below quorum, corrupt surplus signature, duplicate identities and context mismatch | Authenticated native state adapter, session derivation and consensus call sites |
| Native cells | Canonical AuthBytes and native BOC adapter | 20 round-trip/malformed-BOC cases through 32 MiB of incompressible data; direct hash and canonical-partition guard removals | Rust native-cell adapter and native chain apply |
| Identity lifecycle | C++ per-identity register/rotate/retire/cancel and consecutive-block due-transition application | 76 differential cases with controlled, separately typed authority callbacks; predecessor and block-gap guard removals | Native owner/admin adapters, Rust implementation, transactional chain storage and global governance operations |
| Object transfer | C++ canonical inline/manifest handling, bounded reader and per-principal chunk store | Chunk and whole-object hash substitution, quota, duplicate upload, expiry, aggregate read budget; four guard removals | RPC authentication, anchor-scoped access and Rust adapter |
| Thin transport | C++ and Rust framing for all 15 methods, strict duplicate detection after JSON escape decoding, binary shape and request/error correlation | 182 cases per implementation; duplicate-name, request-correlation and error-retry guard removals | Endpoint semantic validators, proof/receipt/permit authentication and services |
| Native registry state | Config46 dictionaries and authenticated due-transition replay, immutable key archive and owned successor state | 501 identities / 2506 keys, exact cell/hash restart, pending effects, duplicate epoch and rejected-block atomicity | Native block apply, elector/config operations, persistent dictionary performance and Rust parity |
| Native state proofs | Actual masterchain Config8/9/10/16/46 and Merkle proofs for profile, policy, key and registry ranges | State-root substitution, omitted entries, false terminal page, unrelated revealed values and capability guard removals | RPC node wiring, committee/certificate/owner proofs, large-proof publication and Rust native adapter |
| Authority primitives | Real C0 PoP, current identity-role-5 verification, independent permit and receipt trust | Wrong network/update/signature/current admin key, stale permits, historical receipts, inclusive 128-block boundary | Native owner execution and governance adapters and all mutation endpoints |
| Signer persistence | Native append-only safety ledger, actual C0 secret provider, witness consumption and sign/get-result service | Both-order conflict rules, exact retransmission, journal/provider backup rollback, stale fence, terminal retention, real fsync failure, unknown outcome refusal | Prepare/stage/retire endpoints, durable receipt issuer and native consensus permissions |
| Operational release | No activation change | No testnet/release acceptance claim | Required testnet, genesis, operator recovery, approvals and C0 performance evidence |

Generated bindings never rewrite the frozen schema or vectors. Parsed transport
frames do not establish chain authority. Snapshot admission validates an owned
roster, but still requires independently authenticated state/committee inputs.
The library checks do not replace native state proofs or production consensus
integration. The lifecycle test callbacks establish control-flow behavior only;
they are not native owner, governance, PoP or administration proof verification.

`ChunkStore` is one authenticated principal's bounded storage and requires caller
serialization. Its TTL expires storage reservations, not signer journal entries
or historical chain keys. `ObjectReader` charges an aggregate budget before
fetching; callers must use one reader for all attachments of an operation.

## Local evidence and CI

Local native and Rust builds and the cases above passed on macOS/ARM. The guard
harnesses compile isolated production mutations and require assertion failures;
compiler errors, imports and abnormal driver exits are not accepted as kills.
AddressSanitizer and UndefinedBehaviorSanitizer checks also pass for native
transfer and transport. Leak detection is unavailable on the local macOS runtime
and is not claimed. There are 15 C++ core/lifecycle/transport/transfer mutations, seven Rust mutations
and three native-cell mutations, with restored baseline runs. The added native
state/authority/proof, journal, signer/provider and local channel harnesses kill
13, 11, 7 and 6 compiled guard removals respectively.

The frozen artifact record passes; all 38 historical production files in its
boundary remain unchanged. The generated binding check, Rust formatting, Clippy with warnings denied and
whitespace checks pass. These results describe the working tree, not a committed
HEAD or a GitHub CI result.

`.github/workflows/validator-auth-p0-implementation.yml` builds the focused native
libraries and Rust crate on Ubuntu x86_64 and ARM, records the checked HEAD, runs
these checks and uploads evidence. The first foundation commit passed both focused CI architectures; the additions
above require their own new-HEAD CI evidence.
It neither triggers the full Ubuntu build nor starts a network.

## Registry capacity and scheduling decision

The confirmed committee limit is 400. It is not an implicit limit on all live
registry identities across elections, committees and future key registrations.
Historical keys and retired identities must remain independently retainable.

The implementation does not invent a 400-identity registry admission rule. Due
indexes are derived only from authenticated VAI1 records and rebuilt during
native state loading/replay. They never replace the committed transitions. The
archive keeps canceled and retired key versions; duplicate per-slot epochs are
rejected. Consecutive blocks apply due effects before administrative requests.

The initial native adapter admits at most one million entries / 256 MiB of decoded
values per local load. These are explicit operational limits: exhaustion fails
without truncating identities or history. It currently owns and copies maps for
transactional successor construction. Persistent native dictionary updates and
measured per-block work remain integration work; this adapter does not claim
constant work independent of archive size.

## Current local signer boundary

The signer validates independently supplied consensus permission, service permit
signature, exact key handle/reference and canonical VAS1 before reserving. It
syncs the journal and witness before a provider invocation. The provider syncs
its own reservation and consumes a witness claim before signing. It retains the
exact signature, verifies it and persists completion. The signer independently
verifies the signature, then syncs its complete result and witness before release.
A repeated completed request returns the original bytes and receipt. An uncertain
request remains reserved; it cannot automatically invoke the provider again.

The file witness is retained separately from signer/provider backup files. It
owns an exclusive OS lock and persists monotonically increasing writer generations,
journal frontiers, receipt hashes and consumed primitive requests. File restoration
against an intact witness fails closed. It is a software C0 deployment component,
not hardware evidence against rolling back the entire host/VM or losing the witness.
All three components currently require serialized ownership; automatic failover
and a remote/HSM witness require their own deployment evidence.

Local tests use real generated provider keys and Ed25519 signatures. Consensus
permissions and receipt issuance use controlled, independently typed test adapters;
this is not a running native consensus adapter or a production receipt-key store.
Separate signer and provider/witness processes now exercise the production local
channel. The host serializes writer-generation changes and actual C0 primitive
execution in one dispatch loop. Both ends check OS peer credentials; private
socket mode, request bounds and deadlines precede request allocation/handling.

The local drill sends SIGKILL before reservation, before the primitive, after the
primitive and after complete commit. Unknown requests remain reserved without
another provider write; completed replies preserve their original receipt/fence
through signer and provider/witness process restarts. Losing the witness stops
calls. These are process-kill tests, not a claim of physical power-loss testing.
The actual fsync error-injection test separately verifies failure handling.
Multi-node native execution remains open. The frozen
profile and all historical production paths remain unchanged.

Permits for a still-live old session can be renewed at a newer independently
trusted masterchain anchor. The VAS1 birth coordinate, keys, committee and policy
remain fixed; permit anchors before session birth are refused. This separates the
permit's bounded freshness window from native session lifetime.
