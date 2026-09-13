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
| C0 provider | Admitted public-key object; canonical, noncofactored verification using existing cryptographic libraries | 86 real signature/encoding cases, including valid R=identity; subgroup and equation guard removals | Signer provider and keyring access restrictions |
| Committee and certificate verification | Owned immutable admitted snapshots, expected-duty binding, complete roster and all signatures | 40 cases across five roles; exact quorum, below quorum, corrupt surplus signature, duplicate identities and context mismatch | Authenticated native state adapter, session derivation and consensus call sites |
| Native cells | Canonical AuthBytes and native BOC adapter | 20 round-trip/malformed-BOC cases through 32 MiB of incompressible data; direct hash and canonical-partition guard removals | Rust native-cell adapter and authenticated Config46/registry carriers |
| Identity lifecycle | C++ per-identity register/rotate/retire/cancel and consecutive-block due-transition application | 76 differential cases with controlled, separately typed authority callbacks; predecessor and block-gap guard removals | Real owner/admin/PoP proof verification, Rust implementation, transactional chain storage and global scheduling |
| Object transfer | C++ canonical inline/manifest handling, bounded reader and per-principal chunk store | Chunk and whole-object hash substitution, quota, duplicate upload, expiry, aggregate read budget; four guard removals | RPC authentication, anchor-scoped access and Rust adapter |
| Thin transport | C++ and Rust framing for all 15 methods, strict duplicate detection after JSON escape decoding, binary shape and request/error correlation | 182 cases per implementation; duplicate-name, request-correlation and error-retry guard removals | Endpoint semantic validators, proof/receipt/permit authentication and services |
| Signer persistence | Frozen SQL contract remains unchanged | No production signer execution claim | Durable transaction journal, provider fencing, rollback detection, receipt issuance and actual failure-path tests |
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
and two native-cell mutations, with restored baseline runs.

The frozen artifact record passes; all 38 historical production files in its
boundary remain unchanged. The generated binding check, Rust formatting, Clippy with warnings denied and
whitespace checks pass. These results describe the working tree, not a committed
HEAD or a GitHub CI result.

`.github/workflows/validator-auth-p0-implementation.yml` builds the focused native
libraries and Rust crate on Ubuntu x86_64 and ARM, records the checked HEAD, runs
these checks and uploads evidence. It has not yet run for this implementation.
It neither triggers the full Ubuntu build nor starts a network.

## Capacity decision required for global scheduling

The confirmed committee limit is 400. It is not an implicit limit on all live
registry identities across elections, committees and future key registrations.
Historical keys and retired identities must remain independently retainable.

A scheduler that simply scans 400 identities would silently add a new registry
admission rule. Before implementing that rule, confirm whether 400 also limits
identities with active or pending keys. If it does not, the authenticated due
index and per-block admission/work budget must be specified explicitly; a local
private queue cannot substitute for replayable chain state. The current library
therefore implements only bounded per-identity transitions and does not invent
a global cap or silently discard due work.
