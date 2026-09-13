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
| C0 provider | Admitted public-key object; canonical, noncofactored verification using existing cryptographic libraries | 86 real signature/encoding cases, including valid R=identity; subgroup and equation guard removals | Native provider inventory reconciliation and routing |
| Committee and certificate verification | Owned immutable admitted snapshots, expected-duty binding, complete roster and all signatures | 40 cases across five roles; exact quorum, below quorum, corrupt surplus signature, duplicate identities and context mismatch | Authenticated native state adapter, session derivation and consensus call sites |
| Native cells | Canonical AuthBytes and native BOC adapter | 20 round-trip/malformed-BOC cases through 32 MiB of incompressible data; direct hash and canonical-partition guard removals | Native chain apply |
| Identity lifecycle | C++ and Rust per-identity register/rotate/retire/cancel and consecutive-block due-transition application | 104 differential cases per language with controlled, separately typed authority callbacks; predecessor and block-gap guard removals | Native owner/admin adapters, transactional chain storage and global governance operations |
| Object transfer | C++ and Rust canonical inline/manifest readers; principal/anchor-scoped C++ store and atomic proof publication | Chunk and whole-object hash substitution, quota, duplicate upload, expiry and aggregate read budget; eight scoped-store guard removals | Authenticated public RPC wiring and Rust storage adapter |
| Thin transport and API association | C++ and Rust framing and semantic association for all 15 methods, including result receipts, proof attachments and cursors | 182 framing cases and 133 semantic cases per language; direct signer-list, receipt-hash and context guard removals | Native node context, committee/certificate RPC and remote mTLS deployment |
| Native registry state | Config46 dictionaries and authenticated due-transition replay, immutable key archive and owned successor state | 501 identities / 2506 keys, exact cell/hash restart, pending effects, duplicate epoch and rejected-block atomicity | Native block apply, elector/config operations, persistent dictionary performance and Rust parity |
| Native state proofs | C++ and Rust actual masterchain Config8/9/10/16/46 and Merkle proofs for profile, policy, key and registry ranges | State-root substitution, omitted entries, false terminal page, unrelated revealed values, detached physical cells, capability and atomic-publication guard removals | RPC node wiring, committee/certificate/owner proofs and Rust global registry apply |
| Authority primitives | Real C0 PoP and current identity-role-5 verification; independent permit/receipt trust in C++ and Rust | Wrong network/update/signature/current admin key, stale permits, historical receipts and inclusive 128-block boundary; 25 shared service-trust/polling cases per language | Native owner execution and governance adapters and native mutation admission |
| Signer persistence | Native append-only safety ledger, actual C0 secret provider, witness consumption and sign/get-result service | Both-order conflict rules, exact retransmission, journal/provider backup rollback, stale fence, terminal retention, real fsync failure, unknown outcome refusal | Native consensus permissions and remote serving |
| Signer administration | Durable prepare/stage/retire/cancel intent execution, provider preparation IDs and PoP reservation IDs | Real PoP and current admin signatures, owner refusal before reservation, exact receipts, cancellation target, provider rollback and six process-kill boundaries | Native owner execution and node context wiring |
| Native Keyring isolation | Factory-installed durable public-key deny set, private-operation guards, shared/exclusive directory locks and an asynchronous drain barrier | Actual signing/decryption/export before designation; every private API refused afterwards; restart, damaged records, competing processes and compiled guard removals | Provider inventory reconciliation before native session admission |
| Service issuer | Purpose-separated persistent C0 service keys, typed permit/receipt signing, local rotation and public policy history | Actual signer receipts, restart, key/policy binding and nine compiled guard removals | Independent operational trust distribution and node permit adapter |
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
and is not claimed. There are 20 C++ core/lifecycle/transport/transfer mutations, 35 Rust mutations
and three native-cell mutations, with restored baseline runs. The added native
state/authority/proof, journal, signer/provider and local channel harnesses kill
25, 11, 7 and 6 compiled guard removals respectively. Scoped object storage,
service issuers and C++ API semantics add eight, nine and eight removals. The
administration harness adds eleven. The combined implementation harness contains
227 compiled guard removals, including 17 API admission/cache checks, 25
native HTTP checks, 17 Rust native cell/proof checks and 25 native Keyring checks.

The frozen wire/API design and fingerprint remain unchanged. The updated evidence
record inventories exact additive Keyring insertions: 36 historical files remain
byte-for-byte unchanged, and removing only the registered insertions from the two
Keyring files recovers their original baseline hashes. The checker rejects changes
to either historical or inserted bytes; the baseline hashes were not replaced. The generated binding check, Rust formatting, Clippy with warnings denied and
whitespace checks pass. These results describe the working tree, not a committed
HEAD or a GitHub CI result.

`.github/workflows/validator-auth-p0-implementation.yml` builds the focused native
libraries and Rust crate on Ubuntu x86_64 and ARM, records the checked HEAD, runs
these checks and uploads evidence. The previous implementation milestone passed both focused CI architectures; each
new addition requires CI evidence attached to its own HEAD.
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
permissions remain controlled, independently typed test adapters. The issuer
rehearsal and separate-process crash drill use the production persistent receipt
key store; they still do not establish a running native consensus adapter.
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

## Service and attachment completion boundaries

`ServiceIssuer` owns a mode-0600 durable store for one independently configured
issuer, audience and purpose. Permit and receipt stores cannot sign each other's
body type. Rotation persists a fresh key and consecutive policy revision before
returning public configuration; it does not install that configuration into any
verifier. Old receipts remain verifiable against retained trust and the independent
witness. Current permit trust rejects older policies after rotation. Only typed
validated local expectations reach permit issuance. No private export/raw-sign
operation is exposed. Operational trust distribution remains separate work.

Native proof publication now stores larger proof BOCs before returning their
manifest. Publication failure produces an error. A real 128-identity registry
with pending operations exercises a proof exceeding 64 KiB. Verification also
counts reachable cells: the generic historical BOC parser can accept a BOC that
contains an unreferenced physical cell, but the P0 proof entry point refuses it.
The historical parser itself is unchanged.

The scoped store reserves complete advertised lengths against principal and
global budgets. Objects cannot be fetched under another principal or full anchor.
Its initial local admission policy limits each principal to four retained objects
in total, including completed objects, and 64 MiB; the global limit is at most
256 MiB. Expiry releases storage only. API parsing and association do not establish
object authority. The shared C++/Rust semantic tests deliberately use proof
fixtures only for attachment integrity; actual Merkle evidence comes from the
separate native proof tests.

Clients can preserve verified request-state observations. The C++ and Rust polling
helpers reject terminal-state regression or byte replacement and prevent a
reserved request from changing statement/fence. Callers must authenticate each
receipt against its original request context before retaining that observation.


## Durable administration and Rust lifecycle parity

The Rust per-identity lifecycle now follows the same frozen oracle as C++: all
four operations, nonce/predecessor checks, archived epochs, exact due coordinates,
bootstrap role-5 admission and read-only session key selection. The 104 shared
cases include missing or denied typed authorizations, 65536-block scheduling and
retained old-session keys. Global native registry storage is still a separate
Rust integration boundary.

Administration uses the existing safety journal and witness, with one shared
sequence of durable frontiers and independently witnessed receipts. Prepare
reserves its canonical request and binds the separate preparation ID to immutable
parameters; renewing a fence cannot change them. The provider first reconciles
that ID, then claims generation before creating private material. A restored
provider cannot regenerate a key after an intact witness consumed its claim.
The local provider admits at most 4096 retained keys; exhaustion does not evict
historical keys. This is an operational storage limit, not a chain registry limit.

Stage performs read-only lifecycle admission, current owner/admin verification,
independent permit verification and exact provider descriptor association before
reservation. That read-only admission requires PoP to be absent and exposes no
successor state. Final chain apply still requires real PoP. The reservation ID is
H(possession-request, complete PoP preimage), excluding permit/fence changes. The
provider persists a reservation, claims the primitive and retains its exact PoP;
the service verifies the signature before committing the complete result and
receipt. An uncertain stage remains reserved and cannot invoke the primitive
again through a renewed request. No generic raw-sign operation is added.

Retire and cancel validate the current administration and exact pending target,
then journal intent only. They never delete provider keys or modify chain state.
All three methods return original complete bytes on an identical request, even
after a new writer generation. Preparation can also reconcile a completed
provider preparation after its signer process died before recording the result.
Reserved/burned sign state receipts remain exclusive to method 5; administration
reservations are internal and expose no alternative public request-state schema.

The added local process rehearsal kills the signer before provider invocation,
after provider completion and after result commit for both prepare and stage. A
separate provider/witness process executes the actual C0 operations over the
credential-checked private channel. It checks exact recovery and refusal across
writer and provider restarts. These six cases supplement the four sign-process
boundaries. They do not replace physical power-loss or native multi-node evidence.
The administration tests use real C0 PoP, current identity signatures and persistent
service issuers; native owner account execution is still an explicitly controlled
admission fixture and is not claimed complete.

## Local API execution and Rust client

The generated route tables come from the frozen 15-method schema. `SignerApi`
dispatches signer methods 1..7 to the persistent services and methods 14/15 to the
principal/anchor-scoped object store. Configured principal, method and identity
admission is enforced before execution; a listener supplies the principal, never
a request header. Public-key reads and cached result queries apply the same
identity restrictions. Cached stage/sign/retire/result responses also require the
configured network/genesis. An unauthorized state query returns UNKNOWN, not an
unproved ABSENT. Malformed framing returns BAD_REQUEST with zero correlation ID
without starting a reservation.

`NativeClientRpc` serves profile, policy, registry and key proofs from an exact
anchor-bound native-state source. Committee/certificate methods remain explicitly
unsupported until native committee/history integration exists. The library does
not infer finality from a supplied root or install peer-supplied trust.

The local listener uses HTTP/1.1 over a private Unix socket. This is a local
transport only; remote HTTP/2 with TLS 1.3 mutual authentication remains a separate
implementation/deployment boundary. Both endpoints authenticate OS credentials.
Headers are bounded to 8192 bytes and 16 fields, bodies to 4194304 bytes, with a
five-second absolute I/O deadline. Duplicate headers, transfer encoding,
compression, redirects and protocol upgrades are refused. The private provider
channel retains its separate 2 MiB frame contract and shares credential checks.

The Rust client uses the generated route table, performs one explicit invocation,
checks canonical framing/correlation and semantic association, and fetches proof
attachments at the request's exact anchor with one aggregate reader budget. Its default
semantic verifier returns `UntrustedResult`; the native state verifier returns
`VerifiedNativeResponse` only after checking independently anchored chain proof.
Independent receipt trust remains a separate verification step. No transport error creates an
automatic mutation retry. Nonblocking I/O drains buffered bytes even when a peer
closes immediately after sending; timeout configuration does not discard them.

The API rehearsal runs real preparation, PoP, signatures, receipt verification,
cache reads, scoped chunks and native profile/policy/registry/key proofs over the
local socket, including Rust-to-C++ calls. The Rust native client now verifies the four state-proof methods itself,
including a referenced 128-identity page; receipt checks in the C++ signer
rehearsal use independent service trust and the retained witness. There are 44 HTTP boundary cases across C++/Rust and 37 Rust
client cases, including all 15 semantic fixture methods, fourteen error codes,
referenced proof fetching and exact invocation counts. Fixture responses are not
chain evidence. Seventeen API mutations and twenty-five HTTP mutations must
compile and fail their named behavioral assertion; seven Rust client admission,
association and correlation removals are part of the 35 Rust guard mutations.

## Rust native verification and one-budget client composition

`tos-validator-auth-native` uses the existing native Rust cell, BOC, dictionary
and Merkle implementation. It implements frozen AuthBytes packing/decoding with
exact canonical partitioning, payload SHA-256, size/depth/occurrence admission
and declared BOC table sizes checked before native allocation. C++ and Rust read
each other's incompressible objects through the 32 MiB boundary. Historical
native codecs are unchanged.

The native state verifier independently checks the full pinned anchor, network,
masterchain state, Config8 capability, mandatory/critical Config9/10 membership,
Config16 ceiling, Config46 version/domain/fingerprint and selected C0 policy.
It recomputes the requested profile/policy/key or complete registry page from
proved dictionaries, rejects detached physical cells and unrelated revealed
values, and compares the complete canonical result. Queue/account roots and
native auxiliary headers are admitted while unrelated descendants remain pruned.

`Client::call_verified` shares framing, correlation and one attachment reader with
an output-specific verifier. The default semantic output remains explicitly
untrusted. `NativeStateVerifier` returns a privately constructed verified type;
it receives an independently established anchor/network, not a peer's new trust
claim. A referenced proof is fetched once, within that same operation budget.
No second semantic decoder re-fetches or double-charges it.

Current native evidence contains 64 cross-checks, including 21 C++-produced native
proof cases and 32 cross-language pack/unpack cases. The 58 Rust HTTP client cases
include those 21 native positive/negative proofs over actual Unix connections.
The real local API test verifies all four native state methods and a referenced
128-identity page in Rust, checks exactly one chunk call, and also exercises the
persistent C++ signer services. Six additional C++ proof mutations and seventeen
Rust native mutations require compiled, named assertion failures. Exported fixture
sets carry completion markers so a missing/partial export cannot silently pass.

Rust linting covers both modified authentication crates with warnings denied;
`--no-deps` excludes unrelated pre-existing lints in the native block dependency.
That dependency is still compiled and executed by the native tests. Rust global
registry replay, native committee/certificate/owner proofs and production node
and CLI wiring remain separate implementation work.


## Native Keyring designation and concurrency

`Keyring::create` installs the isolation layer used by the existing node callers.
The trusted local `protect_validator_auth_key` method blocks new private operations,
drains already-issued raw operations, durably records the public-key hash and then
acknowledges protection. All raw signing forms, decryption, single/bulk secret
export, permanent/temporary import and deletion check that layer. Public metadata
remains available. Retire, cancel, branch rollback and reimport have no removal API.
A bulk export fails explicitly instead of silently returning an incomplete backup.

Legacy instances hold shared directory locks. Designation requires an exclusive
upgrade after local raw operations drain; a competing legacy instance prevents
acknowledgment. A failed upgrade stops that already-drained instance because OS
lock conversion can release its shared lock. A pending designation also blocks
new exports and admissions, including unrelated keys, until the finite drain ends.
Unrelated network keys remain usable by the owning instance afterwards.

The `validator-auth-guard` directory is a durable initialization marker. Its ledger
uses the existing durable-log framing, checksums, exclusive writer lock and sync
rules. Designation requires a same-owner Keyring directory that is not writable
by group or others. Missing/corrupt records, wrong ownership/permissions, links, detached or
replaced open ledger paths and uncertain writes fail closed. The deny archive has
an operational bound of 1,048,576 public-key hashes and a 128 MiB log; exhaustion
stops new designations without dropping history. Empty-directory temporary keyrings
cannot acknowledge persistent protection. This is local storage, not a new wire type.

`test-p0-keyring` uses real native keys and the actual factory, including a separate
process that holds a legacy keyring open. Its actor probe places raw signing and
protection in the same turn, proving that the protection callback follows the raw
result and that private exports are blocked during the wait. The historical
`test-keyring-temp-key` still passes. `keyring_mutations.py` requires exact assertion
failures after compiling the removed guards; unrelated errors and crashes do not
count. AddressSanitizer and UndefinedBehaviorSanitizer also cover the new Keyring,
isolation and durable-log sources through the same complete process test. Local
macOS testing disables leak detection; Ubuntu CI enables it.
Provider inventory reconciliation before native session admission remains
required: a local deny file alone cannot detect restoration of an entire host to
an earlier state without any designation. No hardware rollback claim is made.

The design-era whole-file boundary was evolved deliberately for native integration.
`doc/validator-auth-p0-native-insertions.json` lists the exact added bytes and their
original offsets; `check_production.py` reconstructs and hashes the original files.
The freeze record also covers this insertion inventory and updated evidence scripts.
Historical verifier bodies and historical encodings are unchanged.
