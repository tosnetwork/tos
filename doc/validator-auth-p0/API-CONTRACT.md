# Canonical signer and client contract

Status: frozen design v1, revision 5; no service or network is activated.
[canonical-schema.json](canonical-schema.json) is the sole binary encoding authority.
[transport.schema.json](transport.schema.json) defines the thin JSON shape only.
The reference decoder reads the ordered field arrays directly. Integers, tag/version/
flags, lists and blobs use WIRE.md primitives. Each method has exactly one request
and one success type plus VAEr. There is no peer-selected type name or loose JSON
payload. All 15 method numbers and paths are assigned in the schema. Numbers 1..7
are signer methods, 8..13 are client RPCs, and 14/15 are bounded object download/
upload methods shared by clients and signers. Unknown numbers/versions fail.

## Framing and correlation

POST requests have exactly `api_version`, `request_id`, `request`; responses have
exactly `api_version`, `request_id`, `result`, `error`. api_version is the string
"1". request/result/error contain lowercase hex of their assigned canonical binary
object; exactly one result/error is non-null. No JSON numbers, nested alternatives,
unknown fields, compression or redirects. GET capabilities has no body and is
semantically the canonical empty VAq1 request; its request ID is 32 zero bytes.

Parse UTF-8 strictly and reject duplicate member names, including escaped aliases,
at **every nesting level while parsing**, before constructing a map or invoking
JSON Schema. Schema validation after a last-value-wins parser is nonconforming.
Transport member order and whitespace do not affect signed bytes. Total UTF-8
request/response is <=4194304 bytes; decoded binary object is <=2000000 bytes.
Check declared lengths before allocation. This aggregate cap also bounds the sum
of proof attachments; per-field maxima are not simultaneously guaranteed to fit.
An oversized response returns a bounded error, never a partial object or truncated
proof. All h values are exactly 32 bytes. The only JSON integer is version "1";
all inner integer widths are fixed by the binary schema.

For sign and get_result, request_id is H(sign-request, complete VAS1). All other
non-capability IDs are H(api-request, method:u8 || canonical_request). Responses
must echo that ID and their assigned method result. Error embeds the same ID and
method, even when its result is unknown. A malformed envelope with no recoverable
canonical ID receives BAD_REQUEST with zero ID; no signing may have started.
get_result is explicitly a **sign-result** query, not a generic task-status API.
Other mutating methods reconcile through an explicitly requested identical
method invocation: its exact previously committed result is returned without
another primitive call. Their request ID and result receipt remain method-specific.
Stage additionally reserves H(possession-request, complete PoP preimage), excluding
transport permit/fence changes; one update/key cannot consume capacity twice.
Uncertain stage execution remains reserved/burned and returns RESULT_UNCERTAIN;
only a reviewed recovery can finish it. Retire only journals intent, and prepare
reconciles the provider by its durable preparation ID before generating again.
These are not automatic retry permissions.

Preparation ID is a separate durable idempotency key: equal preparation_id with
different parameters conflicts even though its transport request ID changes.

The request/result association is semantic, not just an envelope echo:

| Method | Additional required association |
| --- | --- |
| get_capabilities | Interface digest matches the accepted profile; sorted unique admitted profiles are a subset of installed profiles; flags are 0/1 and limits no larger than this contract. Claims do not enable a suite. |
| get_public_key | H(key,result) equals requested key_id; this service read is not chain authority. |
| prepare_key | Identity, role/profile, epoch and validity match request; opaque handle nonzero. mode=0 generates and provider_handle=zero; mode=1 selects a nonzero locally provisioned provider handle. Raw key bytes are never accepted. fence is nonzero. |
| stage_key | VAK1 equals VAU1.new_key and returned VAK1; PoP binds this exact update ID and key reference. Only register/rotate; input possession list is empty because this call creates PoP. Verify owner and current admin before invoking PoP. |
| sign | Recompute VAS1 and request ID from canonical empty-signature template; handles are nonzero, unique, and exactly resolve to ordered keyrefs. Returned record reconstructs identical VAS1, has every required signature, same fence and statement ID. Validate actual signatures before consuming as network authority. |
| get_result | Exact requested sign ID, state variant, fence and statement; COMPLETE contains the original SignResult, not a re-signed result. |
| retire_key | Only retire/cancel; key_id and update_id match returned receipt. For cancel, key_id is the pending new key (register/rotate) or old key (retire), resolved from the authenticated target transition. |
| getProfile | Pinned Config46 proof binds interface digest and selected policy; installed/can_parse/can_verify are local claims, active profiles come from the proved policy. All flags 0/1; no inferred activation. |
| getPolicy / getKey | Returned object hashes to requested ID; proof binds that entry at pinned anchor. |
| getRegistry | Query ID, strict identity order, exclusive cursor boundary and authenticated range completeness at one anchor. |
| getCertificate | H(certificate,bytes) equals request ID, era=1, interface digest matches the era; committee and policy proof IDs match the duty. Unsupported historical formats return UNSUPPORTED_PROFILE here; use the existing historical API without conversion. |
| verifyCertificate | Successful response binds exact certificate, duty, policy, committee, sorted unique signers and verified full-roster weight. Invalid/unsupported proofs produce an error, never a successful false/partial weight. A remote assertion is not a light-client proof. |

## Four independent authorization types

VAA1 contains four explicitly typed lists, each 0..1, in fixed order. There is no
untyped "authority proof" union. Owner, possession, administration and governance
use different tags, signing domains and independently trusted verification paths:

* VAOw: owner account and stake ID must equal authenticated VAI1/allocation; its
  proof establishes execution of the exact H(update,VAU1) approval by that account
  under normal stake ownership/value/timelock rules. Operator TLS is not approval.
* VAPo: exact update ID and new keyref; signature is over LIFECYCLE.md's PoP
  preimage, with admitted new-key material. It cannot authorize the old identity.
* VAAd: exact update ID and target identity; canonical VAC1 with role 5 and VAU1
  payload. Every component of that identity's **current inclusion-time** admin
  profile is required. It supplies identity authority, not stake or governance
  weight. Certificate records contain exactly this identity for this purpose;
  use identity-signature verification, not the global two-thirds rule.
* VAGo: exact update ID and trusted governance committee; canonical VAC1 role 5
  satisfying current-policy full-roster quorum plus normal configuration rules.
  The wire committee claim cannot supply its own trust anchor or weight.

Register/rotate require owner+PoP+current admin; the first allocated identity's
register requires owner+PoP and no admin, as specified in LIFECYCLE. Retire/cancel
require current admin only. Election additionally needs owner+current admin and
normal elector checks. Policy/config require governance only, plus native config
rules. All unused lists are empty; extra authorization is rejected, not ignored.
Stage input is the same required set with PoP absent, and its result supplies PoP
for the final apply. A stage receipt or PoP is not evidence of chain inclusion.
The caller must still submit the fully authorized update through the existing
validated native apply path; this profile adds no unauthenticated submit endpoint.

## Context permits and durable receipts

VAPt and VARt are service evidence, **not any of the four chain authorizations**.
Their canonical bodies bind H(service_policy,VASp). Each carries an ordered
list of 1..2 service_component values (suite, parameters, key_id, signature).
Separate locally trusted permit and receipt policies map the stable issuer
principal to its policy ID, exact required component list and public keys.
The received list must equal that required list, sorted and unique; every
component verifies the complete canonical body. Issuer identity and signing key
identity are separate. C0 admits only Pure Ed25519 (1,1), exactly 64 signature
bytes, under WIRE rules; the reference supports no unallocated PQ suite.
A future approved suite can use the existing bounded slots without a wire upgrade.
Service policy revisions start at 1 with zero predecessor and advance by one
with the previous policy hash; installation/rotation is authenticated by the
independent service trust mechanism, never by a peer-supplied policy. Retained
receipts use their explicitly retained trusted historical policy and frontier.
Audience is the configured service/client principal. Unknown issuer, policy or
version fails. An on-chain validator key cannot bootstrap service trust.

Permit binds independently established network/genesis, full masterchain anchor,
registry root, policy, committee, session, identity, method, subject, audience and
fence. Subject for sign is H(statement,VAS1); for stage/retire it is H(update,VAU1).
The authenticated adapter derives all these inputs after validating the candidate/
vote or admin intent; it never signs a peer's self-asserted context. Registry root
is the Config46 identity/key registry commitment authenticated at the anchor.
expires_mc is inclusive, >= anchor.seqno, <= anchor.seqno+128 without overflow;
consumption requires anchor.seqno <= independently trusted current coordinate <=
expires_mc, live session/duty permission and current external fence. Older session
permits can be renewed from the still-fixed snapshot, but admin authority uses
current inclusion state. Permit signature alone does not replace these checks.

Receipt binds issuer/audience, request ID, method, subject, result hash, positive
journal sequence, nonzero fence, state and permit ID. For prepare (no permit),
context_id=zero and subject=H(api-subject,canonical_request); stage/retire use that
same request subject and H(permit,VAPt). Sign uses statement ID and permit ID.
COMPLETE result hash = H(api-result, method:u8 || canonical result_body); the four
explicit *_result_body types in the schema omit receipt and have distinct tags,
avoiding circular commitments. The result must pass semantic association before
receipt verification. RESERVED/BURNED receipts use method=5, original statement
ID, result_hash=zero, original permit ID and fence; they contain no partial result.
Receipt journal sequence is checked against the independently retained frontier
for rollback detection; a valid old signature alone cannot prove freshness.
Receipts convey no quorum weight, key activation, retirement or capacity refund.

Request state tags: ABSENT=0 has zero statement/fence and empty result/receipt;
RESERVED=1 and BURNED=3 have nonzero statement/fence, empty result and one matching
receipt; COMPLETE=2 has one matching SignResult and empty separate receipt. Unknown
state tags are rejected. Durable transitions are ABSENT -> RESERVED -> COMPLETE or
BURNED, never backwards. ABSENT after an uncertain external call does not authorize
another primitive invocation. A retry returns exact committed bytes, including
fence/receipt, even if a newer service instance now reads them. get_result must
verify retained original request/permit context to validate its embedded receipt.

VAEr codes are the 14 fixed schema allocations. request_state additionally allows
UNKNOWN=4 **only in errors**; unknown state must not be reported as ABSENT. Message
is <=256 UTF-8 bytes, diagnostic only. retryable=1 exactly for codes 10/11/12 on
reads (1/2/6/8..14) and identical idempotent chunk uploads (15), otherwise 0. Automatic retry never creates a new sign/preparation/
stage/retirement invocation. Backend failure cannot select weaker crypto.

## Snapshot, cursor and proof references

VAB1 pins masterchain seqno/root/file/resulting-state. Clients independently
establish that block's validity/finality and its state commitment. All nonzero
hashes and all proofs/results/cursors must match this **entire** anchor, not just
height. Local/floating latest state is forbidden for verification.

VAF1 includes this anchor, kind, exact object ID, H(proof,proof bytes) and a
VAOv of transfer kind 5 resolving to at most 64 MiB of native proof BOC. Kind assignments: 1 owner approval execution; 2 policy dictionary
entry; 3 identity dictionary range; 4 key dictionary entry; 5 committee snapshot;
6 Config46 profile. For kind 6, object ID is H(profile_state,VAPs), binding
interface digest, selected policy ID and ordered active suites proved from
Config46 plus the policy map; installed/parse/verify remain service claims.
Unknown kinds are refused. Parse using the existing native
Merkle/BOC verification rules, prove linkage to the independently trusted state
root, and decode/hash the expected value using this schema. Proof hash is an
attachment integrity check only. Native proof verification is a mandatory integration
gate; the reference callback tests binding and fail-closed behavior, not a new
Merkle algorithm. Noncanonical outer objects and extra unrelated values fail.
For committee/policy proofrefs in certificate results/verification requests, object
IDs equal the duty commitments; historical committee retention follows ACTIVATION.

Registry query ID = H(registry-query, VAB1 || limit:u8), limit 1..128. Cursor stores
that query ID, exact anchor and last_identity; start is exclusive. No service MAC
is needed: the cursor has no authority, and clients authenticate the returned range.
Return 1..limit increasing nonzero identities, or an empty **terminal** range when
there are none. Each page's range proof proves all entries after requested start
through returned last (or dictionary end); absence of a cursor proves no further
entry. A next cursor has the same query/anchor and exactly the last returned ID.
The kind-3 proof object ID is H(registry-page, query_id || requested_start:h ||
canonical list(u8,128,Identity) || next_cursor:list(u8,1,Cursor)). An identity's
individual hash is not a completeness proof. Cross-page state roots, duplicate/
reordered identities, skipped entries, and false terminal pages fail. Accumulate
only pages whose native range proof verifies. The empty final page is explicit,
not an absent/malformed response disguised as completion.

C0 retains a 524288-byte active certificate budget. The generic carrier supports
32 MiB canonical objects without changing that policy. Remote service, journal
witness, authenticated BOC proofs and full multi-node execution remain production gates.


## Canonical bounded object transfer

VAOv is the only carrier for certificate and native-proof attachments and new TL
wrappers. Transfer kinds are 1 key, 2 policy, 3 committee, 4 certificate, 5 proof
BOC, 6 envelope, 7 update; these are distinct from proofref semantic kinds.
A nonempty object of <=65536 bytes MUST be inline with no reference. A larger
object MUST have empty inline and exactly one VAOr. Carrier and manifest kinds
must match the expected field. Canonical objects are <=33554432 bytes; proof BOCs
are <=67108864 bytes. These limits never relax active policy or native proof limits.

VAOr binds kind, exact byte length, H(kind-domain, complete object) and ordered
chunk hashes. The kind domains are key/policy/committee/certificate/proof/envelope/
update. Chunk size is 1048576; count is exactly ceil(length/chunk_size), at most
32 for canonical objects or 64 for proof BOCs. All chunks except the last are full.
Chunk i hashes H(object-chunk, object_id:h || i:u8 || chunk_bytes). No alternate
partition, missing/repeated index, extra tail or compression is accepted. Verify
each chunk, then full object hash, then canonical decode and semantic authentication.
Hash consistency supplies integrity only, never authority or proof validity.

Method 14 getObjectChunk and method 15 putObjectChunk use the paths and types in
the machine schema. Both bind the exact request anchor, manifest and zero-based
index. Results echo the entire anchor, H(object_ref,VAOr) and index; download
returns the exact chunk; upload acknowledges only its bounded storage. Neither
acknowledges chain inclusion or signing. A missing object gives HISTORY_UNAVAILABLE;
object-storage quota exhaustion gives STORAGE_UNAVAILABLE (10). An identical upload is idempotent.
After upload, the ordinary typed request uses the same VAOv manifest; the service
resolves it before request validation or any authorized stateful primitive.

Authenticate the transport principal and apply admission quotas before allocation
or fetching. A principal may reserve at most four partial objects and 64 MiB total;
reserve the full advertised length at first chunk. Aggregate resolved attachments
per request are also <=64 MiB, with bounded streaming or one bounded buffer.
Implementations enforce a finite global quota and timeout and may return a bounded
error on exhaustion. Completion, explicit local eviction or timeout releases
storage only, never signer capacity or duty reservations. Retained completed objects
remain subject to the same total storage budget; moving a buffer is not a refund.
Chunk lookup is restricted to the admitted object and principal/anchor context;
it is not a URL fetch or arbitrary storage API. ACLs protect service-specific data.
The Receiver oracle models partial storage and integrity; production implements
transport authentication, aggregate quotas, expiry and completed-object retention.
