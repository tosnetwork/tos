# P0 canonical wire and signing profile

BCP 14 MUST/SHOULD terms describe the proposed contract, not an enabled rule.

## 1. Ordered binary grammar

All integers are big-endian; i32 uses two's complement. h is exactly 32 bytes.
`blob(N)` is u32 length then that many bytes, at most N; no padding. `list(w,N,T)`
is a count in unsigned width w, at most N, followed by inline T objects.
Every tagged object starts with its four ASCII tag bytes, u16 version=1, and
u16 flags=0. Untagged records have only their listed fields. Nested tagged objects
are inline, without an additional implicit length. The sole field-order authority
is canonical-schema.json; the following view is generated and checked by
contract_artifacts.py. bN denotes blob(N); lW/N/T denotes list(uW,N,T).
Zero-or-one lists explicitly encode absence/presence; there are no implicit
optional bytes. Method and authorization semantics are API-CONTRACT.md.

<!-- canonical-schema:begin -->
```text
suite = suite:u16 parameters:u16
keyref = suite:u16 parameters:u16 epoch:u64 key_id:h
component = suite:u16 parameters:u16 epoch:u64 key_id:h signature:b65536
record = identity:h components:l8/2/component
roleref = role:u8 key:keyref
key VAK1 = identity:h role:u8 suite:u16 parameters:u16 epoch:u64 valid_from:u32 valid_until:u32 public_key:b16384 capacity_domain:h capacity_limit:u64
policy VAP1 = revision:u64 previous:h interface_digest:h effective_from:u32 phase:u8 suites:l8/2/suite max_envelope:u32 max_certificate:u32
member = identity:h stake_id:h weight:u64 adnl_id:h keys:l8/10/key
committee VAM1 = policy:h election:h workchain:i32 shard:u64 catchain:u32 anchor_mc:u32 members:l16/400/member
duty VAD1 = network:i32 genesis_root:h genesis_file:h policy:h committee:h session:h workchain:i32 shard:u64 anchor_mc:u32 catchain:u32 position:u64 role:u8 payload_hash:h
statement VAS1 = duty:duty identity:h keys:l8/2/keyref
envelope VAE1 = duty:duty payload:b4096 record:record
certificate VAC1 = duty:duty payload:b4096 records:l16/400/record
update VAU1 = operation:u8 identity:h nonce:u64 previous:h effective_from:u32 old_key:h new_key:b32768 new_policy:b4096 operation_data:b4096
identity VAI1 = identity:h stake_id:h owner_workchain:i32 owner_address:h next_nonce:u64 previous:h active:l8/10/roleref pending:l8/10/transition
activation VAT1 = revision:u64 previous:h next_policy:h effective_from:u32 checkpoint_seqno:u32 checkpoint_root:h checkpoint_file:h checkpoint_state:h
observation VAO1 = suite:u16 parameters:u16 registry_root:h valid_from:u32 valid_until:u32 enabled:u8
transition VATr = operation:u8 role:u8 suite:u16 parameters:u16 old_key:h new_key:h effective_from:u32 accepted_at:u32 nonce:u64 predecessor:h update_id:h authorization_id:h
anchor VAB1 = seqno:u32 root:h file:h state:h
proofref VAF1 = anchor:anchor kind:u8 object_id:h proof_hash:h proof:object_value
owner_auth VAOw = update_id:h stake_id:h owner_workchain:i32 owner_address:h proof:proofref
possession_auth VAPo = update_id:h key:keyref signature:b65536
identity_auth VAAd = update_id:h identity:h certificate:object_value
governance_auth VAGo = update_id:h committee:h certificate:object_value
authorizations VAA1 = owner:l8/1/owner_auth possession:l8/1/possession_auth administration:l8/1/identity_auth governance:l8/1/governance_auth
permit_body VAPb = issuer:h service_policy:h audience:h network:i32 genesis_root:h genesis_file:h anchor:anchor registry_root:h policy:h committee:h session:h identity:h method:u8 subject:h expires_mc:u32 fence:u64
permit VAPt = body:permit_body components:l8/2/service_component
receipt_body VARb = issuer:h service_policy:h audience:h request_id:h method:u8 subject:h result_hash:h journal_sequence:u64 fence:u64 state:u8 context_id:h
receipt VARt = body:receipt_body components:l8/2/service_component
capabilities VAc1 = interface_digest:h installed:l8/2/suite admitted:l8/2/suite max_request:u32 max_result:u32 persistent_journal:u8 fencing:u8 stateful:u8
error VAEr = request_id:h method:u8 code:u16 retryable:u8 request_state:u8 message:b256
cursor VACu = anchor:anchor query_id:h last_identity:h
key_handle VAKh = key:key handle:h
sign_result VASr = request_id:h statement_id:h record:record fence:u64 receipt:receipt
request_state VAQs = request_id:h state:u8 statement_id:h fence:u64 result:l8/1/sign_result receipt:l8/1/receipt
profile_result VAPr = anchor:anchor interface_digest:h policy:h installed:l8/2/suite active:l8/2/suite can_parse:u8 can_verify:u8 proof:proofref
policy_result VAPl = anchor:anchor policy:policy proof:proofref
registry_result VARg = anchor:anchor query_id:h identities:l8/128/identity cursor:l8/1/cursor proof:proofref
key_result VAKr = anchor:anchor key:key proof:proofref
certificate_result VACr = anchor:anchor era:u8 interface_digest:h certificate:object_value committee:proofref policy:proofref
verify_result VAVr = anchor:anchor certificate_id:h policy:h committee:h duty:h signers:l16/400/h weight:u64
capabilities_request VAq1 =
public_request VAq2 = key_id:h
prepare_request VAq3 = preparation_id:h identity:h role:u8 suite:u16 parameters:u16 epoch:u64 valid_from:u32 valid_until:u32 mode:u8 provider_handle:h fence:u64
stage_request VAq4 = key:key handle:h update:update authorizations:authorizations permit:permit fence:u64
sign_request VAq5 = request_id:h key_handles:l8/2/h envelope_template:b262144 permit:permit fence:u64
result_request VAq6 = request_id:h
retire_request VAq7 = key_id:h update:update authorizations:authorizations permit:permit fence:u64
prepare_result VAk3 = prepared:key_handle receipt:receipt
stage_result VAk4 = key:key possession:possession_auth receipt:receipt
retire_result VAk7 = key_id:h update_id:h receipt:receipt
get_profile_request VAq8 = anchor:anchor
get_policy_request VAq9 = anchor:anchor policy_id:h
get_registry_request VAqa = anchor:anchor limit:u8 cursor:l8/1/cursor
get_key_request VAqb = anchor:anchor key_id:h
get_certificate_request VAqc = anchor:anchor certificate_id:h
verify_certificate_request VAqd = anchor:anchor certificate:object_value committee:proofref policy:proofref
sign_result_body VASb = request_id:h statement_id:h record:record fence:u64
prepare_result_body VAkb = prepared:key_handle
stage_result_body VAsb = key:key possession:possession_auth
retire_result_body VArb = key_id:h update_id:h
profile_state VAPs = interface_digest:h policy:h active:l8/2/suite
object_ref VAOr = kind:u8 byte_length:u32 object_id:h chunk_hashes:l8/64/h
object_value VAOv = kind:u8 inline:b65536 reference:l8/1/object_ref
chunk_request VAqe = anchor:anchor manifest:object_ref index:u8
chunk_result VARe = anchor:anchor manifest_id:h index:u8 data:b1048576
put_chunk_request VAqf = anchor:anchor manifest:object_ref index:u8 data:b1048576
put_chunk_result VARf = anchor:anchor manifest_id:h index:u8
service_component = suite:u16 parameters:u16 key_id:h signature:b65536
service_policy VASp = issuer:h revision:u64 previous:h suites:l8/2/suite
```
<!-- canonical-schema:end -->

Unknown versions, nonzero flags, overflow, unknown tags, wrong counts/lengths,
trailing bytes and duplicate/unknown authoritative components MUST be rejected.
There are no ignored extension TLVs, varints or implicit optional fields. Empty signature
and public-key payloads are invalid. Empty lists require explicit semantic permission.
Parsing is not authentication; a structurally representable future suite is not
an admitted C0 suite.

Suite/profile `(1,1)` is the only C0 allocation. Zero is invalid; IDs 2..32767 need
reviewed production allocation; 32768..65535 are private/test IDs forbidden in
production authority. More than two components requires a versioned upgrade.
`H(label,bytes)` is SHA-256(ASCII(`TOS/P0/`+label+`/v1`) || 00 || bytes).
Object IDs use exact schema type names: key, policy, committee, statement,
identity, update, activation, observation, transition, authorizations, permit and
certificate. The separate lifecycle identity-allocation preimage also uses
H(identity,...) as specified in LIFECYCLE.md; it is not a VAI1 state hash. No truncation is permitted.
The interface artifact digest is instead the unprefixed SHA-256 in README.md.
Future PQ review MUST assess these 256-bit hashes and inherited candidate/chain
hashes together; this is not a blanket 128-bit PQ collision-security claim.

## 2. Keys, policies and the complete roster

Key ID = H(key,VAK1), covering the entire immutable descriptor. Epoch starts at 1.
Validity is `[valid_from,valid_until)` at the session's authenticated masterchain
anchor, not local time or message arrival height. The exclusive u32 upper bound
cannot wrap. C0 keys have 32 public-key bytes and all-zero capacity metadata.

Policy ID = H(policy,VAP1). Revision starts at 1 and advances by one; previous is
zero only at genesis. C0 phase=0 requires exactly `(1,1)`, max_envelope=4096 and
max_certificate=524288. C2 phase=2 requires one classical and one approved PQ
profile in ascending `(suite,parameters)` order; C3 phase=3 requires one approved
PQ profile. Phase=1 is not an authoritative encoding: shadow uses separate VAO1
state. Observation enabled is exactly 0 or 1, and its interval is nonempty.

Committee ID = H(committee,VAM1). Include all members, including absent voters,
in strictly increasing identity order. Identities and stake IDs must be unique
and nonzero. Weights come from authenticated election state, are positive, and
sum to at most floor((2^64-1)/3). A wire claim never creates weight. Member keys
are sorted by `(role,suite,parameters)` and contain all required profiles for
roles 1..5: exactly five keys in C0, ten in C2. Key identities match their owner.
Admit actual key bytes before compiling the immutable snapshot.

The committee does not contain its session ID, avoiding a commitment cycle.
For consensus roles the new session ID is H(session, network:i32 || genesis_root:h
|| genesis_file:h || committee_id:h || native_options_hash:h || vertical_seqno:u32
|| key_block_seqno:u32). Inputs come from trusted session creation; dimensions not
used by a legacy creation path are explicitly zero. Roster, workchain/shard,
catchain and anchor are already bound by committee_id. ADNL remains transport
metadata, not a signing credential. Diagnostics never mutate a running snapshot.

## 3. Duty, payload and the bytes actually signed

Roles are proposal=1, notarize=2, finalize=3, skip=4, administration=5. Position is
u64; consensus roles must fit u32 and equal the Simplex slot. Admin uses its u64
operation nonce and target-scoped session as defined in LIFECYCLE.md.
Payload hash = H(payload, role:u8 || canonical_payload_bytes).
Native payloads retain little-endian TL inside this big-endian outer format:

| Role | Exact payload |
| --- | --- |
| 1 | Serialized consensus.candidateId, 40 bytes |
| 2 | Serialized consensus.simplex.notarizeVote including candidate ID, 44 bytes |
| 3 | Serialized consensus.simplex.finalizeVote including candidate ID, 44 bytes |
| 4 | Serialized consensus.simplex.skipVote, 8 bytes |
| 5 | Canonical VAU1 administrative intent |

Constructor, exact consumption and slot/nonce must agree with Duty. The proposal
caller still validates the actual candidate and recomputes its ID. Signing a
claimed candidate hash is not block validation. Expected genesis, policy,
committee, session and duty MUST be derived independently from authenticated state,
not copied from a received object and compared to themselves.

For each signer construct VAS1 from the complete Duty, identity and the exact
sorted required key references. Every required component signs these **identical
complete VAS1 bytes**. Signature bytes are not in VAS1. Ed25519 signs neither JSON,
a supplied prehash, a BOC file hash nor the old dataToSign wrapper. A future suite's
internal preprocessing must be explicit and authenticate the same VAS1.

VAE1 has one record. VAC1 has 1..400 strictly identity-sorted records. Reject
unknown/duplicate signers and nonmatching component profiles, key IDs or epochs.
Complete structural/resource admission before expensive verification. Verify every
included required signature, even surplus signatures after quorum. Return authorized
weight only after all succeed. Require `3*S >= 2*W` with checked/widened arithmetic;
W is the full trusted committee, not a filtered subset or supplied total.

## 4. Exact C0 Ed25519 acceptance

Suite `(1,1)` is Pure Ed25519 with internal SHA-512, not Ed25519ctx/ph. The outer
VAS1 provides domain separation. A and R must be canonical compressed Edwards
encodings: y < 2^255-19, successful curve decoding, and no x=0/sign-bit-1 alias.
Admit A only if A != identity and [L]A=identity, with L the prime subgroup order.
S is little-endian and must satisfy 0 <= S < L. Verify the noncofactored equation
`[S]B = R + [SHA-512(R || A || VAS1) mod L]A`.
R need not have a separate subgroup multiplication because the equation and
admitted A imply it. Cache admitted keys per immutable snapshot; do not put an
extra public-key subgroup multiplication on every vote.
C++ and Rust must prove the same edge-case acceptance set. These rules are for
the new suite only; historical signatures retain their historical rules.

## 5. Bounds and canonical cells

Hard caps: public key 16384 bytes; component 65536; components 2; keys/member 10;
members/signers 400; payload 4096; canonical object 33554432; envelope 262144.
C0 has the tighter policy caps above. A future activation must prove that the
entire selected committee fits its active budgets; do not trim weight/signers to
fit. TOS fixes max_validators=400; profile admission rejects Config16 values
above 400. Archives may retain more than 400 historical identities. C2 has exactly
one classical and one approved PQ component per role; C3 has one approved PQ
component. At 400 members, a C2 certificate with 65536-byte PQ signatures is
26295943 bytes and a five-role C2 committee with 16384-byte PQ public keys is
33294094 bytes. Both fit 32 MiB. These are container bounds, not an algorithm
approval or an active network budget. Larger keys/signatures or a third component
require version 2; supporting every possible future algorithm is not promised.

AuthBytes has version=1, byte_length, SHA-256(raw canonical payload) and one root
reference. Only ordinary level-0 cells occur inside it. A leaf is tag 0, seven-bit
length 1..120, exactly length*8 data bits, no refs. A branch is tag 1, three-bit
child count 2..4, u32 byte_length and that many ordered refs, no extra bits/refs.
For a nonleaf size n choose the smallest capacity `120*4^k` with `n <= 4*capacity`;
split into full capacity chunks and one possibly shorter last chunk, recursively.
No empty leaves, single-child branches, alternate balancing or trailing content.

Limit depth to ten edges below the byte-node root (eleven including AuthBytes),
400000 logical node occurrences and 67108864 serialized BOC bytes. Shared equal
cells are allowed but every occurrence counts; deduplication cannot evade budgets.
Reject cycles/exotic cells. Authenticated Merkle-proof wrappers may exist outside
AuthBytes. Hash reconstructed bytes for object IDs, not BOC index/CRC packaging.
At 32 MiB the canonical tree has 279621 leaves and 93210 branches (372831
occurrences). Native generated TL-B validation and BOC round trips, including
the maximum and malformed cells, are exercised by native-boc.cpp.

## 6. Native TL and legacy formats

The six explicit IDs in wire.tl carry canonical VAOv in `data:bytes`, resolving
to VAE1/VAC1/VAK1/VAP1/VAM1/VAU1 respectively (kind 6/4/1/2/3/7).
API-CONTRACT.md specifies the unique inline/manifest form and chunk resolution.
TL encodes constructor IDs little-endian. Its bytes length must be minimal: one
byte for <254, otherwise 254 plus three little-endian length bytes; zero padding;
no trailing bytes. A TL bytes field is at most 0xffffff bytes; the bounded VAOv
carrier fits it even when the resolved object exceeds that limit. No raw large
canonical object may be placed directly in this field.
Import constructors alongside, never instead of, historical ones. A native TL
parser must accept the combined schema before implementation. The generic bytes
field is not itself a validator: typed decoding and trusted policy verification
remain mandatory. The focused native harness and independent C++/Rust structural codecs test this
contract. Production node, state/proof and service integration remain separate gates.

## 7. P0-era on-chain finality proof (revision 6)

Validator-authenticated finality persists on chain as a distinct BlockSignatures
era, alongside the byte-identical historical `block_signatures_ordinary#11` and
`block_signatures_simplex#12`:

    block_signatures_validator_auth#13 validator_list_hash_short:uint32 catchain_seqno:uint32
      native_session_id:bits256 slot:uint32 candidate_data:^Cell certificate:^AuthBytes = BlockSignatures;

The certificate is the sole signing authority, carried as `pack_bytes(VAC1)` typed
as the AuthBytes cell tree of section 1; there is no 64-byte signature hashmap.
`native_session_id` is the native ValidatorSessionId (lookup and native binding
only, never `Duty.session`); `candidate_data` binds the exact block as in `#12`;
`slot` is the Simplex slot (`Duty.position`). The node transport form is
`tosNode.signatureSet.validatorAuth` (`final:Bool` selects role-2 approval versus
role-3 finality). The certificate ingress bound for this consensus path is
`c0_block_finality_certificate_bytes` (58291), distinct from the generic
`c0_certificate_bytes`. Persistent `#13` is finality-only. The era is selected from
trusted chain state, never from the parsed constructor: a P0-active chain rejects a
legacy-only finality proof and a P0-inactive chain rejects `#13`. Historical
`#11/#12` semantics and the 64-byte Ed25519 proof path are unchanged. Verification
of a persisted `#13` reconstructs the authenticated committee, session and Duty from
trusted chain history and verifies the canonical VAC1 against them; it never requires
a live commitment store.
