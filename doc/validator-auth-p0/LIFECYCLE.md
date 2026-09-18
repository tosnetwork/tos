# Persistent validator identity and key lifecycle

## Identity and genesis

Identity = H(identity, chain_domain:h || stake_id:h || creation_nonce:u64).
The authenticated elector/registry allocates a unique stake ID and creation nonce;
one stake ID cannot receive committee weight twice. A legacy public-key short ID
may remain an index, never an independent recovery authority. ADNL is not authority.
chain_domain is fixed public genesis input, not the zerostate hash. Genesis records
do not contain their own enclosing state's hash. Actual zerostate root/file hashes
enter signed duties after genesis construction, avoiding a circular commitment.

VAI1 holds the owner account, next allowed admin nonce, predecessor view hash and
active RoleRefs and explicit pending VATr records sorted by `(role,suite,parameters)`.
Each list has at most ten entries, one active and one pending transition per
role/profile, at most two profiles per role across their union. Absence of a
pending record means no scheduled operation; there is no time sentinel. Immutable VAK1
versions remain retrievable by key ID in an authenticated public archive.
Registration creates no stake, membership or weight; election logic still does that.

## VAU1 operation semantics

Nonce must be >= the target's next_nonce. Apply sets next_nonce=nonce+1 with checked
arithmetic; UINT64_MAX is rejected. Skipped nonces allow an explicit new owner
intent after a known unusable request without reusing its signed duty. Unknown
broadcast/signing results require reconciliation, not automatic replacement.
Previous is the exact predecessor VAI1 hash, or current policy ID for global
operations. Conflict never means transparently re-sign under a new predecessor.
Unused fixed fields are zero and unused byte fields empty:

| operation | Required nonempty fields |
| --- | --- |
| 1 register | assigned identity and new_key=VAK1; old_key zero |
| 2 rotate | existing identity, old_key, new_key=VAK1 |
| 3 retire | existing identity and old_key; byte fields empty |
| 4 policy | zero target identity, new_policy=VAP1; old_key zero |
| 5 election | existing identity; operation_data = stake_id:h || beneficiary_workchain:i32 || beneficiary_address:h || election_id:h |
| 6 configuration | zero target identity; operation_data = parameter_index:i32 || previous_cell_hash:h || proposed_cell_hash:h |
| 7 cancel | existing identity; operation_data = exact H(transition,VATr); old_key zero; new_key/new_policy empty; effective_from zero |

Fields not listed in a row must be empty/zero. A newly allocated VAI1 has
previous=zero and proven elector allocation; requests reference its actual VAI1
hash as specified below. Later operations also use the actual current identity view. The zero-ID identity record
holds the global admin nonce but is never a committee member. Configuration values
and state proofs are separate bounded attachments whose hashes must match before
apply. Election intents associate identity with an independently authorized stake
operation; existing value/ownership/timelock/selection checks remain mandatory.

## Deterministic pending transition state machine

VATr is defined by the canonical schema (WIRE.md shows a generated view). It stores
operation 1/2/3, role/profile, old/new key IDs, effective coordinate, acceptance
coordinate, nonce, exact admission predecessor, update ID and authorization ID.
The latter is H(authorizations,VAA1) of the fully verified four-type evidence.
VAI1.pending replaces the old pending RoleRef list; there are not two sources of
pending state. Accepted VAU1/VAA1 bytes and key descriptors remain retrievable by
hash in the public archive. The authenticated VAI1 proves that their authorization
was accepted; replay does not consult a private scheduler or re-submit the proof.

Real masterchain coordinates are 0..0xfffffffe. 0xffffffff is an exclusive key
validity upper bound only, never an effective coordinate. Register/rotate require
inclusion <= effective_from < 0xffffffff and a delay <=65536 masterchain blocks.
The new VAK1.valid_from equals effective_from and valid_until is strictly greater;
all arithmetic is checked. For retire only, effective_from=0 means **at inclusion**,
not the literal genesis height. Cancel always has effective_from=0 and executes
at inclusion. Thus neither immediate retirement nor cancellation asks the caller
to predict its inclusion height. Delayed retirement uses a nonzero absolute height.
Same-height registration/rotation is allowed if actually included at that height;
a request included later is rejected, never silently rescheduled.

Apply each masterchain block in this order:

1. Starting from its authenticated parent state, materialize all accepted due
   transitions with E <= block coordinate. Per identity, order by (E,role,profile),
   update active refs atomically, remove due records, and set VAI1.previous to the
   pre-batch VAI1 hash. Keep next_nonce unchanged. No operation is reauthorized at
   its deadline. Validate old refs and archived new descriptor bindings; corrupt
   authenticated state fails rather than skipping an operation.
2. Process validated administrative requests in the native deterministic execution
   order. Each request checks current VAI1 hash, nonce, current inclusion-time
   policy/administration keys and freshness. Increment nonce only on acceptance;
   set previous to that pre-request VAI1 hash. Immediate effects belong to the same
   atomic transaction. Rejecting a request commits none of its staged changes.
3. Commit the resulting registry root, then construct new committee snapshots
   from that state and the session's authenticated anchor. Registry revision
   increments once per block with any identity/key change (including due effects),
   checked for overflow; transaction order never depends on map iteration.

The public reference transition is apply_block(parent, parent.coordinate+1,
ordered_successful_updates). Every intervening block, including empty blocks,
must be replayed. A jump from checkpoint 150 to 210 is forbidden: effects at 200
and 210 must create their separate predecessor links and registry revisions.
Replaying the same blocks with checkpoints at different places produces identical
bytes. A snapshot is a read-only selection from the authenticated resulting state
at its exact anchor; it never advances a registry or rewrites previous. An overdue
pending transition proves that the supplied snapshot state is not current. The
private per-block due helper is not a checkpoint advancement API. Native integration
supplies the authenticated complete ordered list of accepted operations; invalid
inputs fail atomically. Checkpoint/archive roots are authenticated externally;
canonical decoding alone does not establish them. Old snapshots remain immutable.

Register requires no active key in that role/profile; rotate requires the exact
currently active old key and a new key in the **same** role/profile; retire requires
that exact active key and no new key. New epochs strictly exceed every archived
epoch for (identity,role,profile), including canceled keys; no wrap, and epoch
0 or UINT64_MAX is rejected. The authenticated archive can maintain a proved
maximum-epoch index; the reference model scans its supplied archive. A suite
migration stages independent per-profile operations under the same current-policy
authority, then activates only with complete required keys. It is not a cross-profile
rotate that ambiguously chooses a slot.

There is at most one pending transition per role/profile and ten per identity.
The active-plus-planned union has <=2 profiles per role and <=10 slots. A second
operation for an occupied pending slot is CONFLICT, including an immediate one.
There is no replacement-by-overwrite. Cancel identifies the exact VATr hash,
requires a new nonce, current predecessor/current admin authorization and an
inclusion coordinate **strictly before** E. At E due effects run first, so cancel
cannot undo an effective transition. Explicit cancel then a separately authorized
new schedule is the only replacement procedure; the second uses the post-cancel
predecessor. Cancel is never encoded as retirement of the pending key.

Admission-time nonce/predecessor checks are not deadline checks. A role-1 rotation
accepted at 100 for 200 still executes if a role-2 operation changes the identity
hash at 150. The immutable VATr commitments and exact slot old/new keys suffice.
No new authorization is required at E even if the admin keys have since rotated.

At a new session's anchor B < E the old active key remains selected; B >= E uses
the new key or sees the retired slot absent. Eligibility also requires the key's
own [valid_from,valid_until) interval. No schedule can extend an expired key.
A missing required slot causes snapshot construction to fail; never remove that
validator's weight to make a committee pass. Existing sessions keep owned key bytes,
policy and full denominator until their native termination, even past retirement.
There is no added schedule lookup on each signature verification.

Cancel/retire never remove public key history, consumed PoP/signature capacity or
signer safety tombstones. Reorg replay can reconstruct chain selection from an
ancestor; it cannot rewind the signer's irreversible capacity/duty ledger.
The local retire endpoint acknowledges durable retirement intent and reconciliation;
it does not destroy secrets or prematurely disable still-authorized old sessions.

The initial allocated identity is an authenticated nonzero VAI1 with empty refs,
next_nonce=0 and previous=zero. Its first request uses the **hash of that allocated
VAI1** as VAU1.previous (not zero), registers an administration-role key, and uses
owner+PoP without existing admin signatures. Once any public key for that identity
has been archived, this bootstrap exception is permanently unavailable. A scheduled
first admin key must become active before subsequent requests can use it. Genesis
may instead install a complete independently approved offline allocation/key manifest.

The executable reference is `test/validator-auth-p0/lifecycle.py`. Trusted owner,
PoP and current-admin verifier callbacks are separate integration boundaries;
tests exercise their refusal and type binding. They are not production elector,
quorum, native inclusion or Merkle-proof implementations.

## Authorization and proof of possession

New registration requires authenticated stake-owner approval AND new-key PoP.
Existing identity changes additionally require its currently authoritative
administration-role keys: both components in C2, approved PQ in C3. A classical
owner wallet, old keyring handle or operator connection cannot bypass that rule.
Lost-key recovery needs a separately reviewed network-authorized procedure.
This proposal does not make all validator funds or wallets PQ-safe.

Policy changes require the trusted governance committee's current-policy quorum.
Configuration-parameter changes require that quorum plus the normal
configuration-voting rules, in that order and in two stages.

A chain on which validator authentication is active but the configuration
account lacks its committed registry checkpoint is a **fault state, not an
authority state**. The account MAY remain readable and diagnosable, but the
missing checkpoint MUST NOT authorize any state change. Every state-changing
configuration path MUST refuse, including validator-set installation, registry
updates, tick-tock persistence, configuration proposals, configuration-key
actions and configuration-contract code replacement. In particular, neither a
Config8 change that disables validator authentication nor a code replacement is
an in-chain recovery path. Recovery from this state is out of band. Generic
configuration writers MUST also refuse a change that would activate validator
authentication on a chain where it is inactive; P0 activation in this profile is
genesis-only. Any future migration or in-chain recovery procedure requires an
explicitly reviewed profile revision rather than treating absence of the
checkpoint as a credential.

Normal voting runs unchanged until it reaches its threshold. At that point the
proposal is not installed. Its persisted `wins` becomes 0xff, which marks it as
awaiting governance; the marker is a value ordinary voting cannot reach, because
a proposal is stored again only while `wins < min_wins` and `min_wins` is a
uint8. It is not a comparison against the current threshold, which is itself a
configuration parameter a later proposal can change. A completed proposal
registers no further vote and is not reset by a validator-set rotation, whether
that rotation is reached by a vote or by the tick-tock scan; both answer with
status 3, meaning normal voting is complete and the proposal awaits governance.
Its expiry and the existing paid extension of an exact proposal are unchanged,
so a proposal that expires before finalization is removed and must be voted on
again.

Operation 6 finalizes one such proposal. The exact ConfigProposal travels with
the registry message as a third reference rather than inside VAU1, which is
unchanged, and it is bound to the transaction where the message is admitted;
VAUTH_APPLY keeps its two operands. An operation of any other kind must not
carry one, and operation 6 without one is refused. The operation's
`operation_data` must agree with that proposal exactly: `parameter_index` equals
the proposal's `param_id`; the proposal's `if_hash_equal` must be present and
equal to `previous_cell_hash`; and the hash of the proposal's `param_value`
equals `proposed_cell_hash`. A `previous_cell_hash` of zero means the parameter
is currently absent and must still be stated as a present zero condition rather
than omitted, or a proposal asking for no compare-and-swap and one requiring the
parameter to be absent would share an encoding. A `proposed_cell_hash` of zero
means the proposal deletes the parameter.

Finalization is one transaction. It requires the proposal to be present, not
expired and marked awaiting governance; it applies the update under the
governing quorum; it consumes the proposal; and it then applies the existing
acceptance rules -- mandatory, critical and current-hash -- before installing.
The parameter and the registry the operation produced are committed together. If
any step fails nothing moves: the parameter is unchanged, the proposal remains
awaiting governance, the global nonce does not advance and no candidate prefix
is promoted. The commit binds the parameter on both sides, because the proposal
is not an instruction operand and that binding is the only thing tying what was
installed to what was authorized. Election, complaint/config votes
and privileged config paths must be covered before PQ enforcement; key onboarding
alone does not migrate them.

Admin Duty uses workchain=-1, full masterchain shard, governing committee catchain
and anchor, position=VAU1.nonce, and session=H(admin-session, network:i32 ||
genesis_root:h || genesis_file:h || VAU1.identity:h). This namespaces nonces by
target without resetting them when a key, epoch or suite changes. Inclusion must
use current policy/predecessor and occur within 128 masterchain blocks of anchor.
Unlike old consensus sessions, old-era admin duties do not remain new authority.

PoP signs `ASCII("TOS/P0/pop/v1") || 00 || network:i32 || chain_domain:h ||
blob(VAU1) || key_id:h`; blob is u32 length-prefixed. Validate the proposed key and
exact suite before verifying. PoP never supplies ownership or quorum. Genesis
uses the pre-genesis chain_domain and an approved offline allocation manifest,
not a not-yet-known zerostate hash. Stateful PoP consumes the same globally fenced
capacity as ordinary signing.

## Epochs, states and retention

Epoch starts at 1 and strictly increases per `(identity,role,suite,parameters)`;
no wrap. Stateful capacity_domain = H(capacity, suite:u16 || parameters:u16 ||
blob(public_key)); its capacity limit comes from the reviewed suite. The same
material under a new role, identity or epoch cannot obtain fresh capacity. Every
HSM/provider reference to that material shares a single allocation authority.
C0 stateless descriptors have zero capacity metadata.

Local key states: PENDING -> ACTIVE -> RETIRED -> DESTROYED; pending cancellation
uses PENDING -> RETIRED. Destruction means destroying secrets, not public history
or signer tombstones. Reorgs, session pruning and compaction must not rewind safety
state. Public historical descriptors/policies remain authenticated by their era's
state roots; a current registry lookup is insufficient for old proofs.

signer-store.sql is a reference persistence contract, not a mandated storage engine.
u64 values are eight big-endian bytes, not signed SQLite INTEGERs. Public key
versions and consumed capacity are immutable. Terminal results cannot revert to
pending. Cross-role rules and checked arithmetic still need one serialized service
transaction. A local database cannot prove that itself and its backups were not
rolled back; external fencing is specified in SIGNER.md.
