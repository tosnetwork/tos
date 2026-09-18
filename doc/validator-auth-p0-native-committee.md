# Native validator identity and committee derivation

P0 authority is derived from an independently validated masterchain state and its
exact anchor. An API response, network public key, ADNL address or caller-supplied
weight cannot allocate an identity or create committee weight.

## Native election binding

The additive native TL-B alternative is:

```text
validator_auth_binding$_ identity:bits256 stake_id:bits256 = ValidatorAuthBinding;
validator_auth#b3 public_key:SigPubKey weight:uint64 adnl_addr:bits256
  binding:^ValidatorAuthBinding = ValidatorDescr;
```

Both binding fields are nonzero. The referenced ordinary level-zero cell contains
exactly 512 bits and no references. The network public key remains in its existing
field and namespace. The new binding identifies the independently allocated VAI1;
it does not derive identity from a network key or a historical VAK1 public key.
The elector must establish allocation, owner authorization and normal stake rules
before emitting this descriptor. Decoding a descriptor establishes no such facts.

Tags 0x53 and 0x73 retain their historical encoding. Rust's pre-existing 0x93
alternative retains its distinct sequence-number semantics; P0 does not reuse it.
The P0 alternative cannot also contain that sequence-number field. Native C++
parsing, total-set export and all three selection paths preserve the binding.
Descriptor equality includes it. Rust reads, writes and selects the same binding.

## State and selection boundary

`NativeCommittee::derive` checks the exact state hash, masterchain identity,
sequence number and network against the supplied trusted anchor and chain context.
Native Config8 must select version at least 16 and capability 1024; Config9 and
Config10 must include Config46. Config16 must remain internally consistent with
`max_validators <= 400`. Config46 must contain the frozen profile fingerprint and
the independently configured chain domain.

The effective election set uses Config35 when present, otherwise Config34, matching
the existing native current-set lookup. Its time interval must contain the anchor
state's generation time and its counts must fit Config16. The complete elected set
must have explicit, unique identity, stake and network-key bindings. Every binding
must match its VAI1 stake allocation, including elected validators outside the
particular selected subgroup. A malformed or legacy descriptor cannot be silently
removed from the denominator.

Config28 is parsed with its exact native rules before selection. Main-chain
selection, optional shuffle and shard weighted sampling use the existing native
algorithms. A selected shard validator has weight 1. The Rust adapter bounds the
u32 requested shard count by the elected total before the inherited selector's
u16 conversion, preserving the native C++ order of operations even for 65536.

The VAM1 election identifier is `H(election, election_cell_hash:h)`, using the
representation hash of the exact selected Config35/34 cell. It commits to the
whole native elected set and its interval. The VAM1 member list is then sorted by
identity, while a separately owned transport list preserves native selection order.
Only VAM1 and the frozen session construction establish P0 signing context; the
legacy short validator-list hash remains a transport index.

## The manager's session admission

The manager builds a validator group for a shard, and before it does, the
committee that group would run under has to derive. It calls the same
derivation, with the anchor it established itself -- its own applied masterchain
block, naming the very state its validator set was computed from -- and the
chain context it read from its own zero state. Neither is a value a peer
offered, and the context matters for the same reason the zero state does: a
context assembled from the registry under inspection would make the domain
check confirm its own name.

For a period this call applied only what a masterchain state settles on its own,
because the anchor was not available to it and reaching for an unestablished one
would have been worse than not checking. That subset admitted a roster carrying
a binding no registry ever issued: the identity a manager and a producer compare
is a hash of keys, addresses and weights, so it agrees whether or not the
registry issued anything. Derivation refused the same set, and the result would
not have been an unauthenticated chain but a stalled one, with the manager
seating a group and derivation refusing it.

The roster is compared against the one derivation selects, in that order, which
is the whole of what binds a state to a set here: every other rule is about the
state and reaches the roster only through it. Refusal is per shard and is not
fatal -- the node stays a full node for that shard and logs why. The same
applies when the chain has activated the design and this node has not
established its context yet, which is the window right after startup and closes
when the zero state is read.

Both conditions the gate needs arrive asynchronously, from unrelated reads, in
either order, and group creation is otherwise driven by a new masterchain block.
That makes their ordering a liveness question rather than a detail. If the
context is the late one, the startup pass refuses every group; on a chain whose
validators are all in that state, the block that would drive the next attempt is
the one none of them is producing, and nothing asks again. The chain does not
start.

So a refusal for a missing context is remembered, and whichever condition
arrives last creates what was refused -- never before the cleanup records are
loaded, because a group created before them can have its own consensus directory
deleted under it, and never when nothing was refused, because a pass nothing
asked for retires the live groups it does not recreate and fences their session
ids. That decision is one object with six cases and six compiled mutations,
rather than three flags read in three places.

A zero-state read that fails is asked again, with an interval that doubles and
then stops growing. It is bounded in rate rather than in attempts: a bounded
number of attempts is the same permanent stall arriving later, and one transient
archive error would otherwise leave a node unable to validate until somebody
restarted it. The delay is an admission gate rather than only a timer: while one
retry is scheduled, group admission cannot start an immediate read or schedule a
second stream. Each timer carries the generation it owns, so delivery of an older
timer cannot consume a newer retry, and success resets the delay.

The manager no longer discards this decision. The asynchronous birth/committee
admission is driven before a P0 validator group can materialize, the resulting
native session id must equal the manager's canonical ValidatorSessionId, and the
same durably committed owner is handed to the consensus Bus.

## Seating the consensus roster

The Bus does not only hold that owner; it seats from it. On a P0-active chain
the members consensus runs -- their order, keys, weights, ADNL addresses -- are
the committee the authenticated session was committed under, not the validator
set the manager assembled beside it. The manager already confirmed the two agree
before the group was created; seating from the committee is what makes the
committee the authority rather than the agreement. If the two ever diverged,
consensus would follow the committee.

The decision has one type, `ConsensusRoster`, with two constructors and no
third: one takes the historical validator set, for a chain where the design is
inactive; one takes a committed authenticated session. There is no constructor
that seats the historical set for an active chain, so "active, but running the
manager's set" is not a value the type can hold, and a fall back to it would
have to be written first. An active session that produced no committee is a
refusal to start the bus, never a seat of the historical set -- that would turn a
security refusal into a bypass. A released session owns no committee and seats
nothing.

The replacement happens once, in the manager, not only in the bridge. The bus
reseats its members from the committee -- but that reseat is inside the bridge,
after the bridge has already constructed its `ManagerFacade` from the validator
set the manager passed in. Making only the bus authentic would leave the facade,
which collation, validation, accept and broadcast all run through, on the
historical set that merely compared equal during admission. So on a P0-active
creation path the manager replaces its own `val_set` with the committee-adapted
set in `update_shards()`, before `create_validator_group()`, and both consumers
inherit that one authenticated source.

The manager verifies two things after the replacement, because several values
were computed from the historical set before the session was committed: the
canonical group id recomputed from the authenticated set must equal the one the
session was committed under, and the local validator must be a member of the
committee. A disagreement on either is a refusal, not a silent switch to a
different session id or a seat of a non-member.

For a valid chain the adapted set is byte-identical to the manager's -- the
committee's own validator descriptors, its catchain, the shard -- so the set
hash, catchain sequence and every downstream read are unchanged; what changes is
which construction is authoritative. If the two ever diverged, both facade and
bus would follow the committee. The bridge's own reseat remains as a
defence-in-depth adapter at the frozen loop, not an independent derivation.

The adapter and the roster carry five compiled mutations and two static wiring
checks with their own negative controls -- one for the bridge reseat, one for the
manager replacement -- because neither the bridge nor the manager actor can be
instantiated in the focused test tree. Those static checks are weaker than the
four-validator rehearsal and do not replace it.

What this round does not do: C0 certificate verification inside the consensus
message flow, and native signer permissioning, remain the next round. This one
is committee authority at session birth.

## Existing configuration JSON tools

Native config JSON carries the optional `auth_binding` object with exactly
`identity` and `stake_id`, both nonzero lowercase 64-character hex strings.
The existing serializers and parsers preserve it for Config32 through Config37,
including Config34. They also retain the separate `mc_seq_no_since` extension.
A P0 binding requires ADNL and cannot coexist with that sequence extension;
null, malformed or partially specified bindings fail instead of becoming legacy
descriptors. Declared counts must match the list, and a P0 list cannot exceed 400.

The control client checks integer widths before constructing the native set.
Its raw config parser rejects duplicate decoded JSON keys at every depth,
including escaped duplicates, more than 4194304 bytes, more than 200000 values,
and trailing documents. The voting provider uses this same parser. JSON export
and re-import recover exact native descriptor cells for all four native tags.

This is metadata for existing configuration tools. It does not allocate an
identity or replace the canonical binary and thin JSON contract of the new
validator-auth v1 endpoints. Native admission and cryptographic authority remain
mandatory after parsing.

## Keys, history and resources

Snapshot construction reads the resulting registry at the exact anchor and selects
all five C0 roles for every selected validator. An overdue transition, missing role,
expired key, stake mismatch or reuse of an elected network key refuses the whole
snapshot. It never compensates by reducing committee weight. Future pending
transitions do not rewrite active keys. An already constructed snapshot owns its
policy, public keys, roster and complete denominator after later retirement.

Snapshot derivation uses an authenticated entry view. It reads the current policy,
the identity/stake binding of every elected member, and the active/pending key
references needed to validate selected identities. It does not enumerate archived
keys. Repeated reads use an owned cache and spend no additional entry or byte
budget. Every lookup checks the exact dictionary wrapper/leaf shape, bounded
AuthBytes before allocation, the requested identity/key/policy binding, and C0 key
admission. Per-value limits are 4096 bytes for policy/identity and 32768 for keys;
the shared operational budget defaults to one million entries and 256 MiB. These
limits refuse a read without returning a partial roster.

The entry view cannot grant mutation authority: maximum-epoch and first-registration
queries return `read-only-view`. Global policy history, epoch uniqueness, identity
references and control records still require full state validation or authenticated
incremental apply. Both full registry readers remain available for that boundary.
In particular, an unused duplicate archive epoch fails full state validation even
though snapshot selection need not read it. A trusted anchor means an independently
validated state, not a root hash supplied by the proof sender.

The view corpus compares exact values and remaining budgets across C++ and Rust,
including 10000 extra archived keys, repeated reads, minimal pruned histories,
missing required nodes, dictionary tails, substituted IDs and invalid key material.
Native state apply still needs persistent incremental updates before integrated
performance acceptance.

## Committee proofs

A kind-5 VAF1 committee reference carries an actual masterchain Merkle proof.
The verifier pins the full anchor, network/genesis/domain, workchain/shard and
catchain independently, derives the elected set and VAM1, and checks its object ID.
It validates the complete elected binding set while fetching keys only for the
selected snapshot. The retained policy in the result is read from the same state.

Both verifiers reject changed anchors, roots, proof/object IDs, selection context,
unrelated revealed values and detached physical cells. They re-create the usage
proof and require the same native Merkle root. Native header admission reads the
queue/account roots but not their descendants; both languages perform these same
reads. The existing native configuration path rejects global_id=0 in both adapters.

Proofs above the inline bound use the existing authenticated object carrier. The
producer must publish every chunk successfully before returning the reference;
missing storage or publication failure returns an error. The C++ producer and
independent Rust verifier compare full 400-member proofs as well as shard, shuffled
and temporary-election proofs. Certificate RPC and consensus duty/session authority
remain separate integrations.

Tests consume actual native state BOCs, compare C++ and Rust canonical VAM1 bytes,
check native transport order and round-trip the election descriptors. The corpus
includes a complete 400-member snapshot, temporary elections, malformed bindings,
resource exhaustion and old-snapshot retention. Compiled guard removals must cause
named assertion failures; crashes and build failures do not count.

This adapter does not start a validator session, admit a stake transaction or
activate a network. Elector/config execution, node session and consensus wiring,
provider designation reconciliation and multi-node acceptance are subsequent
integration boundaries. Native support advertisement remains disabled until those
boundaries are complete.


## Finalized-head bootstrap at genesis

Session-birth admission cannot use an applied masterchain tip as a substitute for
an independently finalized head. Before the first signed masterchain block there
is exactly one exception: the zero state named by the operator-configured chain
context. The finalized-head establisher accepts it without signatures only when
the block is masterchain seqno zero, its root and file hashes equal the context's
genesis coordinates, and the supplied state hashes to that same genesis root.
Every non-genesis advancement still requires a final signature set and quorum.
This keeps P0 genesis startable without turning the unsigned-bootstrap rule into
a fallback for ordinary blocks.


## Manager finalized-head production feed

The manager supplies the finalized-head seam from two independently learned
facts. A masterchain finality broadcast contributes a receipt only after the
existing native signature verifier accepts it; the receipt is rebuilt through
the same next/current ValidatorSet selection and BlockSignatureSet verifier. A
masterchain state contributes the other half only after it becomes the
manager's contiguous applied tip, at which point the exact original block bytes
are read back from the database and bound to that resulting state. The source
advances only when both halves name one exact BlockIdExt. The configured zero
state remains the only unsigned initial head.

A verified receipt arriving before chain-context establishment is retained as
the highest pending receipt and replayed after source creation; the current
applied tip is offered at that point as well. This closes startup ordering
without treating an applied tip as finalized. Durable reconstruction of a
post-genesis finalized receipt on process restart remains a separate boundary;
until it is supplied, a restarted node starts from the configured genesis head
and advances again on a new native finality observation.


## Durable finalized-head restart recovery

A post-genesis finalized head is now published to manager consumers only after
its chain-bound local journal write has acknowledged. On restart the journal is
decoded against the configured chain context, then the exact masterchain state
and original block bytes for that receipt are read from the node database and
offered back to the same ManagerFinalizedHeadSource. The journal therefore
cannot create authority by itself.

The startup state may be an older key state even when later applied blocks are
already present in the database. Recovering the journal does not bypass that
ordering: validator-auth remains unavailable to collation, validation and group
creation until the manager's own contiguous last_masterchain_seqno_ has caught
up to the recovered finalized anchor. Finality observations arriving during
recovery are retained and replayed afterwards.

The recovered finalized head now drives NativeSessionCommitteeAdmission, and a
validator group cannot start until the resulting context has passed
CommittedNativeSession's durable commit/restart fence.


## Session-continuity store provisioning barrier

Validator groups on an activated chain now wait for a durable local session
commitment store in addition to finalized-head recovery. StateDb carries a
separate provisioned marker. If that marker exists, the manager may only reopen
the existing commitment log/frontier; missing files are loss and are never
silently recreated. If the marker is absent, the manager first tries to reopen
existing files (covering a crash after file creation but before marker commit)
and initializes only when the store is genuinely absent. The store is not made
available to group creation until the marker write acknowledges.

This separates first provisioning from catastrophic continuity loss and gives
the next session-admission wiring a durable commit/restart fence it can require
before a validator group starts.


## Manager-owned authenticated session lifecycle

The live validator path now drives NativeSessionCommitteeAdmission from the
manager's independently finalized head. Historical block requests use the
archive bounded reader, so the declared package payload size is checked before
payload allocation. Historical identity requests use the exact requested state
and ValidatorManagerOptions::get_vertical_seqno(anchor.seqno_); the live manager
identity continues to use get_maximal_vertical_seqno(), exactly as
get_validator_set_id() does.

Admission alone cannot create a group. The resulting native session id must
equal the manager's already-constructed ValidatorSessionId byte for byte. The
manager then tries CommittedNativeSession::restart against the provisioned
continuity store and calls commit_new only for the exact
session-commitment-missing case. Conflicts and storage errors refuse the
session.

The manager retains the committed owner independently of validator-group actor
retirement. Tentative P0 groups are not materialized without that owner. A
validator Bridge asks the manager for the same owner before constructing its
consensus Bus, and the Bus holds that shared owner; observers receive no such
capability. New independently finalized heads call release_if_terminated using
identity inputs derived for that exact head, so local actor retirement cannot
release authenticated committee authority and a durable store record alone
cannot retain it past chain-proven session termination.

The historical unsafe catchain-rotation id rewrite is refused while P0 is
active: P0 v1 is genesis-activated and defines one native session identity, not
a local second identity for recovery.


## Catchain transition first-block liveness

A new session does not need to finalize its own first block before it can be
authenticated. The previous session finalizes the transition masterchain block;
the resulting state of that block already contains the new current catchain and
validator set, so once that block itself is independently finalized it is a
sufficient trusted tip for the new session's birth search.

There was nevertheless a manager deadlock between application and finality.
update_shards() can observe the transition state as soon as the block is applied,
while the validator-auth finalized head still names its predecessor. Admission
correctly returns session-birth-not-current at that moment and remembers the
refusal. If all validators do that, the new session cannot produce another block
to trigger the usual update_shards() retry.

A strictly newer durable finalized-head publication now releases one remembered
group pass after authenticated-session termination is processed. Exact duplicate
heads are no-ops. A permanent refusal records the finalized sequence number, so
the same authority coordinate cannot spin; it is eligible for another attempt
only after the finalized head advances again. This makes the transition block's
own finality, rather than a hypothetical first block from the new session, the
event that starts the new validator group.


## Inactive-chain compatibility

Consensus ownership is explicitly tri-stated at the manager boundary. The
manager returns both whether authenticated-session ownership is required and the
owner itself. On a P0-inactive chain required is false and a validator Bridge
starts the historical consensus path without a native session capability. On an
active P0 chain required is true and a missing or released owner refuses the
validator Bus. A null pointer therefore never has to mean both "legacy feature
not enabled" and "required authority missing".

The consensus Bus retains the explicit required bit beside the optional owner so
later signer/provider integration can preserve the same distinction instead of
re-inferring activation from pointer presence.


## Retry scope and live-session transient refusal

Validator-auth bootstrap now runs only when the current masterchain state
actually enables native session binding. On a legacy/P0-inactive chain startup
does not read the zero state for registry authority, and the retry path resets
rather than scheduling another attempt. A stale delayed callback therefore
cannot turn feature-inactive into a permanent 16-second poller.

Admission is also explicitly a creation/recreation boundary. A live validator
group for the exact canonical session id already owns the immutable, durably
committed CommittedNativeSession that admitted it. Temporary loss of manager
finality/session-store readiness does not revoke that owner, so the live group
bypasses re-admission and follows the ordinary same-id reuse path. It is not
left behind for the tail retirement loop and therefore cannot acquire a
destroyed-session fence merely because the control plane was temporarily unable
to admit a new group. New or recreated groups still require full authenticated
admission; finalized chain state proving a session change remains the authority
that releases the old owner and makes actual retirement permanent.
