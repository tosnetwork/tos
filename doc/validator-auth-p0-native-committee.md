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

What this does not yet do is run the session under the derived committee. The
committee is derived, its roster is required to be the one seated, and then it
is discarded; the asynchronous admission that resolves a session's birth block
and holds the committee for the session's lifetime exists and is not yet driven
by the manager.

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
