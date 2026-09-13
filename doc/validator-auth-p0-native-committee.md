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

## Keys, history and resources

Snapshot construction reads the resulting registry at the exact anchor and selects
all five C0 roles for every selected validator. An overdue transition, missing role,
expired key, stake mismatch or reuse of an elected network key refuses the whole
snapshot. It never compensates by reducing committee weight. Future pending
transitions do not rewrite active keys. An already constructed snapshot owns its
policy, public keys, roster and complete denominator after later retirement.

Both native readers bound the full registry load by one shared entry and byte
budget (defaults: one million entries and 256 MiB of decoded values). The archive
is not limited to 400 identities or keys. The Rust reader independently checks
policy history, immutable key IDs and epochs, identity references, pending
coordinates and control records. Exhaustion produces an error, never a partial
roster. Full dictionary loading remains an implementation cost to replace with
persistent incremental state access before performance acceptance.

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
