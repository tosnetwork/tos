# Authenticated ordered identity application

`apply_native_identity_block` composes the native owner execution verifier, C0
proof of possession and current identity administration verifier with Config46
identity replay. C++ and Rust implement the composition independently. This is a
production library boundary; native elector admission, configuration-contract
execution and installation of its resulting root still require node integration.
No new wire type, signature statement, profile allocation or activation is defined.

The input parent is an independently authenticated registry at coordinate N. Only
N+1 is accepted. All due identity effects are applied first and the inclusion-time
policy is selected before the first ordered request. Each request receives the
current resulting registry, including immutable keys archived by earlier requests
in the same block. A single authority object holding the original parent cannot
be reused across the batch. Registry revision advances once when any identity/key
changes; selecting an already scheduled policy alone does not increment it.

The native context supplies the independently established governing snapshot,
network/genesis/domain and finalized native history. The governing snapshot must
match the current policy, cover the full masterchain and be no more than 128
blocks old. It supplies the expected administration duty; a peer certificate
cannot supply that expectation. Role-5 keys are selected from the current
per-request identity/archive at inclusion, even when the governing consensus
snapshot retains older keys. Complete owner, PoP and administration requirements,
unused authority lists, nonces, predecessors and pending-slot conflicts remain
those of the frozen lifecycle. Governance signatures cannot replace identity keys.

An owner proof must precede the inclusion coordinate. Native history resolves
its coordinate to an independently finalized full anchor. The proof's entire
seqno/root/file/state anchor must equal that result before its native transaction
and approval action are accepted. Missing history fails closed. The owner proof
reader and certificate reader share one aggregate attachment budget across the
batch; a failed batch never exposes a partial successor. Reads do not change the
parent, private signer journals or historical snapshots.

The shared corpus contains 37 masterchain-owner and 37 shard-owner cases. Real
wallet transactions approve a role-5 rotation, after which a second operation in
the same block must use the newly archived key. Old keys, reversed operations,
replayed nonces, stale predecessors, missing owner/PoP/admin evidence, corrupt
signatures, a different finalized fork and peer-selected duty context are refused.
Due and policy boundaries, empty blocks and checkpoint replay compare complete
native cell bytes. The state fixtures model independently trusted inclusion and
history; they are not evidence of native node/elector acceptance.

Eleven C++ and eleven Rust production mutations must compile and trigger their
specific assertions, with passing baselines restored. They remove real verifier
calls, substitute old committee keys, trust a claimed owner anchor, omit policy
selection or suppress registry revision. Full-dependency Ubuntu/ARM ASan, UBSan
and leak checks reproduce both corpora exactly.
