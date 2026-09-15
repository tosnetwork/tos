# Native finalized header witnesses

This additive native implementation witness does not change VAA1, VAF1, the
owner execution proof's two references, or the frozen profile fingerprint.
Its transport is the [native evidence container](validator-auth-p0-native-evidence.md);
concrete transaction host metering remains separate integration work.

## Trust and deterministic execution

`NativeFinalizedHistory::authenticate_header` / `authenticate_header` require an
already authenticated parent masterchain state and full head anchor. The existing
history constructor verifies native network, genesis, capability and chain domain.
The caller establishes head finality independently.

For a coordinate strictly between zero and the head, OldMcBlocksInfo supplies the
complete native block ID. The entry's coordinate must match; root/file hashes must
be nonzero. At the head, the independently trusted full head supplies this ID.
Genesis, future and sentinel coordinates cannot carry header witnesses.

The witness's effective block root must equal that independently selected root.
Native Block and BlockInfo must identify the same network, coordinate and complete
masterchain shard, with `not_master=0`. The native MerkleUpdate's stored **new**
state hash supplies the returned anchor's state root. A head witness must also
match the independently trusted head state root. The returned file hash comes
from the authenticated block ID, never from the witness's BOC encoding.

This operation neither invokes the archive reader nor reads/writes its cache or
read budget. Repeated validation has identical inputs and work. The original-block
history method remains available for offchain archive clients.

## Fixed revealed surface

The root is an unvirtualized, level-zero native MerkleProof cell with 280 bits and
one reference. That reference is the ordinary 64-bit native Block with four
ordered references:

1. Ordinary BlockInfo. Each of its one to three predecessor/master/vertical
   references is a terminal pruned branch with level mask 1. Native header parsing
   determines the exact allowed reference count; masterchain admission further
   rejects `not_master` and non-full shards.
2. Terminal ValueFlow pruned branch, mask 1.
3. Native MerkleUpdate, 552 bits and two terminal pruned state references. Each
   state reference has mask 2 or 3. Mask 3 preserves both significant hashes when
   the original native update contained intrinsic level-one pruned data.
4. Terminal BlockExtra pruned branch, mask 1.

All terminal branches have zero references. Native cell construction enforces
their internal hash/depth shape. Admission opens at most eleven occurrences at
depth three; it performs no recursive peer-controlled subtree walk. Full blocks,
extra reveals, ordinary proof wrappers and disclosed old/new state subtrees are
rejected even when they commit to the correct block. Merkle proofs authenticate
commitments, not an alternative history or finality claim.

Both independent generators prune all unopened references, including ordinary
leaves. They retain the original block's effective hash and new-state commitment.
They never serialize an entire state merely to construct this witness.

## Falsifiable evidence

The shared 25-case corpus checks repeated zero-budget/offline resolution, independent
root and file semantics, malformed history entries, cross-network/coordinate/shard
substitution, excessive reveals, head-state binding and intrinsic Merkle levels.
Rust independently regenerates each accepted witness and compares the native cell
hash to C++. Fourteen C++ and thirteen Rust compiled guard removals fail their
named assertions and restore passing baselines. Full-dependency Ubuntu/ARM
ASan/UBSan/LSan exports equal the ordinary native exports.
