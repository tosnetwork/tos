# Native owner execution proof

The implementation contract in `validator-auth-p0-native-owner.json` fills the
native BOC carried by frozen VAF1 kind 1. It changes no outer wire type, historical
encoding, signature equation or profile fingerprint. It is an implementation
boundary, not evidence of completed elector or consensus integration.

The caller independently establishes a complete finalized masterchain anchor and
the current authenticated identity allocation. The proof cannot select its own
trust anchor. Both its masterchain state and its owner transaction must bind that
anchor. The proved and current allocation must agree on identity, owner account
and stake ID. Register, rotate and election may use this authority; other update
operations are refused. All other required authorizations remain separate.

The proved state must have the expected network, coordinate, chain domain,
version/capability and admitted C0 registry policy. ConfigParam 1 supplies the
approval recipient. For a masterchain owner, the proved block root and coordinate
must equal the anchor, and its native Merkle update must commit the anchor's state.
For a shard owner, the authenticated masterchain ShardHashes must name the exact
owner-containing shard and block root/sequence. An arbitrary owner block is not
an inclusion proof.

Native account-block and transaction augmented dictionaries select the exact
owner account and logical time. A selected ordinary transaction must have a
successful compute phase and action phase, no abort or destruction, no insufficient
funds and zero action result code. Its declared outgoing count must equal the
successful action count. The selected message must originate from the owner,
address the authenticated elector, carry no anycast or state initialization, and
have logical time `transaction_lt + 1 + message_index` without overflow. Its one
body reference contains exactly the ordered approval fields. A message or wallet
signature without successful native transaction execution supplies no authority.

The approval binds the pre-genesis chain domain, stake ID and exact canonical
update hash. Native transaction finality and account execution authenticate the
owner; operator transport credentials have no role. The owner proof does not
assert that the elector has already processed an election or that a new key is
active. Normal election value, ownership, timelock and selection rules and current
nonce/predecessor checks must execute atomically with the eventual update.

The BOC has one ordinary header with exactly two ordered Merkle proof references.
Lengths, cell count, root count, absent cells and physical reachability are checked
before native proof use. The shared object reader accounts for its transfer bytes.
Rebuilding the queried proof must reproduce the complete Merkle roots. Unused
ordinary cells, including leaves, are pruned. Native lower-level pruned branches
inside an existing Merkle update retain their committed hashes. Pruning memoization
includes both cell hash and Merkle depth. Effective virtualization levels advance
through Merkle cells; a uniform descendant offset is incorrect for nested updates.
The dedicated Rust adapter implements this rule without altering historical native
cell or proof code. Native pruning is bounded by cell count, depth and Merkle level.

The tests execute the existing wallet contract with signature verification enabled
for owners in the masterchain and workchain 0. Each executes a correct approval,
wrong update/stake/domain/recipient and insufficient-funds rollback, and rejects a
forged wallet signature before execution. Separate native transaction-field
mutations isolate compute, abort, destruction and individual action guards.
Synthetic block/state containers then prove these real transactions. They are
controlled finality fixtures, not live-node finality or P0 multinode acceptance.
C++ and Rust compare exact verified transaction hashes and refusal codes.
