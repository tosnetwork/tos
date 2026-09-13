# Native registry transaction prefixes

`NativeRegistryBlock` is an immutable accepted prefix of one block. `begin` takes
an independently authenticated native parent and exactly its next coordinate,
materializes due transitions and selects the inclusion-time policy once. Each
`apply_transaction` verifies native owner execution, PoP and current identity
administration against the preceding accepted result, then returns a candidate
successor. The caller replaces the prefix only when the enclosing native
transaction commits successfully.

A failed request returns no candidate and changes neither the accepted prefix nor
its key archive, epoch/due indexes or nonce. Discarding a successful candidate and
retrying from the same prefix produces identical checkpoint bytes. Accepted
requests retain the cumulative state read budget; each request cannot reset the
block's allowance. Failed execution still requires native gas accounting, which
is separate from this state-work budget.

The private block-start revision cannot be supplied by a caller. Due effects and
any number of successful identity transactions increment the parent revision at
most once. An empty block leaves the revision unchanged, including at UINT64_MAX;
any identity/key change at that maximum is rejected. A block starting at
UINT64_MAX-1 can accept multiple transactions and finish at UINT64_MAX.
Restart reconstructs the prefix by replaying transactions from the authenticated
parent. This type intentionally has no untrusted prefix deserialization API.
Validated committed registry checkpoints remain supported by `NativeRegistry`.

The existing whole-block implementation and the new transaction path share the
native dictionary update logic. Both C++ and independent Rust match 80 cases
from actual masterchain/workchain-0 wallet approvals, including same-block role-5
rotation, old-key refusal, due effects, policy boundaries, nonce/predecessor
conflicts, overflow and exact native bytes. The transaction drivers additionally
check each prefix, discarded candidates, rejected requests and cumulative budget
exhaustion. Five C++ and four Rust compiled mutations require named assertion
failures and restored baselines. A C++ aliasing mutation preserves the mutated
object's validity so a moved-from fixture crash cannot masquerade as an isolation
assertion. Full-dependency Ubuntu sanitizer exports agree with normal exports.

This is the registry side of the transaction boundary. Actual config/elector
contract data installation, action-phase commit/rollback wiring, global
operations, consensus sessions and P0-enabled multinode execution remain to be
connected. These prefix tests do not claim that a native configuration contract
already executes them.
