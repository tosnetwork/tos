# Native ingress policy for block-transition workchains

Status: entry/table codecs, configuration lookup and destination admission implemented;
activation/configuration transition enforcement pending.
Not an activated consensus rule.

## Implemented entry codec

The development `WorkchainNativeIngressPolicy` record has tag `0x57495031`,
481 bits and one reference: workchain int32, Basic/Extended flag, engine selector
int64, vm_mode uint64, WorkchainDescr version uint32, executor address bits256,
and an opaque engine-configuration cell reference. Its constructor implies
BlockTransition and standard, non-anycast ingress; it does not permit arbitrary
execution scopes. Basic selectors must fit int32; Extended selectors must fit
uint32 and have vm_mode=0. Negative workchains and absent engine configuration
are rejected. The public decoder does not invoke an engine or interpret its
private configuration payload.

The binding check compares workchain, engine identity/mode and descriptor version
against the supplied normalized ConfigParam 12 descriptor, and requires active,
unsplit execution. `accept_msgs` remains an independent native admission gate,
so closing admission does not invalidate an otherwise unchanged policy binding.
This record does not replace descriptor finality or bind a masterchain state by
itself. Development ConfigParam 84 owns the table. Lookup requires global
version >= 15 and capBlockTransition; below either gate, admission is unchanged.
Once enabled, a missing table is rejected (an explicit empty table is valid).

The table codec has tag `0x57495431` followed by a HashmapE with 32-bit workchain
keys and reference-valued policy entries. Its root is 33 bits and zero/one
references. Empty tables are explicit, not interchangeable with a missing root.
Encoding rejects repeated workchain IDs and is independent of insertion order.
Decoding rejects malformed entry wrappers and a dictionary key that differs
from the enclosed policy's workchain ID, even if generated TL-B validation
accepts the structure. The table codec does not authenticate a configuration
state; callers use the native host's authenticated configuration snapshot.

## Problem demonstrated by the current host

Without the shared policy, `Transaction::check_rewrite_dest_addr` checks workchain
existence, `accept_msgs` and permitted address length, but does not restrict a block
workchain to its executor address. `Collator::process_inbound_message` rejects a final delivery
whose destination differs from the configured executor. Native queue processing
is ordered: a validly funded message to a different address can therefore stop
the receiving workchain's progress.

The receiver cannot fix this by silently marking the message processed: its
principal must remain accounted for, and the sender must obtain an authenticated
terminal disposition. Crediting the executor instead would change the intended
recipient. Creating an ordinary account would violate the singleton executor
state/replay contract. None of these are acceptable shortcuts.

## Decision: configuration-owned destination admission

Introduce a shared native ingress policy that is readable without installing the
destination engine. Do not derive sender admission from the local execution
registry: a Native validator can legitimately lack that foreign engine, and
local plugin availability must not change message-send consensus.

The common policy must authenticate:

- Workchain ID and the execution descriptor/engine identity it applies to.
- Execution scope and the exact executor destination for singleton batches.
- Address representation rules (256-bit standard address, no anycast for this
  host version), policy version, and activation boundary.
- A link to engine-specific configuration, without requiring Native validators
  to interpret proof systems, private state, or engine code.

ConfigParam 12 remains authoritative for the workchain descriptor and its
`accept_msgs` setting. A common configuration record must be checked against
that descriptor, not become a second independent descriptor source. The UNO
specification names ConfigParam 84 as a candidate; this development implementation
uses it for the common table, with engine-specific configuration referenced by
each entry. This is not a production activation or a frozen wire protocol.

Both sender collation and sender independent validation must use the same
resolved common policy through ActionPhaseConfig. Receiver registry resolution
must verify that its engine policy agrees with the common executor address.
Unknown policy versions, mismatched descriptor bindings, or missing required
policy must fail closed. Ordinary workchains outside this opt-in policy retain
their existing address behavior. The rule is gated by global version and the
host capability, not network capability advertisements.

The current resolver binds every table entry against ConfigParam 12 without an
engine registry. Shared transaction configuration loads the resulting destination
map for collation/emulation; independent validation loads the same map. Both
send and bounce destination rewriting reject anycast and non-executor addresses.
Native normalization of a 256-bit addr_var into addr_std remains supported.
Receiver engine resolution requires a matching table entry and executor address.
The opaque engine-configuration payload is not yet an input to engine execution.

Reject a new invalid destination using the native invalid-destination action
path, including existing send-mode and fee semantics. Do not enqueue a message
and then attempt to reject it only at the destination. Native bounce destinations
must also use the common admission policy; audit the second caller of
`check_rewrite_dest_addr`, not just ordinary sends.

## Activation and messages already in flight

M0 decision: slot 84 was unused before the development definition, but an unknown
positive ConfigParam invalidates the entire configuration in old binaries.
The definition in block.tlb therefore introduces a masterchain upgrade boundary.
`valid_config_data` now checks parameter presence against version 15 AND
capBlockTransition, independently of the reader/execution gates. This rejects an
otherwise structurally valid table before activation, even an empty table.
Upgrade readiness and authenticated transition enforcement remain open; this
presence check alone cannot make an old binary understand the new structure.

Retain a formally defined positive parameter as the design direction, with 84
still subject to the final schema freeze. Before the parameter may appear, every
validator (including the next set at the activation boundary) must have upgraded
to the supporting binary, with auditable readiness evidence. Keep the parameter
absent and UNO admission closed during that rollout. Only then may an authenticated
configuration transition introduce it under gates at least as strong as version
15 AND capBlockTransition. Descriptor/state/in-flight checks must precede opening
admission. A capability advertisement alone is not proof of deployment readiness.

Negative keys avoid generic payload validation, not the need for safe activation
or full fail-closed parsing by new readers. They are not the selected compatibility
shortcut. Moving to another positive slot (including the free 46–70 range) would
not change the upgrade obligation.

The Counter genesis at a0d261f6f already contains development parameter 84. It is
a same-new-binary, mock-engine/finality regression fixture, NOT a UNO deployment
template or mixed-version rollout test. Do not reuse it as a deployment path or
introduce deployable positive-index UNO genesis configurations before this freeze.
Production remains blocked on readiness evidence, transition checks and
old/new-binary negative acceptance tests; the current passing harness proves none
of those properties.

Two same-binary Counter negative cases now exercise `valid_config_data` through
create-state: parameter 84 with an old version or missing capability must fail
without a masterchain zerostate artifact. Disabling only the caller's rejection
branch makes both configurations succeed and both tests fail. This establishes
the complete configuration-validation gate, not a mixed-version rollout or an
authenticated configuration-update transition.

Sender admission prevents new wrong-address traffic; it does not dispose of
already committed messages. Activation must not assume an empty queue merely
because the new workchain state has an empty local OutMsgQueue. Foreign source
queues can contain messages addressed to it.

For a fresh workchain, keep native admission closed until descriptor, common
policy, engine configuration and zero state are jointly committed. Opening
`accept_msgs` must require the policy to be installed and consistent.

For an existing workchain or executor-address change, require an authenticated
transition cut and reconciliation of pending imports before switching address
semantics. If this cannot be proved, reject the transition. Do not provide a
development-only reset or an unauthenticated queue purge as a production
migration mechanism. A later general refund/quarantine design would need its
own canonical liabilities, message records, and terminal receipts; it is not
implicitly authorized by this admission policy.

## Required implementation and evidence

1. Freeze and implement the common configuration codec, descriptor binding and
   policy lookup independent of engine registration. Check registry agreement.
2. Feed it into native action configuration in collator, validator and emulator;
   audit every destination-rewrite/send/bounce entry point.
3. Enforce valid activation/configuration transitions, including pending-message
   reconciliation and executor-address continuity.
4. Test identical admission with and without the foreign engine installed;
   correct destination, wrong workchain/address, anycast, alternate encoding,
   missing/unknown policy, mismatched binding and activation boundaries.
5. In the disk harness, make a Native sender attempt a wrong-address transfer
   followed by a valid one. Prove no wrong-address message enters its queue and
   the valid transfer reaches the batch without stalling or losing principal.
6. Test activation with a pending wrong-address message and an address change
   with outstanding traffic. These must reject without changing commitments.
7. Mutation-check admission and transition gates, then rerun self/cross-workchain
   delivery, independent candidate replay, queue cleanup and value-flow tests.

Until these are implemented and verified, the current host remains unsuitable
for production activation even though valid-destination delivery tests pass.
