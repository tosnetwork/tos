# Disposal engine execution and independent replay

The explicit post-admission disposal runner now connects the account engine to
the private disposal allocation overlay. Native envelopes arrive through
`MaterializedNativeCells`; the complete final-import set is kept, including
misdirected destinations. The existing strict runner still rejects those
destinations before invoking the engine.

Roles, limits and pricing have a single source in the borrowed disposal context.
Unsplit-shard, distinct-role and pricing-version consistency checks precede the
engine. They are structural checks, not configuration authentication. The
engine executes once, its effects are encoded once, and the prepared Native
artifacts carry those same input/effects bindings. Disposal exports propagate
as message/transaction/index/LT tuples, not queue-ready envelopes.

Independent replay first compares the reconstructed full input, before invoking
the engine. It then executes once and compares effects, accounts, AccountBlocks,
InMsgDescr, end LT and the optional payout message. Derived export and import
caches are reconstructed, never taken from the caller.

## Compatibility and incomplete integration

An initial blanket rejection of payouts in disposal mode was unnecessarily
restrictive. A positive regression failed with that guard present. Removing it
preserves the existing payout path when there are no foreign imports. Both
entries then produce identical Native roots and payout messages under the same
unsplit identity. The existing payout path still validates the complete inbox
and rejects foreign destinations; it never drops them.

**Joint custody payout and coordinator disposal remains M1 work.** That requires
one combined private settlement, not sequential independent commits or a new
fallback that filters forced imports. This runner is not activated in live
collation or validation. Native queue insertion, metadata, actual-source FIFO,
versioned address exceptions, return authorization and liability accounting
remain necessary. Registration is also not supplied here.

No new voting error category or exception conversion is introduced. A plain
Status is not the production invalid-candidate/local-fault classifier. The
enclosing host must authenticate configuration and account/queue provenance,
perform aggregate admission, and preserve error sources. Repeated bounded input
construction in replay and execution must be charged by that admission policy.
All new counters in the fixture use checked increments; currency and LT
arithmetic continue through the existing checked settlement primitives.

## Evidence

Ten manually rebuilt controls failed at runtime: disable disposal routing,
discard the engine inbox, invoke the engine twice, omit exports, remove each of
three pre-engine context checks, remove pre-engine input comparison, remove
effects comparison, and return caller caches. Tests assert input/root identities,
output counts, and zero/one engine invocations, not error wording.

The additional no-foreign-input payout regression failed before removal of the
overly broad guard and passed afterward. The five registered regression tests
passed after restoration (3.89 seconds); standalone compilation of the replay
header passed. Raw output, exact edits and source/binary hashes are in
`measurements/uno-v2-disposal-runner-evidence.json`, including intermediate and
final diffs. These manual controls are not recurring mutation CI. Ordinary tests
remain in test-workchain-block.

No consensus-judgement source file or error classification changed in this unit.
It awaits M1 milestone review under AGENTS.md; it is not M1 completion.
