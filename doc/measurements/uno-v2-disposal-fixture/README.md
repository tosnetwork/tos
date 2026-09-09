# Disposal fixture initialization and predecessor diagnosis

The failing pair is `AggregateFeeSettlement` followed by `NativeDisposalEntry`.
Both tests pass individually. The integration tree also passed the pair and
full group before this repair: that was masking, not a repair. The predecessor
record is copied verbatim and preserves the exact negative-filter selection.
It was measured at `a0cca7b2a`, not at the integration parent. The two involved
test bodies and disposal header were identical across those pre-repair trees;
other test additions changed layout, not the faulty fixtures' source.
`final-pair.json` selects exactly those two tests on the repaired tree, excluding
the newly added initialization test, and checks the actual Running-test names.

`MsgPrices() = default` leaves six integer fields uninitialized. The disposal
fixture previously filled `fwd_std` only, but its context guard also reads
`fwd_mc.first_frac`. In the recorded failing binary the read-only debugger probe
observed `fwd_std.first_frac=16384` and `fwd_mc.first_frac=2443192600` at the guard.
The unmodified binary rejected the invalid context. An in-memory intervention
on copies of that same uninitialized value made the pair pass without changing
the binary. The diagnostic script checks the binary hash before and after.
This is causal debugging evidence, **not** a regression control: replacing the
garbage value with zero is not the approved fixture repair.
The archived diagnostic script is the original environment-specific command:
it needs the sibling measurement path and the exact recorded pre-repair binary.
It is not a portable replay tool or a replacement for the current source tests.
The local copy of its predecessor record does not supply that historical binary.

The repair explicitly initializes both price schedules in both fixtures. The
mainchain schedule has lump price 100 and first fraction 16384, not a zero-price
default. Production `MsgPrices` and the disposal guard are unchanged by this
commit. Production obtains price schedules from authenticated configuration
and fails on missing configuration; this diagnosed failure is a fixture defect,
not demonstrated production consensus divergence.
The empty-inbox `AggregateFeeSettlement` path did not consume these prices;
initializing it is defensive. `NativeDisposalEntry` is the direct repair.

Two deterministic controls use the final test source:

1. The initializer test first fills every field with **defined** poison values,
   calls the same initializer used by both fixtures, and reads all fields back.
   Removing the mainchain assignment fails directly at `911 != 100`, before any
   transaction or disposal guard. It does not read uninitialized memory.
2. The disposal fixture first demonstrates a valid direct planner call, then
   changes only the initialized mainchain first fraction to 65536. It requires
   rejection and the owner-specified `invalid resolved disposal context` message.
   Removing only that fraction guard fails at `rejected_mc_prices.is_error()`,
   before any enclosing transaction/conservation rejection could mask it.

Each single-source mutant built successfully with `-j32`, exited 1 at the
named assertion, and was restored byte-for-byte. The final binary hash equals
the initial repaired baseline; the exact pair passes and the complete
WorkchainBlock group passes 123 tests. This is not a full repository CTest run
and does not include the opt-in I13 harnesses. Raw logs retain diagnostic
whitespace. Default-member initialization of `MsgPrices` is separate hardening,
not credited with fixing this fixture.

Review residuals: other fixtures still partially initialize price schedules;
the group passing is not a claim that the whole group is free of indeterminate
reads. The separately authorized default-member hardening addresses that type
hazard. The later explicit `joint_prices.fwd_mc` assignment is retained as a
local declaration of that joint fixture's schedule, even though it currently
equals the copied schedule. Test prices are deliberate synthetic values, not
a claim about production mainchain/basechain fee ordering. No additional
pricing policy is introduced to satisfy that review observation.
