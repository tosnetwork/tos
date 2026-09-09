# Determinate message-price defaults

This is type hardening after the independently committed fixture repair
`879e5878a`, not the cause of that repair. The six integer members of
`MsgPrices` default to zero. The parameterized constructor still assigns all
six supplied values, and the test checks six distinct values (101 through
106). No field is added or reordered, and no configuration decoder or failure
path is changed. Zero initialization is not permission to accept a missing
authenticated fee schedule or to omit an explicit fixture schedule.

The actual `test-workchain-block.cpp` translation unit contains
`constexpr block::MsgPrices prices;` **without braces** and checks all six
members at compile time. Value-initialization with braces has a separate
zeroing rule and would not establish this property. Each control removes one
default member initializer and invokes the actual test compiler command with
`-fsyntax-only`, producing the recorded default-initialization error in that
test file. The initialized baseline compiles successfully. These are six
**compile-time controls**, not successful behavioral mutation tests and not
reads of uninitialized memory. Every control's source mutation and exact
restoration hash is recorded; no object file is overwritten by the syntax
checks. Runtime regression is recorded separately in `final-checks.json`.

Review follow-up adds a seventh control: changing `lump_price`'s default to 1
still satisfies const-default-constructibility but fails the actual zero-value
`static_assert` (`1 == 0`). Thus initializedness and the required zero value are
tested separately. The six removal diagnostics are intentionally identical:
one class-level rule is exercised with six distinct single-member omissions,
not six independent diagnostic instruments. Baseline and final compile exit
codes are explicit; empty compiler stderr alone is not success evidence.

The two disposal fixtures retain their explicit nonzero schedules. Other
partially assigned price objects now have determinate remaining fields; this
does not certify the semantic adequacy of every fixture or every price policy.
