# D76 component anchors checkpoint

Specification: memo `8b96aa66`, SHA256 prefix `24291053f8c289fe` (D76 x and b).
D77 arrived during this work; Failed integration follows this checkpoint.
No independent accounting prediction was read.

## Principal x

After actual proof verification, the registered test engine copies the operation's
principal into local-only `effects.payout_principal`. No wire effects decoder
populates that field. Settlement forwards it through the payout overlay into
the Native pair builder independently of its message request and exact q.
After serialization, the Native message's complete CurrencyCollection value
must equal x; mismatch is **-7200**, specifically
`Native payout value differs from authenticated exact x`.
The D75 q comparison remains separate and unchanged in meaning.

Before installing the comparison, the new argument was present but unused.
Actual Native payment=137, actual/declared q=100, declared x=136 and 138:
both exited **1** at `result.is_error()`, having constructed successfully.
After installation both require the exact principal-equality error; x=137
passes. Calls with both anchors are tested with zero legacy ceiling, so they
reach the comparison rather than failing at send-budget pricing. Principal-only
calls retain the old fee ceiling; only exact-q callers lift it for pricing.
No refund path is added.

Logs: `/tmp/uno-d76-lower-red.log`, `/tmp/uno-d76-higher-red.log`,
`/tmp/uno-d76-final-native.log` (**9/9**, exit 0).
Observation is the actual Native pair boundary, not a signed candidate mutation
through the full collator. Removing a plumbing assignment above that boundary
is not covered by these negative tests; no such coverage is claimed.

## Reserve b

The test business codec adds an **optional, explicitly encoded** max_bounce_cost.
Old versions 1-5 retain their byte formats and decode absence as absence, never
as zero or a default. Version 6 adds the reserve to prepare; version 7 includes
the already existing Failed profile as well, with equal withdrawal limits.
These remain test-owned layouts, not a frozen production configuration format.
Explicit fixture reserves are 23 (prior small prepare) and 4000000 (funded
return route); neither is a protocol default/frozen initial value.

Registered configuration resolution rejects a prepare profile with the field
absent: **-7201**, `ConfigInvalid: explicit max_bounce_cost absent`.
Both the actual proof-work admission hook and execution compare claimed b to
the resolved configuration; after encoding the W control envelope, its stored
original_reserve is independently decoded and checked against that configuration.
Mismatch is **-7200**, specifically
`Withdrawal reserve differs from authenticated max_bounce_cost`.

`--check-m5-reserve-admission FIXTURE [direction]` invokes the actual registered
engine hook via its resolved authenticated fixture configuration. Before the
gate was installed, b=22 and b=24 (configured 23) both exited **134** at
`CHECK(result.is_error())`. Afterward both reject at the named reserve equality;
the unchanged input passes. This observation stops **before proof verification**:
the mutated candidates reuse authorization bytes, and this is not a claim of
matching-proof generation or completion of a full prepare contract item.

Logs: `/tmp/uno-d76-b-lower-red.log`, `/tmp/uno-d76-b-higher-red.log`,
`/tmp/uno-d76-b-green.log` (exit 0).
An old version-5 fixture was also attempted: resolution returned the specified
missing-config -7201, then the positive-only CLI aborted while consuming that
error. This is a diagnostic of the rejection point, **not a passing dedicated
missing-configuration test** (`/tmp/uno-d76-b-missing.log`).

## Live positive and limitations

After both gates were installed, the funded return route passed with real
prepare ON/OFF and real wc0 recipient verification (exit 0), fixture
`/tmp/uno-m3-live-kkcqxgom`, log `/tmp/uno-d76-final-live.log`.
x=10000000, q=100, b=4000000, f=257; available=985999643,
R_actual=R_book=989999643, P=10000000, W=14000000. The actual rich return carries
9996070, preserves full original body and LT=16000002. Its hash changed with
the new authenticated genesis/configuration; no old bounce was relabelled as
an input belonging to the new chain.

Three build targets passed; focused confidential-input CTest passed 1/1.
The old f conclusion is obsolete: fee-floor checks are installed; their
independent matching-proof negative remains the separate fee-admission contract.
Unknown-source counter is absent/unmeasured, full prepare contract is still 0/9,
and Failed has not yet published. No guard is retired here.

## Read-only boundary review

Both principal and reserve reviews found no blockers. The reserve follow-up
correctly narrowed the earlier principal review's proposed scratch-ceiling
extension: principal-only calls retain their old ceiling, as x alone does not
authorize extra fees. The actual prepare caller supplies both anchors.
Reserve probes now run in the live script and print the actual error on
mismatch; they remain pre-proof hook probes, not signed-proof contract tests.
The existing confidential-input CTest pass does not cover the new v6/v7 codec
branches; dedicated codec mutation/round-trip coverage remains unclaimed.
The missing-reserve helper branch is defensive after successful configuration
resolution, not an independently demonstrated admission gate. No global error
classification or contract-completion claim follows from this review.
Post-review rebuild and both executable probes passed (Native 9/9):
`/tmp/uno-d76-reviewed-build.log`, `/tmp/uno-d76-reviewed-native.log`,
`/tmp/uno-d76-reviewed-reserve.log`. The live-script addition invokes that same
probe; its integration is committed for future runs, not reported as a second
complete live run after review.
