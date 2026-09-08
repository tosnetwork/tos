# V2 resource-policy wire boundary

In-flight D31 implements the resource object and the approved two-reference
engine-configuration framing, not complete authenticated admission. Version 2
is approved for multiaccount admission; version 1 retains its single-candidate
prototype meaning. Neither value is an implicit configuration default. The
version-2 installation gate is connected through `valid_config_data`; the
complete admission path remains unimplemented.

The five constructors omit explicit tags in `crypto/block/block.tlb`; `tlbc`
derives CRC32 tags from its normalized constructor definitions. Recompute with:

```
build/crypto/tlbc -vvv -q -t crypto/block/block.tlb
```

| Constructor | Tag | Bits / refs |
|---|---|---|
| uno_v2_resource_policy | bbd8a9ec | 64 / 3 |
| uno_v2_resource_input | c5defa2a | 320 / 0 |
| uno_v2_resource_state | 90aef2dd | 304 / 0 |
| uno_v2_resource_work_output | 7a310b92 | 384 / 0 |
| uno_v2_engine_configuration | b7226bea | 32 / 2 |

Each is the sole constructor in its own union; all five tags are distinct and
occur once in the generated constructor-tag tables. The resource object alone
has four cells, 1,072 bits and depth one, excluding framing and business
parameters. Encoding preserves the approved integer
widths, including full uint64 limits and uint32 admission_version. This is not
an input-budget measurement or a deployable capacity figure.

`WorkchainResourcePolicy` is explicitly unresolved wire data. Parsing accepts
representable zero or unknown-version fields without declaring them valid
configuration or supported execution. Installation must separately validate
limit combinations, version capability, compatibility with persistent state
and atomic migration. No live caller is allowed to substitute this parser for
that validation. The framing contains mandatory resource and business-parameter
references, in that order. Business parameters are opaque to the host; the
engine must require their own versioned tag and validate their full contents.
No missing reference selects defaults. Host-visible additions require a new
framing version. This framing does not reinterpret singleton engine payloads.

Resource decoding loads four slices; framing adds one. Business-parameter
decoding is a separate engine responsibility. Exact consumption is required.
It uses generated field/tag unpacking, not the generated quiet cell loader.
Malformed encoding returns an error; acquisition/allocation exceptions remain
exceptions for the provenance-aware caller. There is no new consensus error
category or blanket catch. An explicit special-cell check precedes generated
decoding; this contract does not depend on current or future CRC32 tag values.
The ordinary/special-aware loader never resolves a library ref
as code to execute.

`ResourcePolicyRejectsSpecialBeforeDecoder` uses a test-only permissive decoder
to isolate this boundary from tag rejection: ordinary bytes reach the decoder,
but the same bytes in an encoded library-reference cell must not. Without the
explicit special check, the test fails on acceptance, independently of error
wording. This probe introduces no additional wire constructor.

The in-memory `InputPolicyIdentity` admission_version is widened to uint32,
matching the existing 32-bit host commitment field. High-bit values must remain
distinct, never aliasing 1 or 2. Wire round-trip tests cover 2, 0x10002 and
0x80000002 without claiming support for those unknown versions. No singleton
wire encoding is modified.

The configuration boundary rejects unsupported admission versions, malformed
framing and zero input cells/bits/roots. Binding derives its immutable policy
identity from the same Config root and descriptor. A corrupt authenticated
resource payload is not a candidate-invalid result; unsupported local execution
capability remains local unavailability. The singleton policy type is separate.
This does not yet validate all resource-limit combinations or business parameters.

Adding a future admission profile creates an installation compatibility
boundary: a binary supporting only version 2 rejects a version-3 configuration
that an upgraded binary may accept. Deployment readiness must precede profile
activation, with an explicit first effective block and an upgrade-sequence
dry-run covering mixed support. The advisory global-version ceiling does not
enforce this deployment ordering. At execution time, lack of support for an
already authenticated profile remains LocalUnavailable, not CandidateInvalid.

The complete test configuration exercises `valid_config_data`, including its
mandatory Native parameters and matching descriptor. Removing its resource-gate
call accepts an unsupported version and fails a Boolean acceptance assertion.
Each zero-limit conjunct and the independent identity-version guard also has
a separately rebuilt negative control. Evidence is in
`measurements/uno-v2-resource-policy-wire-evidence.json`. These are manual runs,
not recurring CI mutation jobs. Earlier sections of that artifact retain their
historical source hashes and scopes; they are not snapshots of the final tree.

Remaining D31 integration: complete installation/transition consistency;
one immutable policy through both live entry points; `3 + N_inbound` logical roots and deduplicated
physical closure; bounded inbox construction; state, proof-work and output
budgets; finality representation; full M1 stage-order and atomicity tests.
Fee units must not substitute for proof-work units. Codec tests do not close
any of those live integration gates.

The inbox structural builder now takes `ResolvedBatchInputPolicy` and checks
its `max_inbound` before allocating the sorting vector or loading envelopes.
An explicit allocator lets the tests observe the vector's actual allocation,
not a proxy callback. Native canonical dictionary construction admits each
finalized node before constructing its parent. At most one finalized node is
awaiting admission; rejection stops construction and releases the partial tree.
For N distinct messages, there are exactly 2*N final nodes including the wrapper,
with N bounded by both the authenticated count and the 15-bit wire encoding.
Sorting entries, at most 257 recursive builders, and the caller's union-dedup
map are separate memory objects, not hidden inside the one-node allowance.
This is a construction boundary, not the complete shared input-union session.
The legacy encoder retains its loader/error behavior and full semantic decode;
its wire-only count cap is not an authenticated V2 policy default.

Review follow-up: the new wire-count failure has the candidate-invalid category,
while the legacy API preserves its original code. Uniform zero/one hash-prefix
fixtures exercise canonical same-bit labels independently of random coverage.
The source uses fixed-width geometric bounds rather than an unreachable generic
cell-write guard. Both paths are host construction, not interpreter execution.
Installation/transition compatibility with required system-message progress
remains an activation prerequisite. Executable admission version 2 now rejects
zero in all six input fields, including reads, writes and inbound: disabling
state access or Native ingress is not a substitute for lifecycle controls.
The wire codec still represents zero for diagnosis; installation rejects it,
policy construction returns ConfigInvalid, and an already authenticated bad
cut is AuthenticatedStateCorrupt at registry binding, not CandidateInvalid.
Positivity is necessary, not proof that every positive combination can serve
the required messages, wrappers and state changes.

Batch-session structural-boundary review disposition: the claim that removing the
session's logical-root guard leaves its test green is disputed by a rebuilt
negative control (exit 1, typed-category assertion). The materializer receives
the derived `logical_roots`, not the configured `limits.roots`. Its vector has
exactly that derived length, so its generic root-limit check is unreachable on
this call path. The session guard is the only comparison to the authenticated
root limit. This mechanism, rather than the historical test run alone, explains
why the guard must remain. The raw control is recorded in
`measurements/uno-v2-batch-root-mutation.json`.

The shared-declaration expansion finding is accepted. Structural input admission
must not enumerate the full key set or reconstruct it before commitment. The
new shallow inspection caches `(cell hash, remaining key width)` separately for
read and write trees: at most 257 times the acquired physical closure's cell
count per role, with at most 257 recursive frames. Each shared edge contributes
its cached logical count; checked sums enforce the same authenticated read/write
limits. It does not impose a new ratio between logical keys and physical cells.
Full canonical encoding and write-subset validation remain required after
commitment, before any execution permission is issued. This shallow result does
not close those semantic checks or the later state/work/output admission gates.

Follow-up review confirmed the pre-commitment expansion is removed and identified
a tighter structural argument: within each role, a subtree can finish at only
one remaining width. This needs both disjoint fork/leaf reference profiles and
exact label consumption, not reference counts alone. Let m be remaining width,
n the encoded label length and k=ceil(log2(m+1)). Short labels fix n independently
of m. For a fork, exact bit consumption fixes k for same labels (and then n);
for long labels it fixes k+n, so increasing m cannot decrease m-n-1. In fact
the child width strictly increases. Induction from leaves then excludes a fork
succeeding at two widths. Leaves require n=m: short labels fix m, same labels
fix k and encoded n, and long-label size 2+k+m strictly increases with m.
Relaxing exact label consumption or the leaf profile requires re-proving this
bound. The completed cache therefore has at most one entry per physical cell,
plus at most 257 active frames on the first failing path. The 257-times bound
above is conservative, not the expected reachable footprint. Logical count
limits apply on unwinding; this structural bound, not a small count limit,
protects the traversal itself.

At d2af972ec, session-level tests covered nonempty reads and writes, zero leaf allowances,
malformed read/write leaves, thrown label errors and local acquisition failure.
A shared cell reached at two widths must reject: collapsing the cache key to
hash-only makes that test accept and fail (exit 1). Changing the candidate
dictionary VmError catch to a local failure also fails its typed-category test
(exit 1). Raw controls are in `measurements/uno-v2-declaration-width-mutation.json`
and `measurements/uno-v2-declaration-category-mutation.json`; these are manual
controls, not recurring CI mutation jobs. At that commit, removing the zero leaf
allowance guard or disabling write-leaf shape validation independently made the
same session test incorrectly admit input and exit 1. Their raw outputs are recorded in
`measurements/uno-v2-declaration-leaf-mutations.json`. These close the follow-up
review's requested session controls; they do not establish live D31 acceptance.
The zero-leaf session controls above describe commit d2af972ec, where zero
semantic limits were representable as resolved policies. With the stricter
configuration gate, session count controls instead use two keys under a legal
limit of one; separate typed configuration tests reject each semantic zero.
Their three test-first failures are in `measurements/uno-v2-semantic-zero-config-red.json`.
The direct utility still accepts an explicit zero allowance as an argument and
must reject a nonempty leaf under it. Its dedicated control fails when the leaf
guard is removed: `measurements/uno-v2-direct-zero-leaf-mutation.json`.
Zero inbound still permits internal reads/writes. Its rejection is deliberately
a V2 service-profile restriction: lifecycle pause/retirement must preserve Native
system-message service, not emulate closure through a zero admission allowance.
It is not the same no-state-progress argument as zero reads or writes.
The historical artifacts remain unchanged and must not be cited as tests of
the newer configuration policy.
The live collection, provenance, old-state, proof-work and ordering requirements
remain unchecked in `uno-v2-implementation-plan.md`.
