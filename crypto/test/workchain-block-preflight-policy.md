# Block preflight policy encoding

The bounded policy replaces the old resource-policy constructor. It carries a
mandatory fourth reference, `block_preflight:^ParamLimits`. No old constructor
is accepted. The root also carries mandatory `preflight_allowance:uint64`;
neither allowance nor thresholds have constructor defaults. The existing
`work_output.max_proof_units:uint64` remains a separate per-call bound.

## Existing mechanism correspondence

The source baseline is dd2327c90. `block.tlb:820-830` defines the existing
`param_limits#c3` and ConfigParam 22/23 block limits. This policy uses that exact
TL-B type, including its three uint32 values and ordering constraints. Its child
cell is 104 bits, no references. The policy root is 128 bits and four references.
`block.cpp:670-679` provides the existing ordered decoder; `block.cpp:702-717`
shows classification and the strict `value < threshold` fit predicate. Equality
reaches the threshold. The internal medium threshold is derived, not a fourth
wire field. `block.h:287-323` is the reference for block gas accumulation, not a
license to copy unchecked arithmetic.

The wire thresholds are uint32. Cumulative work requires checked uint64 because
repeated charges can overflow an accumulator; this distinction is intentional.
Neither this codec nor its tests implement accumulation or account execution.
Collator accumulation and validator independent reconstruction belong to the
separate enforcement work. No gate is opened here.

C2 production enforcement is BLOCKED by the retained AccountBinding refusals
and the absence of a production preflight call sequence. It cannot be delivered
by an unused accumulator. Unblocking requires an owner decision on live wiring
and an actual sequence whose full membership can be independently reconstructed.
C3 concrete-engine enforcement is likewise BLOCKED by the absent production
preflight implementation/call site; the host-only meter is not that evidence.

This is policy encoding and migration, not completion of C2. Production
AccountBinding visitors still refuse execution. There is no production batch
preflight call sequence to charge. The per-call allowance now has an explicit
authenticated encoding source, but no production invocation consumes it yet. The return value of `proof_work` bounds subsequent declared
proof work; it must not be used to charge the inspection that computed it.

### Required enforcement controls (not yet implemented)

Only the producer may consume underload/soft as filling heuristics. These fields
currently have no production consumer for this policy. The validator must use
hard alone, with no extra per-call grace allowance. The approved soft=hard
setting requires identical counted invocation sets and authenticated integer
allowances on both sides, no rounding, exemptions or refunds. Shared inclusion
rules must not share accumulator state or candidate verdicts.

The enforcement acceptance controls must include: total equal to hard accepted;
hard+1 rejected specifically for block budget; producer exact-fit admitted and
one-unit excess refused before the callback; a `> hard` to `>= hard` mutation
detected at equality; and a hard-to-soft mutation detected using a separate
soft<hard fixture. Special-path invocations must be charged as ordinary ones.
Refused reservations must never invoke inspection; operations with no inspection
must not acquire a fictitious charge.

## Provisional values and identity

The production export word supplies 0/2/2 (underload/soft/hard) and an explicit
preflight allowance of 1 in the same preflight budget units. This deliberately
small provisional tuple is not an operation-unit calibration, SEND/COLLECT
conversion, or hardware capacity claim. The independent declared-proof-result bound remains 1; equality of the
provisional numbers is not a unit equivalence or a derivation.
The `uno-genesis-resources-approved?` mainnet allowlist remains closed, including
for arbitrary substituted resource values. Before M6 capacity acceptance, no
claim that wc=2 resource quotas are determined is permitted.

The new generated constructor is 0xf37fed2f, replacing 0xbbd8a9ec and the uncommitted
three-tier-only draft 0xfb8a7703. Preflight allowance and thresholds share preflight budget units, distinct
from the declared-proof-result units. Concrete operation weights and any new
admission-version enforcement contract remain pending; existing
callers retain their admission versions. A changed wire tag does not authorize
execution or imply that the old version has acquired a metering guarantee.

The previous 0/1/2 draft was superseded by the approved 0/2/2 tuple. No
production test currently reaches hard refusal, equality acceptance, or special
path charging: the closed gate prevents the invocation sequence itself. Once
that blocker is removed, exact-fit and hard+1, callback-before-refusal, and
special-path inclusion controls become runnable. Strictly below underload=0
remains unreachable by definition. The soft<total<=hard case requires a separate
soft<hard fixture; it is empty under the provisional tuple.

The earlier fixed-input root comparison is fully explained, not attributed to
nondeterminism: adding the 104-bit ParamLimits child changed configuration-account
storage_used by one cell and 104 bits. Reverting both policy and those accounting
bits reproduced the old root exactly. That evidence describes the earlier draft,
not the new allowance-bearing encoding. The new fixed-input comparison also
closes: +1 cell and +168 bits (104 child bits plus 64 allowance bits), and
reverting policy plus that exact storage accounting reproduces the prior root.
Two identical-input runs produce byte-identical BOCs.

## Migration inventory

See `doc/measurements/uno-block-preflight-bounds/constructors.json` for every
baseline C++ location: 26 explicit constructions in 11 files plus the codec's
internal decode construction. The generated block-auto files are build outputs;
the schema remains their source. C++ raw-wire negative tests are migrated too,
while deliberate old-tag rejection inputs retain the old bytes.

The only live hand-written Fift policy is in
`test/test-counter-disk-integration.cmake`; its new ParamLimits child is included
in the existing handwritten-tag guard. Production gen-zerostate, Counter genesis
and network scripts, and tostester's UNO profile get resources from the same
create-state export word rather than independent field encoders.

Two frozen current test inputs required attention:

- The default prepared-local test formerly read the historical
  `doc/measurements/uno-local-profile/run-3/state/zerostate.boc`. It now reads
  `crypto/test/workchain-bounded-zerostate.boc`; the control driver follows that
  same relocation. The old measurement remains unchanged with an inline notice.
- Rust `tosctl/src/block/src/tests/data/mc_state_extra_instances.boc` is extracted
  from the newly generated zerostate. Rust's McStateExtra codec preserves the
  configuration cells opaquely; no independent UnoV2ResourcePolicy decoder was
  found in the inspected Rust source. Its codec does not need a new policy tag.

The genesis oracle is updated individually: only its masterchain zerostate size
and root/file hashes change; basechain state and address summaries are unchanged.
Other oracle entries are not refreshed.

The inventory scanner examined all 66,483 baseline tracked regular files,
4,921 compressed archive members and 867 magic-prefixed base64 candidates, with
zero decompression errors. The complete hit list and bounded search method are
in `migration-scan.json`. Byte hits are not claimed to be independent decoders.
Historical archived BOCs retain their original encoding and provenance; they
are not current decoder inputs. External databases, encrypted archives and
arbitrary non-magic-prefixed encodings are outside that search. Existing local
chains containing the retired policy have no in-place migration supplied by
this patch; no compatibility branch or deployment data rewrite is introduced.

## Controls and limits

`ResourcePolicyBlockPreflight` checks distinct carried values, missing reference,
ordering on decode as well as encode, maximum uint32 values, and both historical
three-reference and otherwise-current four-reference cells with the old tag.
The latter require the exact unrecognized-constructor error, isolating tag
rejection from a missing-reference failure. Existing special-cell and closure
controls now cover the fourth child. A fifth root reference cannot be constructed
as a valid native Cell and is not counted as a successful decoder rejection.

The earlier draft's three mutations (tag reason, omitted fourth reference,
discarded tiers) remain historical. Final `PreflightAllowanceWire` controls cover
six isolated mutations: tag reason, missing-field reason, encoded value loss,
decoded value loss, derivation from max_proof_units, and uint32 narrowing. Each
compiles, fails its designated assertion, and passes after byte-exact restoration
plus explicit object rebuild/relink. An initial empty controls report is an
aborted baseline compilation, not a successful control set. These are codec
tests, not C2/C3 or live call-site evidence.

## Installation compatibility decision still required

**Superseded by the approved static-consistency follow-up:** the following
paragraph describes the 72c8e543b encoding-only state. Resolution now rejects zero
allowance as ZeroLimit and allowance greater than hard as
PreflightAllowanceExceedsBlockBudget. Installation applies the same pure
compatibility check; the comparison widens hard to uint64. Equality is accepted.
Original limitation follows for historical context.

The codec intentionally represents zero and allowance>hard policies. Neither a
positive preflight allowance nor allowance<=hard is currently enforced at
installation. Before claiming an executable preflight profile, the installation
contract must decide these constraints explicitly: a zero request is rejected by
the C3 host, and a request above hard cannot start under the C2 reservation rule.
This is possible unusable configuration, not permission to execute above hard.
No installation rejection or default is added silently by this encoding patch.

The smartcont oracle-control driver must compile and relink from the same build
whose create-state path it supplies: TOS_CREATE_STATE_BINARY now checks equality
with TARGET_FILE, rather than selecting another executable. Handwritten tag
checks cover numeric tag values; broader Fift literal-width checking is not
claimed by this migration.

The static-consistency controls exercise both the typed factory and the real
valid_config_data installation path. A factory-only check would not protect
installation, which invokes validate_native_ingress_presence separately. Tests
cover zero, hard+1, 2^32 against hard=2, UINT64_MAX, and exact equality. They do
not claim that a production accumulator rejects a second call; that call sequence
remains blocked. The codec still represents these values so invalid-policy
fixtures reach the semantic check rather than failing at unrelated framing.
