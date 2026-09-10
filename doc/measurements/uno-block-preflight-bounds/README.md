# Preflight policy encoding and migration

This is **encoding and migration evidence, not C2 completion**. No production
accumulator, validator reconstruction, concrete preflight engine, or live call
site is introduced. The AccountBinding refusals and registry gate are unchanged.

## Authenticated representation

`uno_v2_resource_policy_bounded` has generated tag `f37fed2f`. Root bits are tag
[0,32), `admission_version:uint32` [32,64), and
`preflight_allowance:uint64` [64,128). References are input, state, work_output,
and `block_preflight:^ParamLimits`, in that order. The child is the existing
`param_limits#c3` (8-bit tag followed by three uint32 thresholds).

Allowance and block_preflight use the same preflight budget units. The separate
`work_output.max_proof_units` bounds the **declared result** of inspection, not
work spent producing it. Neither quantity derives from or defaults to the other.
Concrete operation weights and an executable admission-version contract are not
established by this codec. Existing callers retain their explicit versions.
Production supplies provisional allowance 1 and thresholds 0/2/2; mainnet resource
approval remains closed. Zero is representable wire data, not a default or a
claim of a valid C3 allowance.

`tag-tables.json` enumerates 118 generated tag tables / 221 values. The new tag
occurs once; both `bbd8a9ec` and the uncommitted draft `fb8a7703` are absent. The
raw archive retains the compiler output, generated header, and independent CRC
input. Old tags fail the constructor check. A current-tag cell with intact
admission version and all four references, but no allowance or only 63 allowance
bits, fails with `missing or truncated preflight allowance`. The length guard is
header-shape evidence; it does not diagnose the origin of arbitrary damaged bits.

## Six isolated codec mutations

| Mutation | Required failed observation |
|---|---|
| Remove explicit tag check | Exact unrecognized-tag reason |
| Remove allowance-length check | Exact missing/truncated-allowance reason |
| Encode zero instead of allowance | Independent raw 64-bit field read |
| Decode zero instead of allowance | Decoded UINT64_MAX value |
| Encode max_proof_units instead | Independent raw field read, unequal values |
| Narrow decoded allowance to uint32 | Decoded UINT64_MAX value |

Every mutant compiled and linked before execution. Each was restored byte for
byte and the affected copied object and executable explicitly rebuilt/relinked.
No repository source mutation occurred. These controls do not test C2 comparison
or C3 operation enforcement. Constructor static assertions also reject omission
of the sixth required argument.

## Results and retained material

- 128 WorkchainBlock unit cases passed; four Rust McStateExtra cases passed.
- The current registered related-check selection was rerun in Ninja: 26/26,
  zero exclusions in this batch. This is **not the full CTest suite**.
- The earlier 25-pass Makefiles draft excluded proof-operation-trace due to its
  pre-existing Ninja introspection dependency. That run remains historical; the
  new batch includes the check. No driver was weakened or changed.
- The default all target passed after removing the private CMake include and
  with FUNC_BIN/FIFT_BIN/TOL_STDLIB absent. This reused the isolated Ninja build;
  it is not described as a fresh default-configuration build.
- Mainnet approval and generation guards retain their six passing controls.
- Successful Counter fixture archives, activation outputs, trace instrumentation,
  failed preparation runs and raw test output are in `allowance-raw.tar.gz`.
  The copied lifecycle archives success before its normal removal; production
  lifecycle defaults were not changed. Compiled objects/binaries are excluded
  from the raw archive, with tool hashes and compile/link commands retained.

The original eleven-check family is: disk-integration, account-binding-readiness,
idle-replay, self-delivery, cross-delivery, native-sender, engine-config, the two
activation checks, and the two config-presence checks. All eleven were rerun,
not carried forward. The other fifteen names/results are in `report.json`.
None substitutes for independent typed gate-closure evidence.

## Frozen input changes and root explanation

The current default prepared input moves out of the historical measurement
archive to `crypto/test/workchain-bounded-zerostate.boc`. Rust's fixture is the
raw McStateExtra extracted from that production-generated state; Rust preserves
policy cells opaquely. Historical BOCs are not rewritten. The baseline migration
scan and caller inventory are retained separately; current explicit constructors
are in `current-constructors.json`.

Two identical-input generation runs produce identical BOCs. Relative to the
historical policy, the new policy adds one 104-bit ParamLimits cell and 64 root
bits. The configuration account storage_used changes from 189 to 190 cells and
29645 to 29813 bits. Reverting policy leaves exactly this accounting difference;
reverting that difference reproduces the prior native root exactly. See
`root-difference.json`. This is an offline comparison, not a compatibility path.
Only the genesis regression answer changes, to `30fc304c...`; the other smartcont
answers passed unchanged. An old-answer run fails by digest mismatch. The tool
used is now bound by TARGET_FILE; a mismatched explicit override fails rather
than selecting a cwd-relative build symlink.

## Production boundary controls remain blocked

No production invocation sequence exists past the retained AccountBinding
refusals. Consequently exact-hard acceptance, hard+1 rejection, pre-callback
reservation, and special-path inclusion are **not currently measurable there**.
They require an owner decision on live wiring and the actual call sequence.
Neither an unused accumulator nor a test engine removes this blocker. C3's
concrete engine/call site is blocked independently of its committed host API.

After unblocking, required controls include `> hard` changed to `>= hard`, and
hard changed to soft using a separate soft<hard fixture. Validator reads hard
only. Shared inclusion rules do not share totals or verdicts. Underload=0 makes
strictly-low-underload unreachable; soft=hard leaves no soft<total<=hard interval.

Source commit: `72c8e543b367245f63d9cfa80037b239394be6c6`. Final six-control material is under
`controls-final/`; earlier control rounds remain labeled history. After the
26-item batch, review changed only production comments and test diagnostics/
width assertions; the full all target, all 128 block cases, genesis oracle and
six isolated controls were rerun. No blanket post-review full-CTest claim.

Installation compatibility remains an explicit decision: the codec represents
zero allowance and allowance greater than hard. No semantic installation
rejection was added. The reservation contract cannot start such invocations;
this is a possible unusable profile, not permission to exceed the hard bound.
