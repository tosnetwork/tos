# Native bounce body review disposition

Base: `ea4697986`. Review transcript:
`~/memo/reviews/uno-v2-native-bounce-body-review.txt`.
This unit shares encoding only; pricing, address authorization, debit and
batch disposal are not implemented by this helper.

## Accepted

The ordinary-caller fixture used exit code 42 for both compute and action.
That could not detect the wrong selection source. Action now uses 7 while
compute retains 42. The caller test also covers all flags 0/1/2/3 and both
legacy lengths 0/256 across three phase outcomes: 24 combinations. Hand-decoded
direct tests supply the encoding oracle; caller-to-helper hash comparisons
only bind selection and plumbing. Five successfully rebuilt removal controls
fail at the source-selection hash assertion or direct numeric assertions:
action exit-code source, full-body references, original LT, legacy truncation,
and swapped compute counters. Exact substitutions, raw logs and source/binary
hashes are in `measurements/uno-v2-native-bounce-body-evidence.json`.

The legacy original-info ternaries remain, with their dependency documented.
They are not presented as independently witnessed guards against an invalid
ordinary input; real parsing establishes those fields already.

## Additional local finding: an ignored prefix write result

The extracted legacy encoder originally retained an ignored `store_long_bool`.
The ordinary caller supplies an empty builder, so its 32-bit prefix fits.
The reusable helper accepts a caller-owned builder: with 1020 existing bits
and a one-bit body, the prefix write returned false, its result was ignored,
and the one-bit append succeeded. A newly rebuilt test expected an exception
and failed at `exhausted`. The encoder now uses the throwing store operation.
This does not select another settlement branch, introduce a new exception
class, or change the ordinary caller's bytes; it stops silent partial output
when the helper's output builder has insufficient capacity.

The initial catch and the review prose named the wrong class for this path:
`store_long -> ensure_throw` throws CellCreateError, not CellWriteError
(`CellBuilder.h:210-213`). The first post-fix run terminated on that uncaught
class. The test now catches exactly CellCreateError; both failed attempts are
retained rather than credited as successful exception coverage.

## Review wording corrections

The reviewer ran the positive test but did not rebuild or mutate shared files.
Its exit-code-source observation is sound symbolic analysis, not independently
executed removal evidence. This unit's controls must supply that evidence.
File timestamps are not exact build provenance; successful build outputs and
source/binary hashes are archived separately.

Existing Native validator catch clauses are not proof that future batch inputs
are source-correctly classified. Builder errors can come from candidate or
authenticated-state material; the caller must preserve that provenance.
The helper adds no catch or Status conversion and cannot establish that live
admission boundary on its own.

## Separate follow-ups

Default construction of MsgPrices leaves primitive fields uninitialized. The
new fixture explicitly initializes both price records. Auditing other test
and production initialization paths is a separate task; this change does not
install zero-valued production fee defaults or claim those paths are fixed.
The emulator's separate bounce replica and stale comments also remain outside
this extraction. Neither issue is a newly required owner policy decision.

All controls are manual evidence, not recurring mutation CI. This shared
encoding unit does not complete wrong-destination settlement or M1.
