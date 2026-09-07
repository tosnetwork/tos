# Native bounce message boundary review

Base: fa5b8213e. Transcript:
`~/memo/reviews/uno-v2-native-bounce-message-review.txt`.

The reviewer confirmed field order, types, source/destination handling and
ordinary failure returns are preserved. No authorization, fees, LT allocation
or production batch path is introduced by this serialization extraction.

## Capacity coverage (fixed)

The initial 0/32/800-bit vectors missed both the Either selector reservation
and reference pressure. Independent reviewer mutations survived the original
test binary. The revised test pins 350/351 bits, four plain body references,
and three/four body references with an extra-currency dictionary. For these
fixed values the header is 672 bits before the selector; fixed adjacent vectors
are intentional independent expectations, not boundaries inferred from the
serializer under test. Changes to the fixed fields must update their rationale.

## Documentation and optional hash (fixed/deferred)

TL-B field annotations are restored. The new header must be staged explicitly.
A golden full-message hash is deferred: direct field/width checks plus preserved
body hashes and independently failing mutations are the evidence in this unit.
No frozen hash compatibility gate is claimed.

## Exception boundary (pre-existing, deferred)

The helper adds no catch. A bool construction failure remains ordinary failure,
not nofunds. The reviewer identified a pre-existing missing CellCreateError /
CellWriteError catch on the ordinary collator call path. This extraction does
not repair it, and it must not be used as evidence that all production callers
contain all exceptions. The future batch boundary must classify failures by
source; merely choosing rejection by exception class is not sufficient for a
locally assembled or unavailable closure. The review's statement that current
validate-query catches are categorically correct is not extended to that new
boundary. No monetary owner-policy choice is needed to preserve this separation.

Manual controls and regression results are recorded in
`measurements/uno-v2-native-bounce-message-evidence.json`; they are not recurring
mutation CI. Complete disposal, live source-aware admission and M1 acceptance
remain open.

Final evidence: the selector reservation, reference capacity and flags controls
each rebuilt successfully and failed the actual NativeBounceMessage test.
Restored five-target CTest passes (33.18 seconds), and a standalone header
include compiles with the real target flags. Exact substitutions, logs and
source/binary hashes are retained in the evidence artifact.
