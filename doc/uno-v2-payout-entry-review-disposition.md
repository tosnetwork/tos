# Full payout entry boundary review

The read-only transcript is in `~/memo/reviews/uno-v2-payout-entry-review.txt`.
This is an inactive M1 construction/replay unit, not a production acceptance gate.

| Finding | Disposition |
| --- | --- |
| 1: defaulted context changes reconstruction shape | Fixed: all three APIs require explicit input/effects arguments. Two explicit null roots select the low-level participant primitive; the runner supplies the full roots. Missing arguments no longer compile. The eventual live protocol gate must still select the full-entry profile, not infer authorization from this low-level API. |
| 2: third writes not bound to context | Fixed in the overlay: committed write keys equal supplied keys; every update matches supplied data; supplied old hashes match declared reads; all old reads, including read-only accounts, are authenticated against the old dictionary. An explicit read bound is forwarded from the runner. Host workchain, time and LT boundary also match the committed context. |
| 3: guard coverage | Added primitive tests for both hash mismatches, absent payout, null request and extra transfers. Hash controls remove both repeated checks and are explicitly composite. No claim that every duplicated profile/parser guard is independently indispensable. |
| 4: unreachable balance comparison | Removed. The currently supported profile has neither an inbox nor additional allocations; those exclusions establish that entry preparation preserves opening funds before separately checked fee funding. |
| 5: serialized description omitted from verification | Fixed: the overlay decodes each actual description and checks the expected role tag, binding hash, exact reference count, full entry input/effects hashes and absence of trailing data. Construction and independent replay remain separate from engine authorization. |
| 6: unbraced seal conditional | Fixed with braces; all restricted metadata fields are still resealed for both roles. |
| 7: outdated inbox diagnostic | Fixed: it now states that nonempty Native inbox settlement is not integrated. |

No new owner decision is required to remove implicit defaults or enforce an
already committed read/write/data contract. No TL-B constructor, policy value,
fee rule, activation gate or permitted account capability is expanded here.
The two-participant primitive remains explicitly selectable for its existing
tests, but is not presented as a complete batch or an accepted live profile.

Two review assertions need narrower wording. A pruned branch does not by itself
establish LocalUnavailable: prohibited candidate-supplied structure is invalid
input; missing authenticated local state is a different source. Also, four bits
and three references do not prove a builder cannot throw: child depth and
allocation failure still matter. No catch or exception reclassification was
added; propagation to the source-aware boundary remains required.

During preparation, one test initially tried to read a private descriptor field
and failed compilation; it now decodes the serialized Transaction. Another
fixture incorrectly parsed a relaxed payout request as Message Any; it now
constructs a second valid relaxed request. Neither setup failure counts as a
successful mutation control. The final controls rebuild successfully before
executing and asserting failure.
