# Payout currency budget boundary review

Scope: explicit currency-validation budget propagation through the private
payout pair, overlay, replay and settlement runner. This is not M1 acceptance.
The read-only review transcript is in
`~/memo/reviews/uno-v2-payout-budget-review.txt`.

| Item | Disposition | Evidence and limit |
| --- | --- | --- |
| D1 | Fixed instrument gap; partly disputed prediction | A Native-encoded extra-currency coordinator now reaches the overlay and replay, with sufficient/insufficient budget cases. The overlay control substitutes both its pair and independent-row budgets: it proves the combined property, not that either repeated check is indispensable. The prediction that restoring the row's storage-field cast remains green is checked separately by mutation; the existing UINT_MAX test can expose the negative narrowed budget even without extras. |
| D2 | Fixed | Observed Cells assert zero binding loads in the pair and zero state-root loads in the overlay at budget zero. These assertions distinguish early rejection from a later identical Status. No exception-text comparison is used. |
| D3 | Fixed scope and added evidence | The UINT_MAX case is explicitly an API-width probe. A real extra-currency overlay also has identical Native roots at two storage limits with a fixed sufficient budget. This does not establish insensitivity to every possible clamp or every combination of legal limits. |
| D4 | Fixed | The extra-currency balance is decoded from serialized Native AccountStorage as well as checked in the transaction cache. |
| O1 | Deferred to production integration, not a new owner choice | The established source-aware classification contract still applies. A bare Status does not distinguish configuration, candidate and authenticated-state failures. Early ordering alone is not proof of correct classification. No production caller is introduced. |
| O2 | Deferred to resolved-policy integration | No local default, budget value or schema is frozen by this unit. Bounds must come from the same authenticated policy on collate and replay. |
| O3 | Recorded API hazard | Adjacent integer arguments can be swapped. Current call sites are checked; a typed resolved-policy interface remains preferable at production admission. |

The review found no logic defect in the substitution itself. Its statements
about network-wide behavior are hypothetical: these new participant APIs have
only test callers, and live execution scopes remain closed. Removing this
budget inconsistency is preparation for integration, not evidence of fixing an
already activated network. Native storage-size checks remain in place.

Nine controls were rebuilt and each failed its test. `row-storage-reuse`
confirms the disputed D1 prediction: the pre-existing width case rejects the
restored cast even with null extras. The combined overlay-budget control changes
both forwarding and final-row budgets, and does not pretend to isolate either
defensive layer. `persisted-extra-loss` preserves the in-memory balance while
removing extras from the serialized AccountStorage; the new decoded-balance
assertion fails. Guard-order controls count Cell loads, not error wording.

Arithmetic and exception behavior are unchanged. Currency subtraction checks
per-currency funding; no new raw amount arithmetic, catch-all conversion or
policy-dependent narrowing is introduced. Test fixture numbers are not proposed
production parameters. Manual mutation results are archived separately and do
not constitute a recurring mutation CI gate.
