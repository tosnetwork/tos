# Record-context guard measurements

This is a schema-validator unit, not a live collator/validator observation and
not an activation classifier. Source commits and per-file hashes are explicit.
Each isolated removal is syntax-checked, produces precisely its designated
failed unit vector, and is restored byte-for-byte with a reapplication audit.
No production source or shared helper is mutated.

The 43a0dc35e record has twelve context checks. The 3322887d5 record adds the
final typed-result discriminator: a candidate-reject record with otherwise
identical diagnostic fields must fail 316. These are deliberately synthetic
schema records, not fabricated host state or evidence that a live serializer
has read the terminal result correctly. That serializer does not exist here.

The raw resolver run retained alongside them is separate: production returned
Status fields and internal configuration hashes, without transaction/export
claims. Shared-helper expectations and its consumer are measured separately.
