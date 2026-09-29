# C07 diagnosis parser checkpoint (not model acceptance)

The existing closed diagnosis parser now refuses empty or overlength
evidence IDs even if a caller supplies them in its delivered-ID set. A
`hypothesis` finding requires an explicit nonempty `missing_evidence` list.
JSON Schema `maxLength` is measured in Unicode scalar values while the
separate 16-KiB serialized-byte cap remains enforced. The focused tests
include missing-evidence, empty/129-character ID, and 2000/2001-character
multibyte summary controls.

`cargo test -p tos-health-core --locked -j2` exited 0 (3 unit, 33 contracts,
16 R4, 8 rules, 6 witness contract tests and the remaining core targets).
Raw log: `/home/tomi/nhm-c08-mcp-evidence/c07-diagnosis-core-final.log`,
SHA-256 `70bf60e5db78e8f0f12f6bf4aa6f101ac6b563a5badc32fe30b9bf7d9bc495f0`.
`cargo clippy --workspace --all-targets --features mcp --locked -j2 -- -D warnings`
exited 0; raw log `/home/tomi/nhm-c08-mcp-evidence/c07-diagnosis-clippy.log`,
SHA-256 `7fd4befecdff58e17edc09b4b4a88c8b73e1d61fafdffeb0094b136815b2b338`.

This is syntactic/publication-boundary validation only. It does not prove
that a cited evidence item semantically entails an observed claim, provide
an immutable M-watermark package, run AURA, validate a provider protocol or
terminate a real model child. C07 remains disabled and unaccepted.
