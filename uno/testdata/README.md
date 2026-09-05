# Shared public-context vectors

`public-context-v1.txt` is consumed by the C++ `UnoBundleContext` test and Rust
`context::tests::shared_cross_language_vectors`. It is a logical accounting
fixture, not a transaction codec, signature digest or VK-bound proof vector.

Each line has exactly ten whitespace-separated fields:

```text
case_name context principal_hi principal_lo fee_hi fee_lo value_balance spends outputs accepted
```

Unsigned high/low words are decimal u64; the principal and fee are u128 nanotomi
with the high word first. Value balance is decimal i64. The last three fields
are literal 0 or 1. Context names are logical names, not wire discriminants.
Transfer principal and output-only fees are zero because those fields cannot
be represented in the Rust context variants. Invalid extra fields and unknown
wire tags require separate decoder/host tests.

Both readers require the full 26-row corpus, parse without ignoring malformed
rows, and compare acceptance against the same expected result. This supplies
cross-language agreement evidence for these cases, not proof of equivalence for
all inputs or of an FFI implementation. The C++ test reads the source-tree file
at runtime using its CMake-defined path; Rust embeds it with `include_str!`, which
causes rebuilds when the corpus changes.

Mutation checks: removing each implementation's balance comparison makes the
wrong-fee row accepted and fails its test. Reversing the first valid row's expected
result makes both readers fail, confirming they consume this shared oracle.
All mutations were restored. Treat expected results as reviewed specification
data; do not regenerate them from either implementation to make tests pass.
