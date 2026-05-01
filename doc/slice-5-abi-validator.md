# Slice 5 ABI Manifest Validator

`scripts/check-slice-5-abi-manifests.py` validates the repo-side Slice 5
FunC<->Tol ABI manifests and their golden fixtures:

```sh
python3 scripts/check-slice-5-abi-manifests.py
```

The checker is intentionally dependency-free. It enforces the Stage 0
ABI commitments that must not wait for a JSON-schema package in CI:
constrained ABI type names, `uintN` / `intN` width bounds, reserved
getter and public error-code ranges, optional `query_id` presence
indicators, fixture requirements for manual/raw encodings, and
Ed25519 signing-input declarations.

Use `scripts/tol-method-id.py <getterName>` when filling
`getters[].method_id` for auto-derived Tol getters. The script uses the
same formula as the compiler: `crc16(name) | 0x10000`. Getters pinned
with `@method_id(N)` record `N` directly.

For field-level `bits` and `refs`, use an integer only for fixed-size
encodings. Use `null` for variable-size encodings. In particular,
`coins` is encoded as `VarUInteger 16`, so its `bits` value is `null`;
`address`, `any_address`, `cell`, `slice`, `builder`, `dict`, and
`remaining_bits_and_refs` likewise use `null` where the shape is not a
fixed inline bit/ref count.

Stage 1 includes `doc/slice5-abi-manifests/interop_smoke.json`, plus one
FunC-labelled and one Tol-labelled fixture for the same canonical
`InteropTransfer` body. The checker recomputes each fixture's SHA-256
over the canonical body bytes and then requires the FunC and Tol fixture
pairs to match byte-for-byte.
