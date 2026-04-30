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

Stage 1 includes `doc/slice5-abi-manifests/interop_smoke.json`, plus one
FunC-labelled and one Tol-labelled fixture for the same canonical
`InteropTransfer` body. The checker recomputes each fixture's SHA-256
over the canonical body bytes and then requires the FunC and Tol fixture
pairs to match byte-for-byte.
