# T07: isolate test-smartcont's historical validator stake bytes

`crypto/test/test-smartcont.cpp` previously ran the distributed `smartcont/validator-elect-req.fif` and `smartcont/validator-elect-signed.fif` as part of its recorded-answer regression. This was a classical Ed25519 byte-parity test, not a PQ stake test. T07 now loads byte-identical test-only copies from `crypto/test/fift/fixtures/validator-legacy-elect-{req,signed}.fif`; the two source copies differ from the distributed scripts only by their test-only comments. The C++ test explicitly names historical Ed25519 parity and its function is named `run_legacy_validator_fift_script_regression`.

This does **not** retire either distributed base script, prove a PQ stake, or make the fixtures self-contained. They still include `Validator.fif`, which T12 must isolate after T08/T09 and other consumers are handled. `crypto/CMakeLists.txt` installs only `fift/lib/` and `smartcont`, not `test/fift/fixtures/`; T10–T12 must separately inspect the final installed tree and release ZIP.

Local evidence from the current source tree:

| Check | Result |
| --- | --- |
| `cmake --build build --target test-smartcont -j4` | exit 0; `build/test-smartcont` SHA-256 `d728fbc3dafae21bd3d5d2c94750487281a4706e0444bc47ec490b6f71868570` |
| `ctest --test-dir build --output-on-failure -R '^test-smartcont$'` | exit 0, 1/1, 8.61 s |
| `python3 scripts/check-classical-stake-callers.py .` | exit 0, 10 exact executable files |
| Restore the request load to `smartcont/validator-elect-req.fif` | guard exit 1: `test-smartcont no longer loads exactly one test-only test/fift/fixtures/validator-legacy-elect-req.fif` |
| Add a second signed-fixture load | guard exit 1: `test-smartcont no longer loads exactly one test-only test/fift/fixtures/validator-legacy-elect-signed.fif` |
| Restore either mutation | guard exit 0; source returns to the tested form |

Source SHA-256: request fixture `39f9e955eb48ffbb0dca10a85f9441b27979420a1e451fc730f4503b3515b519`, signed fixture `d1e04d6d4acc1863d8bfb53d4c2bc73d407d4a9f4b9b54986138ebfee3005e3f`, C++ `9d5704a89b11c4fb2f4496d55d662efe13f4755853c5f1ed2a837516041b453f`, caller guard `aad06b9e0c19089b1ffc2a3f569d893466dac1c781a0be3a3ee5afb79c32e43b`. The recorded-answer test preserves the pre-existing byte hashes; it does not interpret them as accepted stakes. T07 remains pending committed-tree CI and independent review.
