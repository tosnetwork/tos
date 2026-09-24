# T07: isolate test-smartcont's historical validator stake bytes

`crypto/test/test-smartcont.cpp` previously ran the distributed `smartcont/validator-elect-req.fif` and `smartcont/validator-elect-signed.fif` as part of its recorded-answer regression. This was a classical Ed25519 byte-parity test, not a PQ stake test. T07 now loads byte-identical test-only copies from `crypto/test/fift/fixtures/validator-legacy-elect-{req,signed}.fif`; the two source copies differ from the distributed scripts only by their test-only comments. The C++ test explicitly names historical Ed25519 parity and its function is named `run_legacy_validator_fift_script_regression`.

At T07 this did **not** retire either distributed base script, prove a PQ stake, or make the fixtures self-contained. They still include `Validator.fif`, which T12 must isolate. **T07's then-current install/ZIP surface contained `crypto/smartcont/validator-elect-req.fif`, `crypto/smartcont/validator-elect-signed.fif`, and `crypto/fift/lib/Validator.fif`.** Corrections: T10 retired the first installed file; T11 retired the second. Both are absent from their fresh installed trees and local release-shaped ZIPs. The shared library still ships. `crypto/CMakeLists.txt` installs `fift/lib/` and `smartcont`, not `test/fift/fixtures/`.

Local evidence from the current source tree:

| Check | Result |
| --- | --- |
| `cmake --build build --target test-smartcont -j4` | exit 0; `build/test-smartcont` SHA-256 `d728fbc3dafae21bd3d5d2c94750487281a4706e0444bc47ec490b6f71868570` |
| `ctest --test-dir build --output-on-failure --output-log test/integration/.t07-legacy-smartcont-20260924/test-smartcont-clean.raw.log -R '^test-smartcont$'` | exit 0, 1/1, 8.61 s |
| `build/test-smartcont --regression test/regression-tests.ans --filter ValidatorFiftScriptRegression` | exit 0, named recorded answer 1/1; frozen digest `9db405bf1ebb42d58ecc8d3381c60a43185fcd42844ee9c98d0b4a03f6fd6614` |
| `python3 scripts/check-classical-stake-callers.py .` | exit 0, 10 exact executable files |
| Restore the request load to `smartcont/validator-elect-req.fif` | guard exit 1: `test-smartcont no longer loads exactly one test-only test/fift/fixtures/validator-legacy-elect-req.fif` |
| Add a second signed-fixture load | guard exit 1: `test-smartcont no longer loads exactly one test-only test/fift/fixtures/validator-legacy-elect-signed.fif` |
| Restore either mutation | guard exit 0; source returns to the tested form |

Source SHA-256: request fixture `39f9e955eb48ffbb0dca10a85f9441b27979420a1e451fc730f4503b3515b519`, signed fixture `d1e04d6d4acc1863d8bfb53d4c2bc73d407d4a9f4b9b54986138ebfee3005e3f`, C++ `9d5704a89b11c4fb2f4496d55d662efe13f4755853c5f1ed2a837516041b453f`, caller guard `aad06b9e0c19089b1ffc2a3f569d893466dac1c781a0be3a3ee5afb79c32e43b`. The recorded-answer test preserves the pre-existing byte hashes; it does not interpret them as accepted stakes. T07 remains pending committed-tree CI and independent review.

The two guard mutations have unique reconstructible patches under `test/integration/.t07-legacy-smartcont-20260924/`, both accepted by `git apply --check` against this commit: old product path patch SHA-256 `0687826c9399e900d3e06f6114c2f01d2c6bfeb6dd62d935c6646a2edc6c6099`, raw red `09137c9f967f1ab16aaa34114cd4cb848648fda695cc8640add59336d990dfa9`, exit record `0fd5dc4f251d3257d4d725adfa531a1ddc7d80ccfc6a22d112481eedf025ef69`; duplicate-fixture patch `c07945b6f27d4b13ba7fc194cdba7979d4068d47f61adc16a208c706c3d5437c`, raw red `f5ff376cfcd1f4198e14ad7219d0f4991fefb0ab2c22e5bbe165387089363539`, exit record `06110a87a91ae403daf7278c4a75b93f9664051c41780a11a1acfb725deb6915`. Both were restored before the clean guard and committed source check. The raw `script -e` transcripts include `COMMAND_EXIT_CODE=1`.

Clean raw logs: `test-smartcont-clean.raw.log` SHA-256 `68c6a5caeabc588cdd45fcf40779eca58ae192dbc96ff2c4ef7ab4fcfc66434f`, `recorded-answer-clean.raw.log` `b1386e3bd014fb0cc0d39d852dbc38a43d9aedefcf5be5d6c0ad7d7ce78f0d95`, caller-inventory clean `066340f954d0589e12ffbbbe88dd76b50b08bad32c1a730c273b634971107988`. The frozen `test/regression-tests.ans` is SHA-256 `b1bb966002519463e2218a9c365c4365adc2830ddf3c93913e4027b54d1a87af`. These are local checks, not a pushed-head CI result.
