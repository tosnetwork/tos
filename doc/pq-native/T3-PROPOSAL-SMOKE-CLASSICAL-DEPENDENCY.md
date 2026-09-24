# T08: proposal smoke no longer executes classical validator stake helpers

`crypto/test/fift/validator-proposal-test.fif` is executed by `crypto/test/fift.cpp::test_validator_proposal` in `test-fift`; it is under `crypto/test/fift/`, not in the `crypto/CMakeLists.txt` install inputs (`fift/lib/` and `smartcont`). Before T08, this proposal/complaint smoke also included `Validator.fif` and repeated checks of `validator-elect-req>B`, `validator-elect-body`, and `validator-elect-body+stake`. Those are historical Ed25519 stake bytes, not PQ stake acceptance. The same fixed public key, signature, election values and three byte/cell encodings remain asserted in `crypto/test/fift/validator-proposal-legacy-parity.fif` (T09), so the duplicate stake section was removed here; Proposal/complaint tests remain.

This is **only T08's executable test dependency**. The distributed `crypto/smartcont/validator-elect-req.fif`, `crypto/smartcont/validator-elect-signed.fif` and `crypto/fift/lib/Validator.fif` remain installed, and T09 still includes `Validator.fif`. T10–T12 must handle those consumers and the actual published release ZIP separately; a green proposal smoke is not a PQ vote or stake test.

The recorded answer for `Test_Fift_test_validator_proposal_default` changed from `3c66ad66942f9f063a3d82c24606e5d156d2ca8f3cbb70ee84a42b4eebc2ab6a` to `152fc572d943109e73315aae62818753a40e519c00d74d05fccb74e035d98ee0`, because the redundant stake checks and heading were removed. This was an expected old-answer RED, not a contract or interpreter failure. `Test_Fift_test_validator_proposal_legacy_parity_default` remains `b7c8dd7479a355f69372df386e916e185a2d08291e832057d37df10ad4d01be4`.

Local controls (all raw transcripts under `test/integration/.t08-validator-proposal-20260924/`):

| Command/control | Result | Raw SHA-256 |
| --- | --- | --- |
| `build/test-fift --regression test/regression-tests.ans --filter test_validator_proposal`, before edit | exit 0, 5/5 | `e77656a21564d65cc81bd1e6668fd5a0b0665241c3cfe3934146ed2d56a59218` |
| Same command after source edit, before answer update | exit 1, exact expected/actual digest mismatch above | `f3189a8ec699dab137bdefc51f23e34748c0fabee9857f50cd3607cbaf3cf528` |
| Same command after answer update | exit 0, 5/5, including unchanged T09 parity | `9b225c26b4b4c117e060b9d996a0e499cc4b641e3b0a70dcd4e3030e4571fddd` |
| `./scripts/check-regression-db.sh . build` | exit 0, every recorded answer has a test and every test gives its answer | `ff535974b8a0f8f65be718de33535276bada65eb4f32355f0d8db1b433469618` |
| Reintroduce `"Validator.fif" include` in proposal smoke | caller guard exit 1, names regained classical stake dependency | `2f30d32935dd05b54d151d2b4abb9d0b7f488f8b8efa18eaffeefc9add364807` |
| Remove `"Proposal.fif" include` as a positive control | caller guard exit 1, names missing Proposal helper | `a361383b589442a4d106e029dfb3646869ccc8267ac7b2a5d340ccc49c4b09a5` |
| Restore both changes, `python3 scripts/check-classical-stake-callers.py .` | exit 0, nine inventoried executable files remain | `5d356e08be12e5969de818bbe3488e88a1629198dac2eaa0a44053a5e0e02fff` |

The guard mutations each have a unique patch, both accepted by `git apply --check` against the clean tree: `classical-include-mutant.patch` SHA-256 `c049caa36675af2764cefbbe038cf6d95c5e6c3184000714349c568e78a66822`, and `no-proposal-include-mutant.patch` SHA-256 `f1bab548163152e42d9d3079bfbc4de00ece20041beb9b5b8a0a84fa3fe0dd25`. Raw `script -e` logs contain their command exit codes. Clean source SHA-256: T08 Fift `27353fd903559be4e7345231c7683ab2eeab420dd88dd37fbd52bbb34eac509f`, retained T09 parity `fa9a02f74b6f1f338eac34936250f56070a4025681295c1d09056d508ea27043`, caller guard `dff0b379d7eeaa669b6bcd85c85a88043d6ee63c09920e4d299cdc1c65ec9870`, answer DB `2ec312e73ec6e8efd94d5321f13f0cb259cb2942b2c75c6dbb676695b6cba843`, `build/test-fift` `2a5b914d75460bee87c2d81c61a2069a02686203df96643442dea3e0e2297984`.

A staged local `cmake --install build --prefix /datax/t08-install-stage-20260924` exited 0. The retained installed `smartcont` + `lib/fift` file list `install-source-list.raw.log` has SHA-256 `5aa1ca0f9e40857054a1a1759f8dab61acac27b245f2e18943bfb97058798f51`: it contains the three distributed classical base files above and no `validator-proposal-test.fif`. This is an install-list boundary, not a published ZIP proof. T08 remains pending committed-tree CI and independent review.
