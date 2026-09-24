# T06: liquid-staking legacy operator retirement

Scope: remove a misleading classical operator command from the distributed
smart-contract tree. This does **not** establish launch support for liquid
staking. The current `liquid-staking/controller.func` parses PQ-shaped pool
terms and forwards them to a named Validator Controller, but there is no
liquid-staking product proof of controller deployment/admission, node-bound
authorization, Elector `STAKE_ACCEPTED`, or live ConfigParam 34 pairing.

Before T06, `crypto/smartcont/liquid-staking/controller-elect-signed.fif`
called `Validator.fif`'s classical `validator-elect-req>B`, checked an Ed25519
signature and emitted a body with a raw 256-bit public key and one 64-byte
signature reference. The current controller expects `stake_at`, `max_factor`,
ADNL, `algorithm_id`, public-key ref, signature ref, optional witness. The old
command was therefore not a PQ operator even though it was distributed by
`crypto/CMakeLists.txt`'s `install(DIRECTORY smartcont ...)` and both release
workflows copied the installed `smartcont` tree into `smartcont_lib.zip`.

The exact historical Fift script is now
`crypto/test/fift/fixtures/liquid-controller-legacy-elect-signed.fif`.
`test-smartcont.cpp` loads it only for historical BOC/codec parity; its green
result is not an accepted stake. The source guard refuses restoration of the
old packaged path, an unlisted caller, or removal of that test-only fixture
from the C++ regression. The release source tree no longer contains this
liquid-staking election command. The base `validator-elect-{req,signed}.fif`
and `Validator.fif` remain distributed and counted under T10–T12; this unit
does not retire them.

The compiled-contract `liquid_staking_sandbox` sends a *complete* old-layout
body and requires the liquid controller transaction to abort before emitting
`RELAY_STAKE`; it also requires state to remain at rest. This establishes
contract-level rejection of the retired **layout**, not byte-identical rejection
of the particular BOC emitted by the historical Fift invocation and not a
product end-to-end route. The Rust test uses fixed key/signature bytes rather
than the `test-smartcont` Fift BOC; those two inputs are not asserted equal.
Replacing that input with the existing PQ-shaped `stake_order` made the
negative test fail because the controller accepted it; restoring the old body
made the suite green. The positive relay test remains separate.

Local checks before the final commit:

| Check | Result |
| --- | --- |
| `cargo test -p contracts --test liquid_staking_sandbox --locked` | 9/9 pass |
| `ctest --test-dir build -R '^test-smartcont$'` after rebuilding target | 1/1 pass |
| `scripts/check-regression-db.sh . build` | recorded answers unchanged |
| `scripts/check-classical-stake-callers.py .` | 8 exact files, old liquid operator absent |
| Restore old source path mutation | guard exit 1: `retired liquid-staking Ed25519 operator script is still packaged` |
| Remove C++ fixture reference mutation | guard exit 1: `test-smartcont no longer loads exactly one test-only liquid-controller legacy fixture` |
| Feed PQ order to old-body negative test | test exit 101: `the PQ-shaped controller accepted a classical Ed25519 stake body` |

The independent review of `988fa433a` found that the table above described
red controls without retaining their raw results, and that source-only package
reasoning did not establish an actual install/ZIP listing. Those gaps were
measured separately, without changing the T06 product or test source:

| One-at-a-time control | Direct result | Unique patch / retained evidence |
| --- | --- | --- |
| Restore the exact pre-retirement 41-line liquid Fift operator at its old smartcont path | old file SHA-256 `7828df8219bdbc4595c2af443233e24a07830c050eed336eda7926cc6db6f41c`, identical to `988fa433a^`; guard exit 1 on `retired liquid-staking Ed25519 operator script is still packaged` | [patch](t06-restore-liquid-operator-mutant.patch) `a7afa92633dfd4ff4521995dd51efa00fd1a06fac064a84f37982724e2e7af5b`; [exit/raw](../../test/integration/.t06-liquid-legacy-retirement-20260924/old-path-red.exit.log) `ef68bc2e8d603f9d60a53b0bf8ca9cf9d36f4d4a04ba8d075c7de1321655a583` |
| Point `test-smartcont` away from its single test-only liquid fixture | guard exit 1 on `test-smartcont no longer loads exactly one test-only liquid-controller legacy fixture`; mutant C++ source SHA-256 `52f1a50dee7154e5ff107f467820890655d2be7b11a0e43a6a85d7265c0f350d` | [patch](t06-remove-liquid-fixture-reference-mutant.patch) `98d6b2bbc0ce572ad12e6daf4b0da93bffeea923db77b9dcbd48816814a3c29c`; [exit/raw](../../test/integration/.t06-liquid-legacy-retirement-20260924/missing-fixture-red.exit.log) `f4b81119ef134d6eeb833839f45c453bb6e03a790cba70386c13bdebe640db1f` |
| Feed the existing PQ order into the classical-body refusal test | compiled sandbox exits 101 at the named aborted-transaction assertion, not at setup; mutant Rust source `39497cd44b79ff96fa9545936441c4a2b65ca0b81c1bae27e427465ab6a469d4`, binary `aeea67548087ea564a53b36fa8f15a3d78d80c14bbba8bd17994f369fe846d0e`; restored 9/9 exit 0, binary `ace561aff74e9d6e9afaa3f38d82ee910faa66d5ee5ae8678530d46dc2c67669` | [patch](t06-pq-order-positive-control-mutant.patch) `0db389a5f27346a3dbddfda1022dbcb3c7a96d13437297aa5450b05f6298e0ac` (apply with `--unidiff-zero`); [red raw](../../test/integration/.t06-liquid-legacy-retirement-20260924/pq-order-mutant-final.raw.log) `12ee901bc57843860d27089738ad1ec61d3cedeae0cbbec5ac824749cb72ab33`; [exit record](../../test/integration/.t06-liquid-legacy-retirement-20260924/pq-order-mutant-final.exit.log) `9504ea14f637fe5b764d35cc12ea594e1508cac86e6e309a903570d3c614b2d6` |

All mutations were restored; the tracked production/test source is clean.
The restored full sandbox log is `717768bfd1c300509885c4af660ad2d70f203054f9c614535174332e85a699c9` (9/9, exit 0), and the source guard, `test-smartcont` CTest, and recorded answers returned exit 0 with log hashes `7b6eee96ef4412cfb811a2ce5985feafe27f7a5748f36a10d5ec1c14c6d611ff`, `cb6ac617161068d8c726946c3c7d52120d55b0543167cc68e1e8eb7d83a3a7b8`, and `96db7d96f9e379cd531b400f9dee34f3abca4a55365bca29c15372ff0c343e70` respectively.

On the pushed T06 source at `0f104caee`, `cmake --install build --prefix /datax/t06-install-GdOaki` exited 0. Copying the installed `smartcont` and `lib` trees into the same ZIP structure as both release workflows produced [the retained 324-entry listing](../../test/integration/.t06-liquid-legacy-retirement-20260924/smartcont-lib-zip.list), SHA-256 `6af85c5853d8f9981d8bb528309d84bbc3550125ef1414973712997de233f909`; the local ZIP is SHA-256 `52501b6d1526028bade7d03e96d39a88e857f4847b13fa50c143d35d7d569891`. Neither the old `smartcont/liquid-staking/controller-elect-signed.fif` nor the test-only fixture appears; the three base classical tools remain, as expected. This is a local staged install/ZIP of the exact source, not a published release asset. The [install/ZIP exit record](../../test/integration/.t06-liquid-legacy-retirement-20260924/install-zip.exit.log) is SHA-256 `1981d34a5f3de4ccd4e688ae8b7e1267ace21bd712acd272bfa20aef428d02cc`.

The exact-source `contract-sandboxes.yml` workflow was dispatched at run `36067585788` and is pending terminal result. T06 remains in progress until that suite and independent evidence review finish; T07's other classical Fift callers and liquid-staking PQ product support remain OPEN.

The first `test-smartcont` invocation used a pre-edit binary and failed to load
the moved path; it is not regression evidence. Rebuilding that target and
rerunning produced the passing result above. No real chain was started. T06
retires one unsafe distributed entry point; T3 and liquid-staking product
support remain OPEN.
