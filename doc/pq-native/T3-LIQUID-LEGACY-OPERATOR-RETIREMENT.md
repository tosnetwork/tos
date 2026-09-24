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
contract-level rejection of the retired body, not a product end-to-end route.
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

The first `test-smartcont` invocation used a pre-edit binary and failed to load
the moved path; it is not regression evidence. Rebuilding that target and
rerunning produced the passing result above. No real chain was started. T06
retires one unsafe distributed entry point; T3 and liquid-staking product
support remain OPEN.
