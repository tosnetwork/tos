# V5R2 mobile implementation and remaining acceptance

The active delivery target is the complete V5R1-equivalent wallet with native
ML-DSA-44 PRIMARY and independent SLH-SHA2-128s protection. No Ed25519 R2
wallet authorization is supported. The original design/gas requirements and
[completion inventory](wallet-v5r2-completion-plan.md) remain authoritative;
T13 is explicitly deferred. No merge/default-network activation is approved.

## Source and evidence

TOS `67d7b2598` passed its six configured PR checks, including real HTTP proof
query rejection, compiled route-removal/restoration control, anchored verifier
and configured native chain regressions. The bounded index is
[tos-proof-ci-green-20261007.json](../test/wallet-v5r2/tos-proof-ci-green-20261007.json).
Those checks do not establish full release acceptance.

Android development continues in Draft PR #6 on `feat/v5r2-rescue` (request
construction at `4b77381`). iOS development continues in Draft PR #5 on the
same branch (coordinator at `acbfca7`). Companion source remains in those
repositories. Indexes under `test/wallet-v5r2/` identify each exercised commit,
command/log hashes, semantic controls, excluded attempts and outstanding gates.
Large logs/binaries are outside Git; a scratch path is not an independently
available evidence bundle. Reproduce the committed companion tests.

Implemented components include source-built C/JNI/Swift anchored proof
verification, durable private checkpoint acquisition, bounded HTTP transport,
native-produced proof capabilities, account/config/time binding, current TOS
Account TL-B and strict R2 AUTH decoding, initial/successor tuple observations,
ConfigParam48 PRIMARY retirement checks, fee-clock/slot constraints and
same-checkpoint multi-account coordinators. Android callback cancellation has
runtime interruption/lock-release evidence. iOS callback cancellation has
result-discard/lock-release evidence and requires a bounded provider timeout.
Private checkpoint protection is not hardware monotonic protection against
owner-edited/copied snapshots.

Android PRIMARY Execute request construction uses proven tuple/counters and
rechecks policy/deadline. Its current evidence is compilation plus existing
wire/action regression tests; positive deployed-R2 proof/request coverage is
still missing. Observation/request APIs do not approve an action, use keys,
prove solvency, sign, stage funds, migrate, broadcast or confirm delivery.

## Remaining work

- Obtain independently authenticated deployed R2 wallet/module/vault/config
  proof material and positive/negative coordinator/request integration. Public
  captured proof callbacks, synthetic cells and compiled app modules are bounded
  evidence, not the complete deployed wallet lifecycle.
- Complete actual creation/restore, independent role custody, current-generation
  enrollment and mnemonic recovery discovery, and connect verified state to
  reviewed actions and current-key signing.
- Complete fee solvency/admission from authenticated release configuration,
  durable H20/W4 reservation/cache, loss/exhaustion/competing-device recovery,
  cancellation/retry and fee descriptor rollover.
- Fund/prove both POP roles, stage successor module/vault before migration,
  repeatedly rotate the tuple at the original wallet address, and prove
  transaction-bound recipient delivery after broadcasting/finality.
- Finish legal maximum signed inputs, gas/solvency/action failures, live-node
  admission/fairness, both VM/architecture checks, supported mobile/hardware
  tests, frozen release identities and independent crypto/security review.

The existing `proof-attestation-e2e.py` tests a separate Ed25519 attestation
contract. It is not a V5R2 authorization or lifecycle acceptance substitute.
Local macOS full-node builds encounter a separate Linux diagnostic IPC boundary;
Linux CI validates the node path. This status does not waive that gate or alter
unrelated peer-authentication checks.
