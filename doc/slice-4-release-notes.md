# Slice 4 Release Notes

Status: release-package surrogate complete on 2026-04-30.

Slice 4 adds:

- `@stdlib/postponement` for bounded, storage-owned postponed work.
- Compiler hardening for queue internals and external-message enqueue
  attempts.
- `examples/slice4/postponed-auction.tol`, a reference postponed
  auction contract.
- Behaviour manifests for request servers, state machines, postponing
  state machines, Jetton wallet helpers, NFT item helpers, and multisig.
- `tol new` manifest output with `behaviour_conformance` declarations.
- Generated Slice 4 scaffold examples under `examples/slice4/` for
  Jetton, NFT, and Multisig behaviour conformance.
- Release checks for Slice 4 docs, manifests, examples, and focused
  tests.

Slice 4 does not add protocol mailbox scanning, scheduled wakeups, new
TL-B constructors, new TVM opcodes, or `ErrorClass.BackPressure`
emission.

Verification entrypoint:

```sh
python3 scripts/check-slice-4-release-package.py
```
