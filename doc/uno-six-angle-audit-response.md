# Six-angle audit: first disposition

The 2026-09-06 six-angle audit was read in full. It is static review with stated
coverage exclusions, not execution or full activation acceptance. This response
covers two fixes only; it does not adopt every finding or proposed remedy.

## X-1(a): host enabled with no ingress policies

The activated configuration loader now maps absent ConfigParam 84 to an empty
policy table, just as an explicitly encoded empty table already did. The strict
table decoder still rejects null/malformed input. A present malformed parameter
still fails resolution. A registered block engine still cannot resolve its
workchain without an explicit matching public ingress policy.

This closes the disagreement between the presence check and the runtime loader
for capability-only activation. The new test failed on the original loader's
missing-table error and passed after the change. It tests the sender-side
resolver, local block-engine resolution and malformed-table controls. The
existing missing-table sender test was updated to the deliberately changed
semantics; missing-descriptor and binding-mismatch controls remain rejecting.
All 42 WorkchainBlock tests pass. This is not a live governance migration test.

This does not authorize removing an existing table, executor rebinding, retiring
a workchain, or accepting ConfigParam 84 on old binaries. Those transitions
remain restricted. Binary rollout must still precede introduction of parameter
84. Creating a new policy still requires a new descriptor with admission closed.
The memo's activation sequence should distinguish enabling an idle host from
introducing a policy-bearing workchain; no retirement rule is selected here.

## A6-3: compare before optional export; never overwrite

The build script still generates its diagnostic header in OUT_DIR. It compares
that artifact against the committed header before honoring any export request.
An export now uses exclusive file creation: existing regular files, symlinks and
hardlinks cannot be overwritten. ABI.md documents explicit review/copy from the
reported OUT_DIR artifact instead of using the export variable to regenerate
the committed source in place.

`test-uno-crypto-header-guard` runs actual Cargo builds against a disposable
source copy. Cases cover a normal build, drift with an export back to the
committed header, drift with a new export path, a verified export, existing
header/symlink/hardlink targets, and a restored normal build. Successful runs
remove both their fixture package artifacts and their source directory; failed
runs print and retain the fixture path and per-case logs.

Restoring the original write-before-compare behavior made `drift_same_path`
fail because Cargo returned success instead of rejecting the drift. This was
repeated after isolating each fixture's package identity. Earlier shared-package
runs reused a stale build-script binary despite restored source; a timestamp
refresh alone did not fix this, so those recovery runs are not passing evidence.
The final test uses a distinct package identity, while sharing dependency
artifacts. The original package's release artifacts were cleared and rebuilt
after the mutation experiments; no source header was regenerated or changed.
Final restored CTest runs passed the Rust suite, header guard and real-proof
C++ ABI fixture. The host log is `build/uno-six-angle-host-regression.log`.

This test remains under the existing opt-in crypto CMake flag. Registering it
does not close A6-1's separate requirement for CI to enable the crypto gates or
run the real network test matrix.

## Still open

- X-1(b): distinguish admission closure, execution pause and permanent retirement;
  preserve queued messages, existing obligations and sender restrictions.
- X-2: define scope admission without making global config validity depend on
  which foreign engines happen to be installed in the local registry.
- A6-1 and the remaining build, synchronization and test-harness findings need
  their own verification and disposition.
- H-2, M-2 and the growing single-account state-capacity gate remain open.

No new UNO engine, monetary transition, state layout or production activation
is introduced by these fixes.
