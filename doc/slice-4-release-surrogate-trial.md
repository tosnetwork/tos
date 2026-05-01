# Slice 4 Release Surrogate Trial

Status: repo-side surrogate, 2026-04-30.

The trial validates the path a contract author can follow without
reading compiler source:

1. Inspect `examples/slice4/postponed-auction.tol`.
2. Run the focused postponement tests.
3. Inspect behaviour manifests under `doc/slice4-behaviours/`.
4. Generate a scaffold with `tol new --pattern nft`.
5. Inspect `manifest.json` for `behaviour_conformance`.
6. Run the Slice 4 release-package check.

Observed result:

- `python3 scripts/check-slice-4-release-package.py` passed.
- Generated Jetton, NFT, and Multisig examples each exposed
  `behaviour_conformance` in `manifest.json`.
- The check validated behaviour manifests, the postponed-auction
  reference, focused Slice 4 tol-tester coverage, generated project
  smoke tests, replay stubs, deploy stubs, and observability artifacts.

A real human external-author trial is optional follow-up, not a release
gate for this slice.
