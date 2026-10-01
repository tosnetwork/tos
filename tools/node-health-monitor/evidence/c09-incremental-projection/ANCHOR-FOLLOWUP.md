# C09 global boundary follow-up

Base: `dfec289e28fdf6a9194e2edd14798b0286e40a99` on the isolated
`nhm/c09-anchor-supervisor-followup` branch. This follow-up changes tests only;
no service or business node was restarted.

## Changed-property control

The new `diagnostic_boundary_rewrite_refuses_even_with_unchanged_retained_process`
test writes one valid process parent followed by a diagnostic row. It reads a
caught-up cursor anchored at the diagnostic global M sequence, retains the
process parent, and proves the unchanged snapshot is readable. Rewriting only
the diagnostic row's hash, then deleting that row, must each fail with
`M projection anchor changed` while the process parent remains untouched.

The control passed on restored source. For sensitivity, the exact single
`actual.as_deref() != Some(expected)` guard in `read_process_projection_page`
was compiled as `false && actual.as_deref() != Some(expected)`. The test exited
101 at its first `unwrap_err()` because the changed diagnostic boundary was
accepted as `Ok(ProjectionPage)`. The original source was restored byte for
byte (SHA-256 `0ebdd0f77612692f7c869c4912efa22cf1fef1e7cd5bef351fdf7eb3b0e9f8f3`).
The mutant source SHA-256 was
`02cc38c489900ea16d4101b242543f05f872fb1d0a1b63762d495267d72ed67e`.

## Expired test windows

Two tests had a fixed role window ending at `2026-09-30T00:00:00Z` but used
the current UTC time as their observer receipt. The initial full package run
failed in `witness_cache` at `OutsideWindow != Normal`; the separately observed
`witness_archive` test also failed for the same reason. Only those two tests
now derive their valid role window from their own captured `now`. The outside
window negative in `witness_cache` derives an earlier end from that same time.
Production role qualification and other historical fixtures are unchanged.

## Restored checks

- `CARGO_TARGET_DIR=$HOME/nhm-c09-anchor-build cargo test --locked -j2 -p tos-health-services`:
  exit 0, 151 passed, 4 intentionally ignored across 30 test suites.
- `CARGO_TARGET_DIR=$HOME/nhm-c09-anchor-build cargo clippy --locked -j2 -p tos-health-services --all-targets -- -D warnings`:
  exit 0.
- `cargo fmt --all --check` and `git diff --check`: exit 0.

Raw logs are in `anchor-followup-raw/`; the full log is losslessly gzip
compressed to preserve its exact output bytes:

| File | SHA-256 |
|---|---|
| `full-health-services-restored.log.gz` | `f907b483484a685e67ffb01a9169b1eba2bab3d4fbfb9cf7bdd7f1db959a0e49` (uncompressed SHA-256 `7853d219953e7b838e0f02bd1b16fe4b372e5c1b0f3cfc7878e5fb2392c8da3f`) |
| `mixed-boundary-anchor-mutant.log` | `2570287e8fd7a529d6398e35256688a84fa12e3752f3ee8794bcf4133758815e` |

This is a development source/test check, not C09 deployed availability or
72-hour acceptance.
