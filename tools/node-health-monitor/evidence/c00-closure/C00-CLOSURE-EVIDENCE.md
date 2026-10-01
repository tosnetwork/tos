# C00 closure evidence

This report describes the executor's review candidate. It does not accept C00
and does not certify production deployment, fixtures or later-stage gates.

## Identity and resource bound

- Worktree: `$HOME/tos-node-health-impl`
- Branch and base: `node-health-monitor` at
  `0a3aafda25ad9fa9d93be45156e2df2838646085`
- Memo: `main@6c0536c042405e857bdced8e327b6f018c816526`
- Design blob: `c28a6b2506c98fc728f868081a8192f7d0cd0d0a`
- Work-order blob: `f7cd3371c8023bb61409d5e77fd96a3741f0cddd`
- Final pre-commit host observation: 192 logical CPUs and 126,498,385,920
  available bytes. Builds used `CARGO_BUILD_JOBS=16`; no business service was
  running, started or regenerated.

The exact pre-commit source and log hashes are in `evidence-index.json`. The
commit identity is recorded in the review notification because it is created
after this report.

## Final restored commands

| Command | Exit | Result | Raw log |
|---|---:|---|---|
| `cargo fmt --manifest-path tools/node-health-monitor/Cargo.toml --all -- --check && git diff --check` | 0 | formatter and whitespace clean | `final-fmt-diff.log` |
| `CARGO_BUILD_JOBS=16 cargo clippy --manifest-path tools/node-health-monitor/Cargo.toml --locked --all-targets -- -D warnings` | 0 | both crates, all targets | `final-clippy.log` |
| `CARGO_BUILD_JOBS=16 bash tools/node-health-monitor/scripts/run-contract-tests.sh` | 0 | 20 schemas; six real non-null handler outputs; 64/32 boundary schema; actual doctor refusal; 97 workspace tests | `final-closure-suite.log` |
| `CARGO_BUILD_JOBS=16 CARGO_INCREMENTAL=0 python3 tools/node-health-monitor/tests/c00-closure-mutations.py` | 0 | six baselines green; six mutants compiled and failed their exact assertion; sources restored | twelve files under `mutation-logs/` |

The supervisor independently ran the restored closure entry point with natural
exit 0. Its external raw log and SHA-256 are indexed but not copied into this
executor commit.

## Negative and boundary evidence

- Actual HTTP routes reject invalid clock claims, partial/unknown coverage
  misclassification, differing metric units/epochs/labels/populations, extra
  payload fields, derived evidence without lineage, cross-run/scope misuse,
  malformed network IDs and integer overflow.
- Per-series aggregation deduplicates and preserves earlier gaps. The 64 missing
  fields / 32 gaps boundary is emitted and schema-validated. Both per-series and
  independent two-metric response-wide overflow return `SCHEMA_MISMATCH`.
- `health-contract-check` is executed against production placeholders and exits
  nonzero for exactly 11 missing gates; null counting alone is not treated as
  refusal evidence.
- Mutation logs prove compiled assertion failures, not compiler failures. Every
  subprocess has a 120-second timeout and source restoration in `finally`.

## Failed-run lineage

Failures were retained as engineering evidence, not counted as passes:

1. System `python3 scripts/check-contracts.py` lacked `jsonschema`. Resolution:
   exact Python 3.14.4 plus a hash-locked isolated `.contract-venv`.
2. `cargo test ... -p health-services --test http` used the wrong package name.
   Resolution: `tos-health-services`; exit 0 afterward.
3. One cargo invocation supplied two test filters, which Cargo rejects. The full
   HTTP binary was run instead and passed.
4. The first full closure run found an old assertion expecting the legacy
   arbitrary JSON output. It was changed to assert the typed output while
   retaining watermark and scope invariants.
5. Initial strict Clippy found a large enum variant and an unnecessary lazy
   fallback. Both were corrected; the final all-target run is clean.
6. The first mutation run stopped because its coverage target string no longer
   matched the refactored merge. The target was changed to a compiled semantic
   replacement. A later network-shape mutant survived because the only negative
   was also non-hex; a 63-character lowercase-hex negative made the length rule
   independently sensitive. Final six-mutant evidence is green/red as required.
7. A post-handler boundary response passed Rust DTO deserialization but failed
   the published schema because `missing_evidence.reason` exceeded 256 chars.
   The raw failure is `failed-suite-schema-boundary.log`. The fix emits a truthful
   count summary pointing to the untruncated response coverage. The final suite
   then passed schema validation.

## Inventory truth and not-run gates

`source-manifest.json` contains the exact 16-class C00 truth matrix. Its C00
inventory flag is true, while `complete_manifest=false` and
`production_adapter_inventory_complete=false`. Isolated exporter-actor and
process fixtures are explicitly synthetic; unavailable sources remain null,
disabled and contract-invalid. No production fixture was synthesized.

MCP/rmcp and Prometheus versions, commits and artifacts are inventory-pinned but
disabled. Their runtime gates are C08 and C03. Real source adapters and fixtures
remain C01-C05; production host/failure domains, credentials, performance,
restore and soak remain C09. AI, diagnostics and business validators were not
enabled or exercised.
