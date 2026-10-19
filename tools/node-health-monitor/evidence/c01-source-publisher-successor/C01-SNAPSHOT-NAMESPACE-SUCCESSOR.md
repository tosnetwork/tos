# C01 frozen snapshot metric namespace successor

Status: `READY_FOR_REVIEW`, not accepted. This is the narrow compatibility
successor requested after review of C01 at
`d879adbbcb5521f16633df7935cc415e62a91696`.

## Identity

- Semantic correction: `aa61f57e7bd78c1a1de763339ff090d42eb3889d`
- Reconciled manifest and raw evidence: `711919398d4b979bfb1867f945f97f830ec6146e`
- `SOURCE-SHA256SUMS`: nine changed source, fixture, test and manifest files
- `RAW-SHA256SUMS`: fifteen successor raw logs
- `BINARY-SHA256SUMS`: restored affected native HTTP test binary

The final commit adds only this index and the three checksum files. Its exact
HEAD is reported externally so this file does not claim to hash its own commit.
The original C01 evidence remains unchanged and historical.

## Normative correction

The immutable paired body no longer emits the ambiguous live-looking names
`tos_exporter_collection_inflight`,
`tos_exporter_collection_skipped_total`, or
`tos_exporter_collection_failures_total`.

Their publication-time values use only:

- `tos_exporter_snapshot_collection_inflight`
- `tos_exporter_snapshot_collection_skipped_total`
- `tos_exporter_snapshot_collection_failures_total`

Each family has HELP text defining snapshot-publication semantics. The HTTP
test parses a real generated body, requires all new names and HELP records, and
requires every old name to be absent. During a second 16.5-second collection it
reads the cached generation while actual source work remains active, verifies
the same body/hash/generation, and again proves that only snapshot names are
present. No admission, timing, body-size or collection algorithm changed.

## Results

| Raw evidence | Result |
|---|---|
| `raw/affected-native-build.log` | Affected production exporter and native HTTP test rebuilt, exit 0. |
| `raw/http-fast-write-fixtures.log` | Real exporter body/hash passed and regenerated paired fixtures, exit 0. |
| `raw/http-fast-restored.log` | Restored post-mutation body/hash run, exit 0. |
| `raw/http-slow.log` | 3.5-second collector/2-second owner refusal path, exit 0. |
| `raw/http-lease-snapshot-names.log` | 16.5-second active drain, cached exact pairing, peak one and namespace assertions, exit 0. |
| `raw/hash-mutation-runner.log` and `raw/hash-mutation/` | Baseline compiled/passed; frozen-body mutant compiled and assertion-failed; source rebuilt restored. |
| `raw/c00-schema-restored.log` | 20 schemas, six actual handlers, doctor 11-gate refusal and 97 Rust workspace tests pass, exit 0. |
| `raw/final-manifest-check.log` | Final successor source anchors and computed 107/128 metric manifest validate, exit 0. |
| `raw/fmt-clippy.log` | Rust fmt and locked all-target clippy with warnings denied pass. |

`raw/http-fast-write-fixtures-failed.log` is retained failure lineage from
invoking system Python without `jsonschema`. Its later `EXIT=0` echo is not
valid evidence; the fail-fast contract-venv run supersedes it.

All earlier C01 scope limits remain: synthetic fixtures are not production
fixtures; 128 is the subset cap rather than the global 2048 cap; the 64-slot
registry still has an empty production allowlist; no deployment, business node,
C02, consensus, journal or durability change is included.
