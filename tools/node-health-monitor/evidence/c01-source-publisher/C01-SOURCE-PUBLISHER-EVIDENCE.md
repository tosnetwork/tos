# C01 source publisher closure evidence

Status: `READY_FOR_REVIEW`, not accepted and not a production gate.

## Identity

- C00 base: `87a36e95624726a6f72a31ff07ff8a8ff3b87056`
- Native publisher implementation: `be690c9252b962d21017026f5665b61547dccbdd`
- Reconciled Rust consumer, manifests, fixtures and raw evidence: `c17b45082f7a2a498f810d6b89887f4e0d0b9680`
- Memo order: `main@cb84e1684b46b2d94e0f9c4654020a96ac71ca66`
- Source, test and manifest hashes: `SOURCE-SHA256SUMS`
- Restored native binary hashes: `BINARY-SHA256SUMS`
- Every retained raw log hash: `RAW-SHA256SUMS`

The final review commit only adds this index and the three checksum files. The
exact final branch HEAD is reported with `READY_FOR_REVIEW` so the index does
not attempt to self-hash its own commit.

## Restored validation

| Evidence | Result |
|---|---|
| `raw/final-native-build-restored.log` | Natural exit 0; all affected native test targets and `validator-engine` rebuilt after mutation restoration. |
| `raw/native-units-final.log` | Natural exit 0; source policy, registry, callback completion, enabled/disabled timestamp gate, native snapshot and isolated synthetic benchmark passed. |
| `raw/native-http-all-final.log` | Natural exit 0; fast, slow, disabled, gate-off, multi-source, 16.5-second lease, disconnect, concurrent, error and exact 2 MiB boundary modes passed. |
| `raw/c00-contract-regression-restored.log` | Natural exit 0; 20 schemas, six actual handlers, doctor refusal and all 97 Rust workspace tests passed. |
| `raw/final-fmt-clippy.log` | `cargo fmt --check` and locked all-target clippy with `-D warnings` both exit 0. |
| `raw/final-manifest-validation.log` | Python syntax checks and the contract/manifest checker exit 0. The checker recomputes sparse histogram series, uniqueness, caps, approved names and rejects one faulty count. |

The Rust pairing consumer at the reconciled commit hashes the complete native
OpenMetrics body. `SOURCE-SHA256SUMS` binds `native.rs`, `native_cache.rs`, the
pairing tests and both frozen fixtures. The earlier filtered-body failure is
retained in `raw/c00-contract-regression.log`; the restored pass is the log
listed above.

## Mutation evidence

`raw/mutations-final/` contains nine baseline build/run passes followed by nine
mutants that compile successfully and fail an intended runtime assertion:

1. frozen body/hash identity
2. literal 2 MiB source admission boundary
3. metadata feature gate
4. duplicate-family source merge
5. callback completion timestamp capture
6. bounded counter CAS attempts
7. gauge owner clearing
8. per-path construction gate
9. actual inflight source lease

This count excludes the earlier `lease-after-timeout` mutant in
`raw/mutations/`, which survived because an independent collector busy gate
masked the property. It is retained as failed lineage. The earlier HTTP suite
failure in `raw/native-http-all.log` is also retained and excluded from passing
claims. `raw/final-manifest-validation-failed.log` records a wrong script path;
its misleading follow-on echo is invalid evidence and is superseded only by
the correctly fail-fast `raw/final-manifest-validation.log`.

## Capacity and provenance limits

- The C01 manifest is a bounded subset: mechanically computed 107 series with
  a subset cap of 128. It does not replace the R4 global core cap of 2048.
- The generic registry reserves 64 fixed slots. The production approved-name
  list is empty in C01; test-only names do not authorize production metrics.
- The declared 874 bytes counts tuple value fields only. It is not total heap,
  registry, actor or 2 MiB publisher-body memory.
- Generic registry counters are exposed through OpenMetrics double values and
  do not promise exact `u64`; an approved future typed adapter is required.
- Source fixtures remain explicitly synthetic/unsupported where production
  authority is absent. No production fixture was synthesized.
- Publisher-prepare timing covers synchronous `collection_completed` through
  cache publication. The synthetic microbenchmark is not whole-callback,
  consensus-actor or production C09 performance evidence.
- C01 does not certify deployment, production source availability, C02+, MCP,
  Prometheus runtime gates, consensus, journal or durability changes.

## Independent witnesses

- `/home/tomi/nhm-supervision/c01-independent-lease.log`:
  `e62624350e89ea2f002ee19bde73f340d185512498c6a408c00c00e308bcbaa4`
- `/home/tomi/nhm-supervision/c01-incremental-native-check.json`:
  `d525f73efc6cbed1affeab154dd741d4de0d6c80828b14e49e73a5f743673f57`

These external supervisor files are referenced, not copied or represented as
executor-produced evidence.
