# C04 independent incremental review — 2026-09-29

Scope: isolated native actors and Rust consumers; no business nodes,
deployment, main merge or C04 acceptance.

## Restored native review

- Independently ran the executor's exact restored CTest selector with `-j2`:
  35/35 passed, natural exit 0, 7.59 seconds.
- Read all four compiled mutant receipts and raw target assertion failures:
  nested allowance, refusal stops starts, v2 body refusal, lease retirement.
  Builds exited 0, intended assertion tests exited 1, restored builds and
  control tests exited 0. Independently rehashed the restored source files;
  all four matched their receipt baseline digests.
- Rehashed all 48 native JSON/OpenMetrics pairs against producer-v2/index.json.
  File sizes, file digests, complete EOF body digests and canonical payload
  digests matched. The actual producer binary matched the index digest
  `2f809fe2948141dfb561e44c31a4867b09b93952a324fadf7d2ca8873e07b441`.

## Cross-language review

Independently ran `scripts/run-c04-cross-language.sh` in the Lighthouse tree
using Starbridge's indexed producer-v2 directory. The explicit Rust ignored
test executed and passed. All 48 original pairs passed source schema,
canonical hash and complete-body validation; the generated edge snapshot
passed its schema. Natural script exit was 0. Independent output is retained
in `$HOME/nhm-supervision/c04-final-cross-language`.

The earlier preliminary three-pair run is distinct from these final candidate
pairs. A Rust test failure observed during the temporary masterchain mutant
was mutation-window overlap; the restored nine-test contract suite passed.

## Remaining closure

Review final action/source/persistence and metric manifests, bind source and
logs to committed candidates, integrate native and Rust changes, and verify
the actual integrated tree. C09 performance and production gates remain
unproven. Session actor-drain completion is not established by bus ownership
release; published stopped remains null where that boundary is unverified.
