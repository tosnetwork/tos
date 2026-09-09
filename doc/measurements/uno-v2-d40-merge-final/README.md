# Reviewed migration merge acceptance

Measured production source: `fdae869937b19f3713e356bc85665da50429d563`.
This integrates the reviewed caller/identity migration and Python decoder/tag
inventory update without rewriting any source commit. The accompanying plan
change documents the owner's regression-cleanup procedure; it changes no code.

After the complete default `cmake --build build -j32` succeeded, ordinary CTest
ran 130 entries: **121 passed, nine owner-deferred obsolete fixture shapes,
zero unresolved failures, zero skipped**. Raw CTest/JUnit retains nine failures
and exit code 8; it is not edited to make those tests pass. The nine dispositions
are the owner's 2026-09-09 decision, not general exclusions for their names.
`comparison.json` independently binds each current failure to its new fixture
BOC, bootstrap diagnostic, payload shape and file hashes. Six raw configuration
cells fail framing before genesis comparison, one shell has the synthetic wrong
genesis (7406), and two lack instance configuration (7409).

These 130 ordinary entries do not include the three private I13 harnesses.
Their static `--show-only=json-v1` registration was checked by
`.github/scripts/check-i13-results.py registered`: exactly three expected drivers.
They were not run; their execution remains `workflow_dispatch` only.
The ordinary `test-workchain-handwritten-tags` and `test-counter-python-harness`
both passed. The former includes the Python representation and five-role
inventory checks (972/973). It does not claim the Rust consumer is migrated.

## Cleanup and fresh-run provenance

The previous run was not accepted: the retention cap replaced protocol failures
with environment failures, including three configuration tests which should
pass. Its raw logs/JUnit remain in
`/home/tomi/memo/reviews/d40-python-merge-fdae86993/` under their original names.
No result from that run is substituted for this final run.

With B's explicit pause confirmation and the previous local CTest process
finished, the existing cleanup script ran first in dry-run mode, then with
`--keep-newest 0 --delete`. Both built-in process/reference checks passed.
Directory count changed **26 -> 0**. The script archived 661 top-level diagnostic
files before deletion; `cleanup.json` records the archive path and hash. Nested
databases are not included: this is diagnostic preservation, not a full backup.
The source was not edited during the final regression. B remained test-paused.

Fresh fixtures were created for this final run. No new missing-history failure
appeared. The inspected Python checkpoint test
`test_checkpoint_genesis_timestamp_and_committee_lifetime` creates a new
temporary directory and invokes `create_zerostate` with an explicit historical
time; it does not consume another run's retained fixture. This statement is
limited to inspected and executed tests, not every external/manual scenario.

The stored bootstrap result sidecars observe the collator, not the subsequent
validator terminal result. Bootstrap diagnostics are used to locate immediate
causes, not to infer a candidate-invalid/local-unavailable classification.

## Commands

Additional scan disclosure: the full removed-execution-domain scan fails on
five newly added generated-tag annotation comments in the Counter CMake fixture
(the five UnoV2 type names). The migration's five agreed acceptance checks above
pass; this does not claim all repository guards are green. No annotation or
scan exception was changed here. The raw scan is retained at
`/home/tomi/memo/reviews/d40-python-merge-fdae86993/removed-domain-scan.log` for
the coordinator's disposition.

```sh
python3 test/cleanup-counter-fixtures.py /home/tomi/tos/build --keep-newest 0
python3 test/cleanup-counter-fixtures.py /home/tomi/tos/build --keep-newest 0 --delete
cmake --build build -j32
ctest --test-dir build -j8 --output-on-failure --output-junit /tmp/d40-clean-final-junit.xml
cmake -S . -B /tmp/uno-i13-merge-registration-Tg5Kvb -DCMAKE_PROJECT_TOS_INCLUDE=/home/tomi/tos/crypto/test/workchain-construction-isolation.cmake
ctest --test-dir /tmp/uno-i13-merge-registration-Tg5Kvb -L i13 --show-only=json-v1
python3 .github/scripts/check-i13-results.py registered /tmp/d40-clean-final-i13.json
```
