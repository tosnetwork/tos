# D78 statement boundary review evidence

Reviewed A 5f034af0f; B observation after the run, not a pre-observation prediction.
See ../../uno-m5-d78-boundary-review.md for verdict and limits.

fixture/ preserves the input bytes B decoded. artifact-identities.json was made
by B after execution: it is an artifact identity record, NOT an execution-time
wallet hash. No binary freshness pin existed for A live2. That limit is not
repaired by retaining these files now.

artifacts.cpp is a pinned measurement source for 5f034af0f codec/host schemas,
not a default test or portable standalone tool. It originally read the recorded
/tmp/uno-m3-live-wifgx0up path; fixture/ is its retained equivalent. Reproduction
requires restoring that fixture path or changing only the input directory and
linking matching generated block-auto.cpp plus Native libraries. It reads actual
account roots, test-key decrypts rights, independently accumulates the six-block
ledger from stored candidates, reads fee/effect fields and compares components.
No host publication is produced. Earlier setup failures (missing ingress include,
missing generated-code link object, wrong ValueFlow record type) were corrected;
none is treated as a property red.

tag-control.py records the isolated shadow-header procedure using the configured
Native compile command and the previously used /tmp/b_d75_helpers.py driver.
Only the v2 tag literal becomes same-length v1. tag-mutant.log records the prefix
assertion itself, not merely a failure status. It has baseline/restoration logs.
Default-proof-work.log separately records actual registered CTest execution.
This procedure is measurement evidence, not a new default mutation gate; the
persistent prefix assertion is in crypto/test/test-workchain-proof-work.cpp.

old-hash-check.json checks all seven old artifacts against the PRE-D78 committed
input-identities manifest. old-artifacts-reread.log re-executes the preserved old
probe; the controlling old observation remains the already committed
uno-m5-shortfall-independent/normal.log, not this fresh reread. cross-boundary.json
compares its installed receipt to B's independently decoded new receipt.
