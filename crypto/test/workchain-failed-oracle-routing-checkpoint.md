# Failed routing oracle: partial checkpoint

Specification reference: memo `df061ac5`, SHA256 prefix `c0b4260f00db590d`.
B's `WITHDRAWAL-FAILED` contract and runner are unchanged and retained through
merge ancestry. This checkpoint does not fill the complete `oracle-control` or
`return-cost` slot.

## Observation and execution

`ComputeToOperator` executes the real registered Failed engine and then moves
its compute-fee component into the state-fee component, preserving the total.
Real collation and validator replay both use this isolated test producer.
The independent observer decodes the accepted custody transaction fees and the
coordinator's Native balance. It rejects their wrong allocation with
`FAILED_COST_ROUTING`, even when both backing equations still pass.

The driver requires an actual exported candidate and `validate accept` before
accepting that designated red. It then completes the ordinary Failed run in a
separate output directory. The mutation must not overwrite the backing
observer's append-only observations of the restored run.

`uno-failed-routing-oracle.py` compiles a temporary test-source copy with ONLY
the routing diagnostic/assertion removed. It retains the real producer mutant,
all preceding assertions, and the normal libraries. This copy must successfully
publish the incorrectly routed event; the outer driver must exit 1 with
`FAILED_ORACLE_MISSING:FAILED_COST_ROUTING`. A build failure or earlier refusal
does not qualify. Normal / removed / restored runs rebuild the same live
scenario independently; they do not claim one byte-identical predecessor across
all three runs. Each mutant and its ordinary restoration use the same prepared
predecessor within their run.

## Continuous check and limits

`test-workchain-withdrawal-failed-oracle-routing-partial` is registered in default
CTest for Ninja builds with the real node crypto linkage enabled. This profile
builds `test-m3-live` as part of ALL/all-tests. Nonlinked or non-Ninja builds do
not cover it. D59's runtime default remains closed. The test uses compiler/link
commands from that build to construct the isolated executable and fails closed
on unavailable tools or an unrecognized command shape.

No full contract observation marker is emitted. The other ten designated
mutations and their oracle removals remain missing, so full Failed readiness
remains 0/11. Sequence and prepare successors are not established; no guard is
retired. This does not address the unrelated codec exception assertion, direct
validator unknown-error injection, all error classifications, or shortfall and
late-return branches. Zero unknown observations cover executed paths only.

Changed-boundary checks: C++ test producer/Native observer -> live positive and
designated routing red; Python driver -> oracle-removal missing-red failure and
restored success; CMake -> the partial named CTest. No production consensus
functions or B-owned criteria are changed.

## Execution evidence (2026-09-11)

The linked live target compiled. The direct three-run driver observed exits
`0 / 1 / 0`; the removed-oracle producer itself exited 0 after real validation,
and its driver failed with `FAILED_ORACLE_MISSING:FAILED_COST_ROUTING`.
The default named partial CTest then passed 1/1 with a fresh isolated build and
fresh real scenarios. Evidence directories are
`/tmp/uno-failed-routing-oracle-jnlv_9vb` (direct) and
`/tmp/uno-failed-routing-oracle-n949iybn` (CTest); each contains build and
enabled/removed/restored logs. CTest summary: `/tmp/uno-routing-ctest.log`.
The unchanged B readiness runner still exits 1 listing all eleven missing
complete slots; its own readiness unit tests pass 10/10.
