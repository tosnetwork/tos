# A03 first original-evidence batch: E16, F01, X01

`a03-first-batch.json` indexes **actual retained** source blobs, raw files, binary snapshots, independent reviews and CI metadata for three task IDs against memo task table `331c92eccf13423258653c31c627cd5211922e72`. `scripts/a03_first_batch.py` rehashes every indexed byte and checks the frozen A03 task statuses. The batch is not an A03 acceptance record: every row has `accepted=false`, a bounded applicability scope, explicit gaps and per-ID invalidating changes. The checker returns `integrity_passed=true` only for valid indexed bytes; its default development-gate exit remains 1. `--inventory-only` exits 0 for a valid index without changing that gate result.

- **E16 ✅:** Fixed `84a30e426` single local accelerated network; original console `COMMAND_EXIT_CODE="0"`, report, source blob, ten frozen binaries, Mac exact-run review and three completed/success CI run metadata are indexed. The report itself lacks source commit; first successful stake lacks a same-run five-hop raw BOC join; no OS PID/exe-inode map. The CI jobs do not prove execution of the exact E16 route. Per-ID old-red/new-green/mutant raw still need reconciliation.
- **F01 ✅:** Fixed `2e1a51ad9` accelerated single-host four-validator run; original console `COMMAND_EXIT_CODE="0"`, report, Config34 capture/RPC, independent OS process generations, twelve frozen binaries and Mac exact-run review are indexed. The original console does not preserve exact launch argv, so that field is explicitly missing. A captured GitHub query returned no CI runs for this exact SHA; it does not prove future CI will remain absent. The task-table scope is signed, but A03's complete per-ID run/control record is not. The earlier `d759` run and its failed/cancelled CI remain historical evidence, not this F01 signed run.
- **X01 ▶:** Fixed `6a3ce5361` offline checker/capture source, test logs, manifest and Mac review are indexed. This is an offline candidate, with no live fault-window, binary/process or applicable CI proof. X01 stays open.

The file paths under `/home/tomi/tos-n6` are read-only references to retained original artifacts; if the owner removes or changes them, integrity checking fails. The E16/X01 memo review objects are read from fixed memo commit `77e16f8992bf27f96b36ff2ae3110b8f9c07af91`; F01's newer review is read from `331c92eccf13423258653c31c627cd5211922e72`. CI JSON was read from the run IDs recorded in the batch; the exact-source F01 empty query is retained separately. A changed task status, source blob, console, binary, review or CI record cannot be silently substituted.

Run from the detached candidate tree:

```
python3 scripts/a03_first_batch.py --batch doc/pq-native/a03-first-batch.json --snapshot doc/pq-native/a03-task-snapshot.json --source-repo . --memo-repo /datax/memo-pg-e16-current-20260925 --inventory-only
python3 -m unittest discover -s test/pq-native -p test_a03_first_batch.py -v
```

This index is a first reconciliation slice. It does not upgrade E16/F01's signed task-table scope or close A03/X01. Full per-ID command/exit/raw/control and reviewer causality still need the main A03 ledger gate and independent review.
