# C09 retention dry-run control — no live call

Base source commit: `e4466ee91f78616bfadb6b1ebf7ef8fcef04a87b`. Dry-run script SHA-256: `ee9ce300444386cfc627c8e605cac7c453850131ab921628c881622bfbd4ce3b`; test SHA-256: `1bc550a30ff99e790321943b0563e9c1899068fde4ba4a16d5b12828b7ecc608`.

`python3 -B tools/node-health-monitor/scripts/test-plan-c09-retention-dry-run.py`: 5 disposable SQLite tests, exit 0. They check exact Q cursor/M inode binding, non-process global anchor, Q retained-origin and control source-reference page overlap, unknown source classification, zero deletion candidates, missing or old anchor rejection, over-bound Q pins, private file permissions, and unchanged SHA-256 of M/Q/control fixture files. The snapshot is explicitly provisional: `pin_integrity=not_verified` and `age_eligibility=not_evaluated_unknown_class_or_clock`.

Sensitivity control copied source and tests to a temporary directory and changed only `anchor_seq != q_watermark` to `anchor_seq > q_watermark`. With bytecode disabled, baseline exit 0 → mutant exit 1 on `test_old_anchor_below_global_watermark_refuses` → restored exit 0. This dry-run imposes a stricter equality precondition than the current Q `validate_manager_cursor`, which permits `anchor_seq<=W`; the page producer itself emits equality. The mismatch remains an open Q validator review, not a claim that production already enforces it.

The script has never been invoked on live M/Q/control. It does not persist a prune cursor, classify age eligibility, return deleteable row IDs, or authorize retention. No M/Q/control/collector/service source or runtime was modified.
