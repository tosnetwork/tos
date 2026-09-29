# C09 page-atomic projection and read-only local cost successor

This successor to `REVIEW-RECEIPT.md` remains an isolated development candidate. It does **not** replace the deployed query broker or accept C09 performance/72-hour gates. No AURA calls, credential reads, business-node changes, or writes to the live M database were involved. The opt-in cost test reads M SQLite in read-only mode and writes only a disposable Q ledger.

The initial cursor candidate committed at `9a6a79519b84fdfb79eef7f7036a644bd4af12e3` cloned the resident Q `EvidenceStore` and committed SQLite once **per projected row**. Against about 2,000 real M process rows, its late 256-row catch-up pages took 5.735 and 6.128 seconds, exceeding the existing five-second control connection deadline. That red remains historical evidence, not a passing latency result.

The successor stages one page in one bounded candidate copy, validates each exact M parent, checks active fixed-W eviction, deletes evicted Q rows, and commits the surviving projected rows and parent bindings in one FULL SQLite transaction. It publishes the candidate to memory only after that commit. The existing separate M cursor transaction follows this page commit, so a crash between them replays idempotently. On a failed page transaction, neither Q memory nor durable Q rows advance; a source/cursor error still latches refusal and revokes active grants. The 256-row page, 4096-parent/8-MiB retention, 5-second connection, freshness and grant limits are unchanged.

## Source and raw receipts

Restored source SHA-256: `observability.rs` `1fe93dc386ac7c963426cdd3b8e143f388b0e920196c84c3a39f64a8ad52c25a`; `query_ledger.rs` `571bd571ddaf5305b84af339f044906b9a462c7c1b246ee1db5ef282bf468aa6`; `tests/manager_query_source.rs` `025357ab9f92437922efdcc3d101e599cf0745bf770f522775d709aca2b3bee2`. Raw logs are under `/home/tomi/nhm-c08-mcp-evidence/`, built with locked Cargo `-j2` in `/home/tomi/nhm-c09-projection-build`.

| Raw log | SHA-256 | Result |
| --- | --- | --- |
| `c09-incremental-live-readonly-cost-first.log` | `307a9e37fcc7903e85d8d179c991fbe5cd9e17bc83c6cee37f24386da2b9f1` | Original per-row candidate, natural exit 0 but late pages 5.735/6.128 s: latency red |
| `c09-incremental-live-readonly-cost-batch-final.log` | `c764bda4ede6be4dfdb30e3d65b72c9babdeb65c66c8fb49a40db100a553af3d` | Restored batch source, natural exit 0; nine catch-up pages, maximum 406 ms, steady import 265 ms at that local sample |
| `c09-incremental-batch-workspace-restored.log` | `f13fd916f485194e5cecef101f5f73bdca6d81d4548d7cf22d498ccc7b6c9a1c` | Locked workspace test suite, natural exit 0; opt-in live cost test ignored by default |
| `c09-incremental-batch-fmt-clippy-first.log` | `ff8c672aca8fc8acb842f7b7351da634bbff6e2f6c6066a8103ac85d316faf3e` | fmt check and locked services test Clippy with warnings denied, exit 0 |
| `c09-incremental-batch-atomic-baseline.log` | `3741e1d7cdbeb7df8c9e714a0d766901a90f5b84f38e3ab48102a6c64e23b3ff` | Injection target baseline, exit 0 |
| `c09-incremental-batch-early-publish-mutant.log` | `f96314358ed8e835d5a7ba340afc1de43e859ca1f3f2fa240fd172f5029caf07` | Compiled mutant published Q memory before transaction; exit 101 at intended W=3 versus W=1 assertion after injected third-row failure |

The early-publication mutant source SHA-256 was `e58bb69a715c9a9105b4fc53c89db7613a2d5ae29d9c3fb42032ea855a6d6053`; restored source returned to `571bd571ddaf5305b84af339f044906b9a462c7c1b246ee1db5ef282bf468aa6` before the final workspace and live-read tests. A weaker swap-order mutation compiled but **survived** because the injected insert failed before reaching the swapped lines: `c09-incremental-batch-atomic-mutant.log` SHA-256 `02b6da837e83aeaf5cbbb061375bc7279cd3337550a77eeed124abf9f777cfc0`, exit 0. It is retained as failed sensitivity lineage, not counted as a killed mutant.

This is a bounded local cost observation, not an A–F or 72-hour profile. M was changing while sampled, and the test did not measure concurrent broker control requests, socket drain, worst-case 4096 retained-parent revalidation, restart recovery duration, or the production two-thirds CPU/memory budget. Independent review, integrated deployment/rollback, live concurrent latency, and soak remain open.

## Independent review-gate controls

The exact successor test source SHA-256 is `5c171b04b4b874c8a39ff2758242d879665c419a79076bd7e176a517d1a14142`; production sources above were unchanged. After 4097 historical process rows have been imported, the migration test now inserts **one** more M process row, requires the next import to return one row at global M sequence 4098, and checks the newly issued grant's retained `manager_watermark` is exactly 4098. It also keeps the old pinned grant usable while backlog is incomplete. A separate same-network replacement SQLite file contains the **same** original seq/hash/body; the reader must refuse on database inode rather than incidentally failing a changed hash or anchor.

| Raw log under `/home/tomi/nhm-c08-mcp-evidence/` | SHA-256 | Result |
| --- | --- | --- |
| `c09-incremental-review-gates-restored.log` | `4eb05b551fbabd9cab43c59ad3fed74926c64e0e7bba5283a33163c9e47c0be7` | fmt, locked test Clippy, and focused projection 14/14 natural exit 0; opt-in cost test ignored |
| `c09-incremental-batch-4098-delta-success.log` | `0d58b0b39fc732bef85139a2e2a915deb03729830219a255b5864e881fd8e303` | exact >4096-history-plus-one-delta control, exit 0 |
| `c09-incremental-same-anchor-inode-baseline.log` | `dce5361ece831432e81534f0c59d226419fe7398fe1194420d2861b2bbdb6724` | exact same-body replacement baseline, exit 0 |
| `c09-incremental-same-anchor-inode-mutant.log` | `cfa937aabde74e8e0cb301191ae9a85a39e197ab61a605eed4cbc2bd40e7aa7a` | compiled identity-guard bypass, exit 101 at intended `unwrap_err()` on `Ok(ProjectionPage)` after replacement |
| `c09-incremental-same-anchor-inode-restored.log` | `648953c5b66b9e7361982594ce6352ab64b2fcb7fc43827655af9e32054d6742` | restored exact source, exit 0 |

The inode mutant SHA-256 was `1d24fb75f80856e4362e6581986eb44ea3fed676714c0bd3de434a4c83aac7c9`; the restored `manager_query_source.rs` SHA-256 was `b924353656bdc9d02591a1b80e7454d1b5df84c5038b14b432c285a0cf799385`. An initial version of the one-delta test incorrectly expected `manager_watermark` in the HTTP grant response (it was null); the control was corrected to inspect the actual granted state and then passed. That setup red was not counted as a product failure or sensitivity result.
