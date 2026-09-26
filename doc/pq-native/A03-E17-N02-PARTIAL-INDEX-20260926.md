# A03 E17/N02 partial inventory

This change adds five E17 red raw references and two N02 raw references to
the machine ledger; N02 bootstrap red was already indexed. All rows remain
`accepted=false`, with historical command/exit and control gaps intact.
It does not change the task table or independently sign A03.

## Retained-file binding

Ticket `A03-e17-n02-535-v1.json` ran once against source
535214d5836c5f09f45975689acb8daf8c37c7ae and fixed memo
c73f29ee5ce63d8c96fa93a65ccc4964e3515697. Eight streamed raw hashes matched
explicit unit/role/file/full-SHA lines in their corresponding reports.
Natural wrapper and resource runner exits were 0; accepted_ids remained empty.
Raw `/datax/n6-unit-agents/A03/e17-n02-retained-535-v1.typescript`, SHA256
9a55ff69ba4d1dcb88e365600d6ef960c56e3cba2296258017fdfb8c89d2e7ee.
Runner `/datax/n6-control/runs/n6-heavy-1790393440-26784.json`, SHA256
366d197c212e499ddd3dbe9ee17ae84df0c746c1265a2ff3a20f1bb95e28eb4e.
Outer stdout/stderr was returned in the session only; no separate raw outer
file exists, and none was manufactured later.

## Control source and later binaries

Ticket `A03-control-source-binary-v1.json` ran once; outer/worker exits 0.
Five unique a2b646c80 E17 patches reconstructed exactly the mutant entry hashes
reported by the fixed independent review. No guard test was executed.
N02 follow-up doc commit367e5eec19a2da62a50714a8aee4e099bc4de5f8,
blob6d3c8c8ffbe3378dd16171b554eb4d77d4b1ad3d, names three retained binaries:
`a4-no-bootstrap-mutant`, `a4-no-save-mutant`, `a4-clean-binary` under
`test/integration/.n5-manager-db-fixture-20260924/`. All streamed hashes match.
They are later rebuilds from a4a4d472dcbd7caace1ced0fb755c786ed3eaefc,
not proof of which binary emitted an original b1e red run.

Output root `/datax/n6-unit-agents/A03/control-source-binary-v1/`:

| Original output | SHA256 |
| --- | --- |
| stdout.raw | e7479392861339ffbd22d6cd417ad0827582327c15289d40708bcd524d6a4aff |
| stderr.raw (empty) | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| receipt.json | 81ddbe7da0816789c7448ca304f4f80e77957ad840cfbfccdebd1227b10b745b |

Outer raw files are the sibling `control-source-binary-v1.outer.stdout.raw`
(empty, same empty SHA) and `.outer.stderr.raw` (SHA256
6a10e6e64aed32e3fa887ad48e1ed6c157b50665e846171f2dca5f06ab7c33f4).
Runner unit n6-heavy-1790394833-30600 reports success/status0.
These are new offline receipts, never historical network/guard run receipts.

## Remaining limits

E17 exact a2b source green raw/argv is not indexed; prior65f green is not
relabeled. N02 original argv and original binary execution binding remain
unproved; later rebuilt controls need their own raw/build/source applicability
mapping. No tests or gate re-runs were performed for this index edit; a narrow
fixed-commit validation requires another resource ticket. A03 remains OPEN.
