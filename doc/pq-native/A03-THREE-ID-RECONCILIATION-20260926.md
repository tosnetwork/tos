# A03 three-ID retained-evidence reconciliation (not acceptance)

This offline update extends `a03-first-batch.json` on the `44cde2741` base.
It does not create a historical run receipt or promote any `accepted` flag.
CC retains the N6 node-network slot; no node or packet-injection run was made.

| ID / original source | Original console exit | Indexed bytes after this update | Original launch argv | Controls / remaining blocker |
| --- | --- | --- | --- | --- |
| X01 / `6e863142be50976b998572249fc7fb62a980b808` | Unique `Script done ... COMMAND_EXIT_CODE="0"` | 12 raw, 12 binary snapshots, 3 source blobs, fixed Mac review, 3 successful CI records on docs-only `262f5c5c7` | Absent; reviewer prose is separately checked, not OS argv | The real stop/restart window is signed only in its bounded task scope. No contemporaneous per-run receipt or complete old-red/new-green/mutant-red mapping for the fixed signed source. Historical b207/e036/249 controls cannot be relabelled as this run without source/applicability reconciliation. |
| F01 / `2e1a51ad9f3be29c783aed3f8cff65abbb0dec08` | Unique `Script done ... COMMAND_EXIT_CODE="0"` | 9 raw (adds three H89/H131/H172 check outputs), 12 binary snapshots, 2 source blobs, fixed Mac review, 3 successful CI records on docs-only `38440fe9d` | Absent; start event identifies mode/source/base port but not complete process argv | Runtime transitions, native/header and independent OS data are retained. No complete per-ID control receipts; older H+1/cwd/capital mutants are on predecessor source trees and remain historical until byte equivalence and intended scope are reconciled. |
| E16 / `84a30e4268f94e894497e402d97058cadcbb876d` | Unique `Script done ... COMMAND_EXIT_CODE="0"` | 8 raw (adds two pre-send getters, node1/2 logs, Genesis and live Config readback), 10 binary snapshots, 1 source blob, fixed Mac review, 3 exact-source successful CI records | **Absent** from console header; old index array was documented command text, not a preserved process invocation. Now `argv=null`, explicit gap, and `reported_argv_text` checked against fixed review prose. | Same-run VM85 refusal is a route negative, not an old-production-red/mutant control receipt. First positive stake lacks the same-run five-hop raw BOC join; PID/exe-inode map absent; accelerated Config15/34 only. |

All counts refer to retained files whose SHA is re-read by the inventory
checker, not to a claim that every executable snapshot was independently
observed running. Source blobs are checked with `git cat-file`/`git show` at
the original commits; CI equivalence is a checked docs-only descendant or
exact source, and never proves execution of these live routes.

## New exact raw bindings

E16 retains both getter windows at query IDs `1790348791414184765` and
`1790349985272467639`, SHA respectively `5e12a1544ecda5bf68b08fba609487942d3d85f3302c0ed226772f63d129c6e8`
and `3639809e338da619f6b4d24577b5df7e64e4980aafd45eb2b8c1fd9bb1f1786d`.
The report's transaction LT `901000003` BOC decodes from base64 to SHA
`0f61485c81734e25c5ce203bbfdae158e340b57a1c3b09fb6e4de6b4119f940c`,
equal to the declared value. This check is **BOC byte integrity only**;
the VM85/query/body interpretation remains bound to the fixed Mac raw review.
Two later full heads H343/H344 occur in both original node logs, now indexed;
they are raw observations, not new script assertions or independent ancestry
proofs. Config15 `(600,180,60,180)` and initial Config34 duration 1200 seconds
are retained as this test-only fixture's timing, not production defaults.

F01 adds the existing check outputs `check-89.json`, `check-131.json`,
`check-172.json`, SHA respectively `87894e5cbd293e1d03a764845ccec1bfd4d47a1f41d45ed096b5396e7fb7203a`,
`adfd715975ff54c8ee3a7b6838aa0ebaa5f8de2cbc7ae371574c207cc6a30c35`,
`33e1ae352ce05c764e556302c677c0fbc6cadac657fbf9ff5f20ddfc4ee537f6`.
X01's original raw/OS/absence/index bindings are unchanged.

## What is deliberately not filled

- Original run argv remains missing for all three IDs. Review prose is
  transcription evidence, not a replacement `/proc/cmdline` or raw runner
  command receipt. No post-hoc JSON is being created as proof of execution.
- No new `main/old_red/new_green/mutant_red` historical receipt is generated.
  Missing unique mutation patches/source hashes and per-ID control mapping
  remain gaps. CC's eight symptomatic red tests are not strict unique-mutant
  proof until their source deltas are retained and independently reviewed.
- `accepted=false` remains on all three first-batch entries and every ledger
  row. A03 development gate remains fail closed; human task signoff is not
  expanded and X02/Q01 or other neighboring units are not closed.

Reproduce the offline byte check with:

```
python3 scripts/a03_first_batch.py --batch doc/pq-native/a03-first-batch.json --snapshot doc/pq-native/a03-task-snapshot.json --source-repo . --memo-repo /home/tomi/memo --inventory-only
python3 -m unittest discover -s test/pq-native -p 'test_a03_*.py' -v
```

These commands test an index at the current source, not re-execute any of the
three historical live networks. Original console/review/binary paths and
individual SHA values remain in the machine index, not copied into new fake
run artifacts.
