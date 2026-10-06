# Diagnostic regression receipt

Baseline source: `9960de239fda55dd9888cd23893bd694af130e44`.
The implementation changes diagnostics and their syntactic recognition only;
no VM instruction, storage encoding or implicit numeric conversion changes.
The six fixed-ID fixture pairs exercise one rejected declaration combination
across six return shapes. They are new regression inputs, not reconstructed
historical participant submissions or a new generation study.

## Native verification

From the repository root, build `tol` and `fift`, then run:

```sh
ctest --test-dir build --output-on-failure --no-tests=error \
  -R '^test-tol($|-scaffolds$|-raw-opcode-capacity$)'
```

Result: exit 0, 3/3 CTests. The compiler suite has 705 fixtures; the scaffold
check covers seven patterns. The capacity check covers four assembly cases;
three execute an independent valid ML-DSA-44 signature and an invalid signature,
returning true and false. The raw boundary case is required to fail assembly
with `slice does not fit into cell`, after frontend success.

## Sensitivity controls

The unmodified implementation passed before and after these controls. Tests
were selected by filename, and each failure was checked for its named diagnostic
assertion. Original source and fixtures were restored after every control.

| Change under control | Named test | Result |
| --- | --- | --- |
| Restore baseline parser | `invalid-declaration/diagnostic-fixed-id-1` | exit 2: new cause-specific diagnostic absent |
| Restore baseline query pass | `diagnostic-query-seq-amount` | exit 2: amount incorrectly identified as query ID |
| Restore baseline query pass | `diagnostic-query-valid-dest-amount` | exit 2: later amount incorrectly identified as query ID |
| Restore baseline query pass | `query-id-raw-send-missing` | exit 2: uncertainty wording absent |
| Replace propagated reply field with constant zero | `diagnostic-query-manual-ok` | exit 2: warning appears where the fixture requires none |
| Remove capacity padding from the boundary fixture | `check-raw-opcode-capacity.py` | exit 1: raw boundary unexpectedly assembles |

Additional permanent fixtures cover discarded opcode results, intervening
loads/skips, ordinary and destructured aliases, replacement slices, unknown
parser helpers, control-flow boundaries, helper sends, and typed-envelope
checks. Existing receiver-scope and contract-block getter tests remain in the
full suite. `diagnostic-uint64-coins` retains the explicit-conversion error.

C01 provides text guidance only. C02 manual adjacency remains a heuristic and
helper propagation is not analyzed across function bodies. C03 ships compiler
manual guidance with a native capacity regression test, rather than a lint.
