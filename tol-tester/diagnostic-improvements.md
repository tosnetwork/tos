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


## Review follow-up (2026-10-06)

Reviewed implementation head: `4c83ffcf921b5da2c3d949fcb6880d190d61ee10`
on `fix/tol-diagnostic-improvements`. The proposal PR contains documentation;
these compiler changes remain on the implementation branch.

Three diagnostic defects were reproduced and fixed:

- Conditional expression reads (`?:`, `??`, `&&`, `||`, `match`) could leave an
  opcode prefix pending even when that read need not execute. The next 64-bit
  read was then misclassified as correlation data. All these expression forms
  now invalidate pending manual inference at their boundaries.
- Both tensor and tuple destructuring could replace the tracked body slice
  without invalidating its pending prefix. Assignment targets are now traversed
  for references to that local, including nested destructuring.
- Indirect helper calls have no resolved function pointer. They returned before
  recording uncertainty, incorrectly producing the definite "emits no reply"
  warning. They now invalidate unsupported slice uses and record an unresolved
  helper before returning.

### Validation and sensitivity

Build boundary: fresh native TOL and Fift targets on macOS arm64, with existing
third-party libraries. No full-node or remote native-CI result is claimed.
Run from a configured build directory (the review used `build-review`):

```sh
cmake --build build-review --target tol fift -j 8
ctest --test-dir build-review --output-on-failure --no-tests=error \
  -R '^test-tol($|-scaffolds$|-raw-opcode-capacity$)'
```

Result: exit 0, 3/3 CTests, **713 compiler fixtures**, seven scaffold patterns,
and four raw/symbolic opcode capacity cases. This includes existing typed
propagation, receiver isolation, contract getters and numeric-conversion tests.

The eight added `diagnostic-query-*.tol` fixtures have suffixes `ternary`,
`coalesce`, `short-circuit`, `short-circuit-or`, `match`, `tuple-replace`,
`square-replace` and `indirect-helper`. Each independently returned exit 2 under
an unmodified compiler built from the reviewed head, after successful frontend
compilation: seven failed their forbidden `queryId` warning assertion; the
indirect-helper test lacked the required uncertainty wording. All eight pass
with the fix, and their generated Fift is byte-for-byte identical before and
after it. Repeated compilation of all 39 `diagnostic-*` fixtures produced
identical exit codes, stdout, stderr and (where successful) Fift output.

The six rejected fixed-ID getter fixtures now pin the diagnostic to annotation
line 1 and exclude the generic regular-function error. Temporarily changing
only the cause-specific diagnostic anchor from the annotation to the function
name made `invalid-declaration/diagnostic-fixed-id-1.tol` return exit 2 for the
missing line-1 assertion. Restoring the anchor and rebuilding made all nine
fixed-ID rejection fixtures pass. The indirect-helper warning is pinned to its
handler declaration line as well. No mutation remains in the final source.

Manual correlation inference is still syntactic and heuristic; these changes
do not establish path-sensitive or interprocedural verification. They do not
change accepted TOL syntax, serialization, method IDs, VM instructions or the
raw-assembly policy.
