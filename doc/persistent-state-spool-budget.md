# Persistent-state spool sizing regression

`state-spool-amplification` makes the measurements behind the 600% default
reproducible. The test lives in `test/test-download-state-budget.cpp` and is
included in `scripts/strict-build-targeted-tests.txt`, which the Linux strict
build checks against CTest's actual inventory before running it.

For each unique cell reachable from the root, it calls the production
`CellStorer::serialize_value(1, cell, false)` and adds the record-header size
shared with the production spool writer. It counts that sum twice: once for
the import spool, once for the rollback manifest of an empty CellDb. The
denominator is the actual BoC serialized with mode 31. Shared cells are counted
once, and the visited-cell count must equal both the fixture expectation and
the serialized BoC's declared count. The test fails if the combined bytes
exceed the reservation derived from `PersistentStateBudgetConfig`'s default.
It also checks that the absolute defaults permit two reservations for the
16 GiB design file size.

The fixtures are deterministic:

* Library: the recovery test's binary tree of 524,288 unique 120-byte leaves,
  giving 1,048,575 unique cells.
* Accounts: a 256-bit dictionary with 200,000 keys. Keys are SHA-256 of each
  64-byte value; byte `j` of value `i` is `(i >> ((j % 4) * 8)) ^ j`, truncated
  to one byte. Each entry contains the value, a unique cell holding the same
  64 bytes, and a reference to one shared code cell containing byte `0x42`.
  This gives 600,000 unique cells. This fully specified fixture replaces the
  earlier uncommitted account probe; it does not claim byte identity with it.
* PQ genesis: the committed `test/pq-native/data/c04-pq-genesis.boc`, 396 cells.

After configuring a native build as described in `BUILD.md`:

```sh
cmake --build build --target test-download-state-budget test-state-download-recovery -j8
ctest --test-dir build --no-tests=error --output-on-failure -V -R '^state-spool-amplification$'
ctest --test-dir build --no-tests=error --output-on-failure -R '^(streaming-boc-cell-bounds|streaming-boc-valid-ondisk|test-state-download-recovery)$'
```

The standalone equivalent of the measurement command is:

```sh
build/test-download-state-budget --spool-amplification test/pq-native/data/c04-pq-genesis.boc
```

These measurements establish a regression envelope for these shapes, not a
universal maximum amplification for every valid DAG. The capacity arithmetic
does not constitute an end-to-end 16 GiB import test. The free-space gate is a
point-in-time check for the two spool files plus its documented margin; it
does not reserve filesystem blocks or account for the CellDb copy, compaction,
or unrelated concurrent writers.

## Local measurement receipt

Measured on 2026-10-15 using Apple Clang 21.0.0, Release, macOS 26.6.2 arm64,
starting from source commit `e863380a4edd66ef48cc494b7b50105e5ff9dc5f` plus
the measurement changes in this commit. This is local portability evidence;
Linux build/test and full static-analysis acceptance are separate gates.

| Shape | Unique cells | BoC bytes (mode 31) | Import spool bytes | Rollback bytes | Combined / BoC |
| --- | ---: | ---: | ---: | ---: | ---: |
| Library | 1,048,575 | 72,917,654 | 143,654,800 | 143,654,800 | 394.019% |
| Accounts | 600,000 | 38,637,739 | 85,246,967 | 85,246,967 | 441.263% |
| PQ genesis | 396 | 18,168 | 49,783 | 49,783 | 548.030% |

PQ genesis input SHA-256:
`4e833bf9650c48448969688b862abfd6ad31dd504aa9ab68757db683e47bb162`.

The committed fixtures and generators are the reproducibility source, rather
than a retained large generated BoC or database. The three measurement lines
above contain every byte total needed to recompute the reported ratios.

Measured source SHA-256 values (the 600% version):

| File | SHA-256 |
| --- | --- |
| `test/test-download-state-budget.cpp` | `331936b6c9920cb875b1e9c977485e40bc4ec1f08f62370354945bc9fc609edb` |
| `validator/state-download-buffer.h` | `c09ad4ca1f7c89e3f83ca015df7f34e124c3f9b71debad66253fa92d98ad2d8d` |
| `validator/db/celldb.cpp` | `e5e5fa7da88c9b4acf0a5a782884381e76a5b04adf24ea06460fba609db0e842` |

## Sensitivity control and validation boundaries

Temporarily changing only the default `spool_reservation_ratio_percent` from
600 back to 300, rebuilding `test-download-state-budget`, and rerunning the
standalone measurement command exited **1** at the intended assertion. The
bounded receipt, with the local absolute source prefix omitted, is:

```text
SPOOL shape=library cells=1048575 boc_mode=31 boc_bytes=72917654 spool_bytes=143654800 rollback_bytes=143654800 ratio_percent=394.019 reservation=218752962 default_ratio=300
FAIL test/test-download-state-budget.cpp:4190 expected true: combined_bytes <= reservation
```

The mutation was reverted before committing. This control demonstrates that
the new regression detects the old insufficient default, rather than merely
printing a measurement. To reproduce it, perform the same one-line default
change, rebuild and run the command above, then restore 600 and rebuild.

Local exit-status index:

| Boundary | Check | Exit |
| --- | --- | ---: |
| Serialization and default ceiling | `state-spool-amplification` | 0 |
| Budget lifetime and import bounds | `test-download-state-budget`, `streaming-boc-cell-bounds`, `streaming-boc-valid-ondisk` | 0 |
| CellDb import and restart | `test-celldb-streaming-import`, `test-celldb-actor-restart` | 0 |
| Download rejection, retry, cleanup and persistence | `test-state-download-recovery` (all three cases, including reopen) | 0 |
| CI registration | `check-ctest-inventory.py --build-dir build --expected-file scripts/strict-build-targeted-tests.txt` (15 expected tests) | 0 |
| Default-ceiling sensitivity | Same measurement command with the default temporarily 300 | 1 (expected) |
| Full differential static analysis | `scripts/static-analysis.py` with a clean `19473401a3085cebd4fa5a1dde4b69f299fe362b` checkout/build, LLVM 21.1.8 and CodeChecker 6.29.1 | 2 (unavailable) |

The static-analysis gate's ten positive controls all fired. Its project-wide
dependency scan then refused Linux-specific sources on macOS, starting with
`test/rldp2-decoder-heap-measure.cpp` including unavailable `malloc.h`; this is
not a passing analysis result. Separately, the unchanged
`test-inmemory-celldb-dec` crashed locally: its unconditional `pipe2` call uses
an interface absent from macOS 26.6.2 (`dlsym` confirmed the missing symbol).
That test and the full analysis gate require Linux validation. The first
sandboxed recovery attempt could not reserve a TCP port; the successful run
above used local sockets outside that sandbox.

After restoring the original 600% header (verified against the hash above),
the affected executables were rebuilt. The combined CTest selection of the
seven passing targets listed above then exited **0**: **7/7 passed**, 80.79 s
total, including all three recovery cases. The test translation unit also
passed a separate syntax check using its actual compilation command plus
`-Werror -fsyntax-only`. Changed C++ lines passed clang-format 21.1.8 and the
diff passed the whitespace check.
