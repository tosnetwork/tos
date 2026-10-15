# Python type checking

`uv sync --locked`, `uv run test/tostester/generate_tl.py`, then
`uv run basedpyright` check the complete `test/integration` and `test/tostester`
scope. The same commands run in the independent **Python types** workflow and
in the manual native validation workflow. No diagnostic baseline or source
exclusion is used.

Type, argument, override, assignment and nullability errors are blocking. The
repository retains gradual-typing warnings, including unknown/dynamic values,
as visible advisory diagnostics (`failOnWarnings = false`). The cell codec's
deferred, mutually recursive imports are also advisory; importing the public
facade and running the codec tests exercise those runtime edges. This policy
does not claim that the Python tree is fully annotated or warning-free.

The repair models heterogeneous headers and keyword bundles explicitly,
represents missing proof fields as optional, narrows required fields before
use, and describes dynamic script/module loading at its actual boundary.
Serialization methods differ between TL-B schemes, so only class-level
`deserialize` is part of their common abstract interface. Concrete serializers
retain their own checked signatures. Runtime-supplied blueprint code is passed
explicitly to its constructor rather than assigned to a class constant.

Runtime corrections include an integer hash for complete block identities,
address-kind checks, explicit refusal of unknown/unboxed-without-arguments TL
schemas, and a bounded iterable path for cell bits. Crypto helpers use the
already-installed PyNaCl/PyCryptodome dependencies. The signing harness reads
SDK cells and supplies a provider rather than constructing a view with `None`.
These changes do not add a node RPC or a production signing/deployment path.

## Validation boundaries

- `test/tostester/tests/tostester/test_python_type_boundaries.py` proves that a
  valid assignment passes the configured checker and an incompatible assignment
  exits nonzero with `reportAssignmentType`.
- The same file exercises cell-copy/iterable limits, signed bits, schema refusal,
  required fields, address kinds, full-ID hashing, installed crypto dependencies,
  and SDK signing-view state reads without a network call.
- Seven guard-removal controls individually fail their intended tests and restore
  the exact source bytes before the test file passes again. Their raw receipts
  are retained outside Git at
  `/Users/tomisetsu/.codex/artifacts/tos-python-types-20261015/` through
  2026-11-14; `controls.json` identifies each test and restored source hash.
- Local macOS runs cannot exercise the Linux `/proc` process-identity receipt.
  The unmodified complete Python suite remains required in the Linux chain
  workflow; local runs explicitly deselect that one Linux-only case rather than
  changing its source or treating it as passed.
- Changed Python files must pass Ruff lint and formatting. Codec files receive a
  separate formatting commit so semantic fixes can be reviewed independently.

The original native C++ analysis, ASan and chain receipts apply to their exact
source commit. New Python workflow results must be checked at the repair commit;
passing local checks are not a statement about pending CI or deployment.
