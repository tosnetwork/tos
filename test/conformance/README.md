# Conformance vectors

Shared, versioned test vectors that pin the observable behaviour of the C++ node, in the style of a
multi-client conformance suite: a fixture is an input context plus the effects the C++ reference produced
for it. The same fixtures check

- the C++ node itself: a change that alters any effect fails `ctest -L conformance` until the fixtures are
  regenerated in the same change, so every consensus-visible change shows up as a fixture diff in review;
- any other implementation that exposes the same harness boundary (a Rust node, the `tosctl` VM).

Expected effects come only from running the C++ reference. Hand-written expectations are not fixtures;
authored assertions may be checked against the C++ fill before it is frozen, but they never replace it.

## Layout

```
CMakeLists.txt                    reference library (every ref/*.cpp but the CLI) and the core ctests
parts/<component>.cmake           further targets and tests, one file per component
schema/fixture-v1.schema.json     fixture envelope; schema/common-v1.schema.json shared value types
schema/harness/<h>-v1.schema.json context and effects of harness <h>
ref/common.{h,cpp}                registry, JSON, BOC and stack helpers, the C entry points
ref/harness-<h>.cpp               one harness, registered with CONFORMANCE_REGISTER_HARNESS
ref/conformance-ref-cli.cpp       line-oriented wrapper around the library
runner/conformance.py             create / run / regenerate / validate
runner/harnesses/<h>.py           validator of harness <h>, discovered by name
runner/test_*.py                  runner tests, including controls that make each check fail
migrate/                          converters from older per-family formats, chain replay
vectors/<h>/fixtures/<family>.jsonl and optional <family>.blobs.json
```

Adding a harness is three new files with the same name: `ref/harness-<h>.cpp`,
`runner/harnesses/<h>.py` and `schema/harness/<h>-v1.schema.json`; a runner test fails when the schema and
the validator disagree.

## Harness boundary

Each harness `H` has a C entry point `conformance_H_v1(context_json) -> effects_json` in
`libconformance-ref`, and the CLI `conformance-ref-cli H` reads one context JSON per line on stdin and
writes one effects JSON per line on stdout, in order. Another implementation joins by providing a program
with the same command line and line protocol. A line `{"harness_error": "..."}` means the context was
refused before execution (malformed input, unsupported value); the runner counts it separately and never
treats it as equal to anything.

| Harness | Context | Effects | C++ behind it |
|---|---|---|---|
| `vm` | code, optional c4 data, optional c7, initial stack, global version, flags, gas limit/max/credit, library collections | exit code, gas used, steps, committed flag, committed c4/c5 hashes, final stack | `vm::VmState` |
| `txn` | config, original ShardAccount, inbound message or tick/tock, now, lt, rand seed, libraries, previous blocks | `accepted` with transaction, account and ShardAccount hashes; `rejected` with the VM exit code; `error` | `transaction_emulator_*` (libemulator) |

The `vm` final stack is a list, bottom first, of canonical item texts: `null`, decimal integers, `NaN`,
`cell:<hash>`, `slice:<cell hash>:<bit from>-<bit to>:<ref from>-<ref to>`,
`builder:<bits>:<refs>:<hash>`, `cont:<type>[:nargs=..:save=..:stack=[..]]` and `(...)` for tuples — the
form of `test/rescue-fee-gate/vm-endstate.cpp`. A continuation's code is not part of the effect.

A `txn` error carries no message in its effect: two implementations may word an error differently, so only
the outcome class is compared.

## Fixtures

One JSON object per line, `{"metadata": ..., "context": ..., "effects": ...}`. `metadata.reference_commit`
is the commit of the C++ build that filled the effects (from the binary's own git metadata, refused when the
tree had uncommitted changes); `metadata.source` says where the context came from (`authored`, `fuzz`,
`replay`, or `migrated:<old family>`). Fixture ids are unique within a family.

Any BOC field may be a reference `{"blob": "<sha256 of the BOC bytes>"}` into `<family>.blobs.json`
(`{"<sha256>": "<base64>"}`). `create` moves every BOC longer than `--blob-threshold` characters (default
2048) there, so configurations and large accounts are stored once per family. The runner inlines references
before a context reaches a target; `validate` requires every reference to resolve, every blob to be used and
every digest to match its content.

## External vectors

Most fixtures live in a separate repository, pinned by commit in `VECTORS`; the tree keeps a small seed set
(`vectors/`) so the gate also runs without it. To run everything:

```
test/conformance/fetch-vectors.sh ../conformance-vectors        # clone and check out the pinned commit
cmake -S . -B build -DCONFORMANCE_VECTORS_DIR=$PWD/../conformance-vectors
ctest --test-dir build -L '^conformance$'
```

`conformance-vectors-pin` requires the checkout to be at the pinned commit, without local changes, with
`MANIFEST.json` listing exactly the files present (`runner/vectors_pin.py check`). Without
`CONFORMANCE_VECTORS_DIR`, `conformance-vectors-external` is reported as skipped. Updating vectors: change
them in the vectors repository, run `runner/vectors_pin.py manifest <checkout>`, commit there, and update
`VECTORS` in the same node change. Select the default lane with `-L '^conformance$'`; other lanes have their
own labels.

## Commands

```
# fill effects from the C++ reference for a file of contexts
python3 test/conformance/runner/conformance.py create --reference build/test/conformance/conformance-ref-cli \
    --harness vm --family vm-endstate --source migrated:rescue-fee-gate/vm-endstate contexts.jsonl out.jsonl

# compare a target with the frozen effects (exit 0 only when every fixture compared equal)
python3 test/conformance/runner/conformance.py run --target build/test/conformance/conformance-ref-cli \
    test/conformance/vectors

# refill every fixture with a new C++ build and list the fixtures whose effects changed
python3 test/conformance/runner/conformance.py regenerate --reference build/test/conformance/conformance-ref-cli \
    test/conformance/vectors

# schema, uniqueness and provenance checks
python3 test/conformance/runner/conformance.py validate test/conformance/vectors
```

`run` prints `compared N, equal N, mismatched M, refused R, skipped S` and fails on any mismatch, refusal or
skip. Families of a harness the target does not list in `--info` are skipped, which also fails.

## Changing behaviour on purpose

When a C++ change is meant to alter an effect, run `regenerate` in the same change and commit the updated
fixtures. The list it prints is the behaviour-change report for review; any entry the change did not intend
is a regression.

## Families

| Harness | Family | Fixtures | Context source |
|---|---|---|---|
| `vm` | `vm-endstate` | 128 | `test/rescue-fee-gate/vm_endstate_scenarios.py`, migrated by `migrate/vm_endstate.py`; filled effects equal `test-vm-endstate` output and `vm-endstate-expected.tsv` row for row |

## Chain replay

`migrate/rel02.py chain <test-epoch-replay> <target> test/rel02/corpus` exports every transaction of the
REL-02 corpus as a `txn` context (576: 172 ordinary, 202 tick, 202 tock) and requires the target to reproduce
each on-chain transaction hash and new account hash. The chain is the oracle, so these contexts are not
frozen as fixtures: the corpus already in the tree is the input, and history recorded on the network has to
keep replaying after any change. ctest runs it against the reference as `conformance-rel02-chain`.

