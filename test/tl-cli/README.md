# One TL schema input

Both Rust generation entry points read `tl/generate/scheme/{lite_api,tos_api,toslib_api}.tl`
through `tl_codegen::input`. Run Cargo from the repository or any member directory;
the complete repository layout is required. The JSON file under the Rust API's `tl/`
directory remains generator policy. There is no schema override or private fallback.

The native generator already uses this directory (upstream implementation
`857b8a57a178e6ae0fe7fa86e7d81c5233de8560`, `tl/generate/CMakeLists.txt`). The separate
upstream Rust implementation (`60298de36047b21b5cdaed7e4998aa6d579f661d`,
its API build script and generator grammar) keeps its own schemas
and lacks grouped single-type parsing. This integration preserves that generator's
strategy, adds the minimal grammar needed by the main schema, and removes obsolete
Rust-only protocols. The authoritative schema files themselves do not change.

The 18 existing binary `.tl` response fixtures are not schema copies. Their exact
paths and hashes are in `binary-fixtures.json`; the source guard refuses text or
symlinks masquerading as those fixtures. Existing historical evidence is unchanged.

## Reproduce the checks

Native commands run in `tos-builder-local:24`, with a four-CPU, 10-GiB memory/swap
cap and the checkout plus its Git metadata mounted. No service or external endpoint
is needed. Use two build jobs, and keep at least 200 GiB free on the host filesystem.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21
cmake --build build --parallel 2 --target test-tl-cli-fixtures
build/test-tl-cli-fixtures > build/tl-fixtures.tsv
cmp test/tl-cli/fixtures.tsv build/tl-fixtures.tsv
build/test-tl-cli-fixtures --verify test/tl-cli/fixtures.tsv
# The nested workspace owns a separate lockfile; the outer build cannot validate it.
for manifest in tosctl/src/tl/Cargo.toml tosctl/src/tl/api/Cargo.toml tosctl/src/tl/codegen/Cargo.toml; do
  cargo metadata --manifest-path "$manifest" --format-version 1 --locked > /dev/null
done
cargo test --manifest-path tosctl/src/tl/Cargo.toml --workspace --all-targets --locked
cargo test --manifest-path tosctl/src/Cargo.toml -p tl_codegen --lib --locked
TL_CLI_REVERSE_OUTPUT="$PWD/build/tl-reverse.tsv" cargo test \
  --manifest-path tosctl/src/Cargo.toml -p tl_api --test cli_wire_parity --locked
build/test-tl-cli-fixtures --verify build/tl-reverse.tsv
cargo test --manifest-path tosctl/src/Cargo.toml -p control-client --lib \
  production_request_serializers_match_cpp_and_have_complete_coverage --locked
TOKIO_WORKER_THREADS=2 cargo test --manifest-path tosctl/src/Cargo.toml -p adnl \
  --test test_overlay safe_overlay_broadcast_refuses_without_sending_and_fast_delivers \
  --locked -- --exact
python3 scripts/check-tl-single-source.py . --self-test
ctest --test-dir build -L source-guard --output-on-failure --no-tests=error
python3 scripts/check-classical-carrier-sites.py .
python3 test/pq-native/test_classical_carrier_inventory.py
```

The branch CI runs the standalone workspace commands separately from the outer
workspace checks. With Rust 1.97.1 and dependencies cached, all three metadata
entry points pass at base `3071c6746707e555523af6d2ad1b4efa2fb2c040`, fail with
exit 101 at `32e1446526097fe5e2998b64cef22fb33ad370e2`, and pass after synchronizing
the nested lockfile. Restoring that head's lockfile also makes the complete new
CI step fail at metadata resolution; restoring the fix makes it pass, including
all four codegen tests and six API tests. Local macOS runs require GNU `date`
on `PATH`, as the inherited build scripts use its epoch syntax.

The 98 frozen byte sequences are produced by `fixtures.cpp`, not by Rust or by a
handwritten byte encoder. Native generated classes and store/fetch utilities cover
all 31 control/lite request adapters, their control envelopes, changed records,
optional fields and byte-string boundaries. The JSON-only public API record uses
its generated native ID/fields and native primitive TL codecs. `values.rs` supplies
independent typed expected fields. The Rust test checks those fields and full
consumption rather than `TLObject` equality, which compares only constructor IDs.
The native verifier checks Rust's reverse encoding against native parsing and
serialization of the expected values.

Run the mutation controls in an otherwise idle disposable checkout. They restore
each source before leaving, rebuild, and require a specific semantic failure:

```sh
python3 test/tl-cli/check_controls.py --checkout . --target-dir target \
  --native-tool build/test-tl-cli-fixtures --output-dir build/tl-controls
```

When native tools run in a persistent builder, add `--container CONTAINER`; the
checkout and output directory must be mounted at the same absolute paths. The
runner covers parser grouping, canonical input refusal, stale module removal,
same-width field swaps, retired constructor registration, production serializers,
request coverage, Safe routing, native field/full-consumption/completeness checks
and the input-size limit. Native damaged/missing/duplicate fixtures are separate
negative controls. The loopback overlay test executes both refusal and Fast
positive delivery; the inherited skipped propagation leg is not evidence.

The verifier reads at most 1 MiB plus one probe byte before parsing, even if its
input grows concurrently. Its case/name maps have a fixed 98-entry ceiling;
unknown and duplicate names are refused. Parsed lines are at most the bounded
input, with an additional 32-KiB format limit. All buffers/maps and the one input
file descriptor are scoped to one process invocation; there are no background
threads, sockets or retained node state in the native producer/verifier.

Docker builds now need repository-root context:
`docker build -f tosctl/src/Dockerfile .` (or `Dockerfile.nodectl`). This change
only supplies the required inputs. Recipe-specific ignore files retain the old
exclusion of build outputs and local configuration under the new root context.
Those inherited recipes still name unavailable
`node`/`console` binaries or the obsolete `nodectl` package. They are not verified
release targets. Repairing or retiring them needs a separate packaging decision.

The implementation report and bounded raw receipts are retained in the operator
workspace's `tos-testnet-deploy/tl-unify/` directory through at least 2026-11-22.
`fixtures-index.json` identifies the native producer, inputs and frozen bytes;
the final result index records exact-head checks and any environmental failures.
