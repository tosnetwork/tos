# JSON-RPC transport test link closure

The Linux Clang 21 network-safety ASAN build at `7c9b2629cf0017bc519ce2904f0107ba8fbc1fc8`
failed before running tests: GNU ld could not resolve the BlockHandleImpl constructor
and ApplyBlock vtable requested by the validator factory archive.

The transport executable now links the existing `validator-common` OBJECT library
directly. That library owns `validator/apply-block.cpp` and `validator/block-handle.cpp`.
The production validator and sibling test targets already use this pattern. No
production source, test selection, sanitizer option or workflow is changed.

## Author self-check

- UP: this is locally added JSON-RPC test wiring; sibling factory tests provide the
  established linkage pattern.
- AP/BC: the changed consumer is only `test-json-rpc-transport`. Both missing providers
  belong to `validator-common`; its production objects precede the static archives.
- TE: the original Linux job is an actual failed link, not an ASAN runtime finding.
  Generated baseline linkage omits both providers; fixed linkage includes both before
  `libtos_validator.a`. Both configurations completed with Debug/ASAN enabled on macOS.
- RS: no new runtime state, queue, cache, actor, thread or descriptor. Only the test's
  existing production objects are linked directly.
- DC: this record distinguishes dependency inspection from executed sanitizer tests.
  The current repaired commit still requires homogeneous Linux ASAN CI and non-author
  review. No merge approval is claimed.

## Retained evidence

Raw logs and generated link commands are retained under
`${HOME}/validation/pr328-ci-link-20261027/` until this repair is accepted.
The adjacent JSON index records their sizes/hashes, the repaired implementation
commit and CMake blob identity, and the exact configuration/generation commands.
From a clean checkout of that implementation commit, choose a fresh build directory:

```sh
TASK_LINK_BUILD="${HOME}/validation/transport-link-reproduction"
cmake -S . -B "$TASK_LINK_BUILD" -G Ninja \
  -DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
  -DCMAKE_BUILD_TYPE=Debug -DTOS_USE_ASAN=ON
ninja -C "$TASK_LINK_BUILD" -t commands test-json-rpc-transport
```

Repeat from the recorded parent in another clean directory for the negative
comparison: the original final link omits both common provider objects; the
repair includes them before the static archives. No raw build output is committed.
CMake generation is not a native runtime test; Linux ASAN results must be checked
on the pushed repair head.
