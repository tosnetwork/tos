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

Raw logs and generated link commands are retained at
`/Users/tomisetsu/validation/pr328-ci-link-20261027/` until this repair is accepted.
`results.json` there contains file sizes and SHA-256 values. Its current digest is
`5069a07bcd24e3ec302381ffc6c1fb6b4bbcaaa83aac9e98682b969db228d5cc`.
No raw build output is committed. CMake generation is not a native runtime test;
Linux ASAN results must be checked on the pushed repair head.
