# Build-wiring removed-domain scan controls

Base: `tos@00e3bf507`. Scope: explicit approved build paths and exact root CMake option text; no retired-symbol or EVM rule is relaxed. These are manual controls, not recurring mutation CI.

The unmodified guard failed on the existing three-state build wiring. Baseline:

```text
.github/workflows/build-tos-linux-arm64-appimage.yml:56: Uno outside approved engine paths:         # Release artifacts do not need the isolated UNO crypto test crate.
.github/workflows/build-tos-linux-arm64-appimage.yml:57: Uno outside approved engine paths:         TOS_UNO_CRYPTO_PROTOTYPE_TESTS: 'OFF'
.github/workflows/build-tos-linux-arm64-shared.yml:69: Uno outside approved engine paths:         # aarch64 UNO crypto gates have not yet been measured on CI.
.github/workflows/build-tos-linux-arm64-shared.yml:70: Uno outside approved engine paths:         TOS_UNO_CRYPTO_PROTOTYPE_TESTS: 'OFF'
.github/workflows/build-tos-linux-x86-64-appimage.yml:54: Uno outside approved engine paths:         # Release artifacts do not need the isolated UNO crypto test crate.
.github/workflows/build-tos-linux-x86-64-appimage.yml:55: Uno outside approved engine paths:         TOS_UNO_CRYPTO_PROTOTYPE_TESTS: 'OFF'
CMakeLists.txt:537: Uno outside approved engine paths: # AUTO enables the isolated UNO crypto checks when their pinned native toolchain
CMakeLists.txt:539: Uno outside approved engine paths: get_property(_tos_uno_crypto_tests_cache_type CACHE TOS_UNO_CRYPTO_PROTOTYPE_TESTS PROPERTY TYPE)
CMakeLists.txt:540: Uno outside approved engine paths: if (_tos_uno_crypto_tests_cache_type STREQUAL "BOOL")
CMakeLists.txt:542: Uno outside approved engine paths:     set(_tos_uno_crypto_tests_legacy_value ON)
CMakeLists.txt:544: Uno outside approved engine paths:     set(_tos_uno_crypto_tests_legacy_value OFF)
CMakeLists.txt:546: Uno outside approved engine paths:   set(TOS_UNO_CRYPTO_PROTOTYPE_TESTS "${_tos_uno_crypto_tests_legacy_value}" CACHE STRING
CMakeLists.txt:547: Uno outside approved engine paths:       "UNO crypto tests: AUTO, ON, or OFF" FORCE)
CMakeLists.txt:548: Uno outside approved engine paths: elseif (NOT _tos_uno_crypto_tests_cache_type)
CMakeLists.txt:549: Uno outside approved engine paths:   set(TOS_UNO_CRYPTO_PROTOTYPE_TESTS "AUTO" CACHE STRING "UNO crypto tests: AUTO, ON, or OFF")
CMakeLists.txt:552: Uno outside approved engine paths:       "UNO crypto tests: AUTO, ON, or OFF")
CMakeLists.txt:555: Uno outside approved engine paths: unset(_tos_uno_crypto_tests_cache_type)
CMakeLists.txt:556: Uno outside approved engine paths: unset(_tos_uno_crypto_tests_legacy_value)
assembly/native/build-ubuntu-appimages.sh:45: Uno outside approved engine paths: if [ -n "${TOS_UNO_CRYPTO_PROTOTYPE_TESTS+x}" ]; then
assembly/native/build-ubuntu-appimages.sh:46: Uno outside approved engine paths:   case "${TOS_UNO_CRYPTO_PROTOTYPE_TESTS}" in
assembly/native/build-ubuntu-appimages.sh:49: Uno outside approved engine paths:       echo "TOS_UNO_CRYPTO_PROTOTYPE_TESTS must be AUTO, ON, or OFF"
assembly/native/build-ubuntu-appimages.sh:53: Uno outside approved engine paths:   CMAKE_EXTRA_ARGS+=("-DTOS_UNO_CRYPTO_PROTOTYPE_TESTS=${TOS_UNO_CRYPTO_PROTOTYPE_TESTS}")
assembly/native/build-ubuntu-portable.sh:48: Uno outside approved engine paths: if [ -n "${TOS_UNO_CRYPTO_PROTOTYPE_TESTS+x}" ]; then
assembly/native/build-ubuntu-portable.sh:49: Uno outside approved engine paths:   case "${TOS_UNO_CRYPTO_PROTOTYPE_TESTS}" in
assembly/native/build-ubuntu-portable.sh:52: Uno outside approved engine paths:       echo "TOS_UNO_CRYPTO_PROTOTYPE_TESTS must be AUTO, ON, or OFF"
assembly/native/build-ubuntu-portable.sh:56: Uno outside approved engine paths:   CMAKE_EXTRA_ARGS+=("-DTOS_UNO_CRYPTO_PROTOTYPE_TESTS=${TOS_UNO_CRYPTO_PROTOTYPE_TESTS}")
removed-execution-domain scan failed
```

Each control inserts one comment in a tracked file, runs the full repository scan, removes the comment and verifies that the file's SHA256 is restored. No build or code execution is used as a substitute for the scan.

## outside_uno

Path: `crypto/block/block.cpp`. Injection: `// guard-negative-control: uno`. Exit: 1.

```text
crypto/block/block.cpp:1: Uno outside approved engine paths: // guard-negative-control: uno
removed-execution-domain scan failed
```

## approved_retired

Path: `.github/workflows/build-tos-linux-arm64-shared.yml`. Injection: `# guard-negative-control: Halo2`. Exit: 1.

```text
.github/workflows/build-tos-linux-arm64-shared.yml:1: retired implementation symbol: Halo2: # guard-negative-control: Halo2
removed-execution-domain scan failed
```

## wordlist_other_symbol

Path: `sdk/js/packages/crypto/src/mnemonic/wordlist.ts`. Injection: `// guard-negative-control: Halo2`. Exit: 1.

```text
sdk/js/packages/crypto/src/mnemonic/wordlist.ts:1: retired implementation symbol: Halo2: // guard-negative-control: Halo2
removed-execution-domain scan failed
```

## nonwordlist_lowercase

Path: `crypto/block/block.cpp`. Injection: `// guard-negative-control: orchard`. Exit: 1.

```text
crypto/block/block.cpp:1: retired implementation symbol: orchard: // guard-negative-control: orchard
removed-execution-domain scan failed
```

## root_build_unapproved

Path: `CMakeLists.txt`. Injection: `# guard-negative-control: uno_unapproved_build`. Exit: 1.

```text
CMakeLists.txt:1: Uno outside approved engine paths: # guard-negative-control: uno_unapproved_build
removed-execution-domain scan failed
```

## approved_evm

Path: `.github/workflows/build-tos-linux-arm64-shared.yml`. Exit: 1.

This record uses JSON character escaping so the global textual domain scan
remains unchanged. Decode the strings to recover the exact injection and output.
The staged-file scan caught the original literal in this evidence document;
no documentation exception was added to bypass that check.

```json
{"injection":"# guard-negative-control: e\u0076m","output":".github/workflows/build-tos-linux-arm64-shared.yml:1: removed execution domain: # guard-negative-control: e\u0076m\nremoved-execution-domain scan failed\n"}
```

## Restoration

The first restoration scan, before this artifact was tracked, counted 5240 text
files. The final scan with this artifact staged passed with 5241. All four
injected files are unchanged against the base commit; their restored hashes
are recorded below.

```text
removed-execution-domain scan passed: 5241 text files, 378 binary files and 0 directories skipped
5fd33603ecab13f33b343a20599ca08ef5bf70fde140c19f5fad3e3eb57a0aa0  scripts/check-no-removed-execution-domains.sh
dfb6837c85b128887800eda9a97f9a8e4e8cd16e1bda72215354f080aaaee1a3  crypto/block/block.cpp
caf742746289d4cecab390b1c1439dd66ace4e93fb0fc1c412cc59a5d8d6574e  .github/workflows/build-tos-linux-arm64-shared.yml
0a99d64366fabca3071774f3395354a01b2e4fcdb5908d68fc837129a5b4dc16  sdk/js/packages/crypto/src/mnemonic/wordlist.ts
efc19d5dd84c00d74bc6d9834687e2985defcb352d44635b8ea92e6f0b083964  CMakeLists.txt
```

Only the guard changes. The added paths are the two additional native build scripts and three release workflows using the approved crypto-test switch. Root CMake admits two exact helper identifiers and four exact help/comment lines, not a file-wide exception. The existing path-and-word mnemonic/dependency exceptions, retired-symbol scan and EVM scan remain active even in newly approved paths.
