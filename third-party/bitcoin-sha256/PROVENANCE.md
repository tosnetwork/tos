# Hardware SHA-256 transform import

Source: https://github.com/bitcoin/bitcoin
Revision: `a773e1e33b349dc819b5a0edc1c7a4839dc73b48` (the x86-64 transform file last changed in
`bdb8eadcdc193f398ebad83911d3297b5257e721`, the ARMv8 one in
`86718e4589682529932050dc08998fbb7bd86cef`).
License: MIT (see COPYING).
Imported files are byte-for-byte copies; SHA256SUMS records the import boundary. Each file's Git
blob id equals the upstream blob id at the revision above.

| Imported file | Upstream path |
|---|---|
| `sha256_x86_shani.cpp` | `src/crypto/sha256_x86_shani.cpp` |
| `sha256_arm_shani.cpp` | `src/crypto/sha256_arm_shani.cpp` (includes only standard headers and `<arm_neon.h>`) |
| `attributes.h` | `src/attributes.h` (the only non-standard include of `sha256_x86_shani.cpp`; defines `ALWAYS_INLINE`) |
| `COPYING` | `COPYING` |

Why: the SLH-DSA verifier spends nearly all of its time in SHA-256 compressions. Its hardware
paths use these widely deployed transforms unchanged rather than local implementations.

How `sha256_x86_shani.cpp` is built: only when `TOS_SLHDSA_SHA_NI` is on (Linux x86-64 by
default), exactly as upstream builds it: C++17, definitions `ENABLE_SSE41` and
`ENABLE_X86_SHANI`, and the per-file
flags `-msse4.1 -msse4 -msha`, with this directory on the include path so `<attributes.h>`
resolves to the copy here. No other file is compiled with those flags.
`crypto/pq/slhdsa-sha256-shani.cpp` converts the SLH state layout (chaining value as big-endian
words) to the host-order words `sha256_x86_shani::Transform` takes and calls it for one block.
`crypto/pq/slhdsa-sha256.c` calls it only after CPUID reports SSSE3, SSE4.1, SSE4.2 and SHA,
and otherwise uses the imported portable compression of `third-party/slhdsa-c`.
`sha256d64_x86_shani::Transform_2way` in the same file is compiled but not called.

How `sha256_arm_shani.cpp` is built: only when `TOS_SLHDSA_ARMV8_SHA2` is on (Linux aarch64 by
default), exactly as upstream builds it: C++17, definition `ENABLE_ARM_SHANI`, and the per-file
flag `-march=armv8-a+crypto`. No other file is compiled with that flag, so the rest of the
binary keeps the baseline of its build and still starts on a CPU without the extension.
`crypto/pq/slhdsa-sha256-armv8.cpp` converts the SLH state layout (chaining value as big-endian
words) to the host-order words `sha256_arm_shani::Transform` takes and calls it for one block.
`crypto/pq/slhdsa-sha256.c` calls it only after the kernel reports every extension `+crypto`
enables (`getauxval(AT_HWCAP)` carries `HWCAP_AES`, `HWCAP_PMULL`, `HWCAP_SHA1` and
`HWCAP_SHA2`), and otherwise uses the imported portable compression of
`third-party/slhdsa-c`.
`sha256d64_arm_shani::Transform_2way` in the same file is compiled but not called.

Verification: on either architecture `test-pq-slhdsa-sha256-backend` compares the result
against the unmodified `third-party/slhdsa-c/sha2_256.c`, and the signature vectors run through
the production archive.
