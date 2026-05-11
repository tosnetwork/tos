# Third-Party Notices

This repository is licensed under the **GNU General Public License v3.0**
(see `LICENSE`). It bundles the following third-party components, each
distributed under its own license. The terms below are reproduced for
attribution and notice purposes per the requirements of those licenses;
they do not relicense the upstream code, and the original copyright
holders retain their rights.

For each component listed here we ship the upstream `LICENSE` (or
equivalent) text in-tree under the component's directory.

---

## Foundational acknowledgments

TOS is built on top of foundational open-source blockchain work originally
developed by Telegram, EverX, Erigon, and RSquad Blockchain Lab. The Uno
workchain additionally builds on Polygon's Plonky3 toolkit, NIST PQC
finalists (ML-KEM-768), and the Zcash Orchard specification family. This
repository continues that line of work as its own system while explicitly
acknowledging those prior technical foundations.

---

## `third-party/silkworm/`

- **Project:** Silkworm — Ethereum execution layer in C++
- **Upstream:** https://github.com/erigontech/silkworm
- **Vendored at commit:** `aeb2302` (May 2025)
- **License:** Apache License 2.0 (see `third-party/silkworm/LICENSE`)
- **Copyright:** © The Silkworm Authors

**Modifications by TOS Blockchain Teams** (each tagged with a
`Modifications copyright …` header in the affected file, see
`git log -- third-party/silkworm/` for the full diff):

- `core/chain/config.{cpp,hpp}` — added `osaka_time` field, `is_osaka()`
  helper, JSON in/out, `EVMC_OSAKA` revision dispatch.
- `core/protocol/validation.{cpp,hpp}` — added EIP-7825 per-tx gas cap
  check + `kTxGasLimitExceeded` enum value.
- `core/execution/precompile.{cpp,hpp}` — wired EIP-2537 BLS12-381
  precompiles (0x0b–0x11) onto evmone's `bls.cpp`; added EIP-7951 P-256
  verify precompile at 0x100 via OpenSSL libcrypto; added EIP-7823 1024
  B per-parameter MODEXP input cap; updated EIP-7883 Osaka MODEXP gas
  formula to drop the `/3` divisor (matching go-ethereum + spec
  fixtures). Added `find_precompile()` helper to dispatch out-of-table
  precompiles (P-256 lives at 0x100, beyond the contiguous table).
- `core/execution/evm.cpp` — added EIP-7702 tx-entry delegation
  resolution so the outer call frame redirects to the delegate's code
  while keeping the authority's storage/balance context.
- `core/CMakeLists.txt` — link `OpenSSL::Crypto` for the P-256 precompile.

## `third-party/evmone/`

- **Project:** evmone — fast Ethereum Virtual Machine implementation in C++
- **Upstream:** https://github.com/ethereum/evmone
- **License:** Apache License 2.0 (see `third-party/evmone/LICENSE`)
- **Copyright:** © The evmone Authors

**Modifications by TOS Blockchain Teams** (tagged via per-file
`Modifications copyright …` headers; see
`git log -- third-party/evmone/` for the full diff):

- `lib/evmone/instructions_opcodes.hpp` — added `OP_CLZ = 0x1e`
  (EIP-7939, Fusaka).
- `lib/evmone/instructions.hpp` — implementation of `clz()` over a
  4-word uint256, returning 256 for input 0.
- `lib/evmone/instructions_xmacro.hpp` — registered `OP_CLZ` in the
  X-macro dispatch.
- `lib/evmone/instructions_traits.hpp` — gas cost (5) and traits entry
  for `OP_CLZ` at `EVMC_OSAKA`.

## `jvm/avata/src/softfloat/berkeley/`

- **Project:** Berkeley SoftFloat Release 3e — software IEEE-754
  floating-point arithmetic
- **Upstream:** https://www.jhauser.us/arithmetic/SoftFloat.html
- **License:** BSD-style 3-clause license (see
  `jvm/avata/src/softfloat/berkeley/COPYING.txt`)
- **Copyright:** © 2011-2017 The Regents of the University of California

**Modifications by TOS Blockchain Teams:**

- `platform.h` — constrained the build to Avata's little-endian GCC/Clang
  consensus profile.
- `jvm/avata/src/softfloat/tos_softfloat_fmod.c` — derived from SoftFloat
  f32/f64 remainder logic and changed quotient selection to Java `%`
  semantics (round quotient toward zero).

## Other vendored dependencies (unmodified)

The components below are distributed under their respective licenses
without TOS-side modifications; the upstream LICENSE/COPYING file in
each directory governs the terms. Nothing about including them in this
GPL-3.0 distribution alters their original licensing.

| Path | Project | License |
|------|---------|---------|
| `third-party/abseil-cpp/` | Abseil C++ Common Libraries | Apache-2.0 |
| `third-party/blst/` | blst (BLS12-381 signatures) | Apache-2.0 |
| `third-party/libff/` | libff (alt_bn128 pairing) | MIT |
| `third-party/lz4/` | LZ4 compression | BSD-2 / GPL-2 (per-file) |
| `third-party/ngtcp2/` | ngtcp2 (QUIC) | MIT |
| `third-party/openssl/` | OpenSSL (libcrypto) | Apache-2.0 |
| `third-party/rocksdb/` | RocksDB | Apache-2.0 / dual GPL-2 |
| `third-party/secp256k1/` | libsecp256k1 | MIT |
| `third-party/sodium/` | libsodium | ISC |
| `third-party/wingetopt/` | wingetopt | BSD-3 |

---

## License compatibility notice

This work is distributed under **GPL-3.0**, which the FSF lists as
compatible with Apache-2.0 in the direction we use here (Apache-2.0
code included in a GPL-3.0 work; the combined work is GPL-3.0).
Apache-2.0 §4(a) requires us to ship a copy of the License with
distributed Apache-2.0 components, which we do under each component's
directory; Apache-2.0 §4(b) requires modified files to carry prominent
notices stating that we changed them, which we do via per-file
`Modifications copyright …` headers added in the same commit as the
substantive change.

If you spot an attribution gap, please open an issue.
