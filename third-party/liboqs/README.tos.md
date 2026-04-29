# TOS vendored liboqs

This directory is a vendored copy of Open Quantum Safe `liboqs` for
`uno_workchain` ML-KEM-768 production builds.

- Upstream: https://github.com/open-quantum-safe/liboqs.git
- Pinned commit: `3cb781fd4737c900ad755ee0bb9e1949d0f68955`
- TOS version notes: `uno/crypto/LIBOQS_VERSION.md`

TOS only uses ML-KEM-768 from this tree. The parent build configures liboqs
with `OQS_BUILD_ONLY_LIB=ON` and `OQS_MINIMAL_BUILD=KEM_ml_kem_768` when no
system `liboqs` is explicitly provided.

