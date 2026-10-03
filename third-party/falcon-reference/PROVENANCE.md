# Falcon reference import

Source: https://falcon-sign.info/Falcon-impl-20211101.zip
Revision: Falcon-impl-20211101 (official release archive, no Git revision).
Archive SHA-256: d9f982bd825b9903b57b686d6d26018dac173a1dff09f224cc39302f9d85a595.
Imported files are byte-for-byte copies; SHA256SUMS records the import boundary.
License: MIT (see LICENSE and each source header).

The node and Rust VM compile only codec.c, common.c, shake.c, vrfy.c and the
TOS fixed-profile adapter. No falcon.c, keygen, sampler, FFT, fpr, RNG or signing
code enters the verifier target. The separate offline signer compiles the full
reference API with FALCON_FPEMU=1, FALCON_FPNATIVE=0, FALCON_AVX2=0,
FALCON_FMA=0, FALCON_PREFIX=tos_falcon_inner. No fast-math flags are allowed.
The 2021-11-01 archive includes the external SHAKE RNG initialization correction.
We explicitly seed from checked OS entropy, rather than use the upstream system
RNG adapter. Upstream maintenance and independent audit are not established by
this import. TOS maintainers own this experimental import; production requires
an assigned maintenance team and independent review.

Checked 2026-10-03: NIST still lists FIPS 206 as in development. This is original
Falcon, not FN-DSA or a FIPS certification. The unmaintained pqcrypto-falcon crate
is not used. Pre-standard FN-DSA libraries are not compatible substitutes.
