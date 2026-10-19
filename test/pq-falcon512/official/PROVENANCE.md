# Official original Falcon-512 known-answer tests

Source: https://falcon-sign.info/falcon-round3.zip, linked as the submission
package by https://falcon-sign.info/. Retrieved 2026-10-03.
Archive SHA-256: `d625407dbda9e5835f610aaeba1147e029988a6610e0107dfd292033138e1d47`.
Member: `falcon-round3/KAT/falcon512-KAT.rsp`.
Imported byte-for-byte, 1,250,115 bytes, 100 records (count 0 through 99).
File SHA-256: `dd75c946fdedef4ec46a2bee7e10c65c9126f1a839b9ced6921fd45f7354b5cd`.
File SHA-1: `a57400cbaee7109358859a56c735a3cf048a9da2`.
This SHA-1 is also the expected Falcon-512 KAT digest embedded in the official
`Falcon-impl-20211101/test_falcon.c`. SHA-1 is retained for upstream conformance;
SHA-256 identifies the imported artifact.

All seeds and secret keys are official published **PUBLIC TEST DATA**. They
must never be used for real accounts. The response file is required frozen
input, not TOS-generated run output. The submission supplies the implementation
under the MIT license; see `third-party/falcon-reference/LICENSE`.

`official_kat.py` verifies every original signed-message answer through the
explicit COMPRESSED reference API, rejects an altered message for every record,
and derives each public key from the corresponding published secret key. It
only extracts signed-message framing; it never pads or re-signs these answers.
The unmodified official `test_falcon.c` separately exercises SHAKE, codecs,
verification, RNG, floating-point/polynomials, samplers, signing, key generation
and external APIs. It regenerates all 100 Falcon-512 and 100 Falcon-1024 NIST
KAT records and requires the upstream expected digests. Missing/skipped KAT
markers fail the wrapper even if the executable returns zero.
`official_controls.py` compiles always-accept and always-reject verifier stubs
and a zero-exit suite with no tests. Each must fail a specific KAT assertion;
compiler errors, crashes or unrelated failures do not count. The real API
baseline must then pass. These controls are isolated from production sources.

The original NIST signed-message format is distinct from the TOS 666-byte
PADDED profile. Existing `vectors.json` remains the TOS-generated fixed-profile
and VM corpus, with its same-source API oracle explicitly identified. Official
answers provide an external known-answer baseline; the implementation executing
them is still the pinned upstream reference, not an independent audit or FIPS
206/FN-DSA certification.
