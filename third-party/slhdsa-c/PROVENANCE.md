# SLH-DSA (FIPS 205) import — EXPERIMENT

Source: https://github.com/pq-code-package/slhdsa-c
Revision: `174c02e42257f95c210963272877c49dbb50070f`.
License: ISC (see LICENSE; upstream also offers Apache-2.0 and MIT).
Imported files are byte-for-byte copies; SHA256SUMS records the import boundary.

Imported: slh_dsa.c, slh_sha2.c, sha2_256.c, sha2_512.c and the headers they include. The
SHAKE parameter sets, SHA-3, prehash (HashSLH-DSA) and the upstream test tree are not imported.

The node compiles these files into a verify-only target. The TOS adapter
(`crypto/pq/slhdsa128s.cpp`) exposes exactly one profile: Pure SLH-DSA-SHA2-128s
verification with an explicit context. It does not expose signing, key generation, RNG or any
other parameter set. The other SHA2 parameter tables are still compiled, because they sit in
the same upstream file; the final object-symbol audit required by the rescue design is not done
yet.

This import is a prototype for the wallet rescue design. Conformance (NIST ACVP), independent
interoperability (OpenSSL 3.5) and the symbol audit are release gates, not claims made here.
