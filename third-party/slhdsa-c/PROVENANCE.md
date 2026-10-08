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

Build policy: the imported C target keeps conversion warnings visible but does not
promote them to errors (`-Wno-error=conversion`, private to `tos_slhdsa_native`).
The backend's integer-to-byte packing predates this integration. The TOS C++
adapter and all other targets retain the repository's strict warning policy;
no imported source bytes or SHA256SUMS entries are changed by this build setting.
This exception does not establish conformance or discharge the release audit.

The reviewed local conversion diagnostics cover endian byte stores/16-bit loads,
parameter-derived digest lengths and indices, and MGF counters. For the adapter's
fixed 128s profile (`h=63`, `hp=9`, `m=30`), digest index lengths are 7 and 2 bytes;
the leaf input fits uint32 and the MGF counter is bounded by the fixed digest size.
These observations explain the scoped warning policy; they are not a general
approval of other parameter sets or unbounded caller-supplied parameters.
