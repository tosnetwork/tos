# Experimental balance-kernel vectors

`balance-kernel-v1.txt` freezes one SEND and COLLECT with k=1 through 8.
Each line contains the relation kind, explicit numerical policy, authenticated
context bytes, public points, receipt IDs, Sigma commitments, shared-witness
responses and aggregated range proof. The Rust generator uses public test seeds;
never use these keys or randomness for funds.

Rust regenerates and compares every byte; the C++ test independently reads the
same file and calls the real C ABI. These are kernel regression vectors, not a
production transaction format or evidence of host authentication of the context.
An intentional transcript or layout change requires reviewing and versioning the
affected vectors, not silently regenerating them to make a test pass.

The three `.tag` files contain annotated Git tag objects. Their object hashes and
target revisions are checked by `tests/kernel-gates.py`; they do not assert signed
release provenance. See `../SUPPLY_CHAIN.md` for the source verification policy.

The previous circuit/VK diagnostic belongs to the retired V0 implementation and
is no longer an active verifier gate. Its historical evidence remains in Git.
