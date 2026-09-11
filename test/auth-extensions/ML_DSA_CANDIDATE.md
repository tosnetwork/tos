# ML-DSA-44 candidate validation — off-chain only

This adds real FIPS 204 ML-DSA-44 signing/verification to the authentication
**test infrastructure**, not to the TOS VM or deployed account contracts.
Passing the suite does **not** establish on-chain ML-DSA support.

## Why this first candidate

Ethereum's PQ team names Falcon, Dilithium and SPHINCS+ as execution-layer
candidates; it has not selected a single mandatory wallet algorithm.
EIP-8051 proposes ML-DSA verification and is still Draft. ML-DSA-44 is a
useful first interoperability target because it is standardized in FIPS 204,
has an independent OpenSSL implementation, and has concrete Ethereum
execution-layer proposal work. This is not a probability claim about which
algorithm Ethereum will ultimately adopt.

The suite uses **Pure ML-DSA-44 over the 32-byte TOS-AUTH cell commitment**,
with context `TOS-AUTH-ML-DSA-44-v1`. The context is a test profile only.
It is not HashML-DSA, pre-standard Dilithium2, ML-DSA-ETH, or leanXMSS.
The 1312-byte public key and 2420-byte signature are transported through
ordinary cells without assuming either fits into one cell or a 512-bit slot.
The byte-chain encoding is a test container, not an assigned module wire ABI.

## Executed tests and their scope

Run from the repository root with Python 3.10+ and OpenSSL 3.5+:

```sh
python3 test/auth-extensions/test_ml_dsa_candidate.py
PQ_FIXTURE_OUTPUT=/tmp/ml-dsa-fixture.json \
  python3 test/auth-extensions/test_ml_dsa_candidate.py
```

`OPENSSL_PATH` may select an alternative OpenSSL executable. Missing provider
support is an error, never a successful skip. The CI job uses Debian trixie's
OpenSSL and prints the exact runtime version. No Python package is required.

The seven groups cover real signing/verification and deterministic test keys;
network/account/workchain/epoch/nonce/expiration/kind/payload binding; the
TOS-AUTH domain and ML-DSA context; wrong keys and corrupt signatures; host
fixture length checks; large-key/signature BOC round trips and malformed byte
chains; and alteration of deeply referenced payload bytes. Negative results
are distinguished from OpenSSL setup/provider errors. A positive verification
control must pass first.

These are OpenSSL-backed candidate/serialization tests, not independent NIST
ACVP conformance validation. They demonstrate cryptographic binding, not that
a contract enforces counters, expiration or authority transitions. All fixed
seeds are public test values. The optional fixture contains no private key.

## Review of PR #93 at fefb5b5b3f036636b185a50cc4b9173b6c9aa4b1

The replaceable-root direction is consistent with cryptographic agility.
The reviewed account-level paths bind the module sender, actual account,
network, epoch, nonce, expiration, request kind and payload. Strict modes
block legacy account entry points; hybrid checks the same request with AND
semantics. These are necessary account-layer controls, not evidence of a
particular PQ verifier's correctness.

`test-module.fc` explicitly implements an Ed25519 fixture. Its real relay test
is valuable provenance coverage, but cannot be relabeled as a PQ test.
No direct legacy-authority bypass was established in this review; this is not
an audited security certification or a full independent native rerun.

The following remain release gates for an **on-chain ML-DSA support** claim:

1. Implement verification inside TVM-executed module code, or implement and
   review a separately activated VM primitive. Host verification followed by
   an Ed25519 relay, fabricated sender, boolean, or accept-all module is not
   an acceptable replacement. A native primitive would expand PR #93's scope.
2. Deploy the real module and each account implementation. Submit the raw PQ
   proof to the module; deliver exactly the outbound message emitted by its
   action phase; assert the final account action and state transitions.
3. Reject invalid PQ signatures, malformed/noncanonical encodings, wrong keys,
   cross-network/account replays, stale epochs/nonces, expired requests and
   mixed hybrid approvals. Remove the real verifier call as a mutation and
   require a previously rejected proof to make the test fail.
4. Use actual target-network configurations (including workchain 0), normal
   gas limits, cell-depth/message-size limits and real funding. Measure module
   and account gas separately. Check insufficient funds, failed action phase,
   bounced messages, replay/retry semantics and nonce consistency. The
   account-side internal-message interface alone does not prove a large PQ
   verifier fits the VM's transaction gas limit.
5. Run public known-answer vectors and a second implementation against the
   on-chain verifier. Pin the exact standard, parameter set, context, key and
   signature encoding. Algorithm names alone are not interoperability.
6. Audit immutable module code and every upgrade/recovery authority. Account
   sender-address checks do not pin a module's current code. Demonstrate safe
   root rotation and lifecycle behavior; use PQ-from-genesis initialization
   when a legacy StateInit could otherwise regain control after deletion.

Existing authentication CI and Rust sandbox CI must continue to pass. This
supplement does not alter account bytecode, VM opcodes, network cryptography,
gas settings or the security claim of PR #93.

## Primary references

- https://pq.ethereum.org/ (execution-layer candidates and cryptographic agility)
- https://eips.ethereum.org/EIPS/eip-8051 (Draft)
- https://csrc.nist.gov/pubs/fips/204/final
- https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/
