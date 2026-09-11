# ML-DSA-44 authentication module and native account E2E

## Scope and prerequisites

This is the integration layer above the account authentication root from PR #93
and the native C++ TVM primitive from PR #101. The baseline is main commit
`399484acdd960cf818c455503f33f2d9116d1909`. Neither account bytecode, the PQ verifier,
the opcode tariff nor network ConfigParam 8 is modified by this change. Execution
requires an independently approved activation of TVM v16. The separate Rust VM
is **not** an execution backend for this suite or a claimed part of this change.

The FunC and Tol sources are `crypto/smartcont/mldsa44-auth-module.{fc,tol}`.
They expose the same storage and message formats; their compiled code hashes
and addresses are different. Do not silently substitute one implementation for
the other in an account's registered root.

## Immutable authentication root

Storage is `global_id:int32 public_key:^Cell`. The public key is exactly 1,312
raw bytes in the canonical ordinary, level-zero byte-chain encoding defined by
`docs/tvm-mldsa44.md`: 127 bytes in each non-final cell, one continuation, no
trailing empty cell. The key is immutable: there is no administrator, classical
recovery key, SETCODE, SETDATA, or privileged external entry point. The module
has no nonce database. The existing account remains the authoritative keeper
of its own epoch and nonce, including failed action-phase semantics.

An immutable module may control multiple registered accounts with the same key.
Its StateInit does not include a target account, avoiding a circular dependency
between the module address and an account address whose initial state registers
that module. The signed request binds the exact target and network. Targets must
be canonical, same-workchain, non-anycast internal addresses, distinct from the
module. Rotation deploys a new immutable module and uses the current account's
`AUTH_CONFIGURE` flow; it never mutates the old verifier.

## Wire format and exact signed bytes

A **funded internal** request has body:

```text
submit#4d4c4434 query_id:uint64 envelope:^Cell signature:^Cell

AUTH envelope (unchanged from #93):
  auth#41555448 request:^Cell cosignature:(Maybe ^Cell)

request:
  global_id:int32 account:MsgAddressInt epoch:uint64 nonce:uint64
  valid_until:uint32 kind:uint8 payload:^Cell
```

The ML-DSA signature is a canonical 2,420-byte chain. No public key can be
provided or overridden by the message; the verifier uses its stored key.

Let `D` be the hash of a cell containing the 64-bit big-endian ASCII tag
`TOS-AUTH` and one reference to `request` (the existing `auth_request_hash`).
The signed message is **the 32 raw, big-endian bytes of D**, not its textual hex,
not its BOC serialization, and not the bare hash of `request`.

Use FIPS 204 **Pure ML-DSA-44** with the exact, case-sensitive, 21-byte context
`TOS-AUTH-ML-DSA-44-v1`. This is an application commitment used as the Pure
ML-DSA message, **not** the FIPS HashML-DSA interface or external-mu interface.
The chain verifies using the public `PQCHECKSIG_MLDSA44` binding. The test-only
signer formats `0x00 || context_length || context` for the internal signing API
and verifies its output using the external API before returning it.

The relayer query ID, relayer address and attached funding are transport data,
not spending authority, and are deliberately not covered by D. Changing them
cannot change the authenticated target, payload, epoch, nonce, kind or expiry.
An Ed25519 cosignature is not covered by the PQ signature: in hybrid mode the
account independently requires Ed25519 over **the same D**. It is an AND rule.
Omission, substitution and request mixing are tested at the account hop.

The module checks its configured network against GLOBALID, the request network,
canonical target, exact envelope/request consumption, cosignature shape, kind
0..2 and `now < valid_until <= now + 3600`. It then verifies the PQ signature.
Epoch/nonce are signed but checked against live state by the destination account.
Accounts may apply additional payload/policy restrictions and expiration checks.

## Funding, replay and asynchronous failure

No external message is accepted (exit 1900). The module never calls ACCEPT or
raises its internal-message gas limit. The caller must fund PQ verification,
forwarding and the destination transaction. The test config's gas prices and
limits are unchanged; changing its version to 16 does not activate any network.

After successful verification, RAWRESERVE preserves the old balance after
storage charges, and SENDRAWMSG mode **64** forwards the incoming remainder.
There is no fee-from-reserve +1, ignore-error +2, destruction +32 or whole-balance
+128 flag. The action-phase source is the module address, and the exact AUTH
body is forwarded to the signed destination. Tests pass the actual emitted
message to the account emulator without reconstructing its source or body.

Unknown/empty internal messages are deposits only; bounced messages are ignored.
A replay may be verified and forwarded again at the relayer's expense, but the
account rejects the stale nonce and must not transfer assets twice. No module
counter can get out of sync when the second transaction fails. A successfully
forwarded message is **not** evidence that the account executed its payload.
Inspect both transaction/action results and the account's final counters.

The module is not a custodial refund service. A bounced account relay or a direct
top-up can leave coins in the immutable module's reserve, with no withdrawal
method. Do not send unnecessary funds; model storage and bounce costs. Existing
account purge/redeployment caveats still apply. Use PQ-from-genesis account state
where needed, and keep accounts/modules funded for storage.

## Reproducible build and tests

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target func fift tol emulator -j2
# Explicitly separate test build; signing is never linked into node/VM targets.
cmake -S test/mldsa-auth -B build-auth-signer -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-auth-signer -j2
python3 -m pip install cryptography==46.0.4
python3 test/mldsa-auth/e2e.py --build build \
  --signer build-auth-signer/test-mldsa44-sign --out auth-results
python3 test/mldsa-auth/mutations.py --build build \
  --signer build-auth-signer/test-mldsa44-sign --out auth-mutations
```

To compile the deployable BOCs without the test signer, run
`python3 test/mldsa-auth/build_contracts.py --build build --out auth-contracts`.
`contracts.json` records the actual code hashes and BOC file digests. No account
SDK embeddings are regenerated or changed.

The signer uses the already vendored/pinned mldsa-native v2.0.0, commit
`834a90d5e846ffa1e1611bd24e160bb2e9b86d35`. Its two fixed seeds and Ed25519 keys
are **PUBLIC TEST DATA, NEVER PRODUCTION KEYS**. No private production material,
random-number source, signing API or new provider is added to the consensus VM.

The suite runs both module languages against Wallet V5 FunC, Wallet V5 Tol and
Agent Account, on workchains -1 and 0. It checks real valid/invalid signatures,
wrong keys/context, malformed proof chains, all request commitments, actual
relay provenance, replay, signed wrong nonce/epoch, expiration between hops,
hybrid AND, authenticated rotation, forbidden downgrade, staged migration,
funding, bounced messages, pre-v16 rejection and preservation of module state.
The fixtures begin as funded active accounts at their StateInit-derived addresses;
this is not a claim of a production deployment or a full-node network trial.

`gas.json` records actual per-hop gas, the total computation gas and observed
relay funding for each pair. It is not a new tariff, a gas estimate pretending
to be a measurement, or production-hardware/network-load calibration.
`e2e.json` includes exit/action results, final data hashes and emitted-message
hashes, including rejection paths. Cross-architecture CI compares these files
and all five compiled BOCs byte-for-byte; no wall-clock timings enter consensus.

Two compiling verifier-removal mutations (one per language) must be killed by
executed assertions. Compile errors, crashes and missing reports are not kills;
restored positive baselines must pass. The existing #93 and #101 workflows remain
separate regression gates. A green integration workflow is not an independent
security audit, NIST certification, whole-chain quantum resistance or approval
to activate v16. Review the final commit's actual CI, not an older green run.

Reference: FIPS 204, https://csrc.nist.gov/pubs/fips/204/final .
