# ML-DSA-44 authentication module and native account E2E

## Scope and prerequisites

This integrates the account authentication root from PR #93 with the native C++
TVM primitive from PR #101. The baseline is main commit
`399484acdd960cf818c455503f33f2d9116d1909`. Account bytecode, the PQ verifier,
the opcode tariff and network ConfigParam 8 are unchanged. Execution requires
an independently approved activation of TVM v16. The separate Rust VM is not an
execution backend for this suite or a claimed part of this change.

The FunC and Tol sources are `crypto/smartcont/mldsa44-auth-module.{fc,tol}`.
They expose the same storage and message formats but compile to different code
hashes and addresses. Do not substitute implementations at a registered root.

## Immutable authentication root

Storage is `global_id:int32 public_key:^Cell`. The public key is exactly 1,312
raw bytes in the canonical ordinary, level-zero byte-chain encoding defined by
`docs/tvm-mldsa44.md`: 127 bytes per non-final cell, one continuation, no trailing
empty cell. There is no administrator, classical recovery key, SETCODE, SETDATA
or privileged external entry point. The module has no nonce database. The
account remains authoritative for its own epoch and nonce, including committed
refusal and action-phase semantics.

A module may control multiple registered accounts sharing a key. Its StateInit
does not include a target account, avoiding a circular dependency between the
module address and a PQ-from-genesis account that registers that module. Each
signed request binds the exact target and network. Targets must be canonical,
same-workchain, non-anycast internal addresses, distinct from the module.
Rotation deploys a new immutable module and uses authenticated account root
rotation; it never mutates the old verifier.

## Wire format and exact signed bytes

A funded internal request has body:

```text
submit#4d4c4434 query_id:uint64 envelope:^Cell signature:^Cell

AUTH envelope (unchanged from #93):
  auth#41555448 request:^Cell cosignature:(Maybe ^Cell)

request:
  global_id:int32 account:MsgAddressInt epoch:uint64 nonce:uint64
  valid_until:uint32 kind:uint8 payload:^Cell
```

The signature is a canonical 2,420-byte chain. The request cannot supply or
replace the stored public key.

Let D be the hash of a cell containing the 64-bit big-endian ASCII tag TOS-AUTH
and a reference to request (the existing `auth_request_hash`). The signed
message is the 32 raw, big-endian bytes of D: not its textual hex, its BOC or the
bare hash of request. Use FIPS 204 Pure ML-DSA-44 with the exact 21-byte context
`TOS-AUTH-ML-DSA-44-v1`. This is an application commitment used as the Pure
message, not HashML-DSA or external-mu. The module calls the public
`PQCHECKSIG_MLDSA44` binding. The test signer formats the prefix
`0x00 || context_length || context` for internal signing, then checks the result
with the external verifier API before returning it.

The relayer query ID, relayer address and attached funding are transport data,
not authority. They cannot alter the signed target, payload, epoch, nonce, kind
or expiry. The PQ signature does not cover the Ed25519 cosignature: hybrid mode
independently requires Ed25519 over the same D. Missing, wrong and mixed-request
cosignatures are rejected at the account hop. It is an AND rule.

The module checks its stored network against GLOBALID, the request network,
canonical target, exact envelope/request consumption, cosignature shape, kind
0..2 and `now < valid_until <= now + 3600`. Epoch and nonce are authenticated but
checked against live account state at the destination. Accounts also enforce
their own payload, policy and expiry constraints.

## Funding, replay and asynchronous failure

External requests are rejected with exit 1900. The module does not call ACCEPT
or increase its internal-message gas limit. The caller funds verification,
forwarding and account execution. Normal tests keep fixture gas prices and
limits unchanged. Setting the emulator config version to 16 does not activate
any network. One explicitly marked destination-only limit injection tests the
Agent's committed-refusal semantics; it is not production calibration.

After verification, RAWRESERVE preserves the pre-message balance after storage
charges. SENDRAWMSG mode 64 forwards the incoming remainder. There is no +1
fee-from-reserve, +2 ignore-error, +32 destruction or +128 send-all flag. Tests
deliver the exact message produced by the module action phase, not a message
reconstructed with a fabricated sender. Destination logical time is advanced
past the actual outgoing message LT.

Unknown/empty internal messages are deposits; bounced messages are ignored.
Replaying a request can pay for verification and forwarding again, but the
account must reject the consumed nonce and must not transfer assets twice. No
module counter drifts when the asynchronous second transaction rejects.
Successful forwarding is not evidence of successful account execution: inspect
both transaction/action outcomes and final counters.

This immutable module is not a refund custodian. Bounced relay value and direct
top-ups may remain locked in its reserve; there is no withdrawal method. Avoid
unnecessary funds and account for storage and bounce costs. Existing account
purge/redeployment caveats still apply. Use PQ-from-genesis account state where
required and maintain storage balances.

## Build and native validation

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target func fift tol emulator -j2
cmake -S test/mldsa-auth -B build-auth-signer -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-auth-signer -j2
python3 -m pip install cryptography==46.0.4
python3 test/mldsa-auth/test_protocol.py
python3 test/mldsa-auth/e2e.py --build build \
  --signer build-auth-signer/test-mldsa44-sign --out auth-results
python3 test/mldsa-auth/mutations.py --build build \
  --signer build-auth-signer/test-mldsa44-sign --out auth-mutations
```

`build_contracts.py --build build --out auth-contracts` produces deployable BOCs
and `contracts.json` code-hash/file-digest records without account SDK embedding
changes. The separate test-only signer uses the already vendored mldsa-native
v2.0.0 pin `834a90d5e846ffa1e1611bd24e160bb2e9b86d35`. Its fixed seeds and the
Ed25519 fixtures are PUBLIC TEST DATA, NEVER PRODUCTION KEYS. No signing or RNG
API is linked into the node or consensus verifier.

The suite covers both module languages, Wallet V5 FunC/Tol and Agent Account,
workchains -1 and 0, real valid/invalid signatures, key/context errors, malformed
proofs, every request commitment, relay provenance, replay/nonce/epoch/expiry,
hybrid AND, authenticated rotation, no downgrade, staged migration, insufficient
funding, bounces, external rejection and pre-v16 rejection. It also tests account
policy and an Agent post-accept committed refusal: no asset transfer, counters
consumed, replay rejected. This destination-only failure injection is tagged
`limit_injection: true` and is not a normal gas calibration sample.

Fixtures start as funded active accounts at StateInit-derived addresses. This
is not a production deployment or full-node network trial. `gas.json` records
actual per-hop gas, total computation gas and relay funding; it is not a new
tariff or a production-hardware/load benchmark. `e2e.json` records exits, action
results, persistent-data hashes and emitted-message hashes. CI compares these
records and five compiled BOCs byte-for-byte across x86_64 and AArch64.

Two verifier-removal mutations, one per language, must compile and be killed by
executed assertions; crashes, compilation errors and missing reports do not
count. Restored baselines must pass. The existing #93/#101 workflows remain
separate regression gates. Judge the final commit's actual CI, not an older green
run. A passing suite is not an independent audit, NIST certification, whole-chain
quantum resistance or approval to activate v16.

Reference: FIPS 204, https://csrc.nist.gov/pubs/fips/204/final .
