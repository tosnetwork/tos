# BR1 A1: native boundary and quote authentication

Status: **engineering increment, not the completed production chain adapter**.
Stack base: PR #379 at `771a0bfd411407dec7480967d8c548f449596a51`.
No main merge, code/policy approval, Shield activation or deployment is requested.

## Delivered and deliberately not delivered

`native_adapter.py` connects the existing durable engine to a private, pinned
native-process protocol. `native_process.py` implements its actual process I/O,
identity binding, byte ceilings, deadlines and child cleanup. The wallet crate's
`relayer_quote` module signs and verifies exact quote terms with real ML-DSA-44.
The tests distinguish real process/SQLite/cryptographic execution from fabricated
chain answers.

**There is no native chain/signer/finality provider implementing this protocol in
A1.** An executable that merely echoes these JSON fields is not that provider.
Neither `tos-proof-verify` nor a manual wallet broadcaster implements this new
protocol automatically. Service startup must fail when a required capability is
missing. A provider that claims a capability without doing the verification
violates the trusted computing base; the Python wrapper cannot make its claims
cryptographically true.

A2 remains required: authenticated current Bond/pool state acquisition, full exact
Shield simulation, production custody, durable funding-wallet sequence leases,
funded internal-message construction, exact native acceptance encoding, safe
submission, destination finality and fee-note import. Do not register an unreviewed
provider to get past the startup gate. Test-only signer/transport implementations
are not deployment options.

## Invocation and trust contract

An operator pins the canonical absolute ELF path and its SHA-256 in private local
configuration. The binary must be a regular single-link file, owned by root or the
invoker, executable and not group/other-writable. It is copied into a sealed memfd
while hashing; execution uses that immutable snapshot rather than resolving the
original path again. Each invocation owns a duplicate of the snapshot descriptor,
so closing the program cannot recycle an in-flight executable descriptor.

Arguments are exactly `--stdio OPERATION`. There is no shell, executable search,
HTTP-selected command, inherited secret environment or manual-broadcast fallback.
The private state directory is owned by the invoker. Each request contains:

```json
{"schema":"tos.br1.native.request.v1","nonce":"random-128-bit-hex","operation":"preflight","payload":{}}
```

The actual payload contains the complete locally pinned `Release`, plus the exact
operation inputs. Responses have exactly `schema`, `request_sha256`, `status`, and
`result`. The schema is `tos.br1.native.reply.v1`, the hash is SHA-256 of the entire
request byte sequence, and status is `ok` or `refused`. JSON duplicate members,
nonfinite numbers, schema drift and unrelated invocations refuse. A transport or
verification error is never an execution receipt. `result: null` means unavailable
finality only where the operation explicitly permits it.

A future provider's `capabilities` must bind the release scope and protocol
`tos.br1.native.v1`, with all of:

- `live_bond_v1`, `shield_exact_simulation_v1`, `worker_mldsa44_v1`;
- `funded_wallet_v1`, `wallet_sequence_lease_v1`, `destination_finality_v1`;
- `fee_note_import_v1`, `quote_descriptor_v1`.

Capability negotiation is an availability check, **not an audit or proof**.

| Operation | Required native obligation and wrapper binding |
| --- | --- |
| `preflight` | Authenticate exact code/config/network/canonical actor identity, approved policy, active status, live backing and fresh pinned pool state. Authenticate the quote; decrypt only the worker fee output and verify the complete exact Shield transaction. Return positive bounded funding and full checkpoint identity. |
| `prepare` | Use the journal-assigned slot/time and reserved funding. Durably lease the funding-wallet sequence across crashes/processes. Produce actual ML-DSA acceptance and a funded wallet message. **Never broadcast or otherwise publish bearer material.** |
| `validate_prepared` | Independently decode and verify persisted signatures/messages, exact request, slot, issue time, reserved spend, wallet identity/sequence, TVM message hash, serialized message hash and acceptance hash. Historical byte inspection must not fail solely because the request has since expired. |
| `recheck` | Re-authenticate current eligibility, live balance, pool state and wallet lease immediately before writing. Issue a native one-use permit bound to the exact bytes. Python also limits permits to two and five seconds and consumes one before a write attempt. |
| `broadcast` | Consume the native permit and submit only the exact prepared bytes. A return is transport acknowledgement, not execution. Exceptions leave UNKNOWN and never cause automatic re-signing or retransmission. |
| `evidence` | Authenticate exact destination execution or terminal refusal, not merely a source send, RPC success, majority assertion or spent nullifier. Successful evidence includes the assigned output commitment/slot/index, amount, leaf, pool transaction and checkpoint. Verify and import the worker note only after this proof. |
| `descriptor` / `sign_quote` / `verify_quote` | Derive the pool-specific receiving descriptor at the durably allocated index. Validate all exact terms before signing. Pin the immutable worker's SHA-256 public-key identity and verify the ML-DSA context. |

The provider must independently recompute TVM representation hashes. The local
`body_sha256` and `message_sha256` are serialized-byte integrity digests, not TVM
hashes. A terminal refusal must prove the attempt cannot still execute; a timeout
or source-wallet success cannot release input locks. The fee import and provider
recovery must be idempotent across a crash between native verification/import and
the journal's terminal write.

## Quote bytes and separation

Python `relay_core.encode` supplies sorted-key ASCII JSON with no NaN/Infinity.
A1's Rust primitive authenticates those exact nonempty bytes, at most 16 KiB,
under `TOS-BR1-QUOTE-v1`. It does not parse JSON or decide chain eligibility.
The native caller must enforce canonical terms and the complete B1 field schema.
The public key is 1,312 bytes and the signature is 2,420 bytes. The quote identity
remains `SHA256("TOS-BR1-QUOTE\0" || canonical_terms)`, as in the existing journal.
This is distinct from the on-chain Bond acceptance context and Shield spend
context; quote revisions are not acceptance equivocation.

The module accepts an already-custodied private key and performs no seed loading.
Production key custody integration is still open. Only test sources contain the
public disposable test seeds.

## Resource and lifecycle inventory

| Owned resource | Limit and cleanup |
| --- | --- |
| Native executable snapshot | 128 MiB; one sealed memfd per program, read in 64-KiB chunks; original FD closes on all paths; snapshot explicitly closes after workers finish. |
| Calls and descriptors | Two in-flight invocations; a third is refused before spawning. Each call owns its executable duplicate, three pipes, selector and one direct child. |
| Input / output | 2 MiB request, 2 MiB stdout, 16 KiB stderr; excess aborts, and native stderr is not reflected to public callers. |
| Deadline | One monotonic 1–60 second budget (default 15) for I/O and completion, not a new timeout for each read. |
| Child lifetime | New process group; terminate the group before reaping the direct leader, including on a successful exit with residual children. This is not a sandbox for a malicious executable that deliberately detaches. |
| Permits | Two entries with a five-second monotonic expiry; consume before possible write, even when acknowledgement is lost. |
| Evidence | Exact identity/type checks followed by the existing journal's 16-KiB persisted evidence ceiling and fee-credit binding. |

The native provider's heap, libraries, network acquisition limits and custody
storage are separate review obligations. Process I/O bounds do not bound its RSS.
System libraries remain in the host trust boundary. This increment does not claim
anonymity, a funded live network, post-quantum Groth16 soundness, or Energy support.

## Reproduction and acceptance

```sh
python3 -m unittest discover -s test/bonded-relayer -p test_native_boundary.py -v
python3 test/bonded-relayer/delivery_controls.py --lane adapter --out build/br1-adapter-controls.json
scripts/install-rust-toolchain.sh
cargo test --locked --manifest-path tools/shielded-pool-wallet/Cargo.toml
python3 test/bonded-relayer/delivery_controls.py --lane rust --out build/br1-quote-controls.json
```

The Python suite requires a C compiler and Linux memfd/proc support; missing tools
are failures, not skips. It executes an explicitly test-only C process for OS
behavior. Adapter response fixtures fabricate signatures and chain results and
prove only bindings/state transitions. The Rust tests execute genuine ML-DSA.
Controls mutate the actual guard in a disposable source copy, require its named
assertion failure, restore it and rerun; compilation failures do not kill mutants.
Exact local evidence is in `doc/evidence/br1-delivery/`. Independent non-author
review, native provider integration and all prior production gates remain open.
