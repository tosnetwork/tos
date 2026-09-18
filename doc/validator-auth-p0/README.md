# Validator authentication P0: wire/API profile v1

**Status: design frozen, v1 revision 5; not deployed or activated.**
This directory proposes the P0 contract missing from the signature inventory.
Merging a specification does not enable a verifier, change genesis, or satisfy
production P0 acceptance. The frozen decisions are authorized by the owner request to update and freeze
this design; they are not inferred from the experimental verifier.

Source boundary: `73fdaf5746e6b84cb0f71f11d67a0bf0e579e80a`.
Requirement boundary: [TIP-0002 revision 231570f4ae4511b5e42c6b8ce0fdb5576b2663d9](https://github.com/tosnetwork/TIP/blob/231570f4ae4511b5e42c6b8ce0fdb5576b2663d9/TIPS/tip-0002.md).
The [existing inventory](../tip-0002-p0-readiness.md) remains applicable; it is
regression evidence, not the production implementation of this profile.

## Frozen design decisions

| Boundary | Decision |
| --- | --- |
| Launch authority | C0 admits only `(suite=1, parameters=1)`, Pure Ed25519 with the exact WIRE.md rules. No production PQ algorithm is selected here. |
| Outer format | Typed bounded binary objects and one canonical signing statement; two component slots instead of a fixed outer 64-byte signature. |
| Native transport | Six new TL constructors; historical constructors retain their meaning. |
| Persistent proofs | A bounded canonical four-way byte tree, not an unbounded cell snake. |
| Identity | Authenticated stake identity independent of the current signing algorithm; immutable role/profile/epoch key versions. |
| Persistence | Append-only public versions and separately retained duty/capacity reservations; reserve-before-sign and commit-before-release. |
| Signer | Typed, fenced, idempotent service; no raw consensus-key signing or private-key export endpoint. |
| Activation | Proposed ConfigParam 46 and capability bit 10; policy selected from authenticated state at session birth, not local flags. |
| C1 | Separate diagnostic state; observations cannot rewrite C0 statements or change quorum. |
| C2/C3 | Same-signer AND in C2; approved PQ mandatory in C3; no timeout/recovery fallback to classical authority. |
| Clients | One profile/era contract across C++, Rust, RPC/SDK, archives, light clients and embedded bridge verifiers. |
| Performance | This proposal changes no production call; future C0 integration has explicit caching and measurement gates. |

Read [WIRE.md](WIRE.md), [LIFECYCLE.md](LIFECYCLE.md), [SIGNER.md](SIGNER.md),
[ACTIVATION.md](ACTIVATION.md), and [CLIENTS.md](CLIENTS.md).
[OPEN-DECISIONS.md](OPEN-DECISIONS.md) records the two P1 choices now resolved
in the frozen design. [API-CONTRACT.md](API-CONTRACT.md) fixes all signer/client
semantics. [canonical-schema.json](canonical-schema.json) is the sole ordered
binary encoding authority; WIRE.md carries a mechanically checked generated view.
[transport.schema.json](transport.schema.json) only validates the outer JSON shape.
`profile.json` fingerprints these schema and normative document artifacts. `wire.tl` and `wire.tlb` deliberately remain outside production schemas.

## Evidence and limits

The reference tests under `test/validator-auth-p0/` are specification oracles,
not a deployed signer or validator. Their coverage must be reported separately
from the production-entrypoint tests already provided by the inventory PR.
The SQL file is an executable reference storage contract; SQLite constraints and
reopen tests do not prove HSM fencing, power-loss durability or anti-rollback.
The focused native TL-B/BOC harness validates actual cells and maximum round trips;
it does not implement production state integration. Future-sized signature bytes
are container fixtures, not PQ cryptographic evidence.

## Freeze is distinct from implementation

The interface digest is SHA-256 of the exact committed `profile.json` bytes.
It is a release-artifact fingerprint, not JSON used as a signing statement.
Its artifact_sha256 map binds all normative documents and schemas except itself;
`contract_artifacts.py` checks exact bytes. Vectors bind the resulting profile digest,
so vectors are checked separately to avoid a fingerprint commitment cycle.
The [freeze record](../validator-auth-p0-freeze.json) binds the approved design
artifact hashes, vector hashes, implementation source boundary and owner
authorization. It does not claim independent protocol/security/client approvals
or ratification of a new TIP revision. Those release approvals and TIP publication
remain activation gates. Exact-head CI checks the record and allocation collisions.
An incompatible change to this frozen design requires version 2. Editorial or
implementation changes preserve the normative artifact commitment or undergo
explicit review; a fingerprint alone has no network authority.

P0 implementation requires the actual native/Rust codecs, services, state changes
and testnet gates in CLIENTS.md. C0 launch additionally requires approved genesis,
operator recovery and performance evidence. These are future acceptance gates,
not work claimed completed by this specification.

## Source constraints

`validator/consensus/simplex/pool.cpp::Tsentrizbirkom::check_invariants` permits
notarize plus skip, rejects finalize plus skip, and rejects notarize/finalize for
different candidates. The signer must preserve these distinctions in both orders.
`keyring/keyring.h` exposes untyped signing/export; a new service without closing
old consensus-key access would leave an authority bypass.
Ordinary block proofs sign bare `tos.blockId`; Simplex proofs use their session
wrapper. Neither historical preimage is normalized into the new format.
The current session ID already indirectly commits to the full committee.
The new explicit commitment additionally binds policy and key lifecycle.
Current support-advertisement checks can log and continue; this is not the
fail-closed profile admission required below. Only the dedicated profile workflow is extended; the full Ubuntu build remains manual.

## Primary references

- [Ed25519, RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html), including its verified errata.
- [Stateful signatures, RFC 8391](https://www.rfc-editor.org/rfc/rfc8391.html).
- [NIST SP 800-208](https://csrc.nist.gov/pubs/sp/800/208/final). Research implementations are not automatically approved profiles or compliant hardware.
