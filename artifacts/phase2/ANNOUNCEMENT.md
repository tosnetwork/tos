# Phase-2 ceremony 2 — open participation

This announcement opens registration. The fixed parameters below are published
before the first contribution. Contributions may begin only after the public
announcement snapshot and server-assigned publication receipt are available.

## Fixed parameters

| Field | Value |
|---|---|
| Code revision participants build | `49ef58c0ab98f62b76ae3c61a510980dae131235` |
| Circuit | 18,107 constraints, 19 instance variables, QAP domain 2^15 |
| Phase-1 slice SHA-256 | `1bfd7acdb3ecbfaaa695ab159a7a643a2eb58203a4d93361040c6bd4c2aa3d6e` |
| Starting key SHA-256 | `018853105392e4e0ef82ae59514f137b1f1a19892023b70b72ef58941b017c04` |
| Opening transcript | `7dcfafe1626b5586d5713654c55cc0887590fd789c391ecf1e28bfaf93e66287` |
| Contributions close | Bitcoin height **970141** |
| Beacon | Bitcoin block **970285** |
| Beacon encoding | 64 lowercase ASCII hex characters of the block hash, no newline |
| Beacon witnesses | blockstream.info and mempool.space; independent full nodes may also verify |

Both heights were confirmed by the operator on 2026-09-22. Verify that neither
has been reached before publication. The 144-block gap is a schedule, not a
cryptographic guarantee of unpredictability. Tools do not enforce this timing.
Do not extend the deadline or change the beacon after opening. At close,
publish the ordered contribution digests and pre-beacon transcript with the
observed chain height and hash, before the beacon becomes known.

## Open participation

Anyone may register and contribute during the announced window. The complete
participant list is **not** fixed before opening. `roster.json` is an append-only
public register of names, affiliations, independence declarations, public
signing keys and public identity evidence. Register a participant before their
contribution is accepted, and publish the register revision and SHA-256 with
each accepted contribution. Do not remove or rewrite accepted identities or
keys; retain prior revisions so earlier signatures remain attributable.

Existing and **newly generated signing keys are accepted**, with no minimum
age. Publish the public key under the contributor's account and verify each
attestation against the registered key. A signature proves control of that
key, not actual independence or secret destruction.

The first registered contributor is **tosman**, GitHub account
https://github.com/gtosnetwork-dotcom. The new Ed25519 public key was published
in commit `f5a45898fa810f1bea5bbcaf4f0803be0b2bfb4b`. Its fingerprint is
`SHA256:vKF/wb8PUVfv4CorGJcKJl4sHgNygoenLQnP4OIFhJQ`. Execution is delegated
to an agent on the operator's machine and is declared **not independent**.
This is a valid operator contribution; it does not add an independent party.

No outside verifier needs to be selected before opening. Anyone may verify
at any time. Independent participation and outside verification remain final
acceptance conditions, not barriers to the first contribution. Until those
conditions and final beacon verification are met, do not deploy the parameters.

## Contribution and verification

Build from the pinned code revision. The contribution scalar is generated
inside the Rust contributor using the operating-system random source and is
wiped by the implementation; no scalar file is produced. This does not prove
that operating-system memory, swap or machine snapshots contained no copies.
The signing key is separate and must be retained for identity/signatures.

Publish each accepted contribution, its signed attestation, register revision,
and digests as it is accepted. Later participants extend the published chain.
Use `phase2-verify` for the mathematics and
`test/shielded-pool/verify-attestations.py --in-progress` with the ceremony and
register paths for signature checks while open. The final check omits
`--in-progress` and requires a verified contribution declared independent of
the operator. The declaration itself needs human review.

See [PARTICIPANT-GUIDE.md](PARTICIPANT-GUIDE.md) and the
[operator runbook](../../doc/shielded-pool-phase2-runbook.md).

## Publication record

- Public announcement snapshot: https://github.com/tosnetwork/tos/releases/tag/shielded-pool-phase2-announcement-v2
- The release carries this announcement as an attached file and points to the
  announcement commit. Keep its original asset and commit for verification.
- GitHub assigns the publication timestamp. `publication-receipt.json` records
  the API response after publication and before opening; it is not a timestamp
  claimed by the contributor or a locally chosen commit date.
- Observed at 2026-09-22T10:30:21Z: both blockstream.info and mempool.space
  returned Bitcoin height **968132**, hash
  `00000000000000000001a163a4ef5a112108071bd3de134946d2bbc0422c7668`.
- Initial register revision: `49ef58c0ab98f62b76ae3c61a510980dae131235`.
- Initial register SHA-256: `abc6532e7aeaade754babd485d943f161093ed3921b4730a24cc69ea3190ebc7`.

The public GitHub release is the third-party-hosted announcement snapshot;
no separate archive.org capture is claimed. Release metadata is retained in
the publication receipt. Hosting records can be changed by their owner;
independent observers may retain additional copies. Later registration is
allowed under the rules above and does not change the fixed parameters.
