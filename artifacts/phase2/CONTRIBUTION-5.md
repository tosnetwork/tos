# Phase-2 contribution 5 — onemailweb3-design

This bundle extends the four-contribution chain at upstream revision
b6478c920d49e6268987ecde83219e94e8bbaada with one participant contribution.
Registration and contribution are submitted for operator acceptance; neither
is represented here as accepted upstream.

Participant: https://github.com/onemailweb3-design
Signed identity and attestation:
https://gist.github.com/onemailweb3-design/8c17f093726d46685eca68d89b5a7536
Public account signing key:
https://api.github.com/users/onemailweb3-design/ssh_signing_keys

The participant declares they are an independent external developer, not a
TOS member or part of its operating team. This is self-declared. Execution
was delegated to an automated agent over SSH on a participant-designated VPS.
See the signed attestation for scope, controls and limitations.

## Revisions and digests

- Announced code: 49ef58c0ab98f62b76ae3c61a510980dae131235
- Built code (signed privacy mapping): f7f141589a788c8aa06bee32d7799c25cbfab356
- Rust: 1.97.1; release binaries built from source with the lockfile.
- Participant-published register: 387417d4667a98bcea08e3998cef979ba0ef8c64
- Register SHA-256: 67054a21d5b249e9c847dfd8b726464456bccdac659090c482d652e0828bab07
- Contribution digest: ed4b9b45c179b3a5c7e1102dc47505ee81f726bcb077699564e18f022b26c5a4
- Resulting transcript: 3a9cb40dfabfd61eaa6ea350e06e9ef63061e1482a1f0e9d794225c6e3e4da27
- Ceremony key file SHA-256: b0bc8de88dd92e0ae9efeec2c2ca72cb734004324df903e20507ab736a67189b
- Verified 1,248-byte verifying-key SHA-256: ddf9ad62df7ac2c1dc7b77d5ee7c43b3fc1501f83f7cb42c1cdf4380d59f024c

## Verification performed

The pinned phase2-verify binary rebuilt the starting key, matched the
announced digest, and audited all five contributions (exit 0).
The attestation verifier from upstream revision b6478c920d49e6268987ecde83219e94e8bbaada
verified all five signatures and their bindings to contribution/transcript
digests (exit 0). It reports missing public identity evidence for inherited
participants tosdev2 and tosdev3.

Negative checks against disposable copies rejected a false key-file digest
and an altered contribution digest in attestation 5.

Swap and core dumps were disabled during contribution; live checks confirmed
zero swap use and core limits of zero. Original system settings were restored.
No contribution scalar was requested or exposed. The signing private key is
retained separately and is not included.

## Reproduce

With the pinned ceremony binaries built and this bundle extracted:

    /path/to/phase2-verify ceremony
    python3 /path/to/tos/test/shielded-pool/verify-attestations.py ceremony --roster roster.json --attestations . --in-progress
    sha256sum --check SHA256SUMS

The mathematical verifier reports NOT FINISHED: the beacon has not been
applied. Do not treat this bundle as finalized or deployable parameters.
Contributions close at Bitcoin height 970141; the beacon is height 970285.
The two announced witnesses reported heights 968232 before contribution and
968233 afterward. Final acceptance and deployment checks remain outstanding.

The archive normalizes ownership, permissions and timestamps and includes
only public files. SHA256SUMS covers the payloads; its detached SSH signature
uses namespace file and the published participant signing key.

## Published contribution bundle

Release: https://github.com/onemailweb3-design/tos/releases/tag/shielded-pool-phase2-contribution-5-onemailweb3-design

Archive SHA-256: ef1c096b4395632d0f21f63bcaa6cc831df70d99e24924c380312424c1e4944d

The release also carries the archive checksum and its detached SSH signature.
The public bundle contains the complete five-contribution chain, inherited
attestations, participant register, identity statement, signatures and
verification evidence. Upstream operator acceptance remains pending.
