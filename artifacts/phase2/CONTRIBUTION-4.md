# Contribution 4 — BmswapProtocol

Status: participant contribution awaiting operator acceptance; **not final parameters**.

The participant declares they are not part of the TOS operating team and is
registered as independent. This is a self-declaration, not external verification.
The account has repository administrator access. Execution was delegated to an
automated agent over SSH on the participant-designated VPS; reviewers should
consider these disclosed facts when assessing independence.

- Public identity, signing key and signed attestation: https://gist.github.com/BmswapProtocol/60bcbe525d52446fee3775790baa7903
- Built revision: `f7f141589a788c8aa06bee32d7799c25cbfab356` (signed privacy mapping verified).
- Register revision: `424597fe05830222e4b43dd16b02d6cd75753674`.
- Register SHA-256: `554b2ad454bbc67bcdb55858d286a5499002fe34c5e5c49899cd293866ce9372`.
- Contribution digest: `246b9d7406a6b349ba51a092aa69c111a429e8eab528142008b1d7f096f6413e`.
- Transcript: `46166e20210e3a2fb753158d480cb556cf7a3fb95376ca65b92bf661a92f3b5a`.
- Resulting key SHA-256: `d44d89c01a2c18581018826d1a21e9bc37ab8641ffe00262bc3d8d7235806dc1`.

## Verification

The preceding release archive matched its published SHA-256. Fourteen ceremony,
announcement, register, attestation and public-key files matched the published
checkout. All three preceding signatures verified. The mapped clean checkout
built with `cargo build --release --locked --bins` using Rust 1.97.1.

The contributor rebuilt the starting key, audited the preceding chain, and
added exactly one contribution. The first three record entries are unchanged.
A separate `phase2-verify` run audited all four contributions and reported
`NOT FINISHED`, as expected without the future beacon. Both the in-progress
and independence-enforcing attestation checks passed against the published
register. They check the independence declaration, not its truth. The known
missing public identity evidence for tosdev2 and tosdev3 remains reported.

Swap was disabled throughout contribution and verification, core dumps were
disabled, and swap was restored afterwards with zero bytes used. The signing
private key is retained separately and is not part of the publication. This
makes no claim about provider memory snapshots or forensic erasure.

Both announced Bitcoin witnesses returned height 968229 before contribution
and after verification, below close 970141 and beacon 970285. Timestamped
observations are in `evidence/bmswap-height-before.json` and
`evidence/bmswap-height-after.json`. These are contributor observations.

Evidence logs replace the local working-directory path with `<ceremony>`;
public digests and signed attestation bytes are unchanged. The release archive
uses normalized owner, timestamps and modes and contains no signing private key.

## Publication and remaining gates

Release: https://github.com/BmswapProtocol/tos/releases/tag/shielded-pool-phase2-contribution-4

The release receipt records the server-assigned publication timestamp and
archive digest after upload and download verification. Scheduled closing,
beacon processing, outside verification, independence review and deployment
acceptance remain outstanding. No parameters were finalized or deployed.

## Access change during publication

The registration commit reached the upstream ceremony branch. The subsequent
contribution push was refused with HTTP 403. A fresh permissions query showed
this account had read-only upstream access. Earlier statements about admin
access describe the preparation-time observation; the signed bytes are retained.
The contribution is therefore published in the participant fork for operator
acceptance, not represented as already accepted into the upstream chain.
