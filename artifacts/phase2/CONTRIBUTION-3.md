# Contribution 3 — tosdev3

Status: **accepted contribution to an open ceremony; not final parameters**.
The contributor is registered as not independent of the operator. This is the
third such contribution, so the ceremony's independent-participation condition
is still unmet and the final gate still refuses.

| Field | Value |
|---|---|
| Contributor | tosdev3, affiliation `community` |
| Built from | `f7f141589a788c8aa06bee32d7799c25cbfab356` |
| Announced revision it maps from | `49ef58c0ab98f62b76ae3c61a510980dae131235` |
| Register revision | `8865f435d5ccbfa4aba5f7fc8063d9bda65c83d6` |
| Register SHA-256 | `fcb0b90c0eb39bcb10c0d71d8299665aa0110ec4ae25f5dbd1d0cd24c3408d17` |
| Contribution digest | `5619a6e1aab154546061a8c65b35f98a973fc69f365b8665d702e0e82e96e468` |
| Transcript after contribution | `d05541b101c7c94a85bdcb3491a66d3448ec7e955b2e080825e75cdfbdfdf21f` |
| Resulting key.bin SHA-256 | `43bad49013e26a203b411210a4837ba7adb32fb1be187490a99e52e51c696138` |
| Verifying key SHA-256 | `cf6f16a551ac247f6f12659009c1d86c8ccbe71eac1924ba3bf6b95cdee7c66f` |

## What was checked before extending the chain

Recorded in [evidence/received-3.log](evidence/received-3.log), and done on
the contributing host rather than taken on trust from the previous one.

- The published contribution-2 archive was downloaded and its SHA-256 matched
  the recorded `b7ccbe20…`.
- Eleven files from that archive — the three ceremony files, the register, the
  announcement, both attestations with their signatures, and the registered
  public keys — were compared byte for byte against the published branch. All
  matched.
- tosman's signed commit mapping verified against tosman's registered key, and
  the mapped revision was checked out and confirmed clean.
- Both existing attestations verified against the published register.
- `secret.rs` and `entropy.rs` hashed to `d44fac7d…` and `f80e55c0…`, the same
  bytes reviewed for the previous contribution at the same revision.

## Validation performed

- `cargo build --release --locked --bins` at the mapped revision succeeded.
- `phase2-contribute` rebuilt the starting key from the committed phase-1
  slice and matched the announced `018853105392e4e0ef82ae59514f137b…`, audited
  the two contributions already in the chain, and added exactly one entry.
- `phase2-verify` reported `the chain audits: 3 contribution(s)`, and
  `NOT FINISHED` as expected before the beacon.
- `test/shielded-pool/verify-attestations.py` ran against the **published**
  register, whose digest matched the value recorded in the attestation. With
  `--in-progress` all three contributions verified. Without the flag it
  **refused, exit status 1**. Both runs are in
  [evidence/attestation-binding-3.log](evidence/attestation-binding-3.log).
- Bitcoin height from both announced witnesses: 968141 at 2026-09-22T12:17:36Z
  before contributing and 968141 at 12:26:00Z after, both below the announced
  close at 970141, with block 970285 not yet existing. Contributor
  observations, not independent publication evidence.
- Swap was disabled for the whole contribution and restored afterwards, with
  the swapfile then reporting no used pages.

The contribution run and its `phase2-verify` output are in one log,
[evidence/contribution-3.log](evidence/contribution-3.log), because they were a
single scripted run with swap disabled across both. There is no separate
`verify-3.log`.

## Publication

[Release](https://github.com/tosnetwork/tos/releases/tag/shielded-pool-phase2-contribution-3),
server-published at **2026-09-22T12:29:24Z**, tagged on this contribution's
commit; the API response is retained in
[contribution-3-publication-receipt.json](contribution-3-publication-receipt.json).
The published attachment was downloaded again afterwards and compared byte for
byte against the local archive; they are identical, and its SHA-256 is
`3fe7f063eec267044d24371bfa21e2af91e7a62dcd0a70a3db9abac7f367263c`.

## What a third machine does and does not buy

This contribution ran on a different host, from a different provider, than
contributions 1 and 2. That is a real if narrow gain: a phase-2 ceremony is
sound if **any single** scalar was honestly drawn and destroyed, so spreading
the draws across machines spreads the risk that one host's generator, memory
or snapshots were compromised.

It buys nothing against the risk the ceremony's independence rule is actually
about. That rule asks whether some contributor could draw and destroy a scalar
without the others being able to compel or observe them. All three draws were
made by one party on hardware that party administers, so the answer is still
no, and three contributions inside one party's control are not more
independent than one.

- The host is administered by the operator and execution was driven by an
  automated agent over SSH.
- The signing key was generated on that host, has no passphrase, and no public
  identity evidence is registered for it.
- The host serves a live website and was not destroyed afterwards.

## Correction: the attestation's claim about tooling is now out of date

[attestation-3.txt](attestation-3.txt) says of the signing key that "no tool in
this repository reports that absence". That was accurate for the revision this
contribution was built from, `f7f14158…`, and for every verifier run recorded
in this contribution's evidence, all of which used that revision.

It stopped being true in `157cb39062dd603fc80eff197b0d86c139aee6b1`, which
made `verify-attestations.py` report a register entry carrying no
`published_at` — on the contribution's own line and again in a summary. That
commit was authored at 12:24:54Z and this attestation was signed at
approximately 12:26Z, so the sentence was already stale when it was signed.
Nobody noticed until afterwards.

The signed bytes are **not** being edited. An accepted contribution is not
rewritten, and a signature over corrected text would be a different document
pretending to be this one. The correction lives here instead, and the current
tool's actual output is recorded in
[evidence/identity-evidence-report.log](evidence/identity-evidence-report.log):

```
  3  signed by tosdev3 -- NOT independent of the operator, NO PUBLIC IDENTITY EVIDENCE
```

The underlying fact the sentence was reporting is unchanged and still true:
no public identity evidence is registered for this key. What changed is that
a reader no longer has to take a contributor's word for the gap.

## Next contribution

The ceremony remains open and still needs what it has not got. Register your
public key and identity, extend this exact chain, and publish your signed
attestation with the register revision used for acceptance. Do not replace any
existing contribution.

Final acceptance requires a contribution from a party outside the operator's
control, closing at the announced height, the future beacon, and outside
verification. No deployment or address freeze has been performed.
