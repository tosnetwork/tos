# Contribution 2 — tosdev2

Status: **accepted contribution to an open ceremony; not final parameters**.
The contributor is registered as not independent of the operator, so this
contribution does not advance the ceremony's independent-participation
condition. It extends the chain and nothing more.

| Field | Value |
|---|---|
| Contributor | tosdev2, affiliation `community` |
| Built from | `f7f141589a788c8aa06bee32d7799c25cbfab356` |
| Announced revision it maps from | `49ef58c0ab98f62b76ae3c61a510980dae131235` |
| Register revision | `b4f706f9b84ba46266b8cb0b7e3563ad1904ce05` |
| Register SHA-256 | `976a11c9e2e9b234c3e71f98e17620443010917467c335e938abd8daf4bd40d8` |
| Contribution digest | `035ea5be0dd986d6cd4b3688e9e88edac22a1bd07937953d553a0ecfc0f7966c` |
| Transcript after contribution | `f4e542800d0484cabdf226bdaa7bbbe1239aea894e90ed59a9ed65b8ec06d54c` |
| Resulting key.bin SHA-256 | `45efe34ff2eabcae5a23bc00d03d2dada9ce7b60e8e98cfd98b046a2214420d1` |
| Verifying key SHA-256 | `f54cb4c2b7086f23052f4ed997dc458e402139a589f35f1799c65963db5b24f9` |

## Order of operations

1. The published contribution-1 release was downloaded and its SHA-256 matched
   the recorded `1af43216…`. Its ceremony files, register, announcement and
   signed attestation were compared byte for byte against the published
   branch; all eight matched.
2. tosman's signed commit mapping was verified against tosman's registered
   key, and the mapped revision was checked out and confirmed clean. The
   announced revision itself no longer exists after the privacy-only history
   rewrite.
3. tosman's attestation was verified against the register before the chain was
   extended. A contributor who does not check the chain they are extending is
   signing for someone else's work as well as their own.
4. The signing key was generated, swap was disabled, and the contribution ran.
5. The register was published with this contributor and key, in the revision
   above, **before** this contribution record.
6. This record, the signed attestation and the verification evidence follow.

## Validation performed

- `cargo build --release --locked --bins` at the mapped revision succeeded.
- `phase2-contribute` rebuilt the starting key from the committed phase-1
  slice and matched the announced `018853105392e4e0ef82ae59514f137b…`, audited
  the one contribution already in the chain, and added exactly one entry.
- `phase2-verify` exited 0 and reported `the chain audits: 2 contribution(s)`.
  It also reported `NOT FINISHED`, as expected before the beacon.
- `ssh-keygen -Y verify`, namespace `file`, verified the attestation against
  the key published in the register revision above.
- `test/shielded-pool/verify-attestations.py` was run against the **published**
  register, whose digest matched the value recorded in the attestation. With
  `--in-progress` both contributions verified and the independence gap was
  reported. Without the flag it **refused, exit status 1**, naming the missing
  independent participant. Both runs are in the evidence directory; the
  refusal is the expected and correct answer at this point, and it is recorded
  rather than omitted.
- `secret.rs` and `entropy.rs` were read before contributing. The production
  path offers one entropy source, has no seeded constructor, mixes any
  participant-supplied material in rather than substituting it, and the secret
  type is not `Clone`, not `Display`, not `Serialize`, prints a placeholder
  under `Debug`, and zeroizes on drop.
- Bitcoin height was observed from both announced witnesses before and after
  contributing: 968136 at 2026-09-22T11:24:05Z and 968139 at
  2026-09-22T11:50:16Z, both agreeing, both below the announced close at
  970141. Block 970285 does not exist. These are contributor observations, not
  independent publication evidence.

## Publication

[Release](https://github.com/tosnetwork/tos/releases/tag/shielded-pool-phase2-contribution-2),
server-published at **2026-09-22T12:06:00Z**; the API response is retained in
[contribution-2-publication-receipt.json](contribution-2-publication-receipt.json).
The published attachment was downloaded again afterwards and compared byte for
byte against the local archive; they are identical, and its SHA-256 is
`b7ccbe20ec1d6e7a07a8f89b3ebc3ada636718cc52ec86304f9a572586071413`.

This release was published three times, and the record says so because the
alternative is a receipt whose timestamp nobody can account for.

1. **11:59:50Z** — created with the tag on the default branch rather than on
   the contribution commit, which is not where a ceremony tag belongs. Deleted
   with its tag.
2. **12:00:46Z** — recreated against `b12c646143f5181b354e38c361d92ef30b9064c7`.
   The published attachment was downloaded and verified. The operator then
   deleted this release by accident while clearing the first one.
3. **12:06:00Z** — recreated again, same tag, same commit, same archive.

The archive's bytes and SHA-256 are identical across all three; only the
publication and asset-upload timestamps moved, and the current receipt records
the current ones. Deleting a release does not recall copies already fetched,
and the tag was public throughout. No ceremony artifact, attestation or
signature was touched by any of this: it is packaging history, not chain
history.

## What this contribution does not establish

Stated here because none of it is visible in the artifacts afterwards.

- **It is not independent.** The contribution host is administered by the
  operator, execution was driven by an automated agent over SSH, and the
  signing key was generated on that host and remains there. No party outside
  the operator holds it. The register records `independent_of_operator: false`
  for exactly this reason.
- **The key has no public identity evidence.** `roster.json` carries no
  `published_at` for tosdev2, so a reader cannot trace the key to a person who
  can be asked. When this contribution was accepted the register was held only
  to a name, a boolean and a parseable key, so this entry passed every
  automated check that a well-evidenced one would, and no tool said otherwise.
  `verify-attestations.py` reports it now, in
  `157cb39062dd603fc80eff197b0d86c139aee6b1`. The gap itself is unchanged; the
  signed attestation's sentence about tooling describes the state at signing.
- **The host was not destroyed.** It runs unrelated services. Swap was
  disabled for the whole contribution and restored afterwards with the
  swapfile reporting no used pages, which closes the swap path; it says
  nothing about hypervisor memory or provider snapshots.
- **The signing key has no passphrase**, because the run was non-interactive
  and a passphrase prompt in that setting waits forever rather than failing.

## Next contribution

The ceremony remains open. Register your public key and identity, extend this
exact chain, and publish your signed attestation with the register revision
used for acceptance. Do not replace either existing contribution.

Final acceptance still requires a contribution from a party outside the
operator's control, closing at the announced height, the future beacon, and
outside verification. Two contributions exist and neither is independent, so
`verify-attestations.py` refuses the ceremony at its final gate today. No
deployment or address freeze has been performed.
