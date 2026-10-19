# Phase-2 ceremony 2 — announcement, 2026-10-19

This is the standalone announcement for ceremony 2. It is published before
any contribution and before the public opening directory is generated.
The [withdrawn ceremony](../phase2/SUPERSEDED.md) is not reused. Only its
tooling, circuit and committed phase-1 slice carry forward.

## 1. Fixed close and future beacon

| Commitment | Value |
| --- | --- |
| Start date | 2026-10-19 UTC |
| Announcement anchor | 972107 |
| Anchor hash | `000000000000000000005b07b4c1217913dacb5e88562c2025a38487b3f60a39` |
| Contributions close | **972111**, anchor + 4 |
| Beacon | **Bitcoin block 972112**, close + 1 |
| Beacon encoding | 64 lowercase ASCII hexadecimal hash characters, no newline |
| Witnesses | blockstream.info and mempool.space, independently; any independent full node |
| Target completion | 2026-10-19 07:00 UTC / 16:00 JST, subject to block arrival |

Both sources agreed at the following observations immediately before preparing
this publication. Neither close nor beacon had been mined at these readings.

| Source | Tip height | Tip hash | UTC observation interval |
| --- | --- | --- | --- |
| https://blockstream.info/api | 972107 | `000000000000000000005b07b4c1217913dacb5e88562c2025a38487b3f60a39` | 2026-10-19T05:20:07.905715+00:00 to 2026-10-19T05:20:10.090278+00:00 |
| https://mempool.space/api | 972107 | `000000000000000000005b07b4c1217913dacb5e88562c2025a38487b3f60a39` | 2026-10-19T05:20:10.090409+00:00 to 2026-10-19T05:20:10.143951+00:00 |

Contributions must be publicly delivered and checked **before the chain reaches
972111**. They close at that height, not at the wall-clock target. The beacon
is the strictly later block 972112. A late beacon means **wait**, never switch
to a mined block or another height. Heights and roster never change after this
announcement. A missed contribution deadline requires abandonment and a newly
announced ceremony, not an extension.

This short four-block contribution window and one-block beacon gap do not
guarantee completion by a wall-clock time. They do not provide an absolute
protection against private mining or prove publication timing by themselves.
Independent public observation of this announcement and the participant's
handoff is required. Disagreement or reorganisation must be reported, not
resolved by silently choosing another beacon.

The beacon is public and adds no secrecy. Setup security requires at least one
contributor to keep unpredictable randomness secret and destroy it; a beacon
cannot rescue colluding contributors. Verification cannot prove destruction.
Circuit correctness, phase-1 custody and deployment acceptance remain separate
assumptions.

## 2. Fixed source, circuit and opening digests

| Commitment | Value |
| --- | --- |
| Source commit to build | `66fb007e7d3d6b509c32ad1b3ce4af470d96a53c` |
| Circuit | 18,107 constraints, 19 instance variables, QAP domain 2^15 |
| Committed phase-1 slice SHA-256 | `1bfd7acdb3ecbfaaa695ab159a7a643a2eb58203a4d93361040c6bd4c2aa3d6e` |
| Phase-1 provenance | Sapling slice; 87 attested human contributions and a public random beacon |
| Starting key SHA-256 | `018853105392e4e0ef82ae59514f137b1f1a19892023b70b72ef58941b017c04` |
| Opening transcript | `7dcfafe1626b5586d5713654c55cc0887590fd789c391ecf1e28bfaf93e66287` |

The source is an immutable full commit, not a moving branch. The opening key
is deterministic from the committed slice and circuit; each contributor builds
and checks it independently. Its matching the old opening digest does not reuse
any old contribution. The production opening is generated only after this
announcement has been pushed and is publicly visible.

## 3. One pinned independent contributor and verifier

The exact [roster.json](roster.json) bytes have SHA-256
`7e08f623ab1dcac8ce1be9712e2af0e3a71ddc6ca7d7b87995b71610295add8a`. They are fixed before opening.

- Name and SSH principal: **ffreeofmoney-bit**.
- Affiliation: independent; `independent_of_operator: true`.
- Public key: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICP1m+HPuKXnJxxUby47zOZHQcDFj+ugG7N1x5gnwr6q`.
- Public key identity: https://github.com/ffreeofmoney-bit.keys.
- Participant's own public publication repository:
  https://github.com/ffreeofmoney-bit/tos-phase2-ceremony-2.
- The same participant independently verifies the complete beacon-finalized
  transcript and publishes a separate signed verification result.

This is a pseudonymous account created for the participant's safety, to avoid
retaliation for taking part. Independence is declared by the participant and
confirmed by the owner; the account's recent creation is intentional. The
account was created on 2026-10-19 at 04:35 UTC and its publication repository
at 05:06 UTC, as supplied by the owner. Independence rests on that declaration
and confirmation, not on account history. The test lead confirmed the public
key endpoint serves exactly the pinned key and the repository is public.

The roster carries public key material inline. The signature verifier checks
key bindings and attestations; it cannot establish independence or secret
erasure. No project-controlled agent counts as this independent contributor.
There is no project contribution in this run and no private signing key is
supplied to the project. No further identity may be added after publication.

## 4. Publication and reporting record

This file is published alone in its announcement commit on
[`agent/phase2-ceremony-2`](https://github.com/tosnetwork/tos/tree/agent/phase2-ceremony-2/artifacts/phase2-ceremony-2).
The roster was committed separately beforehand. The public opening files must
be in a later separate commit and push. The GitHub-visible announcement commit
and its push time are the public precedence evidence requested by the owner.
Commit-authored time alone is not independent evidence of publication.
The exact announcement commit hash and observed push interval will be recorded
with the later opening publication; this avoids a self-referential commit hash
or rewriting this announcement after publication. No external archive snapshot
is claimed to exist. Readers should retain the immutable commit URL and their
own observation of its precedence before contributing.

Reporting channels are GitHub issues on
https://github.com/ffreeofmoney-bit/tos-phase2-ceremony-2/issues and
https://github.com/tosnetwork/tos/issues.

## 5. Contribution and public handoff

Follow [INDEPENDENT-PARTICIPANT.md](INDEPENDENT-PARTICIPANT.md), steps 0–8,
and the commands it links in [PARTICIPANT-GUIDE.md](PARTICIPANT-GUIDE.md),
using the exact source commit above. Verify the incoming transcript before
contributing on your own machine. Complete the no-swap/no-core-dump precautions
before randomness exists, destroy the contribution randomness, and sign only
statements you can truthfully support. The wrapper signs automatically; that
signature cannot prove erasure.

Publish the updated `key.bin`, `contributions.bin`, `ceremony.json`, signed
attestation and whole-file SHA-256 values in your own public repository before
close. Use a commit or release assets, respecting the guide's file-size limits.
A private project handoff does not substitute for your publication. The project
fetches your exact public bytes and compares them with the hashes in your
commit/release text, then verifies the transcript and attestation. Stop on any
mismatch. Never hand over entropy, dumps, private keys or machine images.

## 6. Independent complete verification before final parameters

After close and once block 972112 exists, the project compares its hash from
two independent sources and applies the beacon. It publishes that complete
transcript as audit input, not as an approved final parameter release.

The participant obtains the named source independently, builds the verifier,
reads the beacon independently, audits the complete transcript including the
last beacon step, and verifies all contribution attestations against the
original pinned roster. A final audit must explicitly say **finished** and use
neither `--in-progress` nor unsigned waivers. The participant signs a separate
PASS or REFUSED report including source, roster, beacon, transcript and derived
verifying-key hashes, and publishes it in their own public repository.

Only after that signed independent PASS does the project verify its signature,
repeat the checks, compare the full independently derived verifying-key digest,
and publish final parameters with the full transcript, original announcement,
roster, signed contribution attestation, independent signed report and outputs.
The project's own verification **does not replace** the participant's complete
independent verification. A failure blocks final publication and must be
reported publicly. Deployment still requires the separate acceptance gate.

## 7. Refusal conditions

Refuse or abandon if a contribution arrives at or after 972111, the beacon
height or roster changes after announcement, the opening digests disagree,
a signature or transcript check fails, independence is misrepresented,
randomness precautions cannot truthfully be attested, or the independent
complete verification does not PASS. Never waive these to meet the time target.
