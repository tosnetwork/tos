# Independent participant: contribute once, then verify independently

You are both a contributor and the independent verifier. Setup security requires
at least one contributor to destroy unpredictable secret randomness; verification
alone cannot prove destruction. Independence means the project neither controls
you nor coordinates your randomness or verdict. Public scheduling and file
exchange are necessary; a shared machine or a directed verdict is not independent.
Circuit correctness and deployment acceptance remain separate requirements.

This is an instruction, not an announcement. The draft's 2026-09-22 heights have
expired. Do not begin until a fresh complete announcement is public. The
[participant guide](PARTICIPANT-GUIDE.md) is the single command reference.
The [withdrawn ceremony](../phase2/SUPERSEDED.md) must not be reused.

## 0. You send your public key; the project pins the roster

Send only your signing public key and public identity binding, never a private
key. Follow the guide's [signing identity](PARTICIPANT-GUIDE.md#5-your-signing-identity)
and [roster checks](PARTICIPANT-GUIDE.md#5d-pin-the-announced-roster).
The project pins the actual key, SSH principal or GPG signing fingerprint, and
your independence declaration before announcement. Supply your own public GitHub
repository URL for contribution and verification publication.

Use a machine you control with the guide's [measured requirements](PARTICIPANT-GUIDE.md#1-the-machine):
Ubuntu 24.04 or Debian 12, 1 GB RAM, 5 GB free disk and two cores (measured peak
255 MB; allow headroom). Arrange an independent Bitcoin network path and retain
your signing identity for the final report. Do not use a project-controlled VM.

## 1. Project publishes the standalone announcement

Before any contribution, the project publishes and archives the announcement on
its own. It fixes the source commit, opening digests, roster and roster SHA-256,
contribution-close height and an **unmined** beacon height. No draft field may
remain. Publication together with the first contribution is insufficient.

## 2. You check precedence, future beacon and incoming transcript

Independently archive the announcement and its observable publication record.
Check it preceded all contributions. Observe the Bitcoin tip yourself: the
anchor exists, the close height is ahead, and the beacon height is strictly later
and still unmined. Check your exact key and truthful independence in the pinned
roster. Do not accept the expired draft values or a later roster replacement.

Obtain source independently at the announced commit and follow
[source checking](PARTICIPANT-GUIDE.md#3-get-the-code), the
[pinned toolchain](PARTICIPANT-GUIDE.md#4-install-rust-at-the-version-this-repository-pins),
[source review](PARTICIPANT-GUIDE.md#6-read-the-two-files-you-are-being-asked-to-trust)
and [incoming transcript verification](PARTICIPANT-GUIDE.md#7a-build-the-verifier-and-check-the-incoming-transcript).
The guide explicitly handles an empty opening transcript. Do not use a supplied
binary. Signature checks cannot establish announcement precedence or erasure.

If any check fails, stop and publicly report the discrepancy with hashes,
heights and observation times through your own repository and
`<REPORTING_CHANNEL>`. Never waive it or silently switch heights.

## 3. You contribute, destroy randomness and sign

Complete [memory precautions](PARTICIPANT-GUIDE.md#6a-prepare-the-machine-before-any-contribution)
before entropy exists, then [contribute once](PARTICIPANT-GUIDE.md#7b-make-your-one-contribution)
and [check your work](PARTICIPANT-GUIDE.md#8-check-your-own-work-before-you-hand-it-on).
The wrapper signs the contribution attestation automatically; that signature
cannot prove destruction. Complete [destruction and disposal](PARTICIPANT-GUIDE.md#11-destroy-the-randomness-and-dispose-of-the-environment)
before publication, and sign only statements you can truthfully support.

Require process exit, no swap/core dumps or memory snapshots during contribution,
and disposal of controlled ephemeral storage/VM or appropriate machine erasure.
Deletion alone cannot prove provider or SSD copies disappeared. Retain the
signing key separately; never hand over entropy, keys, dumps or machine images.
If a run may have appended before failing, report it rather than contributing again.

## 4. You publish in your own public GitHub repository

Follow [the publication procedure](PARTICIPANT-GUIDE.md#9-publish-in-your-own-public-repository).
Publish the updated `key.bin`, `contributions.bin`, `ceremony.json`, attestation
and signature under your own control, before close. Commit them or use release
assets; publish their whole-file SHA-256 values in the commit/release text.
The tool emits a cumulative contribution file, not a standalone one-step file;
its whole-file hash differs from the per-entry digest in your attestation.

The guide covers GitHub's 100 MiB ordinary-file limit and release assets under
2 GiB. Keep exact public URLs and independently observable timestamp/height
evidence; author-controlled commit dates alone are insufficient. A private
handoff or a project-hosted copy does not replace your public publication.

## 5. Project fetches and checks your public bytes

The project follows [the handoff checks](PARTICIPANT-GUIDE.md#10-project-fetch-and-handoff),
fetches from your exact public commit/release, checks every SHA-256 against the
published text, and preserves your original attestation and signature. Any
mismatch stops the ceremony. You retain your own public copy.

## 6. Project waits for close and applies the announced beacon

Only after the close height and once the announced beacon block is mined does
the project apply its hash. If late, **wait**; never replace it with an already
mined block, change the height or extend the contribution deadline. If your
contribution missed close, refuse this run and require a newly announced ceremony.
The project supplies the complete beacon-finalized transcript for your audit;
this is not yet permission to publish final parameters.

## 7. You independently verify everything and publish a signed result

Follow [final verification](PARTICIPANT-GUIDE.md#12-independently-verify-after-the-beacon)
from an independently obtained checkout at the announced commit. Read the Bitcoin
block through your own network path. Check the exact beacon bytes, complete
mathematical transcript including the last beacon step, your contribution and
position, and every attestation against the original pinned roster. Require an
explicit **finished** result: exit 0 can also mean an unfinished valid transcript.
Do not use unsigned waivers or `--in-progress` for the final audit.

[Sign your separate PASS or REFUSED report](PARTICIPANT-GUIDE.md#13-sign-and-publish-your-independent-verification-statement)
and publish it, its signature, output and hashes **in your own public GitHub
repository**. Include the independently derived verifying-key hash, source,
roster, announcement and observed beacon identities. The attestation verifier
checks contribution attestations, not this separate report's signature.
If anything fails, publish a signed refusal and public evidence; do not endorse
parameters or create another contribution to conceal a failed run.

## 8. Project verifies and publishes final parameters only after your PASS

Only after step 7 passes does the project publish final parameters matching your
independently derived key, with the full transcript, announcement, pinned roster,
all signed contribution attestations and your signed independent verification.
**The project's own verification does not replace step 7.** You do not deploy the
pool; the project still owns the [deployment acceptance gate](../../doc/shielded-pool-ceremony.md#the-acceptance-gate).

## Timeline to fill before announcement

| Point | Action |
| --- | --- |
| Before `<START_DATE>` | Your public key and repository supplied; roster pinned. |
| `<START_DATE>`, `<ANCHOR_HEIGHT>` | Project publishes announcement alone; you check it. |
| Before `<CONTRIBUTION_CLOSE_HEIGHT>` | You contribute and publish the signed public handoff. |
| At close | No more contributions. |
| `<BEACON_HEIGHT>` | Wait for the block, then project applies beacon. |
| After beacon | Your independent signed PASS, then project final publication. |

Require `<ANCHOR_HEIGHT> < <CONTRIBUTION_CLOSE_HEIGHT> < <BEACON_HEIGHT>`.
The project fills placeholders before announcement, including `<REPORTING_CHANNEL>`.
Today's target is 2026-10-19 07:00 UTC (16:00 JST), not permission to bypass a
height, rush verification or substitute a beacon. Bitcoin timing cannot guarantee
that target. No contribution deadline is extended after announcement.
