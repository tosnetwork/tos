# TOS Shielded-Pool Trusted Setup — Ceremony 3 Participant Guide

> **CEREMONY 3 REGISTRATION OPEN; CRYPTOGRAPHIC CONTRIBUTIONS NOT OPEN (2026-11-16).**
> Independent contributor **registration** is open through
> [GitHub Issue #483](https://github.com/tosnetwork/tos/issues/483) from
> **2026-11-16 07:42:00 UTC (16:42 JST)** to
> **2026-11-23 07:42:00 UTC (16:42 JST)** — precisely seven days.
> **Do not generate, submit, or accept a cryptographic contribution yet.**
> The [2026-10-19 ceremony 2](../artifacts/phase2-ceremony-2/README.md) is
> complete and closed. Its source commit, roster, inputs, close and beacon
> **must not be reused**. Registration does not guarantee a 300 TOS payment.

This is the **Ceremony 3 participant entry point**, consistent with the
[public registration announcement, Issue #483](https://github.com/tosnetwork/tos/issues/483).
Issue #483 is an **official registration notice**, not the immutable
cryptographic-parameter announcement. A separate fixed-parameter announcement,
fresh opening data, and audited contribution deadlines must be public **before
the first actual contribution**. The
[ceremony 2 technical guide](../artifacts/phase2-ceremony-2/PARTICIPANT-GUIDE.md)
is historical reference material only, not an active contribution target.

## 1. Ceremony 3 identity, registration window and outstanding commitments

| Field | Verified status / required value |
| --- | --- |
| Ceremony number | **Ceremony 3** (public recruitment identifier; cryptographic protocol/circuit must be pinned separately) |
| Independent contributor registration | **OPEN** — [Issue #483](https://github.com/tosnetwork/tos/issues/483) |
| Registration starts (UTC / JST) | **2026-11-16 07:42:00 UTC / 2026-11-16 16:42:00 JST** |
| Registration closes (UTC / JST) | **2026-11-23 07:42:00 UTC / 2026-11-23 16:42:00 JST** |
| Registration policy and submission channel | Follow [Issue #483](https://github.com/tosnetwork/tos/issues/483): publicly controlled SSH/GPG signing identity, own public repository, truthful independence declaration and GitHub comment |
| Cryptographic contribution status | **NOT OPEN** — registration is not permission to generate randomness or submit a transcript |
| Immutable cryptographic ceremony announcement (commit URL) | **TBD — not yet published**. Issue #483 is not this announcement |
| Full pinned source commit, protocol/circuit and build/toolchain | **TBD — required before contributions** |
| Fresh opening phase-1, starting-key and transcript digests | **TBD — required before contributions** |
| Public contributor roster and published per-revision hashes | **TBD — must define append-only registration binding before contributions** |
| Cryptographic contribution opening and fixed close (UTC and/or exact Bitcoin height) | **TBD — not the registration deadline above** |
| Future Bitcoin beacon height and encoding | **TBD — fixed before the future block is mined** |
| Public input/handoff, operator-verification and independent final-audit process | **TBD — required before contributions** |
| 300 TOS claim channel, funding, payment network, eligibility and payout timing | **TBD — see section 5** |

**Stop condition:** register now if eligible, but **do not contribute** while
the cryptographic announcement, source/circuit, verified opening, exact
contribution close and future beacon remain TBD. A registration comment, copied
command or historical contribution record cannot substitute for these items.
The registration deadline is fixed by Issue #483's GitHub creation timestamp;
do not silently extend it. A separate immutable cryptographic announcement must
be independently observable **before the first contribution**, and its fixed
contribution-close rule must never be extended after publication. A dynamic
participant roster is acceptable only if its public, append-only registration
and per-contribution revision rules are precommitted and auditable.

## 2. What an independent contributor prepares in advance

1. A machine under **your own control**, separate from the operator: Ubuntu
   24.04 or Debian 12, approximately 2 CPU cores, at least 1 GiB RAM and 5 GiB
   free disk. The historical guide measured this environment; a changed circuit
   or toolchain may need new measurements.
2. Your own public GitHub repository for publishing the *entire public*
   contribution bundle, signed attestation and whole-file SHA-256 manifest.
3. A pre-existing, public SSH or GPG signing identity wherever the new
   announcement requires one. Give the operator **only the public key,
   fingerprint, public identity binding and repository URL**. Never give the
   operator your private key, seed phrase, entropy, crash dump or memory image.
4. An environment where no swap, core dump, debugger, hibernation or VM
   snapshot can preserve the secret random scalar. Verify this **before**
   contribution, not after. If erasure conditions cannot be established, do not
   sign a false erasure attestation.
5. Enough time to verify the pinned source, input transcript and roster,
   perform **one** contribution, independently verify it and publish it before
   the announced deadline.

Independence is substantive: do not use a project-controlled machine, remotely
managed environment or operator-supplied precompiled binary. A signature can
prove key possession and message integrity; it **cannot** prove the true
independence of a person or the destruction of a secret.

## 3. How to contribute **after** the separate cryptographic announcement is published

These are gates, not an invitation to start early:

1. Obtain and independently archive the **immutable new announcement**. Check
   its ceremony number, protocol/circuit, full source commit, published roster
   hash, opening digests, exact closing condition and future beacon. Verify
   that the close/beacon have **not** already passed. Check the identity of the
   operator and the independently observed announcement publication time.
2. Confirm your exact public signing key, principal/fingerprint and truthful
   independence declaration in the **announced** roster according to the
   announced registration policy. A newly substituted roster is a refusal.
3. Clone `https://github.com/tosnetwork/tos.git` yourself and check out
   **the new announcement's exact full commit**; never use the old
   `66fb007e7d3d6b509c32ad1b3ce4af470d96a53c` by default. Review
   `tools/shielded-pool-ceremony/src/secret.rs` and `entropy.rs`, and build
   the announced contributor and verifier from source using its pinned
   toolchain. If the new protocol/circuit changes tooling, follow the
   *new* announcement rather than assuming historical commands still apply.
4. Get the **current** public `ceremony/` input and attestations via the
   announced channel, compare the SHA-256/opening digests, and independently
   verify the cumulative transcript **before** contributing. Recheck source,
   roster, incoming record and deadline if any input changes.
5. With your own signing key and the required no-swap/no-dump/no-snapshot
   precautions, make **one** contribution via
   `scripts/shielded-pool-phase2-contribute.sh` **only if the new announcement
   explicitly names this tool and input format**. The tool draws random entropy
   locally, re-randomizes the public parameters, and emits an attestation.
   If a run fails after possibly appending, report it; do not rerun blindly.
6. Independently verify the updated transcript and attestation/signature as
   prescribed by the new announcement. During an open ceremony the historic
   verifier may report `NOT FINISHED`; that does not waive a failed signature,
   digest, chronology or independence check.
7. Dispose of secret-bearing state as the security guide requires. Publish
   the **complete public** updated `key.bin`, `contributions.bin`,
   `ceremony.json`, signed `attestation-N.txt`, and `SHA256SUMS` under
   **your own GitHub account**, before the fixed close. Do not upload private
   keys or entropy. Send the immutable public commit/release URL and manifest
   to the announced reporting channel.
8. The operator fetches the *same published bytes*, checks whole-file hashes,
   contribution chain, signed identity and acceptance criteria, then records
   a public ACCEPTED or REJECTED result. A private handoff or GitHub comment
   alone is not a completed, accepted contribution.

For detailed historical command examples, see the
[ceremony 2 participant guide](../artifacts/phase2-ceremony-2/PARTICIPANT-GUIDE.md).
Its path names, roster, source commit and Bitcoin heights are historical.
**Do not copy any ceremony 2 command or hash into a new live contribution
without checking the new pinned announcement.**

## 4. Final verification is distinct from a contribution

The new announcement must name who performs independent final verification.
An independent verifier must observe the prescribed beacon independently,
check the full *finished* transcript and every signature against the pinned
roster, publish their signed PASS or REFUSED report, and disclose failures.
A completed contribution is **not** proof that a ceremony is finalised or
deployable. No project-side verification can replace a required independent
PASS, and deployment still has its separate acceptance gate.

## 5. Announced community offer: 300 TOS per verified contribution (claim terms pending)

The [Ceremony 3 registration notice, Issue #483](https://github.com/tosnetwork/tos/issues/483)
quotes the community offer: **"300 TOS for each completed contribution that
passes operator verification."** This is a public recruitment offer, **not a
verified or funded payout mechanism**. Registering alone is not reward-eligible;
the cryptographic contribution phase is still closed. The operator must
publish binding eligibility and payment terms **before accepting any
reward-eligible contribution**. Do not imply an automatic on-chain transfer or
a guaranteed payment merely for registering. The missing policy must specify:

- Which new ceremony is eligible; when participation opens/closes; whether a
  person may receive more than one reward; and what counts as independent.
- Which checks constitute **operator verification** (including correct
  transcript, registered public signing identity, signed attestation, public
  publication and a submission before the fixed close); a written acceptance
  record and an appeal/dispute channel.
- **Asset and network** (mainnet TOS or testnet TOS), the treasury/funding
  authorization, actual payout source and any exclusions or limits. A
  contribution does not mint new TOS.
- **Claim procedure:** where to submit the public contribution URL and
  designated receiving address, how to prove control of the address without
  revealing a private key/seed phrase, the claim deadline, expected payment
  timing, who pays transaction fees, and where the payout transaction or
  refusal will be recorded.
- How a participant receives a receipt and checks final payout independently.

**The 300 TOS amount is publicly advertised, but cannot currently be claimed.**
Only a completed, independently sourced and signed contribution that passes
the published operator checks may become reward-eligible, subject to the
announced claim terms. No payment should be described as funded, due or sent
without evidence. Never ask contributors for an activation fee, private key or
wallet recovery words.

## 6. Operator publication checklist

**Registration is already OPEN under Issue #483.** Before changing the
*cryptographic contribution status* from **NOT OPEN** to **OPEN**, publish a
separate immutable announcement with independently observed publication
precedence; bind the announced source/circuit and fresh opening hashes; define
the publicly auditable registration/roster revision policy and its signature
verification; choose a genuinely future Bitcoin beacon and fixed
contribution-close condition; name independent final verification and refusal
rules; and publish funded reward/claim terms. Replace the cryptographic TBD
fields above with **exact canonical links and values** in a separately
reviewed change. Do not treat the registration deadline as a contribution
deadline or silently alter the historical ceremony 2 record.

Do not edit or reinterpret the immutable [ceremony 2 announcement](../artifacts/phase2-ceremony-2/ANNOUNCEMENT.md)
or append contributions to the closed 2026-10-19 transcript.
