# TOS Shielded-Pool Trusted Setup — Next-Round Participant Guide

> **NOT OPEN — onboarding information only (2026-11-16).**
> No new ceremony is announced by this document. **Do not generate or submit a contribution yet.**
> The [2026-10-19 ceremony 2](../artifacts/phase2-ceremony-2/README.md) is **complete and closed**.
> Its old announcement, roster, source commit, Bitcoin closing/beacon heights,
> and ceremony data must **not** be reused.
> This document is not an announcement, an extension of an old deadline, or an
> authorization for reward payment.

This page is the prospective **participant entry point**, not a replacement for
immutable historic ceremony records. It will be usable for a new round only
after the operator publicly publishes the new, complete announcement **before
any contribution**. The [ceremony 2 technical guide](../artifacts/phase2-ceremony-2/PARTICIPANT-GUIDE.md)
is a reference for the tool's mechanics, **not** an active registration or
contribution target.

## 1. Current round identifier, announcement and deadlines

| Field | Status / required value |
| --- | --- |
| New ceremony number and protocol/circuit identifier | **TBD — not assigned or approved**. Do not assume the next round is called "ceremony 3". |
| Participation status | **CLOSED / NOT OPEN** until an independent, complete announcement is public |
| Canonical announcement URL (immutable commit) | **TBD** |
| Pinned TOS source commit (full SHA) and build/toolchain requirements | **TBD** |
| Public opening parameters: phase-1 slice, starting-key and transcript digests | **TBD** |
| Participant roster URL and pinned roster SHA-256 | **TBD** |
| Registration policy and deadline | **TBD**, must be published before opening |
| Contribution opening and close (UTC time and/or exact Bitcoin height) | **TBD**; a relative promise such as "this week" is not a deadline |
| Future beacon block height and encoding | **TBD**; must be publicly fixed before it is mined |
| Public reporting channel and operator-verification procedure | **TBD** |
| Reward eligibility, payment network, claim channel and payout schedule | **TBD**, see section 5 |

**Stop condition:** any TBD item needed to establish the ceremony's identity,
precedence, valid submission window, public verification or reward eligibility
means **do not contribute**. In particular, an operator message, a copied
command, or the historical five-contribution record is not a replacement for
the canonical new announcement. An announcement must be independently observable
before the first contribution; it must not be rewritten to move a deadline or
change the roster after opening.

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

## 3. How to participate **after** the new announcement is published

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

## 5. Proposed contributor reward: 300 TOS (terms pending)

An outreach message states: **"300 TOS for each completed contribution that
passes operator verification."** This is the current *proposed campaign
wording*, **not yet a verified, funded or approved payout policy in this
repository**. Do not imply an automatic on-chain transfer or guaranteed
payment. Before recruiting contributors for rewards, the operator must
publish an immutable campaign policy specifying:

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

**Until those terms and the new announcement are public, the 300 TOS offer
must not be represented as currently claimable.** Never ask contributors to
pay an activation fee or reveal wallet recovery words.

## 6. Operator publication checklist

Before marking this guide **OPEN**, publish an immutable announcement and
public receipt/archival evidence; fix the roster and its SHA-256; publish
the exact code and circuit commitments; choose a verifiably future beacon and
fixed contribution-close condition; name independent verification and refusal
rules; and publish the full reward/claim policy. Then replace the TBD entries
above with **exact canonical links and values** in a separately reviewable
documentation change.

Do not edit or reinterpret the immutable [ceremony 2 announcement](../artifacts/phase2-ceremony-2/ANNOUNCEMENT.md)
or append contributions to the closed 2026-10-19 transcript.
