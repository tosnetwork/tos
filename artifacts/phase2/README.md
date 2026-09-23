# Phase-2 ceremony — open participation

**Status: five contributions are signed and verified, two of them registered
as outside the operator; registration remains open until the announced close.
Parameters are not finalised and must not be deployed.**

`verify-attestations.py` refused this ceremony at its final gate for as long
as every contribution came from the operator's own side. On 2026-09-23 that
stopped being true: **BmswapProtocol contributed and the gate passes.** The
refusal was never about the count -- three operator contributions did not
move it and a fourth would not have -- it was about whether anybody outside
could have failed independently.

That gate passing is a statement about a *declaration*. The tool reads
`independent_of_operator` from the register; it reports what the participant
declared and what the operator accepted, and no tool can do more than that.
[The acceptance record](ACCEPTANCE-4.md) sets out what was verified
independently, what the participant disclosed against their own interest, and
what still rests on their word.

Registration stays open. Each further contribution from a party the operator
does not control widens the ground the ceremony stands on, and that is worth
more than any number of further operator-run ones.

Read the acceptance records rather than the count. Contribution 4 is what
closed the gate and does so on its own; contribution 5's acceptance record
sets out both the participant's declaration and what the operator observed
about the machine it ran on, so that a reader can weigh the entry themselves
instead of reading `true` off a register.

[Contribution 5, from onemailweb3-design](CONTRIBUTION-5.md), and the
[operator's acceptance record](ACCEPTANCE-5.md);
[download the participant's bundle](https://github.com/onemailweb3-design/tos/releases/tag/shielded-pool-phase2-contribution-5-onemailweb3-design);
submitted as [PR #116](https://github.com/tosnetwork/tos/pull/116). Its first
four contributions were byte-identical to this chain and the mathematics
audits five.

[Contribution 4, from BmswapProtocol](CONTRIBUTION-4.md), and the
[operator's acceptance record](ACCEPTANCE-4.md);
[download the participant's bundle](https://github.com/BmswapProtocol/tos/releases/tag/shielded-pool-phase2-contribution-4).
The bundle matched SHA-256 `f3065f74d72f50f7a6e5da3a685fe0804a8fa1a3cbf52d87b331d0851c3ca3e1`,
its first three contributions were byte-identical to this chain, and the
mathematics audits four.

[Contribution 3 and verification evidence](CONTRIBUTION-3.md);
[download the public bundle](https://github.com/tosnetwork/tos/releases/tag/shielded-pool-phase2-contribution-3);
[server publication receipt](contribution-3-publication-receipt.json).
The bundle matched SHA-256 `3fe7f063eec267044d24371bfa21e2af91e7a62dcd0a70a3db9abac7f367263c`.

[Contribution 2 and verification evidence](CONTRIBUTION-2.md);
[download the public bundle](https://github.com/tosnetwork/tos/releases/tag/shielded-pool-phase2-contribution-2);
[server publication receipt](contribution-2-publication-receipt.json).
The bundle matched SHA-256 `b7ccbe20ec1d6e7a07a8f89b3ebc3ada636718cc52ec86304f9a572586071413`.

[Contribution 1 and verification evidence](CONTRIBUTION-1.md).
[Download the public contribution bundle](https://github.com/tosnetwork/tos/releases/tag/shielded-pool-phase2-contribution-1);
[server publication receipt](contribution-1-publication-receipt.json).
The privacy-cleaned bundle matched SHA-256 `1af43216e0231c36c94eb8bc037a68ec1218a7ab7568b49ea54dd491f51d981b`.

See [ANNOUNCEMENT.md](ANNOUNCEMENT.md) for the fixed parameters and open
registration rules. The publication receipt was recorded before opening.

See [privacy cleanup and signed commit mapping](PRIVACY-CLEANUP.md) for the
metadata-only history rewrite and unchanged signed artifact payloads.

## If you are going to contribute

**[`PARTICIPANT-GUIDE.md`](PARTICIPANT-GUIDE.md)** — every command, from an
empty VPS to a published attestation. It assumes you have never seen this
repository. Roughly 25 minutes, most of it waiting.

## This is the second attempt, and the reasons matter

A first ceremony was run and **withdrawn on 2026-09-22**. Its directory has
been removed rather than kept alongside this one — two ceremony directories
invite exactly one mistake, which is contributing to the wrong one, and it
produced nothing worth keeping. It remains in git history: the artifacts were
added in `7ec052e00` and `7ed85e8dc`, and removing them here does not remove
them from the repository's past.

The three reasons it was withdrawn are written down here because **every one
of them is invisible in the artifacts afterwards** — a ceremony that made all
three mistakes produces a file indistinguishable from one that made none.

### 1. The beacon was a block that had already been mined

It named a Bitcoin block that was already six deep. The announcement said so,
and said a redo should use a future height, but being honest about a weakness
does not remove it: every contributor could read the beacon before drawing
their scalar.

**What this ceremony does instead:** the beacon is a block that does not
exist, and contributions close 144 blocks before it. Independent publication
evidence must establish that contributions closed before the beacon became
known. The height gap supplies a schedule, not a proof of unpredictability;
the ceremony tools do not enforce the deadline.

### 2. Nothing verified signatures

The contribution script could sign from the day it was written, and **no tool
in this repository ever checked a signature.** A ceremony with nine forged
attestations and one with nine genuine ones passed every check that existed,
identically. An instrument that answers by staying silent.

**What this ceremony does instead:**
`test/shielded-pool/verify-attestations.py` exists *before* the ceremony
opens, and it refuses a document naming a contribution the chain does not
contain, a valid document moved to another position, a signature from a key
nobody published, a genuine signature over different bytes, a roster listing
one key under two names, and a ceremony in which no verified contribution
comes from anyone declared independent of the operator. Twenty-three cases
exercise acceptance and refusals for specific reasons.

### 3. The announcement and the first contribution were published together

Both arrived in the same push, minutes apart. No outside observer saw the
announcement while it was still a commitment rather than a description, so
"announced first" could only be asserted by the party who wrote both.

**What this ceremony does instead:** the announcement is published and
archived, with the publication recorded, before `phase2-begin` is run at all.

### What was *not* wrong with it

Worth stating, because withdrawing a ceremony invites the assumption that the
machinery failed, and it did not. The mathematics audited, the chain linked,
the starting key rebuilt from the committed phase-1 slice, and the result
cross-checked against a second pairing library. **The same code runs this
ceremony.** It was withdrawn for what surrounded the computation.

No contribution carries over. The starting key is the same digest, but that
is a property of the construction — it is a function of the circuit and the
phase-1 slice, not of any ceremony.

## Open participation

The operator has removed the requirements to fix the entire participant list,
use old signing keys, or name outside verifiers before opening. Participants
may join throughout the contribution window, and newly generated signing keys
are accepted. Register each public key and identity before accepting its
contribution, then publish the register revision and digest with that contribution.

An operator contribution can be first. It is valid but does not count as an
independent participant. Outside participation and verification remain final
acceptance conditions; neither needs to be arranged before the first contribution.

| Step | State |
|---|---|
| Publish fixed circuit, code revision, deadline and beacon | see published announcement |
| Publish and retain announcement snapshot and publication receipt | completed before opening |
| Register tosman and its new public signing key | public key and initial register published |
| Open and accept the first signed contribution | completed: tosman, not independent |
| Register and accept additional participants | open: tosdev2 and tosdev3 registered and accepted, neither independent |
| Accept a contribution from an independent party | **not done; the final gate refuses without it** |
| Close, apply the announced beacon, verify and accept | only after all final gates pass |

The confirmed heights remain **970141** (close) and **970285** (beacon).
The initial register is not a closed list. Never rewrite accepted identities,
keys or contributions; publish additions with their history.

## Files

- [ANNOUNCEMENT.md](ANNOUNCEMENT.md): formal announcement.
- [PARTICIPANT-GUIDE.md](PARTICIPANT-GUIDE.md): contribution instructions.
- [roster.template.json](roster.template.json): registration format.
- [keys/tosman.md](keys/tosman.md): first contributor's public signing identity.
- [keys/tosdev2.md](keys/tosdev2.md): second contributor's public signing
  identity, and what is missing from it.
- [keys/tosdev3.md](keys/tosdev3.md): third contributor's public signing
  identity, on a differently hosted machine, and what that does not change.

The published announcement and publication receipt identify the opening.
The beacon and final verification results appear only after closing.
Operator procedure: [runbook](../../doc/shielded-pool-phase2-runbook.md).
