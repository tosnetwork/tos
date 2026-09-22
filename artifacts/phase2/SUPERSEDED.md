# SUPERSEDED — this ceremony was withdrawn and must not be deployed

**Status: withdrawn, 2026-09-22. Kept as a record of what was done, not as a
source of parameters. No verifying key derived from this directory may be
deployed, frozen into genesis, or published as a TOS shielded pool parameter.**

It is replaced by [`../phase2-ceremony-2/`](../phase2-ceremony-2/).

## Why it was withdrawn

Three reasons, in descending order of how much they matter.

### 1. The beacon was a block that already existed

`ANNOUNCEMENT.md` pins Bitcoin block **968100**, and states that the block was
already six deep when it was fixed. That announcement was honest about the
weakness — it says so in its own text, and says a redo should use a future
height — but honest about a weakness is still the weakness.

A beacon exists so the finished parameters depend on a value **nobody could
predict while contributing**. Every contributor to this ceremony could read
the beacon before drawing their scalar. What remained was the narrower
property that the beacon was fixed *before* contributions and so could not be
chosen adaptively at closing time. That is worth something and it is not the
property the beacon is for.

### 2. Nothing was signed, and nothing verified signatures

Contribution 1 is unsigned. `attestation-1.txt` explains why, and the reason
given is correct — an agent has no identity that predates the ceremony, and
minting a key to sign with produces a signature anyone could have made.

The deeper problem is on the other side: **no tool in this repository checked
attestations at all.** The contribution script could sign; nothing verified.
A ceremony where every attestation is forged and one where every attestation
is genuine produced identical output from every check that existed. That is
an instrument that answers by staying silent, and the fix is not to sign the
old one — it is to build the verifier first, which
`test/shielded-pool/verify-attestations.py` now is.

### 3. The announcement and the first contribution were published together

The runbook requires the announcement to be public *before* anyone
contributes. Here both arrived in the same push, minutes apart. No outside
observer saw the announcement while it was still a commitment rather than a
description, so "announced first" cannot be evidenced from outside this
repository — only asserted by the party who wrote both.

## What was *not* wrong with it

Stated because withdrawing a ceremony invites the assumption that the
machinery failed, and it did not:

- the mathematics audits. Every contribution in `ceremony/` verifies, the
  chain links, the proof of knowledge holds, and the result was cross-checked
  against a second pairing library;
- the starting key rebuilds from the committed phase-1 slice to the digest
  this directory states;
- no secret was ever written, printed or retained, and there is nowhere in
  this directory for one to go.

The ceremony was withdrawn for what surrounded the computation, not for the
computation. The same code runs ceremony 2.

## What carries over, and what does not

| | |
|---|---|
| the tooling | carries over, with attestation verification added |
| the circuit and phase-1 slice | carry over unchanged |
| the starting key | rebuilds to the same digest — it is a function of the circuit and the slice, not of a ceremony |
| **the contributions in `ceremony/`** | **do not carry over.** Ceremony 2 begins from the starting key again |
| **the beacon** | **does not carry over.** Ceremony 2 names a height that has not been mined |

Contribution 1 is not re-used. It could be, arithmetically — but it was made
before an announcement that no longer stands, under a beacon that no longer
applies, and carrying it forward would mean the new ceremony's record pointed
at an attestation describing a different ceremony. A contribution costs about
two minutes; the confusion would outlast that by years.
