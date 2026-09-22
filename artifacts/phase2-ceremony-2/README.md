# Phase-2 ceremony 2 — not open

**Status: being prepared. Nothing has been contributed. No parameters from
this directory exist yet, and none may be deployed.**

Ceremony 1 is withdrawn — [`../phase2/SUPERSEDED.md`](../phase2/SUPERSEDED.md)
says why. Its directory is kept unedited, because editing a published
announcement is the thing this whole process exists to prevent.

## What has to happen before this opens

In this order. The order is the point: each step is only worth something if
the ones before it are already public.

| # | step | who | state |
|---|---|---|---|
| 1 | attestation verification exists and can fail | done | `test/shielded-pool/verify-attestations.py`, 19 cases, each watched to fail |
| 2 | recruit participants, at least one independent of the operator | **operator** | **blocked — needs people** |
| 3 | collect each participant's already-public signing key into `roster.json` | operator | blocked on 2 |
| 4 | fix the beacon height and the closing height | operator | **confirmed 2026-09-22**: close 970,141, beacon 970,285 |
| 5 | publish the announcement, archive it, record where and when | operator | blocked on 2–3 |
| 6 | run `phase2-begin`, publish the starting digests | operator | blocked on 5 |
| 7 | contributions, in any order, each signed | participants | blocked on 6 |
| 8 | close at the announced beacon, verify from outside | verifiers | blocked on 7 |

## If you are going to contribute

**[`PARTICIPANT-GUIDE.md`](PARTICIPANT-GUIDE.md)** — every command, from an
empty VPS to a published attestation. It assumes you have never seen this
repository. Roughly 25 minutes, most of it waiting.

## What is in here

```
ANNOUNCEMENT.draft.md    the announcement, with every undecided field marked TO FIX
PARTICIPANT-GUIDE.md     how to contribute, from a bare VPS, one command at a time
roster.template.json     the participant roster to fill in and pin
```

`roster.json`, `ceremony/`, `beacon.bin` and `attestation-N.txt` appear as the
steps above are taken. There is nowhere in any of them for a secret to go,
which is why they live in a public repository while the ceremony runs.

## Why there is a verifier before there is a ceremony

Contributions could be signed since the contribution script was written, and
**nothing anywhere verified a signature**. A ceremony with nine forged
attestations and one with nine genuine ones passed every check this
repository had, identically.

So step 1 came first this time. The verifier refuses a document naming a
contribution the chain does not contain, a valid document moved to another
position, a signature from a key nobody published, a genuine signature over
different bytes, a roster listing one key under two names, and a ceremony in
which no verified contribution comes from anyone independent of the operator.
Each of those is a test that has been watched to fail.
