# Phase-2 ceremony 1 — WITHDRAWN

**This ceremony was withdrawn on 2026-09-22. It is kept as a record. Nothing
in this directory may be contributed to, deployed, or frozen into genesis.**

Why it was withdrawn: [`SUPERSEDED.md`](SUPERSEDED.md).

## Go here instead

| | |
|---|---|
| the live ceremony | [`../phase2-ceremony-2/`](../phase2-ceremony-2/) |
| **if you are contributing** | [`../phase2-ceremony-2/PARTICIPANT-GUIDE.md`](../phase2-ceremony-2/PARTICIPANT-GUIDE.md) — every command, from a bare VPS |
| the announcement | [`../phase2-ceremony-2/ANNOUNCEMENT.draft.md`](../phase2-ceremony-2/ANNOUNCEMENT.draft.md) — still a draft; it becomes `ANNOUNCEMENT.md` when published |
| the procedure | [`../../doc/shielded-pool-phase2-runbook.md`](../../doc/shielded-pool-phase2-runbook.md) |

## What is still in this directory, and why it is not edited

```
ANNOUNCEMENT.md     the announcement as it was published. Unedited.
attestation-1.txt   what contribution 1 said. Unedited.
beacon.bin          the block hash this ceremony would have closed with
ceremony/           the starting key, one contribution, and the record
```

`ANNOUNCEMENT.md` and `attestation-1.txt` are the published record and are
left byte-for-byte as they went out. Editing a published announcement is the
thing this whole process exists to prevent, and a withdrawn ceremony whose
announcement had been quietly improved afterwards would be worth less than one
that stayed wrong in public.

This file is different: it is a status page, not a record. It used to say
"open, announced, one contribution" and gave instructions for contributing.
Leaving that in place would have pointed the next reader at a beacon that no
longer applies and a chain that will never be closed — a stale status page is
a hazard in a way that a stale historical document is not.

## The arithmetic here was never the problem

Every contribution in `ceremony/` verifies, the chain links, and the starting
key rebuilds from the committed phase-1 slice to the digest this directory
states. It was withdrawn for what surrounded the computation — an
already-mined beacon, no verifier for the attestations, and an announcement
published in the same push as the first contribution.

The same code runs ceremony 2.
