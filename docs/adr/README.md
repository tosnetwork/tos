# Architecture Decision Records

This directory holds the Architecture Decision Records (ADRs) for the
TOS Blockchain Library.

## What an ADR is

An ADR is a short, durable document that captures one architectural
choice the project has made: the context that forced the decision,
the alternatives considered, the decision itself, and the consequences
the team is committing to live with. ADRs are written once and then
treated as historical record. Subsequent decisions that change course
do not edit the original — they author a new ADR that supersedes it
and link back.

A good ADR answers, ten years later, the question "why is the system
this way and not the other plausible way?"

## Index

| Number   | Title                                              | Status   |
| -------- | -------------------------------------------------- | -------- |
| ADR-0001 | [Streaming cell import and DAG residency](0001-streaming-cell-import-and-residency.md) | Accepted |

## Conventions for adding a new ADR

1. Pick the next sequential number, four digits, zero-padded
   (e.g. `0002`).
2. Create `docs/adr/NNNN-short-kebab-case-title.md`.
3. Use the following section skeleton:
   - `# ADR-NNNN: Title`
   - `## Status` — one of `Proposed`, `Accepted`, `Superseded by
     ADR-XXXX`, `Deprecated`. Include the date in the form
     `YYYY-MM-DD`.
   - `## Context` — what forces the decision; the constraints
     applicable at the time.
   - `## Decision` — the choice made, in declarative voice.
   - `## Consequences` — both the benefits the team accepts and the
     costs the team commits to live with.
   - `## References` — file paths (with line ranges where helpful),
     commit hashes, audit notes.
4. Add a row to the index table above. Keep the table sorted by
   number ascending.
5. Cite file paths with line numbers wherever possible. ADRs are
   read against future code; a stable path + line range that
   resolves under `git blame` years later is more useful than a
   floating prose reference.
6. Never delete or rewrite an accepted ADR. To revoke or amend it,
   write a new ADR with status `Supersedes ADR-XXXX` (or
   `Deprecated`) and link both directions.
