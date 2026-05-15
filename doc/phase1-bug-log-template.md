# Phase 1 Closed Testnet — Bug Log

> **Status**: open ledger; append-only.  Every issue surfaced during
> Phase 1 closed testnet lands here BEFORE it's worked on.  An entry
> with no resolution is fine — it's open work; an issue surfaced and
> never logged is a process failure.
>
> See [`phase1-bring-up.md`](phase1-bring-up.md) §4 for severity
> definitions.

---

## Template (copy + fill for each new entry)

```markdown
### #NNN  <short title>

* **Severity**: P0 / P1 / P2 / P3
* **Reported**: YYYY-MM-DD by @<reporter>
* **Reproducer**: <one-line command or test scenario>
* **Observed**: <what actually happened>
* **Expected**: <what should have happened>
* **Workchain**: wc=0 / wc=1 / wc=2 / wc=3 / cross
* **Reproducible?**: yes / sometimes / once
* **Validator(s) affected**: all / specific operator(s)
* **First seen at commit**: <git sha>
* **Status**: open / triaged / in-progress / fixed (commit) / wontfix

**Details**

<paragraph or two of context, log excerpts, etc.>

**Resolution**

<empty while open; filled with commit sha + Phase-N reference once fixed>

---
```

## Severity ladder

| Sev | Definition | Action |
|---|---|---|
| **P0** | Consensus divergence; data loss; validator crash; `sk_bad_state` on a should-work tx | **Halt testnet**; fix; relaunch with new genesis |
| **P1** | Wrong result on a documented happy path; DoS surface admitted in production | Fix before continuing; no halt unless reproducer trivial |
| **P2** | UX issue; doc gap; surprising-but-correct behavior | Track, batch-fix |
| **P3** | Cosmetic; observability gap | Track for Phase 2 (public testnet) |

## Triage SLA

* P0 → respond within 2 hours, fix within 24 hours
* P1 → respond within 1 business day, fix within 1 week
* P2 → respond within 1 week, fix in a batched release
* P3 → no SLA; review at end-of-week

## Closure rules

Before marking an entry **fixed**:

1. The commit that closes it MUST cite the bug ID in its message
   (so `git log --grep '#NNN'` works).
2. A regression test MUST be added that would have caught the
   bug.  (If "no automated test possible," explain why explicitly
   and have a second reviewer agree.)
3. The next-week stand-up reviews recently-closed entries to
   verify the fix held.

## Pre-seeded entries (carried over from engineering arc)

These are the issues that the Phase O–FF engineering audit
identified BEFORE Phase 1 started.  They're listed here so the
test plan can verify they stay fixed during Phase 1 operation:

### #000  Reference: Phase DD critical consensus bug (FIXED before Phase 1)

* **Severity**: P0
* **Reported**: 2026-05-14 by Phase-DD audit
* **Reproducer**: Deploy any wc=3 contract via `tosctl jw deploy-contract`
  with the documented `--stdlib-hash` value; call any method on it.
  Pre-fix: every call rejects with `sk_bad_state`.
* **Observed (pre-fix)**: `JVAC.stdlib_hash` (plain `sha256(rt.jar)`)
  never matched `runtime->rt_jar_hash()` (domain-tagged hash).
* **Expected**: hashes match; calls succeed.
* **Workchain**: wc=3
* **Reproducible?**: yes (every deploy)
* **Validator(s) affected**: all
* **First seen at commit**: pre-Phase-DD
* **Status**: fixed (`c14a21f80` Phase DD + `58a2b7292` Phase EE
  direct parity test)

**Details**

The off-chain `default_activation_with_stdlib` used plain
`sha256(stdlib_bytes)`; the on-chain runtime's
`hash_boot_classpath` used a domain-tagged + length-prefixed +
trailing-count-anchored hash.  The dispatch engine compares the
two on every wc=3 call (gate at `dispatch-engine.cpp:350`).
Phase DD extracted a shared `compute_canonical_stdlib_hash`
helper and rewired both call sites through it.

**Resolution**

Phase DD landed the algorithm alignment + the
`Test_JvmWorkchainCore_StdlibHashAlgorithmAlignment` regression
test.  Phase EE added a direct parity test that writes bytes to
a tempfile and asserts `hash_boot_classpath(file) ==
compute_canonical_stdlib_hash(bytes)`.  Future drift breaks both
tests in lockstep with the actual consensus failure mode.

**Phase-1 verification action**: confirm `journalctl -u
tos-validator@1 | grep stdlib_hash` shows the canonical post-DD
value `ae4ff3b7e557a8acffe31e9b41959e811c67dea87b6c6c3e38129466e5ade765`
on every validator boot.

---

## (New entries below this line)

<!-- Append-only.  Newest at the top. -->
