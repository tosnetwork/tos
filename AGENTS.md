# Working on tos

## Instruments lie by staying silent

A measurement that returns nothing is not an answer. Before trusting silence,
prove the instrument speaks.

This is the single most expensive failure mode in this repository, because the
things we build here — a VM, a consensus engine, contracts that hold other
people's money — all fail quietly by default. A contract that was never
deployed reports no bugs. A test that was never compiled prints no failures.

### A test that cannot fail is not evidence

Before believing a new test, **remove the thing it tests and watch it go red.**
If it stays green, it is measuring nothing, and you have learned nothing.

This applies with full force to negative tests — "malformed input is rejected",
"the unauthorized caller fails", "the overflow is caught". Those are the tests
most likely to pass for the wrong reason, because *any* error makes them pass,
including an error in the test setup that means the code under test never ran.

### Local traps that have already cost someone an hour

**A frozen BOC does not track its source.** Editing
`crypto/smartcont/*.fc` does not update the compiled artifact. For the
prediction market the chain is:

```
crypto/smartcont/prediction-market-code.fc          # source you edited
scripts/update-prediction-market-code.py            # regenerates
crypto/smartcont/prediction-market-v1.boc.base64    # frozen artifact
tosctl/src/node-control/contracts/tests/prediction_market_sandbox.rs   # runs the artifact
```

Run the sandbox without regenerating and it exercises the **previous** contract
while reporting on your new one. Every other frozen-artifact contract has the
same shape. Regenerate, then check the artifact's diff is only what you meant.

**An unreachable `throw_unless` looks exactly like a working one.** A phase gate
whose condition is already guaranteed by a different function's invariant never
fires, never fails a test, and silently stops protecting anything the day that
other invariant moves. When you add a guard, construct the input that trips it.
If you cannot, the guard is decoration — either it is redundant, or the
condition is wrong.

**Compiling a contract is not running it.** FunC accepts a great deal of code
whose first execution throws. Compute-phase unit tests are not enough for
anything that emits actions: action-phase failures roll back state in ways that
only a sandbox with a real action phase will show.

**Gas numbers in comments rot.** A comment claiming a path costs N gas is a
claim about a build that may no longer exist. Re-measure before relying on it;
if you rely on it, say which commit measured it.

**A doc line can be stale and backwards at the same time.** `800e6d1a2` corrected
a README that framed a shipped component as future work and understated proof
sizes by 10×. It had been wrong for weeks and nothing failed. Verify docs
against source, not against memory.

## Review at the milestone, and at the consensus boundary

Have Claude Code review the work when a milestone is finished — M0, M1, M2 and
so on. Do not stop for a review after each file, each fix, or each instrument;
that costs more than it returns.

```
cd /home/tomi/tos && claude -p "<what changed, which findings it closes, what to look at>"
```

One exception, kept narrow because late discovery there is the expensive kind:
review as soon as it lands, without waiting for the milestone, when a change
touches consensus judgement — `validate-query.cpp`, `collator.cpp`,
`transaction.cpp`, `workchain-execution-dispatch.cpp` — or adds an error
classification. Everything else waits.

At a milestone the review is large, so say what changed and which findings it
closes rather than asking for a read of the whole diff.

Four things the review must check, because each has already gone wrong here:

1. **Error classification.** For every new failure path: is this an invalid
   candidate the network must reject, or a local fault this node must abstain
   on? Conflating the two lets a crafted input make honest nodes abstain, or
   makes a node with missing data reject a valid candidate.
2. **Whether the test can fail.** Remove what it tests and watch it go red. A
   test whose dependency is missing must fail, not skip. An assertion with no
   diagnostic output produces an empty log, and an empty log cannot be told
   apart from a build that never ran.
3. **Arithmetic.** Checked operations throughout. Before any subtraction, state
   the invariant that keeps it from underflowing — write it down rather than
   trusting it.
4. **Exception classes.** Does each new `catch` cover what is actually thrown?
   `CellCreateError` and `CellWriteError` do not derive from `VmError`; three
   catch clauses once missed both and the thread terminated.

Act on the result: apply what you agree with, write down why for what you do
not, and stop and ask for anything that needs an owner decision. Say in the
commit message that it was reviewed.

Between reviews you are on your own for the four checks above. Run them
yourself as you write — they are cheap to apply and expensive to retrofit,
and the first review under this rule found two tests that appeared to run and
did not.

Review transcripts are working material, not repository documentation. Keep
them in `~/memo/reviews/`; what lands here is the fix and the test.

## Conventions

- Everything in this repository is written in English: documents, comments,
  identifiers, commit messages, test names, and assertion text. This is a
  public repository read by people who do not read Chinese, and it shares a
  tree with upstream-derived code. Working material outside the repository has
  no such constraint.
- Financial arithmetic uses `checked_*`, never raw `+ - * /`. A bound that
  holds "because of a limit declared elsewhere" is not a checked operation —
  it is a dependency on a constant nobody will remember to re-check.
- Every `Result`/`Option` is handled explicitly. No `.unwrap()` in production
  paths.
- Verification and execution stay separate: `verify` is read-only and predicts
  nothing; all state change happens in `apply`.
- Do not reference external project names or issue trackers in comments or
  commit messages. Comments explain intent, not history.

`CLAUDE.md` is a symlink to this file, so Codex and Claude Code read the same
instructions.
