# Platform CI scope

This document lists which platforms CI builds and tests, when, and what is deliberately out of
scope. The definitions live in `scripts/platform-matrix.json`, and
`scripts/check-workflow-policy.py` checks the workflows against them.

## Tiers

| Tier | Runs on | Members |
|---|---|---|
| per-PR gates | every pull request (unchanged) | the existing workflows, including the seven required checks |
| platform | every pull request into `main` and push to `main` that can affect a build; the nightly run; a manual dispatch | Linux x86-64 and arm64 (shared); macOS 14 arm64 (portable, shared); macOS 15 arm64 (shared) and x86-64 (portable, shared); wasm; Windows MSVC, MinGW64 and UCRT64 (client toolchain) |
| nightly | the scheduled run at 02:23 UTC and a manual dispatch | every platform member, plus Android toslib, the x86-64 and arm64 AppImages, cppcheck, and the Linux x86-64 build without the compile cache |

`.github/workflows/platform-matrix.yml` runs all tiers. Its `platform-gate` job gives one
verdict for the whole matrix (`scripts/platform_gate.py`):

- An expected member passes only if it succeeds. Skipped, cancelled or failed fails the gate.
- These also fail the gate:
  - an unexpected member that failed or was cancelled;
  - a member missing from `needs`;
  - an unknown job in `needs`;
  - a relevance job that failed or gave no valid answer.
- A documentation-only change (`doc/**`, `**/*.md`, `memo/**`, `LICENSE*`, `.gitignore`,
  `.github/ISSUE_TEMPLATE/**`) gets "not applicable" and passes.

Relevance fails safe. A change counts as documentation-only only when the diff succeeded and
listed at least one file, and every listed file is documentation. A new branch, a force push,
an unknown event or any error makes the change relevant.

The nightly run is `.github/workflows/platform-nightly.yml`, which calls the matrix and
then reports. A failing night opens or updates the issue "Nightly platform matrix is
failing", and a green night closes it. That report is the only job with a write grant. It
lives outside the matrix because a workflow that pull requests trigger holds no write
permission (`scripts/check-workflow-supply-chain.py`).

## Workflow rules

`scripts/check-workflow-policy.py` runs in the Lint workflow's `hygiene` job, a required check,
on every change, together with actionlint's structural checks. A policy violation therefore
blocks a merge. It requires:

- every job that runs steps has `timeout-minutes`;
- every workflow declares `permissions`;
- automatically triggered workflows declare `concurrency`;
- callable workflows do not group on `github.workflow`;
- release workflows never cancel a run in progress;
- no runner uses a `*-latest` label;
- no trigger names `master` or `testnet`;
- the matrix matches `scripts/platform-matrix.json`;
- inherited platform workflows run only through the matrix, by hand, or on a `v*` tag;
- release builders keep their `v*` tag;
- matrix members use no secret but `GITHUB_TOKEN`;
- a workflow that pull requests run is push-triggered only for `main`, the
  `node-health-monitor` integration branch, or tags. A push to a pull request's own branch
  falls in a different concurrency group and would run the same change a second time, and
  CI concurrency is shared by every open pull request. The cost: a pull request run tests
  the merge with its base while a branch push tests the branch head, and a branch has no
  automatic run until it has a pull request. Dispatch a workflow on the branch to test its
  head deliberately.

Timeouts follow max(30, 2 × the longest successful run in the last 20), rounded up to 10
minutes. Lanes without a successful sample start at 240 minutes (macOS, Windows) and 180
minutes (Linux, wasm). Each is revisited after ten successful runs. Existing values are
never lowered.

## Self-hosted routing

Linux x64 jobs can run on the project's own runner instead of a GitHub-hosted machine.
Each runs in a fresh VM that is discarded after the job. Every `ubuntu-24.04` job that runs
for a pull request or a push to `main` is routed, provided its workflow grants no write
permission and reads no secret beyond `GITHUB_TOKEN`. `ROUTED_FIRST` and `ROUTED_SECOND`
in `scripts/test_check_workflow_policy.py` pin the exact list. The following stay hosted:

- workflows that publish or write: releases, image pushes, cache clearing, and the
  nightly report;
- the platform matrix's orchestration jobs. A schedule there would start a whole hosted
  matrix, and the nightly workflow already exercises it;
- dispatch-only jobs, and push-only jobs on branches other than `main`, which the
  expression never routes;
- `ubuntu-22.04` jobs (the VM image is 24.04), and every arm, macOS and Windows job.

Each routed job chooses its runner with one fixed `runs-on` expression. It selects the
`tos-vm` label only when all of the following hold:

- the repository variable `SELF_HOSTED_LINUX` is `true`; and
- the event is either a push to `main`, or a pull request whose head branch is in this
  repository and whose author and triggering actor (for a re-run, the person re-running it)
  are both in the JSON list in the repository variable `CI_TRUSTED_LOGINS`.

Every other event runs on `ubuntu-24.04`, as before. That covers fork pull requests,
pull requests from anyone not listed, dispatches and schedules. Clearing the variable or
setting it to anything but `true` changes every later routing decision without a commit.
A job is routed when it is queued, and a rerun decides again. So jobs already queued for
the self-hosted label need cancelling and rerunning, and running jobs finish under the
runner's drain policy.

Each workflow with a routed job carries exactly one weekly schedule. A scheduled run is never routed,
so the hosted path runs at least once a week whatever the variable says. The jobs keep
their own package-install steps for the same reason: the VM image has those packages
preinstalled, so on the VM the steps find nothing to do, but the hosted fallback needs
them.

R12 in `scripts/check-workflow-policy.py` enforces this:

- the expression must be exactly this one (whitespace aside);
- no job may name a self-hosted label any other way;
- a workflow with a routed job must grant no write permission, use no secret beyond
  `GITHUB_TOKEN`, and have exactly one weekly schedule;
- each routed job's timeout plus a 15-minute setup margin must fit the runner host's
  165-minute per-job cap, so a hang ends at the job's own timeout.

## Deliberate exclusions

- **Windows builds the client toolchain only** (`TOS_CLIENT_ONLY`, see `BUILD.md`):
  fift, func, tlbc, tol, lite-client, toslib, toslibjson, toslib-cli and the emulator. The
  node's key and configuration files rely on POSIX file semantics that are not ported.
  Windows CI builds the client set and its tests but does not run them, as upstream does not.
- **Linux-only tests.** These are registered only on Linux, and the reason is recorded where
  each is registered:
  - `docker-validator-role` and `snapshot-import-offline`: they test the node container's
    entrypoint scripts, which run only in the Linux image (bash 4, GNU coreutils, the LP64
    `struct flock` layout, `/proc/locks`).
  - `quic-admission-global-limit` and `quic-admission-full-table`: they need 38 distinct
    loopback sources (127.0.0.2–39). Linux routes 127/8 to loopback; macOS has only 127.0.0.1.
  - The `LD_PRELOAD`/`/proc` live-commit check, and the diagnostic IPC test. The diagnostic
    channel authenticates its peer with Linux socket credentials.
- **Open on macOS:** `test-http-server-limits`, the unread-output case. It assumes the kernel
  honours 4 KiB socket buffers. The test now prints the buffer sizes the kernel actually
  granted; this item stays open until the test passes on macOS.
- **Timing bounds are enforced on Linux only.** `n6-microbench-smoke` bounds normalised
  p95 timing ratios, calibrated on Linux, the validator platform. Elsewhere the ratios are
  printed and reported, not enforced: macOS is uncalibrated, and one macOS 14 run exceeded
  a bound (3.05 against 3.0). Sizes, verification counts and the structural cap are
  enforced everywhere.
- **Packaging lanes are nightly, not per pull request.** This covers the AppImages and
  Android. They also run on every `v*` tag, which is what release collection uses. cppcheck
  reports nightly and gates nothing.
- **Shell inside workflow steps is not linted.** actionlint runs with shellcheck and pyflakes
  disabled. The inherited scripts would report many existing findings, and a check that is
  red every day gets ignored.
- **No merge queue.** No workflow declares `merge_group`. Adding it without auditing every
  checkout and event-specific script would claim semantics that were never tested.
- **The live tag path is untested by this work.** `scripts/test_release_artifacts.py`
  checks the release contract, but no `v*` tag was pushed to exercise it.

## Promotion

`platform-gate` is not a required check. Making it one is an owner decision. The intended
bar is ten consecutive green runs on `main` over at least three days, counting only runs whose
expected set was the whole platform tier. Nightly-only failures count as release blockers
after seven consecutive green nights.
