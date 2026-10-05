# Local CI replay

Runs this repository's pull-request workflows on a local machine, against one
exact commit, so a change is verified before anyone waits on GitHub. GitHub
CI remains a second signal, not the verification of record.

```
scripts/local-ci/run.sh <commit> [options]
```

`run.sh` supplies the one Python dependency (PyYAML) through `uv` and runs
`local_ci.py`. Docker must be usable by the invoking user.

## What it does

1. **Clone.** Makes a fresh `--depth 1` clone of the exact commit from
   `--source` (default: the repository this script lives in; a URL works too,
   with a full 40-hex commit id). The base for path filters and changed-file
   checks is the merge base of the commit with `origin/<base-branch>`.
2. **Images.** Builds `Dockerfile.builder` target `builder-24` from the commit
   under test as `tos-builder-local:24-<blob id of Dockerfile.builder>`, and on
   top of it the hosted-runner layer `Dockerfile.runner` as
   `tos-local-ci-runner:24-<blob id>-<layer hash>`. Existing tags are reused.
3. **Plan.** Reads `.github/workflows/*.yml` from the commit and selects every
   workflow whose `pull_request` trigger fires for this change (base-branch
   filter, `types`, `paths`/`paths-ignore` against the changed files). Job-level
   `if:` is evaluated for a `pull_request` event, matrices are expanded, and
   `needs:` is honoured.
4. **Run.** Each job gets its own container. The clone is copied onto the
   container overlay (the Docker root's disk, not a bind mount), owned by uid
   1001. Jobs with `container:` run in the builder image as root at
   `/__w/tos/tos`, so a root `git` meets the same "dubious ownership" refusal it
   meets on GitHub; hosted-runner jobs run as uid 1001 (`runner`, password-less
   sudo) at `/home/runner/work/tos/tos`. Every `run:` block is executed with the
   shell GitHub would use (`bash -e`, or `bash --noprofile --norc -eo pipefail`
   for `shell: bash`), with `GITHUB_OUTPUT`, `GITHUB_ENV`, `GITHUB_PATH`,
   `GITHUB_WORKSPACE`, `RUNNER_TEMP` and the `${{ }}` expressions evaluated.
5. **Report.** `summary.txt`, `summary.md` and `summary.json` in the results
   directory, one log per step under `logs/<workflow>/<job>/`, and the exit
   status is nonzero if any step failed.

A step is `pass` only if its command ran and exited 0. Everything that did
not run is `skip` with the reason: an earlier failure, a false `if:`, an
unsupported runner, an action that is not replayed, or an exclusion flag.

## Options

| option | effect |
|---|---|
| `--workflow wf[:job]` | run only these (repeatable); default is the PR-triggered set |
| `--exclude wf[:job]` | report these as skipped (e.g. the ASAN jobs) |
| `--skip-step REGEX` | skip steps whose `workflow:job:step` matches (e.g. mutation runners) |
| `--jobs N` | rewrite `-jN`, `-j"$(nproc)"`, `--parallel N` on cmake/ninja/make lines to N; each rewrite is printed in the step log |
| `--cpuset 0-95` | CPUs given to every job container (`nproc` inside reports this many) |
| `--parallel K` | jobs at once (default 2) |
| `--min-free-gb G` | do not start a job while less than G GiB is free (default 30) |
| `--repeat-step REGEX:N` | run matching steps N times, failing on any round (randomized suites); each round has its own log |
| `--base COMMIT` | base for path filters and changed-file checks; use `<merge>^1` to replay a merged pull request on the base branch |
| `--keep-going` | run a job's later steps after a failure; GitHub would not, and such steps are annotated |
| `--no-cache` | do not emulate `actions/cache` (cold compiler caches) |
| `--base-branch`, `--head-branch`, `--pr` | values for the `github` context |
| `--list` | print the plan and the workflows that are not triggered, then exit |
| `--keep` | leave job containers in place for inspection |

Example, the full PR set on 96 cores:

```
scripts/local-ci/run.sh 92722f4bd --pr 135 --head-branch fix/security-findings \
  --jobs 96 --cpuset 0-95 --parallel 3 --keep-going
```

Post-merge, on the merge commit, with the randomized command suite run three times:

```
scripts/local-ci/run.sh <merge-commit> --base <merge-commit>^1 --jobs 96 --parallel 3 --keep-going \
  --repeat-step 'Run command tests including backup:3'
```

Only the fast source checks:

```
scripts/local-ci/run.sh HEAD --workflow source-guards --workflow build-tos-linux-x86-64-werror:hygiene \
  --workflow no-removed-execution-domains-scan
```

## Actions

| action | replay |
|---|---|
| `actions/checkout` | the pre-made depth-1 clone; `fetch-depth: 0` deepens it from the source with every remote branch and tag |
| `actions/setup-python` | the requested Python from the image's tool cache (installed with uv) put first on `PATH` |
| `astral-sh/setup-uv` | the image's uv put on `PATH` |
| `dtolnay/rust-toolchain` | `rustup toolchain install` + `rustup default` |
| `actions/cache`, `cache/restore`, `cache/save` | the cached path becomes a symlink into a persistent local volume (`tos-local-ci-cache`), keyed by path |
| `Swatinem/rust-cache` | skipped; the cargo registry is shared through the same volume, target directories are cold |
| `actions/upload-artifact` | files copied to `artifacts/<job>/<name>` in the results directory |
| local composite actions (`./.github/actions/*`) | executed step by step |
| anything else | skipped, with the action named |

`docker` inside a hosted-runner job is a stand-in (`shim/docker`): pulling and
running the repository builder image runs the command in the job container,
which is built from the same Dockerfile target; any other use (a detached
service container, another image) is reported as `skip` because the step
cannot run here.

## Differences from GitHub that remain

- The commit itself is tested, not GitHub's merge commit with the base branch.
- The hosted runner is approximated by `Dockerfile.runner`; tool versions that
  a workflow does not pin (Node.js, stable Rust, the runner's preinstalled
  packages) can differ. Jobs that ask for `ubuntu-22.04` run on the 24.04
  image, and the summary says so.
- Job containers get `net.unix.max_dgram_qlen=512`, the value a systemd host
  (and the hosted runner VM) sets; a fresh Docker network namespace has 10,
  which makes bursts over Unix datagram sockets drop.
- With `--jobs`, build parallelism differs from the workflow's `-j2`; test
  invocations are not changed.
- `timeout-minutes` and `concurrency` are not enforced.
- Not replayed, because they need GitHub itself: jobs on arm64, macOS or
  Windows runners; reusable workflow calls; artifact downloads between
  workflows, including jobs that compare results across architectures;
  steps that need real Docker; registry logins and image pushes; jobs gated on
  `workflow_dispatch` or `push` (they are reported as skipped by their `if:`).

## Disk and cleanup

Results default to `~/.cache/tos-local-ci/<commit>-<time>/` (clone, logs,
summaries). Job containers are removed when each job ends; build trees live
only inside them. The images and the `tos-local-ci-cache` volume are kept for
the next run; remove the volume to reclaim its compiler caches.
