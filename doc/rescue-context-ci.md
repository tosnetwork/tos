# Rescue context CI suites

`rescue-context.yml` runs the same serial corpus in isolated jobs. The baseline is
main commit `8bf39647d6cde0b00fc8c49e8ecb354be85d4897`. Its 52 named build/control
steps (one build and 51 test/control groups) and their exact shell bodies are
pinned in `test/wallet-quantum/rescue-ci-contract.json`.

| Suite | Architectures | Scope |
| --- | --- | --- |
| fee-lifecycle | x86-64, ARM64 | Fee baseline, CLI preparation, custody, sessions and POP receipts |
| fee-successor | x86-64, ARM64 | Successor tree, key reuse rejection and joint migration |
| fee-promotion | x86-64, ARM64 | Successor tree, installed route rotation and repeated recovery |
| signer-core | x86-64, ARM64 | Rust native wallet signer and proven-key controls |
| signer-custody | x86-64, ARM64 | Native signer, SDK wire, restoration and custody controls |
| release-wallet | x86-64, ARM64 | Generated admission configuration, whole transactions, release bundle, SDK recovery and receiver delivery |
| vm-ingress | x86-64, ARM64 | Receipt-bound timing, ingress, Falcon/version checks and C++/Rust VM parity |
| mutations | x86-64 | The formerly x86-only fee/VM deletion and mutation controls |

Existing x86-only controls inside the other suites remain x86-only. There are
15 workers, with a matrix parallelism limit of 16 so all can start together.
The longest suites are listed first if hosted capacity causes a queue.
Every worker retains the original 180-minute timeout; tests, iteration counts,
compiler flags, native `-j2` setting and failure behavior are unchanged.

Each worker checks out the exact PR head, builds its own native/Rust drivers and
regenerates its prerequisites in original order. Shared configuration, SDK and
fee baselines are repeated where needed. Mutable LMS trees, custody stores and
journals are never transferred between workers. Controls which rewrite source
and rebuild binaries stay serial within their own workspace. Every worker must
restore tracked source before emitting a success receipt.

The existing native-cache action caches only C/C++ objects, with its compiler,
CPU and runner-image identity and strict content-based keys. The rescue profile
is capped at 1 GiB per worker. No test results, Rust target trees, signing state
or generated transaction fixtures are cached. Rust feature builds remain local
so mutation controls do not reuse another worker's modified binaries.

Public artifacts have unique architecture/suite names and retain the existing
14-day retention and exclusions for test-only LMS trees. Small success receipts
are uploaded separately. The two existing `parity (ubuntu-24.04, 180)` and
`parity (ubuntu-24.04-arm, 180)` checks remain as final gates. Both require the
entire matrix to succeed and all 15 receipts to match the source SHA, run ID,
coverage contract and expected check list. Attempt-specific artifact names avoid
upload collisions on partial reruns. Successful workers from an earlier attempt
of the same source/run remain valid, and the newest receipt per worker is used.
Duplicates within one attempt, foreign/future receipts and incomplete coverage
fail the gate. The matrix-result check still rejects a failed or cancelled
current worker, even if an older success receipt exists.

## Maintenance and validation

The coverage checker and its negative controls run before native builds and in
the existing required `source-guards` job. They reject dropped/changed commands,
lost architecture coverage, skipped controls, missing prerequisites, reordered
steps, optional receipts and swallowed matrix failures. Intentional corpus
changes require an explicit contract update and review.

```sh
python3 scripts/check-rescue-context-ci.py
python3 scripts/test_rescue_context_ci.py
# Also validate both changed workflows with actionlint.
```

## Timing and the one-hour target

The first nine-worker run (38839495687) passed in 1h53m29s, compared with
2h51m06s for the serial workflow in run 38827740352. Its ARM fee suite still
took 91m38s, and four-worker scheduling delayed later suites. Raising parallelism
alone cannot remove that serial bottleneck.

The refined schedule separates the Rust signer block from custody and divides
fees into initial/session, successor/migration and installed-route groups.
Each fee worker independently builds the CLI and regenerates its needed baseline,
recovery tree and successor fixture. Exact original command bodies are unchanged.

Using the maximum observed duration of each original step on each architecture,
plus corresponding setup/helper durations, the projected longest worker is
55m02s. This assumes simultaneous starts and comparable hosted hardware/load;
it excludes runner queueing and is not a measured result for the new schedule.
See `rescue-context-ci-timing.json` for per-worker estimates and source evidence.
The matrix limit does not increase account or ARM runner capacity. A sub-hour
workflow cannot be guaranteed if runners queue or the corpus runs more slowly.
Cold runs repeat builds and prerequisites, increasing total runner minutes.

## Local checks before pushing

Run the coverage checker and negative controls above, actionlint, Ruff on both
Python files, and `git diff --check` locally before pushing workflow changes.
For test-body changes, also run the affected native/Rust/Python control locally
with its prerequisites and verify that its intended negative assertion can fail.
Local checks catch wiring mistakes before using hosted runner time. They do not
replace Linux x86/ARM execution, full receipt coverage, or mandatory checks.
See `rescue-context-ci-validation.json` for local evidence and outstanding CI.
