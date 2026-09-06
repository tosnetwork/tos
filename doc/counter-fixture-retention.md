# Counter disk-test fixture lifecycle

The disk integration script runs inside a parent-owned lifecycle. Every child
exit of zero, including early returns and expected-rejection scenarios, removes
that run's fixture. Unexpected errors preserve the complete directory and print
`FAILED ... retained for inspection: <path>`. The active path is printed before
launch so an outer timeout or killed parent still leaves a visible location.
When the child returns, its standard output and error are saved in `lifecycle.log`
alongside the existing per-command logs. An externally killed parent may not
reach that capture step; the already-written command logs remain in the fixture.
Absence of `.completed-failure` is not evidence of success: it means active or
interrupted. Do not delete a fixture just because its parent disappeared.

Admission is serialized with a build-local CMake file lock. By default at most
16 managed fixtures may exist, including active, failed and interrupted runs.
At the cap, no new directory or worker is created. This bounds a crashloop
without evicting diagnostics or guessing which processes are still using them.
`COUNTER_MAX_FIXTURES` can explicitly change the limit for manual runs. Existing
unmarked legacy fixtures are not automatically deleted or counted as managed.

After inspecting retained failures, an operator can use the explicit Linux
maintenance utility on an idle test host:

```sh
python3 test/cleanup-counter-fixtures.py /absolute/path/to/build
python3 test/cleanup-counter-fixtures.py /absolute/path/to/build --delete
```

The first command is a dry run. The second preserves the newest ten complete
fixtures by default and archives top-level diagnostic files from the rest before
removing those exact directories. `--keep-newest` changes the retention count.
Databases in deleted fixtures are not in the archive and must be regenerated;
this is explicit destructive maintenance, not the automatic failed-run policy.
The script refuses if a test process or accessible open descriptor/cwd references
fixtures. Operators must prevent new test launches during maintenance, especially
legacy launchers that do not participate in lifecycle admission. It never scans
Rust targets, integration build trees or other worktrees as cleanup targets.

The lifecycle regression test uses tiny synthetic workers. It checks success
cleanup, failed-log retention, visible diagnostics, and admission refusal without
deleting either failed or incomplete fixtures. Mutation tests must demonstrate
that dropping cleanup, deleting on failure, and bypassing the cap each fail.
