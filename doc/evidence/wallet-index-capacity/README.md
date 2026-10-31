# Replica capacity tool validation

This package validates the measurement tool. **It contains no completed real-testnet
capacity acceptance.** The intended offline EPOCH-6 generation and fresh-node
preparation evidence still have to be supplied on the measurement host.

The [runbook](../../wallet-index-replica-capacity.md) gives the production commands,
input requirements, conditional two-hour/six-hour targets, and the distinction
between measured, failed and unavailable outcomes. [validation.json](validation.json)
pins the tested files, preserves the four targeted mutation failures and restored
result, and records the two explicitly synthetic native smoke outcomes.

## Executed checks

- Twelve tests pass on Python 3.12 and through the fresh CTest registry on Python
  3.14. Ruff 0.15.2 lint and formatting pass.
- Four syntactically valid mutations each cause the intended named assertion
  failure: remove Full readiness enforcement, remove the complete target-hash
  check, count unknown preparation as zero, or remove the SIGTERM handler.
  The last control proves a native child remains alive through `kill(pid, 0)`;
  the unmodified tool terminates it and retains an interruption receipt.
- The CTest inventory includes all 66 required source guards. Removing only this
  test's generated registration makes the inventory fail with its exact missing
  name; restoring it passes. No native production rebuild is claimed for this
  configure-and-test check.
- Both native fixture paths reach Full at H=467, serve window B=400, match the
  existing independently rebuilt reference, and leave source metadata unchanged.
  Both return **exit 2 / capacity unavailable**, even with preparation set to zero,
  because the input is explicitly labelled `fixture-smoke`.

The native binaries were built at `f7535841bd860eaacd1e0f268a3571a235bf24b0`;
the service/core implementation is unchanged through the recorded base commit.
Binary hashes and the full block identities are in the JSON. These runs exercise
the actual import, service, readiness and canonical-dump commands using the
existing disposable native image. Their short timings and memory observations
are functional instrumentation evidence, not the real-replica capacity envelope.
The [earlier native evidence package](../wallet-index-review/README.md) describes
that source-pinned image and its generation/verification commands.

## Reproduce the tool checks

```sh
python3 -B scripts/test_wallet_index_replica_capacity.py
python3 scripts/check-source-guard-inventory.py --build-dir build
ctest --test-dir build -R '^wallet-index-replica-capacity$' --no-tests=error --output-on-failure
uv run ruff check scripts/wallet-index-replica-capacity.py scripts/test_wallet_index_replica_capacity.py scripts/check-source-guard-inventory.py
uv run ruff format --check scripts/wallet-index-replica-capacity.py scripts/test_wallet_index_replica_capacity.py scripts/check-source-guard-inventory.py
```

To repeat a sensitivity control, copy both harness files to a temporary isolated
directory, apply exactly the JSON's `mutation.before` to `mutation.after` once,
compile that Python source, and invoke its named test. Require its specific
assertion failure, then rerun the unchanged twelve-test suite. A syntax/setup
error is not a valid negative result. No database snapshots, full build logs or
continuous sample streams are committed here.
