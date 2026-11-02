# Store crash control receipts

Baseline and restored matrices pass all22 cases. Six mutations compile successfully and fail in the intended runtime invariants. The synchronized race requires both Stores open, then both processes inside consume BEGIN while a parent write lock prevents either commit; only the exact permit-rejection guard may lose. SQLite/I/O errors fail the test. Raw receipts retained through2027-02-01 UTC via existing authorized toserver SSH access.

## prepared-durability

Exit 1; SHA-256 `899971f4065532b3b0ca0c074b2c9335b32ef7671719c15b93f243dfdd8253b5`.

```text
Error: message durability
```

## consume-atomicity

Exit 1; SHA-256 `6caa7b870f9e07e7e65b7342df02b77904ac0098f2b8f67c59541f189ac85e34`.

```text
Error: permit/send-claim atomicity
```

## refusal-atomicity

Exit 1; SHA-256 `f5a294ea021e9a34d609c4e58e10191d11c323eb4709a6c6118bc61b473a1a12`.

```text
Error: retirement/permit atomicity
```

## fee-durability

Exit 1; SHA-256 `7fd8abb27963801c6be87903be30bde487e9d803840ae4f02ddf5d1cf17fd93d`.

```text
Error: fee credit durability
```

## concurrent-double-claim

Exit 1; SHA-256 `7996b24f5929d6dd1d1c13a3d437ee6c0cf4e6d29aaa051955c47d4ea6afe15b`.

```text
Error: two processes did not have exactly one send claimant
```

## unexpected-loser-error

Exit 1; SHA-256 `0641a3e87063699dba94dd8697249ccb1e7cf3b4c3ebad11190163773aed8c8f`.

```text
Error: losing claimant did not reach the permit guard: Error: unexpected storage error in claimant

Caused by:
    synthetic unrelated storage failure
```

## Reproduce

Use a disposable checkout without another compiler/editor, Rust1.97.1, Cargo/Rayon/Tokio at most2workers, under the host thermal guard:

```sh
python3 test/bonded-relayer/native_faults/storage_controls.py --checkout "$PWD" --out /path/to/new-receipts
```

The runner restores exact Store bytes in finally; compilation/setup failure is never counted. Abruptly interrupting the runner can leave a mutation in that disposable checkout; inspect git diff before reuse. The restored full matrix is required.

Upstream comparison: these provider/test paths are absent at upstream857b8a57a178e6ae0fe7fa86e7d81c5233de8560; TOS base bb2b07a40d838940bc16efa6cf72d24bc343c148. No production behavior change.
