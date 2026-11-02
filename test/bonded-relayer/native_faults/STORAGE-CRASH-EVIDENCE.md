# Store crash control receipts

The baseline/restored runs pass 22 cases. Four targeted transaction mutations compile successfully and fail in the intended runtime invariants. Raw output is retained through 2027-02-01 UTC on the authorized test host; the JSON index records digests and existing SSH access. No compilation/setup error counts as a failure receipt.

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

## Reproduce

Use an isolated checkout without another compiler/editor. Run with Rust 1.97.1, at most two Cargo/Rayon/Tokio workers, under the host thermal guard:

```sh
python3 test/bonded-relayer/native_faults/storage_controls.py --checkout "$PWD" --out /path/to/new-control-receipts
```

The runner mutates only `provider/src/store.rs`, restores its exact original bytes in `finally`, builds before every runtime check, and reruns the complete restored matrix. Interrupted machine/process termination can leave a mutation in the disposable checkout; inspect git diff before reuse.

Upstream comparison: BR1 provider Store and this harness are absent in upstream ton-c 857b8a57a178e6ae0fe7fa86e7d81c5233de8560; TOS base bb2b07a40d838940bc16efa6cf72d24bc343c148. Test-only changes, no production behavior change.
