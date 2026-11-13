# Prepared-recovery control receipts

106Python tests PASS;32native tests PASS in default/public-testnet-pilot modes; five Python guard removals and two compiled native guard removals fail in the intended runtime checks. Five real historical finalized local messages recover exactly, with15changed-binding refusals and no new signatures or sends. The retained custody is explicitly quiesced: the driver verifies the named local service is inactive/MainPID0 before/after checks, preventing unrelated custody-lock refusals from counting as guard evidence. Raw receipts retained through2027-02-01 via existing authorized toserver SSH; JSON index records source/driver/log hashes.

## tick-recovery

Exit 1; SHA-256 `1806da034b8e5e03c0e8feb036af54e78b2ecdeb883203a69c0e3612099ee65b`.

```text
FAIL: test_lost_prepare_reply_recovers_sealed_bytes_without_preparing_again (test_relay_service.ServiceTests)
AssertionError: 'reserved' != 'broadcast'
Ran 1 test in 0.013s
FAILED (failures=1)
```

## expired-dispatch

Exit 1; SHA-256 `aa98ddb3dc5466f4e3bace39034111fb3df2437bc0d8e79e4b8777e93054df8d`.

```text
FAIL: test_expired_sealed_recovery_keeps_bytes_and_never_broadcasts (test_relay_service.ServiceTests)
AssertionError: 'broadcast' != 'unknown'
Ran 1 test in 0.014s
FAILED (failures=1)
```

## operation-route

Exit 1; SHA-256 `41260cf1b6770fb32d7ab6ff0bc9600fc7b8c0f9620b35ea71661414ecf95d50`.

```text
FAIL: test_recovery_operation_reaches_the_sealed_process (test_native_boundary.ProcessTests)
AssertionError: recovery operation did not reach the sealed process: unknown native operation
Ran 1 test in 0.117s
FAILED (failures=1)
```

## uncertain-locks

Exit 1; SHA-256 `da334567e5499b5955ef9a4d3f1a41589a7eeb32f9e6aa856a3428dadb5910e5`.

```text
FAIL: test_uncertain_native_recovery_keeps_expired_reservations (test_relay_service.ServiceTests)
AssertionError: 'cancelled' != 'reserved'
Ran 1 test in 0.014s
FAILED (failures=1)
```

## validation-before-journal

Exit 1; SHA-256 `06e1ad794fbc5eea26027447fe50b12d3c833af56003335f6c986fbf82243e19`.

```text
FAIL: test_recovered_bytes_require_validation_before_journaling_or_send (test_relay_service.ServiceTests)
AssertionError: 'prepared' != 'reserved'
Ran 1 test in 0.013s
FAILED (failures=1)
```

## missing-native-validation

Exit 1; SHA-256 `3f9fe4000bca82105638576c751aab1a9eeff3e9fdf3ae9c7391ee68e72a88cd`.

```text
    raise AssertionError("changed " + field + " recovered")
AssertionError: changed slot recovered
```

## unsigned-cancellation

Exit 101; SHA-256 `fa82b8f00a057dbf5d6924b13054e85ce784ad7f9729fcd44bfb278164fc73dd`.

```text
test prepared::recovery_tests::recovery_distinguishes_missing_lease_from_interrupted_unsigned_lease ... FAILED
unsigned native lease must not authorize cancellation
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 31 filtered out; finished in 0.02s
```

## Reproduce

Run private-custody controls only in an isolated checkout with no other compiler/editor and no queued local relayer attempts. Pause only the named disposable local service through systemctl, run under the host thermal guard with at most2Cargo/Rayon/Tokio workers, and restore the service in finally/trap. Never copy custody, reset journals or stop validators.

```sh
python3 test/bonded-relayer/native_faults/prepared_controls.py --out /new/python-controls
python3 test/bonded-relayer/native_faults/prepared_native_controls.py --checkout "$PWD" --custody /retained/local-operator --inactive-unit LOCAL.service --out /new/native-controls
```

The native runner requires CARGO_TARGET_DIR and the repository-pinned Rust toolchain (this evidence was recorded with 1.99.1), builds before every runtime check and restores exact prepared.rs bytes in finally. Setup/compilation failures are never RED evidence. The historical fixture driver accepts global-id3 only; it emits sanitized hashes, not signed payloads, seeds, tokens or SQL snapshots. Fresh end-to-end lost-reply execution is not claimed by these historical lookups.

Upstream comparison: BR1 Rust/Python paths absent at upstream857b8a57a178e6ae0fe7fa86e7d81c5233de8560; base bb2b07a40d838940bc16efa6cf72d24bc343c148. No inherited core change.
