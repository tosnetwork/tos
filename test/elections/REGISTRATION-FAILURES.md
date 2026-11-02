# Executed registration controls

Core b119553bd8c33e6314cdae37793226abd0d858df. All66Rust tests passed;14 matching mutations below failed in the intended test body; restored66GREEN. Reproduce with registration_controls.py and registration-controls.json in this directory. No signing, chain send or deployment is performed.

Raw logs retained through2027-02-01UTC on the authorized test host at `/tos/build/e6-election-lifecycle/controls-r3/`, accessible with existing authorized SSH. The excerpts below are bounded actual failures, not setup/compiler errors.

## pending_delay

Test `registration::tests::late_election_covers_close_margin_and_full_term`, exit101; raw SHA-256 `47897d8d00704abfb2cff2f2229bdc56a447085b791d0e2a986839fc0c8d48af`.

```text
test registration::tests::late_election_covers_close_margin_and_full_term ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 65 filtered out; finished in 0.00s
thread 'registration::tests::late_election_covers_close_margin_and_full_term' (2045916) panicked at node-control/elections/src/registration.rs:138:9:
assertion `left == right` failed
```

## announced_duty

Test `registration::tests::announced_term_extends_original_election_without_new_identity`, exit101; raw SHA-256 `4eb041e7afe9cf6cf0640ea34eaff642c338d72fb6aff33bc1ccc3db9785c297`.

```text
test registration::tests::announced_term_extends_original_election_without_new_identity ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 65 filtered out; finished in 0.00s
thread 'registration::tests::announced_term_extends_original_election_without_new_identity' (2056622) panicked at node-control/elections/src/registration.rs:150:9:
assertion `left == right` failed
```

## extended_installed_set

Test `registration::tests::installed_expired_set_is_retained_during_another_delay`, exit101; raw SHA-256 `6f79945a9d5a3fdd2c03c2092e60e357721f46d9916e734e866520651d90baf6`.

```text
test registration::tests::installed_expired_set_is_retained_during_another_delay ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 65 filtered out; finished in 0.00s
thread 'registration::tests::installed_expired_set_is_retained_during_another_delay' (2068184) panicked at node-control/elections/src/registration.rs:164:9:
assertion `left == right` failed
```

## address_membership

Test `registration::tests::unrelated_and_already_retained_addresses_do_not_write`, exit101; raw SHA-256 `2033b1cb19e816eef825331aa81540b10048a731ff5cebaa7050eaba13f71706`.

```text
test registration::tests::unrelated_and_already_retained_addresses_do_not_write ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 65 filtered out; finished in 0.00s
thread 'registration::tests::unrelated_and_already_retained_addresses_do_not_write' (2079778) panicked at node-control/elections/src/registration.rs:170:9:
assertion failed: duty_renewals(&cfg, Some(&unrelated), None, 1000).unwrap().is_empty()
```

## never_shorten

Test `registration::tests::address_repair_never_shortens_permanent_expiry`, exit101; raw SHA-256 `7a7f7a83afa935dadd27086a696d81a3f2319e5bbdca4e893aeb33e720666de4`.

```text
test registration::tests::address_repair_never_shortens_permanent_expiry ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 65 filtered out; finished in 0.00s
thread 'registration::tests::address_repair_never_shortens_permanent_expiry' (2090854) panicked at node-control/elections/src/registration.rs:181:9:
assertion `left == right` failed
```

## key_width

Test `registration::tests::malformed_and_excessive_registration_inputs_refuse`, exit101; raw SHA-256 `b6ac67c82e073c8968be727faa383b22c00b58b99b00f5b3a5f013c8d38d54f7`.

```text
test registration::tests::malformed_and_excessive_registration_inputs_refuse ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 65 filtered out; finished in 0.00s
thread 'registration::tests::malformed_and_excessive_registration_inputs_refuse' (2100758) panicked at node-control/elections/src/registration.rs:189:18:
called `Result::unwrap_err()` on an `Ok` value: [Renewal { election_id: 100, key_id: [], adnl: [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2], until: 20300 }]
```

## record_bound

Test `registration::tests::malformed_and_excessive_registration_inputs_refuse`, exit101; raw SHA-256 `44e2355f85683ad4530f47b5a69c921a833d27d88b8c0c992556592de5d74a7a`.

```text
test registration::tests::malformed_and_excessive_registration_inputs_refuse ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 65 filtered out; finished in 0.00s
thread 'registration::tests::malformed_and_excessive_registration_inputs_refuse' (2111292) panicked at node-control/elections/src/registration.rs:199:51:
called `Result::unwrap_err()` on an `Ok` value: []
```

## early_fee_warning

Test `runner::runner_tests::fee_alert_precedes_actual_stake_exhaustion_and_has_exact_boundary`, exit101; raw SHA-256 `57e3779a36309d789a008d4ee8777c098b7866180ebcc71af6c35f35ec1319da`.

```text
test runner::runner_tests::fee_alert_precedes_actual_stake_exhaustion_and_has_exact_boundary ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 65 filtered out; finished in 0.00s
thread 'runner::runner_tests::fee_alert_precedes_actual_stake_exhaustion_and_has_exact_boundary' (2122397) panicked at node-control/elections/src/runner_tests.rs:2553:60:
called `Option::unwrap()` on a `None` value
```

## existing_key_read

Test `runner::runner_tests::existing_key_export_failure_never_becomes_a_fresh_key`, exit101; raw SHA-256 `17e27486653cec06ecdf142302a4caf216eb9364b12f8a9f4beaba77cb2dbbf7`.

```text
test runner::runner_tests::existing_key_export_failure_never_becomes_a_fresh_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 65 filtered out; finished in 0.00s
thread 'runner::runner_tests::existing_key_export_failure_never_becomes_a_fresh_key' (2132666) panicked at node-control/elections/src/runner_tests.rs:2578:14:
called `Result::unwrap_err()` on an `Ok` value: Some(ValidatorEntry { key_id: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], public_key: [], adnl_addrs: [], expired_at: 0 })
```

## closed_fee_warning

Test `runner::runner_tests::fee_warning_is_visible_with_closed_elections_and_does_not_send`, exit101; raw SHA-256 `06d3d2553ba573011325d276a20f5b8acb802ede8172d7ff700ede0107cfafbc`.

```text
test runner::runner_tests::fee_warning_is_visible_with_closed_elections_and_does_not_send ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 65 filtered out; finished in 0.02s
thread 'runner::runner_tests::fee_warning_is_visible_with_closed_elections_and_does_not_send' (2144604) panicked at node-control/elections/src/runner_tests.rs:2614:52:
called `Option::unwrap()` on a `None` value
```

## unavailable_fee_warning

Test `runner::runner_tests::fee_balance_read_failure_is_an_alert_not_silent_health`, exit101; raw SHA-256 `af4caf5ba94311289aa0e8fc40004f64abcb98803cdd52ac0c8d1742bdef1c3a`.

```text
test runner::runner_tests::fee_balance_read_failure_is_an_alert_not_silent_health ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 65 filtered out; finished in 0.00s
thread 'runner::runner_tests::fee_balance_read_failure_is_an_alert_not_silent_health' (2156621) panicked at node-control/elections/src/runner_tests.rs:2630:14:
called `Option::unwrap()` on a `None` value
```

## closed_duty_renewal

Test `runner::runner_tests::closed_elector_still_extends_actual_announced_duty_without_spending`, exit101; raw SHA-256 `872d95adcbbfd757c589e1c49c6e62b376913998b20439a953bcd753442e109d`.

```text
test runner::runner_tests::closed_elector_still_extends_actual_announced_duty_without_spending ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 65 filtered out; finished in 0.00s
thread 'runner::runner_tests::closed_elector_still_extends_actual_announced_duty_without_spending' (2166077) panicked at node-control/elections/src/runner_tests.rs:2681:5:
assertion `left == right` failed
```

## longest_shared_duty

Test `registration::tests::multiple_duty_addresses_share_the_longest_permanent_deadline`, exit101; raw SHA-256 `61fca277f4e28ae2f75e539fc021461d204329e29a396c48952b7013b212bfd3`.

```text
test registration::tests::multiple_duty_addresses_share_the_longest_permanent_deadline ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 65 filtered out; finished in 0.00s
thread 'registration::tests::multiple_duty_addresses_share_the_longest_permanent_deadline' (2179675) panicked at node-control/elections/src/registration.rs:211:13:
assertion failed: plans.iter().all(|plan| plan.until == 20300)
```

## renewal_snapshot_order

Test `runner::runner_tests::closed_elector_still_extends_actual_announced_duty_without_spending`, exit101; raw SHA-256 `6ec0cd1c1f6683f83c817228dda52da8e8a3c85c53516e2c11d78876bbd42069`.

```text
test runner::runner_tests::closed_elector_still_extends_actual_announced_duty_without_spending ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 65 filtered out; finished in 0.00s
thread 'runner::runner_tests::closed_elector_still_extends_actual_announced_duty_without_spending' (2189719) panicked at node-control/elections/src/runner_tests.rs:2681:5:
assertion `left == right` failed
```
