# Executed registration controls

Core da5c6df82ff8616d5768143a1daeb368b0f087ce. All68Rust tests passed;17 matching mutations below failed in the intended test body; restored68GREEN. Reproduce with registration_controls.py and registration-controls.json in this directory. No signing, chain send or deployment is performed.

Raw logs retained through2027-02-01UTC on the authorized test host at `/tos/build/e6-election-lifecycle/controls-r5/`, accessible with existing authorized SSH. The excerpts below are bounded actual failures, not setup/compiler errors.

## pending_delay

Test `registration::tests::late_election_covers_close_margin_and_full_term`, exit101; raw SHA-256 `0613943f68af8dfbcfa96883059d69909f56133245fdb64040d3e2e4aeef5fe3`.

```text
test registration::tests::late_election_covers_close_margin_and_full_term ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.00s
thread 'registration::tests::late_election_covers_close_margin_and_full_term' (1052671) panicked at node-control/elections/src/registration.rs:138:9:
assertion `left == right` failed
```

## announced_duty

Test `registration::tests::announced_term_extends_original_election_without_new_identity`, exit101; raw SHA-256 `3ca732f18b65a99b1a45da4356eadd2210c6736aa2cd4edef7c56db35532ef77`.

```text
test registration::tests::announced_term_extends_original_election_without_new_identity ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.00s
thread 'registration::tests::announced_term_extends_original_election_without_new_identity' (1063199) panicked at node-control/elections/src/registration.rs:150:9:
assertion `left == right` failed
```

## extended_installed_set

Test `registration::tests::installed_expired_set_is_retained_during_another_delay`, exit101; raw SHA-256 `4be08df483f75d4079e38076abe1ee6d74d7e52236b2178c0cf64c2976a0d705`.

```text
test registration::tests::installed_expired_set_is_retained_during_another_delay ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.00s
thread 'registration::tests::installed_expired_set_is_retained_during_another_delay' (1073604) panicked at node-control/elections/src/registration.rs:164:9:
assertion `left == right` failed
```

## address_membership

Test `registration::tests::unrelated_and_already_retained_addresses_do_not_write`, exit101; raw SHA-256 `4296d8628317a5be2bb25dfee43e1156fdcddc3a9932105b02411ee3dbc6cdd5`.

```text
test registration::tests::unrelated_and_already_retained_addresses_do_not_write ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.00s
thread 'registration::tests::unrelated_and_already_retained_addresses_do_not_write' (1086693) panicked at node-control/elections/src/registration.rs:170:9:
assertion failed: duty_renewals(&cfg, Some(&unrelated), None, 1000).unwrap().is_empty()
```

## never_shorten

Test `registration::tests::address_repair_never_shortens_permanent_expiry`, exit101; raw SHA-256 `9c801f158500b22035031053a085cfc502c5973f6dff1e08dbe3ca20064a4575`.

```text
test registration::tests::address_repair_never_shortens_permanent_expiry ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.00s
thread 'registration::tests::address_repair_never_shortens_permanent_expiry' (1097955) panicked at node-control/elections/src/registration.rs:181:9:
assertion `left == right` failed
```

## key_width

Test `registration::tests::malformed_and_excessive_registration_inputs_refuse`, exit101; raw SHA-256 `2c0a0e1f3b1fd40a9077eeb9e8e9d9c24f138d39199388a47e40c6db2d0de6bf`.

```text
test registration::tests::malformed_and_excessive_registration_inputs_refuse ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.00s
thread 'registration::tests::malformed_and_excessive_registration_inputs_refuse' (1108863) panicked at node-control/elections/src/registration.rs:189:18:
called `Result::unwrap_err()` on an `Ok` value: [Renewal { election_id: 100, key_id: [], adnl: [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2], until: 20300 }]
```

## record_bound

Test `registration::tests::malformed_and_excessive_registration_inputs_refuse`, exit101; raw SHA-256 `111548dd8ce94e3b004e1b9634cd89e683246374d08ffb350abb83ac5811a4c8`.

```text
test registration::tests::malformed_and_excessive_registration_inputs_refuse ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.00s
thread 'registration::tests::malformed_and_excessive_registration_inputs_refuse' (1119962) panicked at node-control/elections/src/registration.rs:199:51:
called `Result::unwrap_err()` on an `Ok` value: []
```

## early_fee_warning

Test `runner::runner_tests::fee_alert_precedes_actual_stake_exhaustion_and_has_exact_boundary`, exit101; raw SHA-256 `91c0ffce85dc2f939d963fe607ff213c03626882b1649122ed1af12805ce892b`.

```text
test runner::runner_tests::fee_alert_precedes_actual_stake_exhaustion_and_has_exact_boundary ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.00s
thread 'runner::runner_tests::fee_alert_precedes_actual_stake_exhaustion_and_has_exact_boundary' (1131903) panicked at node-control/elections/src/runner_tests.rs:2553:60:
called `Option::unwrap()` on a `None` value
```

## existing_key_read

Test `runner::runner_tests::existing_key_export_failure_never_becomes_a_fresh_key`, exit101; raw SHA-256 `7d028d095c712891e026d621c713e4184d09ac9518cfd3956f400b3196e2ec4e`.

```text
test runner::runner_tests::existing_key_export_failure_never_becomes_a_fresh_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.00s
thread 'runner::runner_tests::existing_key_export_failure_never_becomes_a_fresh_key' (1143524) panicked at node-control/elections/src/runner_tests.rs:2578:14:
called `Result::unwrap_err()` on an `Ok` value: Some(ValidatorEntry { key_id: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], public_key: [], adnl_addrs: [], expired_at: 0 })
```

## closed_fee_warning

Test `runner::runner_tests::fee_warning_is_visible_with_closed_elections_and_does_not_send`, exit101; raw SHA-256 `8ccbf043ce982385065aefdd60215639ec892b984e589b3daf0339f8f42a831b`.

```text
test runner::runner_tests::fee_warning_is_visible_with_closed_elections_and_does_not_send ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.02s
thread 'runner::runner_tests::fee_warning_is_visible_with_closed_elections_and_does_not_send' (1153411) panicked at node-control/elections/src/runner_tests.rs:2614:52:
called `Option::unwrap()` on a `None` value
```

## unavailable_fee_warning

Test `runner::runner_tests::fee_balance_read_failure_is_an_alert_not_silent_health`, exit101; raw SHA-256 `fd60a3337825f88cbae5a1c62d1021fe2dac2f38640272bda4c3890ef66509a9`.

```text
test runner::runner_tests::fee_balance_read_failure_is_an_alert_not_silent_health ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.00s
thread 'runner::runner_tests::fee_balance_read_failure_is_an_alert_not_silent_health' (1164714) panicked at node-control/elections/src/runner_tests.rs:2630:14:
called `Option::unwrap()` on a `None` value
```

## closed_duty_renewal

Test `runner::runner_tests::closed_elector_still_extends_actual_announced_duty_without_spending`, exit101; raw SHA-256 `792a064b42eb10a7f97defdb306eff52feb7b96df00b5a7a1688d4305fe1ff08`.

```text
test runner::runner_tests::closed_elector_still_extends_actual_announced_duty_without_spending ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.00s
thread 'runner::runner_tests::closed_elector_still_extends_actual_announced_duty_without_spending' (1176926) panicked at node-control/elections/src/runner_tests.rs:2681:5:
assertion `left == right` failed
```

## longest_shared_duty

Test `registration::tests::multiple_duty_addresses_share_the_longest_permanent_deadline`, exit101; raw SHA-256 `44a1a030244a8494f3d7ddde662fe89be01c5419779e616fd68f3a1855f46ec9`.

```text
test registration::tests::multiple_duty_addresses_share_the_longest_permanent_deadline ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.00s
thread 'registration::tests::multiple_duty_addresses_share_the_longest_permanent_deadline' (1187766) panicked at node-control/elections/src/registration.rs:211:13:
assertion failed: plans.iter().all(|plan| plan.until == 20300)
```

## renewal_snapshot_order

Test `runner::runner_tests::closed_elector_still_extends_actual_announced_duty_without_spending`, exit101; raw SHA-256 `17c563eb73464adcff2405902a798e434e8e2be6ec9fd1a7bc974b14af607e01`.

```text
test runner::runner_tests::closed_elector_still_extends_actual_announced_duty_without_spending ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.00s
thread 'runner::runner_tests::closed_elector_still_extends_actual_announced_duty_without_spending' (1198881) panicked at node-control/elections/src/runner_tests.rs:2681:5:
assertion `left == right` failed
```

## node_failure_isolation

Test `runner::runner_tests::failed_registration_isolated_from_healthy_nodes_even_when_excluded`, exit101; raw SHA-256 `8c1f33dcbff2a19b4f8604a585389363a6a35cc326bbe17e8a3230e2421be468`.

```text
test runner::runner_tests::failed_registration_isolated_from_healthy_nodes_even_when_excluded ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.00s
thread 'runner::runner_tests::failed_registration_isolated_from_healthy_nodes_even_when_excluded' (1210437) panicked at node-control/elections/src/runner_tests.rs:2743:50:
called `Result::unwrap()` on an `Err` value: node [node-1] retain installed election duty
```

## unknown_config_guard

Test `runner::runner_tests::failed_config_read_never_becomes_missing_keys_or_new_signing`, exit101; raw SHA-256 `222fec8c18c010f46cd3aaeb31206210aa62f46c7699fee464ec36488484990b`.

```text
test runner::runner_tests::failed_config_read_never_becomes_missing_keys_or_new_signing ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.00s
thread 'runner::runner_tests::failed_config_read_never_becomes_missing_keys_or_new_signing' (1221131) panicked at node-control/elections/src/runner_tests.rs:81:1:
MockElectionsProviderImpl::new_validator_key: Expectation(<anything>) should not have been called
```

## unknown_config_propagation

Test `runner::runner_tests::failed_config_read_never_becomes_missing_keys_or_new_signing`, exit101; raw SHA-256 `29831241ba305ee10edf5588874957a7dbc82a89bcd29caff198da8398c09ce7`.

```text
test runner::runner_tests::failed_config_read_never_becomes_missing_keys_or_new_signing ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 67 filtered out; finished in 0.00s
thread 'runner::runner_tests::failed_config_read_never_becomes_missing_keys_or_new_signing' (1231885) panicked at node-control/elections/src/runner_tests.rs:81:1:
MockElectionsProviderImpl::new_validator_key: Expectation(<anything>) should not have been called
```
