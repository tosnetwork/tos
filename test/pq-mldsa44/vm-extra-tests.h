/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Included by test.cpp inside its anonymous namespace, after the shared harness.
// Prices here are specification literals, deliberately NOT implementation constants.
long long expected_raw_gas(const Cells& input) {
  long long gas = 50000 + 34 + 5;  // base, 24-bit instruction, implicit return
  std::set<std::string> loaded;
  for (auto cell : input) {
    while (cell.not_null()) {
      gas += loaded.insert(cell->get_hash().to_hex()).second ? 100 : 25;
      const auto slice = vm::load_cell_slice(cell);
      gas += slice.size() / 8;
      cell = slice.size_refs() ? slice.prefetch_ref() : Cell{};
    }
  }
  return gas;
}

void extended_boundaries(const Vector& good, Cell compiled, std::ostream& out) {
  const auto canonical = cells(good);
  const bool method = compiled.not_null();
  auto invoke = [&](const Cells& input, int version = 16, long long gas = 1000000, bool ignore = false) {
    return execute(input, version, gas, ignore, compiled, method);
  };
  const auto baseline = invoke(canonical);
  check_execution(good, baseline);
  for (int version = 0; version < 16; ++version) {
    auto result = invoke(canonical, version);
    require(result.exit == 6, "public binding accepted an old VM version");
    print_execution(out, "binding-version-" + std::to_string(version), result);
  }
  auto exact = invoke(canonical, 16, baseline.gas);
  check_execution(good, exact);
  print_execution(out, "binding-exact-gas", exact);
  auto insufficient = invoke(canonical, 16, baseline.gas - 1);
  require(insufficient.exit == -14 && !insufficient.committed, "binding OOG committed or returned normally");
  print_execution(out, "binding-oog", insufficient);

  auto swapped = canonical;
  std::swap(swapped[0], swapped[1]);
  auto swapped_result = invoke(swapped);
  require(swapped_result.exit == 0 && swapped_result.value == 0, "message/context argument order not bound");
  print_execution(out, "binding-swapped-message-context", swapped_result);
  swapped = canonical;
  std::swap(swapped[2], swapped[3]);
  auto bad_lengths = invoke(swapped);
  require(bad_lengths.exit == 9, "signature/public-key argument order not bound");
  print_execution(out, "binding-swapped-key-signature", bad_lengths);

  auto invalid = good;
  invalid.signature[0] ^= 1;
  invalid.expected = 'I';
  auto checked = invoke(cells(invalid), 16, 1000000, true);
  check_execution(invalid, checked);
  print_execution(out, "binding-ignore-classic", checked);
  for (int operand = 0; operand < 4; ++operand) {
    auto input = canonical;
    input[operand] = vm::CellBuilder().store_long(1, 1).finalize();
    auto result = invoke(input);
    require(result.exit == 9 && !result.committed, "malformed operand was accepted or committed");
    print_execution(out, "binding-malformed-operand-" + std::to_string(operand), result);
  }

  if (!method) {
    // Error paths must be actual VM errors, not false verification results.
    for (int count = 0; count <= 4; ++count) {
      td::Ref<vm::Stack> stack{true};
      for (int i = 0; i < count; ++i) stack.write().push_smallint(i);
      vm::VmState state{vm::load_cell_slice_ref(opcode()), 16, std::move(stack),
                        vm::GasLimits{1000000, 1000000}};
      const int result = ~state.run();
      require(result == (count == 4 ? 7 : 2), "incorrect stack-type/underflow error");
      require(!state.committed(), "stack rejection committed state");
      out << "stack-error-" << count << '\t' << result << '\t' << state.gas_consumed() << '\n';
    }
    auto during_load = invoke(canonical, 16, 50133);
    require(during_load.exit == -14 && !during_load.committed, "operand-load gas was not charged");
    print_execution(out, "oog-during-first-cell-load", during_load);
  }
}

template <class Work>
double median_microseconds(Work work, int batch = 8) {
  std::vector<double> samples;
  work();  // untimed warm-up; all timed invocations still check their results
  for (int trial = 0; trial < 7; ++trial) {
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < batch; ++i) work();
    samples.push_back(std::chrono::duration<double, std::micro>(
        std::chrono::steady_clock::now() - start).count() / batch);
  }
  std::sort(samples.begin(), samples.end());
  return samples[samples.size() / 2];
}

void calibrate_gas(const std::vector<Vector>& vectors, const std::string& report_path) {
  // TEST-ONLY fixed key, never wallet material. Only the benchmark signs; the
  // consensus library remains verify-only. Compare against the same Ed25519
  // implementation that CHKSIG uses, priced at its paid-call tariff (4,000).
  const std::string seed(32, '\x42');
  const std::string message(32, '\x24');
  td::Ed25519::PrivateKey sk{td::SecureString{td::Slice{seed}}};
  auto pk_result = sk.get_public_key();
  auto sig_result = sk.sign(td::Slice{message});
  require(pk_result.is_ok() && sig_result.is_ok(), "Ed25519 calibration control failed");
  auto pk = pk_result.move_as_ok();
  auto signature = sig_result.move_as_ok();
  const double ed_us = median_microseconds([&] {
    require(pk.verify_signature(td::Slice{message}, signature.as_slice()).is_ok(),
            "Ed25519 calibration verification failed");
  }, 64);
  require(ed_us > 0, "invalid calibration clock");

  std::ofstream report(report_path);
  require(bool(report), "cannot write calibration report");
  report << std::fixed << std::setprecision(6)
         << "{\n  \"schema\": 1,\n  \"ed25519_paid_gas\": 4000,\n"
         << "  \"ed25519_wrapper_median_us\": " << ed_us << ",\n  \"cases\": [\n";
  bool first = true;
  double worst_ratio = 0;
  std::string worst_id;
  for (const auto& v : vectors) {
    if (v.expected == 'M') continue;  // encoding rejection is separately tested
    const auto input = cells(v);
    const auto baseline = execute(input);
    check_execution(v, baseline);
    const double us = median_microseconds([&] { check_execution(v, execute(input)); });
    // Charge only the 50,000 base here: disregarding byte/load fees makes this
    // headroom estimate conservative. Runtime never changes consensus prices.
    const double ratio = (us / 50000.0) / (ed_us / 4000.0);
    if (ratio > worst_ratio) { worst_ratio = ratio; worst_id = v.id; }
    require(v.id.find_first_of("\"\\\r\n") == std::string::npos, "unsafe calibration case ID");
    if (!first) report << ",\n";
    first = false;
    report << "    {\"id\": \"" << v.id << "\", \"verdict\": \"" << v.expected
           << "\", \"vm_median_us\": " << us << ", \"gas\": " << baseline.gas
           << ", \"normalized_cpu_per_gas\": " << ratio << "}";
  }
  require(!first, "no calibration vectors");
  report << "\n  ],\n  \"worst_case\": \"" << worst_id << "\",\n"
         << "  \"worst_normalized_cpu_per_gas\": " << worst_ratio << ",\n"
         << "  \"model_gas_budget\": 1000000,\n  \"workloads\": [\n";
  first = true;
  for (const auto& v : vectors) {
    if (v.id != "openssl-auth-commitment" && v.id != "openssl-maxima" && v.id != "signature-bit-0") continue;
    const auto input = cells(v);
    const auto single = execute(input);
    const int calls = static_cast<int>(1000000 / single.gas);
    require(calls > 0 && calls <= 24, "unexpected model workload size");
    vm::CellBuilder builder;
    for (int i = 0; i < calls; ++i) {
      builder.store_long(0xf93100, 24);
      if (i + 1 < calls) builder.store_long(0x30, 8);
    }
    const auto code = builder.finalize();
    const auto batch_result = execute(input, 16, 1000000, false, code, false, calls);
    check_execution(v, batch_result);
    require(batch_result.gas <= 1000000, "model workload exceeded its fixed gas budget");
    const double us = median_microseconds([&] {
      check_execution(v, execute(input, 16, 1000000, false, code, false, calls));
    });
    if (!first) report << ",\n";
    first = false;
    report << "    {\"id\": \"" << v.id << "\", \"calls\": " << calls
           << ", \"gas\": " << batch_result.gas << ", \"median_us\": " << us << "}";
  }
  report << "\n  ]\n}\n";
  report.flush();
  require(bool(report), "calibration report write failed");
  std::cout << "CALIBRATION ed25519_us=" << ed_us << " worst=" << worst_id
            << " normalized_cpu_per_gas=" << worst_ratio << '\n';
  // A noisy host can fail a performance gate, but can NEVER alter VM behavior.
  // Review the archived measurements before changing a fixed protocol price.
  require(worst_ratio < 1.0, "PQ CPU/gas exceeds the existing paid Ed25519 tariff; review calibration");
}
