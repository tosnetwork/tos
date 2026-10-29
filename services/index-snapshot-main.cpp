/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include <atomic>
#include <iostream>
#include <string>

#include "td/utils/OptionParser.h"
#include "td/utils/misc.h"
#include "td/utils/port/signals.h"
#include "validator-engine/wallet-index-snapshot.h"

namespace {
std::atomic<bool> cancelled{false};
void request_stop(int) {
  cancelled = true;
}
}  // namespace

int main(int argc, char** argv) {
  std::string action, index, snapshot, digest;
  td::OptionParser parser;
  parser.set_description("Offline wallet-index snapshot: create, verify or restore a trusted operator's index.");
  parser.add_option('h', "help", "show help", [&] {
    std::cout << (PSTRING() << parser);
    std::exit(0);
  });
  parser.add_option('\0', "action", "create, verify or restore", [&](td::Slice v) { action = v.str(); });
  parser.add_option('\0', "index-dir", "stopped source index (create) or new destination index (restore)",
                    [&](td::Slice v) { index = v.str(); });
  parser.add_option('\0', "snapshot", "snapshot file (new file for create)", [&](td::Slice v) { snapshot = v.str(); });
  parser.add_option('\0', "sha256", "trusted publisher's SHA-256 (required for verify and restore)",
                    [&](td::Slice v) { digest = v.str(); });
  auto parsed = parser.run(argc, argv);
  if (parsed.is_error() || snapshot.empty() || (action != "create" && action != "verify" && action != "restore") ||
      (action != "verify" && index.empty()) || (action == "verify" && !index.empty()) ||
      (action == "create" && !digest.empty()) || (action != "create" && digest.size() != 64)) {
    std::cerr << "specify --action, --snapshot and the action's --index-dir / --sha256 options\n";
    return 2;
  }
  td::Bits256 expected;
  if (action != "create") {
    auto decoded = td::hex_decode(digest);
    if (decoded.is_error() || decoded.ok().size() != 32) {
      std::cerr << "--sha256 must contain 64 hexadecimal digits\n";
      return 2;
    }
    expected.as_slice().copy_from(decoded.ok());
  }
  auto signal_status = td::set_signal_handler(td::SignalType::Quit, request_stop);
  if (signal_status.is_error()) {
    std::cerr << signal_status.message().str() << '\n';
    return 1;
  }
  using tos_wallet_index::WalletIndexSnapshotFile;
  auto result = action == "create" ? WalletIndexSnapshotFile::create(index, snapshot, [] { return cancelled.load(); })
                : action == "verify"
                    ? WalletIndexSnapshotFile::verify(snapshot, expected, [] { return cancelled.load(); })
                    : WalletIndexSnapshotFile::restore(snapshot, index, expected, [] { return cancelled.load(); });
  if (result.is_error()) {
    std::cerr << result.error().message().str() << '\n';
    return 1;
  }
  const auto& info = result.ok();
  std::cout << "sha256=" << td::hex_encode(info.sha256.as_slice()) << " bytes=" << info.bytes
            << " records=" << info.records << "\nanchor=" << info.checkpoint.anchor.to_str()
            << "\ncheckpoint=" << info.checkpoint.committed.to_str() << '\n';
  return 0;
}
