/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Acquisition and storage of proof material. Nothing here verifies anything:
// material is untrusted input to proof-verify.h, whether it was fetched from a
// lite-server or read from a directory.
#pragma once

#include <memory>
#include <optional>
#include <string>

#include "proof-verify.h"

namespace tos::proofverify {

class LiteTransport {
 public:
  virtual ~LiteTransport() = default;
  // Sends one lite API query and returns the raw answer. A lite-server error
  // answer is returned as an error.
  virtual td::Result<td::BufferSlice> query(td::BufferSlice request) = 0;
};

struct FetchOptions {
  double timeout_seconds{20.0};
  double min_interval_seconds{0.2};
};

td::Result<std::unique_ptr<LiteTransport>> connect_liteserver(const std::string& config_path,
                                                              const FetchOptions& options);

td::Result<Material> fetch_material(LiteTransport& transport, const Anchor& anchor, const Request& request,
                                    const std::optional<LiveState>& state);

td::Result<Material> read_material(const std::string& directory);
td::Status write_material(const std::string& directory, const Material& material);

td::Result<std::string> read_bounded_file(const std::string& path, std::size_t max_bytes);

}  // namespace tos::proofverify
