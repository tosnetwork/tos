/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <set>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include "auto/tl/lite_api.hpp"
#include "auto/tl/tos_api_json.h"
#include "block/mc-config.h"
#include "lite-client/ext-client.h"
#include "lite-client/query-utils.hpp"
#include "td/actor/actor.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/Time.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/lite-tl.hpp"

#include "material.h"

namespace tos::proofverify {

namespace {

class ExtLiteTransport final : public LiteTransport {
 public:
  explicit ExtLiteTransport(FetchOptions options) : options_(options), scheduler_({1}) {
  }

  ~ExtLiteTransport() override {
    scheduler_.run_in_context([&] { client_.reset(); });
    scheduler_.stop();
  }

  td::Status start(std::vector<liteclient::LiteServerConfig> servers) {
    scheduler_.run_in_context([&] { client_ = liteclient::ExtClient::create(std::move(servers), nullptr); });
    return td::Status::OK();
  }

  td::Result<td::BufferSlice> query(td::BufferSlice request) override {
    // One request at a time, never faster than the configured interval.
    const auto now = td::Time::now();
    if (last_query_ > 0 && now < last_query_ + options_.min_interval_seconds) {
      std::this_thread::sleep_for(std::chrono::duration<double>(last_query_ + options_.min_interval_seconds - now));
    }
    last_query_ = td::Time::now();
    auto wrapped =
        tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(request)), true);
    std::atomic<bool> done{false};
    td::Result<td::BufferSlice> answer{td::Status::Error("lite-server query did not complete")};
    scheduler_.run_in_context([&] {
      td::actor::send_closure(client_, &liteclient::ExtClient::send_query, "proof-verify", std::move(wrapped),
                              td::Timestamp::in(options_.timeout_seconds),
                              td::PromiseCreator::lambda([&](td::Result<td::BufferSlice> result) {
                                answer = std::move(result);
                                done.store(true, std::memory_order_release);
                              }));
    });
    auto deadline = td::Timestamp::in(options_.timeout_seconds + 5.0);
    while (!done.load(std::memory_order_acquire)) {
      scheduler_.run(0.01);
      if (deadline.is_in_past()) {
        return td::Status::Error("lite-server query timed out");
      }
    }
    if (answer.is_error()) {
      return answer.move_as_error_prefix("lite-server query failed: ");
    }
    auto bytes = answer.move_as_ok();
    auto error = tos::fetch_tl_object<tos::lite_api::liteServer_error>(bytes.clone(), true);
    if (error.is_ok()) {
      return td::Status::Error(PSLICE() << "lite-server error " << error.ok()->code_ << ": " << error.ok()->message_);
    }
    if (bytes.size() > kMaxFileBytes) {
      return td::Status::Error("lite-server answer exceeds size limit");
    }
    return std::move(bytes);
  }

 private:
  FetchOptions options_;
  td::actor::Scheduler scheduler_;
  td::actor::ActorOwn<liteclient::ExtClient> client_;
  double last_query_{0};
};

template <class T>
td::Result<td::BufferSlice> ask(LiteTransport& transport, tos::tl_object_ptr<T> query) {
  return transport.query(tos::serialize_tl_object(query, true));
}

std::string numbered(const char* prefix, std::size_t index) {
  char buffer[32];
  std::snprintf(buffer, sizeof(buffer), "%s-%04zu.tl", prefix, index);
  return buffer;
}

td::Status write_new_file(const std::string& path, td::Slice data) {
  int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) {
    return td::Status::PosixError(errno, PSLICE() << "cannot create " << path);
  }
  std::size_t written = 0;
  while (written < data.size()) {
    auto result = ::write(fd, data.data() + written, data.size() - written);
    if (result < 0) {
      if (errno == EINTR) {
        continue;
      }
      auto status = td::Status::PosixError(errno, PSLICE() << "cannot write " << path);
      ::close(fd);
      return status;
    }
    written += static_cast<std::size_t>(result);
  }
  if (::fsync(fd) != 0 || ::close(fd) != 0) {
    return td::Status::PosixError(errno, PSLICE() << "cannot finish " << path);
  }
  return td::Status::OK();
}

}  // namespace

td::Result<std::string> read_bounded_file(const std::string& path, std::size_t max_bytes) {
  int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) {
    return td::Status::PosixError(errno, PSLICE() << "cannot open " << path);
  }
  struct stat info{};
  if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0 ||
      static_cast<std::uint64_t>(info.st_size) > max_bytes) {
    ::close(fd);
    return td::Status::Error(PSLICE() << path << " is not a bounded regular file");
  }
  std::string data(static_cast<std::size_t>(info.st_size), '\0');
  std::size_t done = 0;
  while (done < data.size()) {
    auto result = ::read(fd, data.data() + done, data.size() - done);
    if (result < 0 && errno == EINTR) {
      continue;
    }
    if (result <= 0) {
      ::close(fd);
      return td::Status::Error(PSLICE() << path << " changed while it was read");
    }
    done += static_cast<std::size_t>(result);
  }
  char extra = 0;
  auto tail = ::read(fd, &extra, 1);
  ::close(fd);
  if (tail != 0) {
    return td::Status::Error(PSLICE() << path << " changed while it was read");
  }
  return data;
}

td::Result<std::unique_ptr<LiteTransport>> connect_liteserver(const std::string& config_path,
                                                              const FetchOptions& options) {
  TRY_RESULT(text, read_bounded_file(config_path, 1u << 20));
  TRY_RESULT(json, td::json_decode(td::MutableSlice(text)));
  if (json.type() != td::JsonValue::Type::Object) {
    return td::Status::Error("lite-server configuration is not a JSON object");
  }
  tos::tos_api::liteclient_config_global config;
  TRY_STATUS_PREFIX(tos::tos_api::from_json(config, json.get_object()), "lite-server configuration is malformed: ");
  TRY_RESULT(servers, liteclient::LiteServerConfig::parse_global_config(config));
  if (servers.empty()) {
    return td::Status::Error("lite-server configuration lists no server");
  }
  auto transport = std::make_unique<ExtLiteTransport>(options);
  TRY_STATUS(transport->start(std::move(servers)));
  return std::unique_ptr<LiteTransport>(std::move(transport));
}

td::Result<Material> fetch_material(LiteTransport& transport, const Anchor& anchor, const Request& request,
                                    const std::optional<LiveState>& state) {
  Material material;
  tos::BlockIdExt target;
  if (request.target) {
    target = *request.target;
  } else {
    if (request.mode != Mode::Live) {
      return td::Status::Error("target block is not specified");
    }
    TRY_RESULT(raw, ask(transport, tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>()));
    auto info = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(raw.clone(), true);
    if (info.is_error()) {
      return td::Status::Error("latest block answer is malformed");
    }
    target = tos::create_block_id(info.ok()->last_);
    material.masterchain_info = std::move(raw);
  }
  const auto start = chain_start(anchor, target, request, state);
  auto current = start;
  while (current != target) {
    if (material.chain.size() >= kMaxChainResponses) {
      return td::Status::Error("proof chain needs too many responses");
    }
    TRY_RESULT(raw,
               ask(transport, tos::create_tl_object<tos::lite_api::liteServer_getBlockProof>(
                                  1, tos::create_tl_lite_block_id(current), tos::create_tl_lite_block_id(target))));
    auto chain = tos::fetch_tl_object<tos::lite_api::liteServer_partialBlockProof>(raw.clone(), true);
    if (chain.is_error()) {
      return td::Status::Error("proof chain answer is malformed");
    }
    auto reached = tos::create_block_id(chain.ok()->to_);
    const bool complete = chain.ok()->complete_;
    material.chain.push_back(std::move(raw));
    if (complete) {
      break;
    }
    if (reached.seqno() <= current.seqno()) {
      return td::Status::Error("proof chain answer makes no progress");
    }
    current = reached;
  }
  if (request.mode == Mode::Live && state && state->head && target.seqno() > state->head->id.seqno()) {
    TRY_RESULT(raw, ask(transport,
                        tos::create_tl_object<tos::lite_api::liteServer_getBlockProof>(
                            1, tos::create_tl_lite_block_id(target), tos::create_tl_lite_block_id(state->head->id))));
    material.descent.push_back(std::move(raw));
  }
  if (!request.config_params.empty()) {
    TRY_RESULT(raw,
               ask(transport, tos::create_tl_object<tos::lite_api::liteServer_getConfigParams>(
                                  0, tos::create_tl_lite_block_id(target),
                                  std::vector<td::int32>(request.config_params.begin(), request.config_params.end()))));
    material.config = std::move(raw);
  }
  if (request.account) {
    TRY_RESULT(raw, ask(transport, tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                                       tos::create_tl_lite_block_id(target),
                                       tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                                           request.account->workchain, request.account->addr))));
    auto answer = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(raw.clone(), true);
    material.account = std::move(raw);
    if (!request.get_methods.empty()) {
      const int mode = block::ConfigInfo::needCapabilities | block::ConfigInfo::needPrevBlocks;
      TRY_RESULT(config, ask(transport, tos::create_tl_object<tos::lite_api::liteServer_getConfigAll>(
                                            mode, tos::create_tl_lite_block_id(target))));
      material.exec_config = std::move(config);
      if (answer.is_ok() && !answer.ok()->state_.empty()) {
        TRY_RESULT(libraries, required_libraries(answer.ok()->state_.as_slice()));
        if (!libraries.empty()) {
          if (libraries.size() > 16) {
            return td::Status::Error("account references more libraries than one proof can carry");
          }
          TRY_RESULT(raw_libraries,
                     ask(transport, tos::create_tl_object<tos::lite_api::liteServer_getLibrariesWithProof>(
                                        tos::create_tl_lite_block_id(target), 0,
                                        std::vector<td::Bits256>(libraries.begin(), libraries.end()))));
          material.libraries = std::move(raw_libraries);
        }
      }
    }
  }
  return material;
}

td::Result<Material> read_material(const std::string& directory) {
  DIR* dir = ::opendir(directory.c_str());
  if (dir == nullptr) {
    return td::Status::PosixError(errno, PSLICE() << "cannot open material directory " << directory);
  }
  std::set<std::string> names;
  while (auto* entry = ::readdir(dir)) {
    std::string name = entry->d_name;
    if (name == "." || name == "..") {
      continue;
    }
    names.insert(name);
    if (names.size() > kMaxChainResponses + 16) {
      ::closedir(dir);
      return td::Status::Error("material directory has too many entries");
    }
  }
  ::closedir(dir);
  Material material;
  auto load = [&](const std::string& name) -> td::Result<td::BufferSlice> {
    TRY_RESULT(data, read_bounded_file(directory + "/" + name, kMaxFileBytes));
    names.erase(name);
    return td::BufferSlice(data);
  };
  auto optional = [&](const char* name, std::optional<td::BufferSlice>& slot) -> td::Status {
    if (names.count(name)) {
      TRY_RESULT(data, load(name));
      slot = std::move(data);
    }
    return td::Status::OK();
  };
  TRY_STATUS(optional("masterchain-info.tl", material.masterchain_info));
  TRY_STATUS(optional("config.tl", material.config));
  TRY_STATUS(optional("account.tl", material.account));
  TRY_STATUS(optional("exec-config.tl", material.exec_config));
  TRY_STATUS(optional("libraries.tl", material.libraries));
  for (std::size_t index = 0; names.count(numbered("chain", index)); ++index) {
    TRY_RESULT(data, load(numbered("chain", index)));
    material.chain.push_back(std::move(data));
  }
  for (std::size_t index = 0; names.count(numbered("descent", index)); ++index) {
    TRY_RESULT(data, load(numbered("descent", index)));
    material.descent.push_back(std::move(data));
  }
  if (!names.empty()) {
    return td::Status::Error(PSLICE() << "material directory has an unexpected entry " << *names.begin());
  }
  return material;
}

td::Status write_material(const std::string& directory, const Material& material) {
  if (::mkdir(directory.c_str(), 0700) != 0) {
    return td::Status::PosixError(errno, PSLICE() << "cannot create material directory " << directory);
  }
  auto put = [&](const std::string& name, const td::BufferSlice& data) {
    return write_new_file(directory + "/" + name, data.as_slice());
  };
  if (material.masterchain_info) {
    TRY_STATUS(put("masterchain-info.tl", *material.masterchain_info));
  }
  for (std::size_t i = 0; i < material.chain.size(); ++i) {
    TRY_STATUS(put(numbered("chain", i), material.chain[i]));
  }
  for (std::size_t i = 0; i < material.descent.size(); ++i) {
    TRY_STATUS(put(numbered("descent", i), material.descent[i]));
  }
  if (material.config) {
    TRY_STATUS(put("config.tl", *material.config));
  }
  if (material.account) {
    TRY_STATUS(put("account.tl", *material.account));
  }
  if (material.exec_config) {
    TRY_STATUS(put("exec-config.tl", *material.exec_config));
  }
  if (material.libraries) {
    TRY_STATUS(put("libraries.tl", *material.libraries));
  }
  return td::Status::OK();
}

}  // namespace tos::proofverify
