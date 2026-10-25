/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include <iostream>

#include "td/utils/OptionParser.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/signals.h"
#include "vm/vm.h"

#include "service-common.h"

int main(int argc, char **argv) {
  using namespace tos;
  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  std::string config, key_file;
  td::IPAddress listen, index;
  listen.init_host_port("127.0.0.1:8080").ensure();
  JsonRpcServer::Options options;
  int threads = 4;
  td::OptionParser parser;
  parser.set_description("Standalone wallet JSON-RPC service. Use a TLS reverse proxy for public write access.");
  parser.add_option('h', "help", "show help", [&] {
    std::cout << (PSTRING() << parser);
    std::exit(0);
  });
  parser.add_option('C', "global-config", "trusted liteserver configuration", [&](td::Slice v) { config = v.str(); });
  parser.add_checked_option('\0', "listen", "HTTP bind address (default 127.0.0.1:8080)",
                            [&](td::Slice v) { return listen.init_host_port(v.str()); });
  parser.add_checked_option('\0', "index-address", "internal wallet index HTTP address (loopback only)",
                            [&](td::Slice v) { return index.init_host_port(v.str()); });
  parser.add_option('\0', "readonly", "disable transaction submission", [&] { options.readonly = true; });
  parser.add_option('\0', "api-key-file", "read HTTP API key from a file", [&](td::Slice v) { key_file = v.str(); });
  parser.add_option('\0', "cors-origin", "allowed browser origin", [&](td::Slice v) { options.cors_origin = v.str(); });
  parser.add_option('\0', "trust-proxy-headers", "honor source headers from trusted proxies",
                    [&] { options.trust_proxy_headers = true; });
  parser.add_option('\0', "trusted-proxy", "trusted proxy IP (repeatable)",
                    [&](td::Slice v) { options.trusted_proxies.push_back(v.str()); });
  parser.add_checked_option('\0', "request-timeout", "backend timeout, 1 to 300 seconds", [&](td::Slice v) {
    TRY_RESULT(n, td::to_integer_safe<int>(v));
    if (n < 1 || n > 300)
      return td::Status::Error("request-timeout must be 1..300");
    options.request_timeout = n;
    return td::Status::OK();
  });
  parser.add_checked_option('\0', "threads", "scheduler threads, 1 to 32", [&](td::Slice v) {
    TRY_RESULT(n, td::to_integer_safe<int>(v));
    if (n < 1 || n > 32)
      return td::Status::Error("threads must be 1..32");
    threads = n;
    return td::Status::OK();
  });
  auto parsed = parser.run(argc, argv);
  if (parsed.is_error()) {
    LOG(ERROR) << parsed.error();
    return 2;
  }
  auto servers = services::read_liteservers(config);
  auto admission = json_rpc::check_listen_admission(listen, options.readonly);
  if (servers.is_error() || admission.is_error()) {
    if (servers.is_error())
      LOG(ERROR) << servers.error();
    if (admission.is_error())
      LOG(ERROR) << admission;
    return 2;
  }
  if (index.is_valid() && !json_rpc::is_loopback_bind_address(index)) {
    LOG(ERROR) << "index-address must be loopback; use a local authenticated tunnel for remote services";
    return 2;
  }
  if (!key_file.empty()) {
    auto key = td::read_file(key_file);
    if (key.is_error()) {
      LOG(ERROR) << key.error();
      return 2;
    }
    options.api_key = td::trim(key.ok().as_slice()).str();
    if (options.api_key.empty()) {
      LOG(ERROR) << "empty API key";
      return 2;
    }
  }
  td::set_default_failure_signal_handler().ensure();
  td::set_signal_handler(td::SignalType::Quit, services::request_stop).ensure();
  td::actor::Scheduler scheduler({static_cast<size_t>(threads)});
  td::actor::ActorOwn<liteclient::ExtClient> client;
  td::actor::ActorOwn<JsonRpcServer> server;
  scheduler.run_in_context([&] {
    vm::init_vm().ensure();
    client = liteclient::ExtClient::create(servers.move_as_ok(), nullptr);
    options.lite_query_sender = services::lite_sender(client.get(), options.request_timeout);
    if (index.is_valid())
      options.index_query_sender = services::index_sender(index, options.request_timeout);
    server = JsonRpcServer::create({}, std::move(options));
    td::actor::send_closure(server, &JsonRpcServer::listen, listen);
  });
  while (scheduler.run(0.1)) {
    if (services::stop_requested.load())
      scheduler.stop();
  }
  return 0;
}
