/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <atomic>

#include "lite-client/ext-client.h"
#include "validator-engine/json-rpc-server.h"

namespace tos::services {

// One configured, authenticated liteserver. It is a trusted data source, not
// a replacement for a proof-verifying light client.
td::Result<std::vector<liteclient::LiteServerConfig>> read_liteservers(const std::string &path);
JsonRpcServer::LiteQuerySender lite_sender(td::actor::ActorId<liteclient::ExtClient> client, double timeout);
JsonRpcServer::IndexQuerySender index_sender(td::IPAddress address, double timeout);
extern std::atomic<bool> stop_requested;
void request_stop(int);

}  // namespace tos::services
