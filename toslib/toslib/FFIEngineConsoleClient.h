#pragma once

#include "auto/tl/tos_api.h"
#include "keys/keys.hpp"
#include "td/utils/port/IPAddress.h"

#include "EngineConsoleClient.h"
#include "FFIEventLoop.h"

namespace toslib {

class FFIEngineConsoleClient {
 public:
  FFIEngineConsoleClient(FFIEventLoop& loop, td::IPAddress address, tos::PublicKey server_public_key,
                         tos::PrivateKey client_private_key);

  FFIEngineConsoleClient(FFIEngineConsoleClient&&) = default;

  ~FFIEngineConsoleClient() {
    if (!client_.empty()) {
      loop_.run_in_context([client = std::move(client_)]() mutable { client.reset(); });
    }
  }

  void request(tos::tl_object_ptr<tos::tos_api::Function> query,
               td::Promise<tos::tl_object_ptr<tos::tos_api::Object>> promise);

  FFIEventLoop& loop() {
    return loop_;
  }

 private:
  FFIEventLoop& loop_;
  td::unique_ptr<td::Guard> counter_;
  td::actor::ActorOwn<EngineConsoleClient> client_;
};

}  // namespace toslib
