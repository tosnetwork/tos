#pragma once

#include "adnl/adnl-ext-client.h"
#include "keys/keys.hpp"
#include "td/actor/actor.h"
#include "td/actor/coro_task.h"
#include "td/utils/port/IPAddress.h"

namespace toslib {

bool is_engine_console_query(const tos::tl_object_ptr<tos::tos_api::Function>& function);

class EngineConsoleClient : public td::actor::Actor {
 public:
  EngineConsoleClient(td::IPAddress address, tos::PublicKey server_public_key, tos::PrivateKey client_private_key);

  void on_ready();
  void on_stop_ready();

  td::actor::Task<tos::tl_object_ptr<tos::tos_api::Object>> query(tos::tl_object_ptr<tos::tos_api::Function> function);

 private:
  td::IPAddress address_;
  tos::PublicKey server_public_key_;
  tos::PrivateKey client_private_key_;
  td::actor::ActorOwn<tos::adnl::AdnlExtClient> client_;
  bool ready_ = false;
  std::vector<td::Promise<td::Unit>> pending_ready_promises_;
};

}  // namespace toslib
