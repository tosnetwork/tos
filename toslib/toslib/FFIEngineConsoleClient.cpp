#include "FFIEngineConsoleClient.h"

namespace toslib {

FFIEngineConsoleClient::FFIEngineConsoleClient(FFIEventLoop& loop, td::IPAddress address,
                                               tos::PublicKey server_public_key, tos::PrivateKey client_private_key)
    : loop_(loop), counter_(loop.new_actor()) {
  loop_.run_in_context([&] {
    client_ = td::actor::create_actor<EngineConsoleClient>("EngineConsoleClient", address, server_public_key,
                                                           client_private_key);
  });
}

void FFIEngineConsoleClient::request(tos::tl_object_ptr<tos::tos_api::Function> query,
                                     td::Promise<tos::tl_object_ptr<tos::tos_api::Object>> promise) {
  loop_.run_in_context(
      [client = this->client_.get(), query = std::move(query), promise = std::move(promise)]() mutable {
        td::actor::send_closure(client, &EngineConsoleClient::query, std::move(query), std::move(promise));
      });
}

}  // namespace toslib
