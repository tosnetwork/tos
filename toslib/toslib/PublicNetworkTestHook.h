#pragma once
// Compiled only into the dedicated Q01 test library; never the release toslib ABI.
#ifndef TOSLIB_Q01_TEST_NETWORK
#error Q01 test hook requires its dedicated target
#endif
#include "lite-client/ext-client.h"
#include <memory>
namespace toslib {
struct QueryTraceContext {
  td::uint64 public_request_id{0};
  td::uint32 transport_generation{0};
  td::uint64 arm_token{0};
  bool decoder_negative{false};  // Explicit test-only single-byte decoder input control.
};
class PublicNetworkTestHook {
 public:
  virtual ~PublicNetworkTestHook() = default;
  virtual td::actor::ActorOwn<liteclient::ExtClient> decorate(
      td::actor::ActorOwn<liteclient::ExtClient> real, td::uint32 generation) = 0;
  virtual void arm(td::uint64 id, std::string nonce, td::Promise<QueryTraceContext> ack) = 0;
  virtual void send_bound_query(QueryTraceContext context, td::BufferSlice data,
      td::Timestamp deadline, td::Promise<td::BufferSlice> promise) = 0;
};
}
