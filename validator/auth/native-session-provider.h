#pragma once

#include <array>
#include <cstdint>
#include <memory>

#include "native-session-continuity.h"
#include "node-provisioning.h"

namespace tos::auth {

struct NativeSessionC0Route {
  Keyref key;
  Hash handle{};
  bool operator==(const NativeSessionC0Route&) const = default;
};

// A local capability binding one reconciled C0 provider inventory to one
// authenticated native session member. It is deliberately not durable chain
// state: restart authenticates the session birth again and reconciles the
// provider again. The capability retains no provider object and exposes no raw
// signing operation; it only maps the immutable session key for a role to the
// opaque handle admitted by ProviderSessionAdmission.
class NativeSessionC0Authority {
 public:
  NativeSessionC0Authority(const NativeSessionC0Authority&) = delete;
  NativeSessionC0Authority& operator=(const NativeSessionC0Authority&) = delete;
  NativeSessionC0Authority(NativeSessionC0Authority&&) = default;
  NativeSessionC0Authority& operator=(NativeSessionC0Authority&&) = default;

  static Result<NativeSessionC0Authority> install(
      const std::shared_ptr<CommittedNativeSession>& session,
      td::Ref<vm::Cell> authenticated_birth_state,
      C0SigningProvider& provider, const Hash& identity,
      StateReadBudget budget = {});

  Result<NativeSessionC0Route> route(std::uint8_t role) const;

  const Hash& identity() const {
    return identity_;
  }
  std::uint32_t coordinate() const {
    return coordinate_;
  }
  const Hash& session_id() const {
    return session_id_;
  }

 private:
  NativeSessionC0Authority(
      std::weak_ptr<CommittedNativeSession> owner,
      ProviderSessionAdmission admission, Hash identity,
      Hash session_id, std::uint32_t coordinate,
      std::array<Keyref, 5> role_keys)
      : owner_(std::move(owner)), admission_(std::move(admission)),
        identity_(identity), session_id_(session_id), coordinate_(coordinate),
        role_keys_(std::move(role_keys)) {
  }

  std::weak_ptr<CommittedNativeSession> owner_;
  ProviderSessionAdmission admission_;
  Hash identity_{};
  Hash session_id_{};
  std::uint32_t coordinate_{};
  std::array<Keyref, 5> role_keys_{};
};

}  // namespace tos::auth
