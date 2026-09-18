#include "native-session-provider.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <optional>

#include "block/mc-config.h"

#include "registry-view.h"

namespace tos::auth {
namespace {

Hash state_hash(const td::Ref<vm::Cell>& state) {
  Hash value{};
  if (state.not_null()) {
    auto owned = state->get_hash();
    std::copy_n(owned.as_slice().ubegin(), value.size(), value.begin());
  }
  return value;
}

// ProviderSessionAdmission needs only the current identity, its exact key
// descriptors and the coordinate. RegistryView supplies those facts from the
// authenticated birth Config46 without turning this read-only session path into
// a mutable registry or checkpoint restore path.
class BirthRegistry final : public CurrentRegistry {
 public:
  BirthRegistry(RegistryView view, std::uint32_t coordinate)
      : view_(std::move(view)), coordinate_(coordinate) {
  }

  Result<std::optional<Identity>> lookup_identity(
      const Hash& identity) const override {
    auto found = view_.identity(identity);
    if (!found.ok()) {
      if (found.error().code == "history-unavailable")
        return std::optional<Identity>{};
      return found.error();
    }
    return std::optional<Identity>{found.value()};
  }

  Result<Key> find(const Hash& key) const override {
    return view_.find(key);
  }
  Result<std::uint64_t> latest_epoch(const Hash& identity,
                                     KeySlot slot) const override {
    return view_.latest_epoch(identity, slot);
  }
  Result<bool> ever_registered(const Hash& identity) const override {
    return view_.ever_registered(identity);
  }
  const Hash& chain_domain() const override {
    return view_.chain_domain();
  }
  const Hash& current_policy() const override {
    return view_.current_policy();
  }
  std::uint32_t coordinate() const override {
    return coordinate_;
  }

 private:
  RegistryView view_;
  std::uint32_t coordinate_{};
};

Result<std::array<Keyref, 5>> member_keys(
    const NativeSessionCommitteeContext& context, const Hash& identity) {
  if (identity == Hash{})
    return Error{"session-member-nonmember"};

  const auto& members = context.committee().snapshot().committee().members_;
  auto found = std::find_if(
      members.begin(), members.end(),
      [&identity](const Member& member) { return member.identity_ == identity; });
  if (found == members.end())
    return Error{"session-member-nonmember"};
  if (std::find_if(std::next(found), members.end(),
                   [&identity](const Member& member) {
                     return member.identity_ == identity;
                   }) != members.end())
    return Error{"session-member-nonmember"};
  if (found->keys_.size() != 5)
    return Error{"session-c0-keys"};

  std::array<Keyref, 5> result{};
  for (std::size_t i = 0; i < result.size(); ++i) {
    const auto& key = found->keys_[i];
    if (key.role_ != i + 1 || key.identity_ != identity || key.suite_ != 1 ||
        key.parameters_ != 1)
      return Error{"session-c0-keys"};
    auto reference = key_reference(key);
    if (!reference.ok())
      return reference.error();
    result[i] = reference.value();
  }
  return result;
}

}  // namespace

Result<NativeSessionC0Authority> NativeSessionC0Authority::install(
    const std::shared_ptr<CommittedNativeSession>& session,
    td::Ref<vm::Cell> authenticated_birth_state,
    C0SigningProvider& provider, const Hash& identity,
    StateReadBudget budget) {
  if (!session || !session->context_)
    return Error{"session-context-missing"};

  auto role_keys = member_keys(*session->context_, identity);
  if (!role_keys.ok())
    return role_keys.error();

  const auto birth = session->birth_;
  if (authenticated_birth_state.is_null() ||
      state_hash(authenticated_birth_state) != birth.state)
    return Error{"session-c0-birth-state"};

  auto config = block::Config::extract_from_state(
      authenticated_birth_state, block::Config::needCapabilities);
  if (config.is_error())
    return Error{"session-c0-config"};
  auto registry_cell = config.ok()->get_config_param(46);
  if (registry_cell.is_null())
    return Error{"session-c0-registry"};

  auto view = RegistryView::open(registry_cell, birth.seqno, budget);
  if (!view.ok())
    return view.error();
  if (view.value().chain_domain() != session->chain_.chain_domain)
    return Error{"session-c0-chain"};

  BirthRegistry registry(std::move(view.value()), birth.seqno);
  auto admission = ProviderSessionAdmission::reconcile(
      registry, provider, identity);
  if (!admission.ok())
    return admission.error();
  if (admission.value().identity() != identity ||
      admission.value().coordinate() != birth.seqno)
    return Error{"session-c0-admission"};

  for (const auto& key : role_keys.value()) {
    auto handle = admission.value().route(key);
    if (!handle.ok())
      return Error{"session-c0-committee-key"};
  }

  return NativeSessionC0Authority(
      session, std::move(admission.value()), identity,
      session->native_session_id_, session->p0_session_id_,
      birth.seqno, role_keys.value());
}

Result<NativeSessionC0Route> NativeSessionC0Authority::route(
    std::uint8_t role) const {
  if (role < 1 || role > role_keys_.size())
    return Error{"session-c0-role"};

  auto session = owner_.lock();
  if (!session || !session->context_)
    return Error{"session-context-released"};
  if (session->native_session_id_ != native_session_id_ ||
      session->birth_.seqno != coordinate_)
    return Error{"session-c0-context"};

  auto current = member_keys(*session->context_, identity_);
  if (!current.ok())
    return current.error();
  const auto& expected = current.value()[role - 1];
  if (expected != role_keys_[role - 1])
    return Error{"session-c0-context"};

  auto handle = admission_.route(expected);
  if (!handle.ok())
    return handle.error();
  return NativeSessionC0Route{expected, handle.value()};
}

}  // namespace tos::auth
