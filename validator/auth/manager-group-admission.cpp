#include <algorithm>

#include "manager-group-admission.h"

namespace tos::auth {
bool authenticated_session_admission_required(bool auth_active, bool live_same_session) {
  return auth_active && !live_same_session;
}

double next_chain_context_retry(double previous) {
  if (!(previous >= chain_context_retry_floor)) {
    return chain_context_retry_floor;
  }
  return std::min(previous * 2.0, chain_context_retry_ceiling);
}

bool ChainContextRetryGate::read_may_start() const {
  return !scheduled_;
}

std::optional<ChainContextRetryTicket> ChainContextRetryGate::failed() {
  if (scheduled_) {
    return std::nullopt;
  }
  delay_ = next_chain_context_retry(delay_);
  scheduled_ = true;
  ++generation_;
  return ChainContextRetryTicket{generation_, delay_};
}

bool ChainContextRetryGate::due(std::uint64_t generation) {
  if (!scheduled_ || generation != generation_) {
    return false;
  }
  scheduled_ = false;
  return true;
}

void ChainContextRetryGate::succeeded() {
  delay_ = 0.0;
  scheduled_ = false;
}
}  // namespace tos::auth
