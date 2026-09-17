#include <algorithm>

#include "manager-group-admission.h"

namespace tos::auth {
double next_chain_context_retry(double previous) {
  if (!(previous >= chain_context_retry_floor)) {
    return chain_context_retry_floor;
  }
  return std::min(previous * 2.0, chain_context_retry_ceiling);
}
}  // namespace tos::auth
