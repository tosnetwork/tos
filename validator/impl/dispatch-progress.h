#pragma once
#include "td/utils/common.h"

namespace tos::validator {
// Production's node-local soft limit is at least the chain hard limit. A
// validator enforces the chain minimum, using the authenticated cleanup point.
inline bool dispatch_progress_required(td::uint64 old_size, td::uint64 post_cleanup_size, td::uint64 soft_limit,
                                       td::uint64 hard_limit) {
  return old_size <= hard_limit || post_cleanup_size <= soft_limit;
}
inline bool is_pre_dispatch_cleanup(int mode, int normalized_tag) {
  return mode == 1 && normalized_tag == 6;
}
}  // namespace tos::validator
