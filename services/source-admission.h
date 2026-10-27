/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <algorithm>
#include <cstdint>

#include "td/utils/Status.h"
#include "td/utils/logging.h"

namespace tos::services {

// Descriptor admission for source reads. A source read can open one archive
// slice, which then holds up to that slice's weight in descriptors until the
// archive LRU closes it again; closing is asynchronous and waits for the
// slice's active queries. Running out of descriptors inside the node database
// layer aborts the process, so a read is admitted only while the descriptors
// held, plus room for the largest slice seen, stay within the budget.
struct SourceAdmission {
  // Descriptors the process may hold (its soft RLIMIT_NOFILE less a margin
  // for sockets and other files opened between checks).
  std::uint64_t budget = 0;
  // Room kept for one slice open before any slice has reported its weight.
  std::uint64_t min_reserve = 512;
};

// `open_fds` negative means the count is unavailable; the read is then
// refused, since nothing else bounds it. Admission depends only on the
// descriptors actually held: a refused read changes nothing, while slices the
// LRU closed meanwhile release theirs, so a refusal clears by itself once the
// count is back within the budget.
inline td::Status admit_source_request(const SourceAdmission& admission, std::int64_t open_fds,
                                       std::uint64_t largest_slice_files) {
  if (admission.budget == 0) {
    return td::Status::OK();
  }
  if (open_fds < 0) {
    return td::Status::Error("source read refused: the process's open descriptors cannot be counted");
  }
  auto reserve = std::max(admission.min_reserve, largest_slice_files);
  auto held = static_cast<std::uint64_t>(open_fds);
  if (held > admission.budget || admission.budget - held < reserve) {
    return td::Status::Error(PSTRING() << "source read refused: " << held << " descriptors held, " << reserve
                                       << " reserved for an archive slice, budget " << admission.budget
                                       << "; replay resumes when archive slices have closed");
  }
  return td::Status::OK();
}

}  // namespace tos::services
