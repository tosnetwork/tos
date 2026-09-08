/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <algorithm>
#include <cstddef>
#include <map>
#include <string>

#include "td/utils/RateLimiterWindow.h"
#include "td/utils/Time.h"
#include "td/utils/int_types.h"

namespace tos {

// Sliding-window request budget keyed by source address.
//
// Kept free of any actor, socket or option dependency so the admission
// decision can be exercised on its own: a budget nothing can test is
// indistinguishable from one nothing consults.
//
// The table is keyed by remote input, so it carries its own ceiling.
// Reclaiming the least recently seen address means a caller actively
// spending its budget is never the one dropped, and rotating addresses
// cannot be used to clear a window that is already spent.
class PerIpRateGate {
 public:
  PerIpRateGate(double window, td::uint64 limit, std::size_t max_sources)
      : window_(window), limit_(limit), max_sources_(max_sources) {
  }

  // Returns false once `source` has spent its budget for the current
  // window. A window or limit of zero disables the gate; an empty source
  // has no remote caller to attribute to and is always admitted.
  bool consume(const std::string &source, td::Timestamp now) {
    if (window_ <= 0.0 || limit_ == 0) {
      return true;
    }
    if (source.empty()) {
      return true;
    }

    auto it = budgets_.find(source);
    if (it == budgets_.end()) {
      if (max_sources_ > 0 && budgets_.size() >= max_sources_) {
        auto oldest = std::min_element(budgets_.begin(), budgets_.end(), [](const auto &a, const auto &b) {
          return a.second.last_seen.at() < b.second.last_seen.at();
        });
        if (oldest != budgets_.end()) {
          budgets_.erase(oldest);
        }
      }
      Budget budget;
      budget.window = td::RateLimiterWindow{window_, static_cast<size_t>(limit_)};
      it = budgets_.emplace(source, std::move(budget)).first;
    }

    it->second.last_seen = now;
    if (!it->second.window.check(now, 1)) {
      return false;
    }
    it->second.window.insert(now, 1);
    return true;
  }

  std::size_t tracked_sources() const {
    return budgets_.size();
  }

 private:
  struct Budget {
    td::RateLimiterWindow window;
    td::Timestamp last_seen;
  };

  double window_;
  td::uint64 limit_;
  std::size_t max_sources_;
  std::map<std::string, Budget> budgets_;
};

}  // namespace tos
