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
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/

#include <array>

#include "td/utils/FileLog.h"
#include "td/utils/PathView.h"
#include "td/utils/Slice.h"
#include "td/utils/TsFileLog.h"
#include "td/utils/common.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"
#include "td/utils/port/path.h"
#include "td/utils/port/thread_local.h"

namespace td {
namespace detail {
namespace {

// Parses a decimal number of at most 9 digits that makes up all of `s`.
bool parse_small_number(Slice s, int64 &value) {
  if (s.empty() || s.size() > 9) {
    return false;
  }
  value = 0;
  for (char c : s) {
    if (c < '0' || c > '9') {
      return false;
    }
    value = value * 10 + (c - '0');
  }
  return true;
}

// Removes the archives of every per-thread log of `path` beyond the kept
// number: <path>.thread<N>.log.old.<k> for k >= keep_rotated. Only thread 0
// opens its file at start (and prunes it then); the others open on their
// first append, which a thread that stays idle in this process never reaches,
// so without this a reduced kept number would leave a previous run's idle
// threads' generations on disk forever. One scan of the log directory, so the
// cost does not depend on how many generations or threads could exist.
void prune_idle_thread_archives(const string &path, int32 keep_rotated, int32 max_threads) {
  PathView view(path);
  string dir = view.parent_dir().empty() ? string(".") : view.parent_dir_noslash().str();
  string prefix = PSTRING() << view.file_name() << ".thread";
  vector<string> doomed;
  WalkPath::run(dir, [&](CSlice name, WalkPath::Type type) {
    if (type == WalkPath::Type::EnterDir) {
      return name == dir ? WalkPath::Action::Continue : WalkPath::Action::SkipDir;
    }
    if (type != WalkPath::Type::RegularFile) {
      return WalkPath::Action::Continue;
    }
    Slice base = PathView(name).file_name();
    if (!begins_with(base, prefix)) {
      return WalkPath::Action::Continue;
    }
    // <N>.log.old.<k>
    Slice rest = base.substr(prefix.size());
    auto dot = rest.find('.');
    int64 thread = 0;
    int64 generation = 0;
    Slice marker(".log.old.");
    if (dot == Slice::npos || !parse_small_number(rest.substr(0, dot), thread)) {
      return WalkPath::Action::Continue;
    }
    rest = rest.substr(dot);
    if (!begins_with(rest, marker) || !parse_small_number(rest.substr(marker.size()), generation)) {
      return WalkPath::Action::Continue;
    }
    if (thread >= 1 && thread < max_threads && generation >= keep_rotated) {
      doomed.push_back(name.str());
    }
    return WalkPath::Action::Continue;
  }).ignore();
  for (auto &file : doomed) {
    unlink(file).ignore();
  }
}

}  // namespace
class TsFileLog : public LogInterface {
 public:
  Status init(string path, td::int64 rotate_threshold, bool redirect_stderr, td::int32 keep_rotated) {
    path_ = std::move(path);
    rotate_threshold_ = rotate_threshold;
    keep_rotated_ = keep_rotated;
    redirect_stderr_ = redirect_stderr;
    for (int i = 0; i < (int)logs_.size(); i++) {
      logs_[i].id = i;
    }
    prune_idle_thread_archives(path_, keep_rotated_ < 1 ? 1 : keep_rotated_, static_cast<int32>(logs_.size()));
    return init_info(&logs_[0]);
  }

  vector<string> get_file_paths() override {
    vector<string> res;
    for (auto &log : logs_) {
      res.push_back(get_path(&log));
    }
    return res;
  }

  void append(CSlice cslice) override {
    return append(cslice, -1);
  }
  void append(CSlice cslice, int log_level) override {
    get_current_logger()->append(cslice, log_level);
  }

 private:
  struct Info {
    FileLog log;
    std::atomic<bool> is_inited{false};
    int id;
  };
  int64 rotate_threshold_;
  int32 keep_rotated_ = 1;
  bool redirect_stderr_;
  std::string path_;
  std::array<Info, MAX_THREADS> logs_;

  LogInterface *get_current_logger() {
    auto *info = get_current_info();
    if (!info->is_inited.load(std::memory_order_relaxed)) {
      CHECK(init_info(info).is_ok());
    }
    return &info->log;
  }

  Info *get_current_info() {
    return &logs_[get_thread_id()];
  }

  Status init_info(Info *info) {
    // Pass the configured rotation threshold through to each per-thread
    // FileLog. Historically this was hardcoded to int64 max, which left the
    // stored rotate_threshold_ (and TsFileLog's DEFAULT_ROTATE_THRESHOLD)
    // dead: the on-disk log grew without bound. Each thread keeps its own
    // file pair, so this bounds every file to rotate_threshold_ (+ at most one
    // trailing append) plus its retained `.old`.
    TRY_STATUS(info->log.init(get_path(info), rotate_threshold_, info->id == 0 && redirect_stderr_, keep_rotated_));
    info->is_inited = true;
    return Status::OK();
  }

  string get_path(Info *info) {
    if (info->id == 0) {
      return path_;
    }
    return PSTRING() << path_ << ".thread" << info->id << ".log";
  }

  void rotate() override {
    for (auto &info : logs_) {
      if (info.is_inited.load(std::memory_order_consume)) {
        info.log.lazy_rotate();
      }
    }
  }
};
}  // namespace detail

Result<td::unique_ptr<LogInterface>> TsFileLog::create(string path, td::int64 rotate_threshold, bool redirect_stderr,
                                                       td::int32 keep_rotated) {
  auto res = td::make_unique<detail::TsFileLog>();
  TRY_STATUS(res->init(path, rotate_threshold, redirect_stderr, keep_rotated));
  return std::move(res);
}
}  // namespace td
