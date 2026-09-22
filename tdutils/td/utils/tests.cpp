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
#include <iostream>
#include <map>

#include "td/utils/Parser.h"
#include "td/utils/PathView.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/Time.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/FileFd.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"

namespace td {

struct TestInfo {
  string name;
  string result_hash;  // base64
};
StringBuilder &operator<<(StringBuilder &sb, const TestInfo &info) {
  // should I use JSON?
  CHECK(!info.name.empty());
  CHECK(!info.result_hash.empty());
  return sb << info.name << " " << info.result_hash << "\n";
}

class RegressionTesterImpl : public RegressionTester {
 public:
  static void destroy(CSlice db_path) {
    unlink(db_path).ignore();
  }

  RegressionTesterImpl(string db_path, string db_cache_dir) : db_path_(db_path), db_cache_dir_(db_cache_dir) {
    load_db(db_path, tests_, true).ensure();
    // The answer file is the shared resource, so every writer to the same path
    // must derive the same lock regardless of where that caller keeps its cache.
    db_lock_path_ = db_path_ + ".lock";
    if (db_cache_dir_.empty()) {
      db_cache_dir_ = PathView(db_path).without_extension().str() + ".cache/";
    }
    mkdir(db_cache_dir_).ensure();
  }

  Status verify_test(Slice name, Slice result) override {
#if TD_HAVE_OPENSSL
    auto hash = PSTRING() << format::as_hex_dump<0>(Slice(sha256(result)));
#else
    auto hash = to_string(crc64(result));
#endif
    TestInfo &old_test_info = tests_[name.str()];
    if (!old_test_info.result_hash.empty() && old_test_info.result_hash != hash) {
      auto wa_path = db_cache_dir_ + "WA";
      write_file(wa_path, result).ensure();
      return Status::Error(PSLICE() << "Test " << name << " changed: " << tag("expected", old_test_info.result_hash)
                                    << tag("got", hash));
    }
    auto result_cache_path = db_cache_dir_ + hash;
    if (stat(result_cache_path).is_error()) {
      write_file(result_cache_path, result).ensure();
    }
    if (!old_test_info.result_hash.empty()) {
      return Status::OK();
    }
    old_test_info.name = name.str();
    old_test_info.result_hash = hash;
    is_dirty_ = true;

    return Status::OK();
  }

  void save_db() override {
    if (!is_dirty_) {
      return;
    }
    SCOPE_EXIT {
      is_dirty_ = false;
    };
    // The answer file is shared by several test binaries. Lock a stable sidecar
    // (locking db_path_ itself would lock the old inode across rename), reload
    // the newest record under that lock, and merge our additions before the
    // atomic replace. A unique temporary file prevents stale or concurrent
    // writers from sharing the old fixed `.new` pathname.
    auto lock_file = FileFd::open(db_lock_path_, FileFd::Read | FileFd::Write | FileFd::Create).move_as_ok();
    lock_file.lock(FileFd::LockFlags::Write, db_lock_path_, 6000).ensure();
    SCOPE_EXIT {
      lock_file.lock(FileFd::LockFlags::Unlock, db_lock_path_, 1).ensure();
    };

    std::map<string, TestInfo> latest;
    load_db(db_path_, latest, true).ensure();
    for (const auto &[name, info] : tests_) {
      auto [it, inserted] = latest.emplace(name, info);
      if (!inserted && it->second.result_hash != info.result_hash) {
        Status::Error(PSLICE() << "Concurrent regression result disagrees for " << name).ensure();
      }
    }

    string buf(2000000, ' ');
    StringBuilder sb(buf);
    save_db(sb, latest);
    auto db_parent_dir = PathView(db_path_).parent_dir_noslash().str();
    auto [new_db, new_db_path] = mkstemp(db_parent_dir).move_as_ok();
    SCOPE_EXIT {
      unlink(new_db_path).ignore();
    };
    new_db.write_all(sb.as_cslice()).ensure();
    new_db.close();
    rename(new_db_path, db_path_).ensure();
  }

  Slice magic() const {
    return Slice("abce");
  }

  void save_db(StringBuilder &sb, const std::map<string, TestInfo> &tests) {
    sb << magic() << "\n";
    for (const auto &it : tests) {
      sb << it.second;
    }
  }

  Status load_db(CSlice path, std::map<string, TestInfo> &tests, bool missing_is_empty) {
    auto data_result = read_file(path);
    if (data_result.is_error()) {
      auto error = data_result.move_as_error();
      if (missing_is_empty && error.code() == ENOENT) {
        return Status::OK();
      }
      return error.move_as_error_prefix(PSLICE() << "Can't read regression database " << path << ": ");
    }
    auto data = data_result.move_as_ok();
    ConstParser parser(data.as_slice());
    auto db_magic = parser.read_word();
    if (db_magic != magic()) {
      return Status::Error(PSLICE() << "Regression database " << path << " is corrupt: wrong magic " << db_magic);
    }
    while (true) {
      TestInfo info;
      info.name = parser.read_word().str();
      if (info.name.empty()) {
        break;
      }
      info.result_hash = parser.read_word().str();
      tests[info.name] = info;
    }
    return Status::OK();
  }

 private:
  string db_path_;
  string db_cache_dir_;
  string db_lock_path_;
  bool is_dirty_{false};

  std::map<string, TestInfo> tests_;
};

void RegressionTester::destroy(CSlice path) {
  RegressionTesterImpl::destroy(path);
}

unique_ptr<RegressionTester> RegressionTester::create(string db_path, string db_cache_dir) {
  return td::make_unique<RegressionTesterImpl>(std::move(db_path), std::move(db_cache_dir));
}

TestsRunner &TestsRunner::get_default() {
  static TestsRunner default_runner;
  return default_runner;
}

void TestsRunner::add_test(string name, unique_ptr<Test> test) {
  for (auto &it : tests_) {
    if (it.first == name) {
      LOG(FATAL) << "Test name collision " << name;
    }
  }
  tests_.emplace_back(name, std::move(test));
}

void TestsRunner::add_substr_filter(string str) {
  if (str[0] != '+' && str[0] != '-') {
    str = "+" + str;
  }
  substr_filters_.push_back(std::move(str));
}

void TestsRunner::set_regression_tester(unique_ptr<RegressionTester> regression_tester) {
  regression_tester_ = std::move(regression_tester);
}

void TestsRunner::set_stress_flag(bool flag) {
  stress_flag_ = flag;
}

void TestsRunner::set_pretty_output(bool flag) {
  pretty_output_ = flag;
}

bool TestsRunner::use_pretty_output() const {
  return pretty_output_;
}

void TestsRunner::run_all() {
  while (run_all_step()) {
  }
}

bool TestsRunner::run_all_step() {
  Guard guard(this);
  if (state_.it == state_.end) {
    state_.end = tests_.size();
    state_.it = 0;
  }

  while (state_.it != state_.end) {
    auto &name = tests_[state_.it].first;
    auto test = tests_[state_.it].second.get();
    if (!state_.is_running) {
      bool ok = true;
      for (const auto &filter : substr_filters_) {
        bool is_match = name.find(filter.substr(1)) != string::npos;
        if (is_match != (filter[0] == '+')) {
          ok = false;
          break;
        }
      }
      if (!ok) {
        ++state_.it;
        continue;
      }
      if (pretty_output_) {
        std::cerr << "Running test " << name << "..." << std::endl;
      } else {
        LOG(ERROR) << "Run test " << tag("name", name);
      }
      state_.start = Time::now();
      state_.start_unadjusted = Time::now_unadjusted();
      state_.is_running = true;
    }

    if (test->step()) {
      break;
    }

    auto passed = Time::now() - state_.start;
    auto real_passed = Time::now_unadjusted() - state_.start_unadjusted;
    ++executed_tests_;
    if (test_failed_) {
      if (pretty_output_) {
        std::cerr << "FAIL" << std::endl;
        failed_tests_.push_back(name);
      } else {
        LOG(ERROR) << "FAILED in " << format::as_time(passed);
      }
      any_test_failed_ = true;
    } else {
      if (pretty_output_) {
        std::cerr << "PASS in " << (PSTRING() << format::as_time(passed)) << std::endl;
        ++passed_tests_;
      } else if (real_passed + 1e-9 > passed) {
        LOG(ERROR) << format::as_time(passed);
      } else {
        LOG(ERROR) << format::as_time(passed) << " real[" << format::as_time(real_passed) << "]";
      }
    }
    if (regression_tester_) {
      regression_tester_->save_db();
    }
    state_.is_running = false;
    test_failed_ = false;
    ++state_.it;
  }

  auto ret = state_.it != state_.end;
  if (!ret) {
    if (pretty_output_) {
      if (failed_tests_.empty()) {
        std::cerr << passed_tests_ << " test(s) passed" << std::endl;
      } else {
        std::cerr << failed_tests_.size() << " test(s) failed:" << std::endl;
        for (auto &failed_name : failed_tests_) {
          std::cerr << " - " << failed_name << std::endl;
        }
      }
    }
    state_ = State();
    test_failed_ = false;
  }
  return ret || stress_flag_;
}

Slice TestsRunner::name() {
  CHECK(state_.is_running);
  return tests_[state_.it].first;
}

Status TestsRunner::verify(Slice data) {
  if (!regression_tester_) {
    LOG(INFO) << data;
    LOG(ERROR) << "Cannot verify and save <" << name() << "> answer. Use --regression <regression_db> option";
    return Status::OK();
  }
  return regression_tester_->verify_test(PSLICE() << name() << "_default", data);
}

void TestsRunner::register_test_failure() {
  CHECK(state_.is_running);
  test_failed_ = true;
}

bool TestsRunner::any_test_failed() const {
  return any_test_failed_;
}

}  // namespace td
