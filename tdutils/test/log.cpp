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

#include <functional>
#include <limits>

#include "td/utils/FileLog.h"
#include "td/utils/Slice.h"
#include "td/utils/TsFileLog.h"
#include "td/utils/benchmark.h"
#include "td/utils/filesystem.h"
#include "td/utils/format.h"
#include "td/utils/logging.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/path.h"
#include "td/utils/port/thread.h"
#include "td/utils/tests.h"

char disable_linker_warning_about_empty_file_tdutils_test_log_cpp TD_UNUSED;

#if !TD_THREAD_UNSUPPORTED
template <class Log>
class LogBenchmark : public td::Benchmark {
 public:
  LogBenchmark(std::string name, int threads_n, std::function<td::unique_ptr<Log>()> creator)
      : name_(std::move(name)), threads_n_(threads_n), creator_(std::move(creator)) {
  }
  std::string get_description() const override {
    return PSTRING() << name_ << " " << td::tag("threads_n", threads_n_);
  }
  void start_up() override {
    log_ = creator_();
    threads_.resize(threads_n_);
  }
  void tear_down() override {
    for (auto path : log_->get_file_paths()) {
      td::unlink(path).ignore();
    }
    log_.reset();
  }
  void run(int n) override {
    for (auto &thread : threads_) {
      thread = td::thread([this, n] { this->run_thread(n); });
    }
    for (auto &thread : threads_) {
      thread.join();
    }
  }

  void run_thread(int n) {
    auto str = PSTRING() << "#" << n << " : fsjklfdjsklfjdsklfjdksl\n";
    for (int i = 0; i < n; i++) {
      if (i % 10000 == 0) {
        log_->rotate();
      }
      log_->append(str);
    }
  }

 private:
  std::string name_;
  td::unique_ptr<Log> log_;
  int threads_n_{0};
  std::function<td::unique_ptr<Log>()> creator_;
  std::vector<td::thread> threads_;
};

template <class F>
static void bench_log(std::string name, int threads_n, F &&f) {
  bench(LogBenchmark<typename decltype(f())::element_type>(std::move(name), threads_n, std::move(f)));
};

TEST(Log, TsLogger) {
  bench_log("NewTsFileLog", 4,
            [] { return td::TsFileLog::create("tmplog", std::numeric_limits<td::int64>::max(), false).move_as_ok(); });
  bench_log("TsFileLog", 8, [] {
    class FileLog : public td::LogInterface {
     public:
      FileLog() {
        file_log_.init("tmplog", std::numeric_limits<td::int64>::max(), false).ensure();
        ts_log_.init(&file_log_);
      }
      ~FileLog() {
      }
      void append(td::CSlice slice) override {
        ts_log_.append(slice, -1);
      }
      std::vector<std::string> get_file_paths() override {
        return file_log_.get_file_paths();
      }

     private:
      td::FileLog file_log_;
      td::TsLog ts_log_{nullptr};
    };
    return td::make_unique<FileLog>();
  });

  bench_log("noop", 4, [] {
    class NoopLog : public td::LogInterface {
     public:
      void append(td::CSlice slice) override {
      }
    };
    return td::make_unique<NoopLog>();
  });

  bench_log("FileLog", 4, [] {
    class FileLog : public td::LogInterface {
     public:
      FileLog() {
        file_log_.init("tmplog", std::numeric_limits<td::int64>::max(), false).ensure();
      }
      ~FileLog() {
      }
      void append(td::CSlice slice) override {
        file_log_.append(slice, -1);
      }
      std::vector<std::string> get_file_paths() override {
        return file_log_.get_file_paths();
      }

     private:
      td::FileLog file_log_;
    };
    return td::make_unique<FileLog>();
  });
}

TEST(Log, TsFileLogRotationBoundsFileSize) {
  // A TsFileLog created with a finite rotation threshold must actually rotate:
  // once the active file passes the threshold it is renamed to `.old` and a
  // fresh truncated active file is opened, so no single file grows without
  // bound. This guards the historical dead bound where init_info() hardcoded
  // the per-thread FileLog threshold to int64 max, leaving the configured
  // rotate threshold ignored and the on-disk log unbounded. Reverting
  // init_info() to std::numeric_limits<int64>::max() makes this test fail: the
  // active file then retains all ~400 KiB written below, far above the 16 KiB
  // threshold.
  const td::int64 threshold = 16 * 1024;
  const std::string base = "tmplog_rotate_test";
  std::string line(200, 'x');
  line += '\n';
  const int lines = 2000;  // ~400 KiB total, >> threshold

  std::vector<std::string> paths;
  {
    auto log = td::TsFileLog::create(base, threshold, false).move_as_ok();
    for (int i = 0; i < lines; i++) {
      log->append(line);
    }
    paths = log->get_file_paths();
    // Every active per-thread file that exists must be bounded by the
    // threshold plus at most one trailing append (rotation happens after a
    // whole append, so a bounded overshoot is expected).
    bool saw_written_file = false;
    for (auto &path : paths) {
      auto r_stat = td::stat(path);
      if (r_stat.is_error()) {
        continue;  // per-thread slot that was never written to
      }
      saw_written_file = true;
      auto size = r_stat.ok().size_;
      ASSERT_TRUE(size <= threshold + static_cast<td::int64>(line.size()));
    }
    ASSERT_TRUE(saw_written_file);
  }

  for (auto &path : paths) {
    td::unlink(path).ignore();
    td::unlink(path + ".old").ignore();
  }
}

TEST(Log, FileLogKeepsTheConfiguredNumberOfRotatedFiles) {
  // One rotated file per log keeps minutes of a busy validator's log, so an
  // engine exit leaves no evidence. With keep_rotated = 3 the log keeps .old,
  // .old.1 and .old.2, newest first, and drops anything older.
  const std::string base = "tmplog_keep_test";
  auto cleanup = [&] {
    for (auto suffix : {"", ".old", ".old.1", ".old.2", ".old.3"}) {
      td::unlink(base + suffix).ignore();
    }
  };
  cleanup();
  {
    td::FileLog log;
    log.init(base, 100, false, 3).ensure();
    ASSERT_EQ(3, log.get_keep_rotated());
    // Each append is one generation: it passes the threshold, so it is rotated
    // away and the next append starts a fresh file.
    for (char generation : std::string("ABCDE")) {
      log.append(td::CSlice(std::string(150, generation) + "\n"), VERBOSITY_NAME(INFO));
    }
  }
  auto first_byte = [](std::string path) -> char {
    auto r = td::read_file_str(path);
    return r.is_ok() && !r.ok().empty() ? r.ok()[0] : '-';
  };
  ASSERT_EQ('E', first_byte(base + ".old"));
  ASSERT_EQ('D', first_byte(base + ".old.1"));
  ASSERT_EQ('C', first_byte(base + ".old.2"));
  ASSERT_TRUE(td::stat(base + ".old.3").is_error());
  cleanup();

  // The default keeps one rotated file, as before.
  {
    td::FileLog log;
    log.init(base, 100, false).ensure();
    ASSERT_EQ(1, log.get_keep_rotated());
    for (char generation : std::string("AB")) {
      log.append(td::CSlice(std::string(150, generation) + "\n"), VERBOSITY_NAME(INFO));
    }
  }
  ASSERT_EQ('B', first_byte(base + ".old"));
  ASSERT_TRUE(td::stat(base + ".old.1").is_error());
  cleanup();
}

TEST(Log, FileLogRemovesGenerationsBeyondAReducedLimit) {
  // A restart with a smaller kept number must not leave the older generations
  // on disk forever, or the disk budget the number sets is not kept.
  const std::string base = "tmplog_prune_test";
  auto cleanup = [&] {
    for (auto suffix : {"", ".old", ".old.1", ".old.2", ".old.3", ".old.4"}) {
      td::unlink(base + suffix).ignore();
    }
  };
  auto stage = [&] {
    for (auto suffix : {".old", ".old.1", ".old.2", ".old.3", ".old.4"}) {
      td::write_file(base + suffix, "x").ensure();
    }
  };
  cleanup();
  stage();
  {
    td::FileLog log;
    log.init(base, 1 << 20, false, 3).ensure();
  }
  ASSERT_TRUE(td::stat(base + ".old.1").is_ok());
  ASSERT_TRUE(td::stat(base + ".old.2").is_ok());
  ASSERT_TRUE(td::stat(base + ".old.3").is_error());
  ASSERT_TRUE(td::stat(base + ".old.4").is_error());
  {
    td::FileLog log;
    log.init(base, 1 << 20, false, 1).ensure();
  }
  ASSERT_TRUE(td::stat(base + ".old").is_ok());
  ASSERT_TRUE(td::stat(base + ".old.1").is_error());
  ASSERT_TRUE(td::stat(base + ".old.2").is_error());
  cleanup();

  // A gap in the numbering does not stop the removal: .old.2 is missing, .old.3
  // and .old.7 must still go.
  for (auto suffix : {".old", ".old.1", ".old.3", ".old.7"}) {
    td::write_file(base + suffix, "x").ensure();
  }
  {
    td::FileLog log;
    log.init(base, 1 << 20, false, 2).ensure();
  }
  ASSERT_TRUE(td::stat(base + ".old.1").is_ok());
  ASSERT_TRUE(td::stat(base + ".old.3").is_error());
  ASSERT_TRUE(td::stat(base + ".old.7").is_error());
  td::unlink(base + ".old.7").ignore();
  cleanup();

  // Reinitializing the same log with a smaller number prunes at once: a quiet
  // log may never rotate again.
  {
    td::FileLog log;
    log.init(base, 1 << 20, false, 3).ensure();
    for (auto suffix : {".old", ".old.1", ".old.2"}) {
      td::write_file(base + suffix, "x").ensure();
    }
    log.init(log.get_path().str(), 1 << 20, false, 1).ensure();
    ASSERT_EQ(1, log.get_keep_rotated());
    ASSERT_TRUE(td::stat(base + ".old").is_ok());
    ASSERT_TRUE(td::stat(base + ".old.1").is_error());
    ASSERT_TRUE(td::stat(base + ".old.2").is_error());
  }
  cleanup();
}
#endif
