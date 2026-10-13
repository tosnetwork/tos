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

#include <cerrno>
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

TEST(Log, TsFileLogPrunesIdleThreadArchivesAtStart) {
  // A per-thread log opens its file on the thread's first append. A thread
  // that logged in a previous run with a larger kept number but stays idle now
  // must still lose the generations beyond the reduced number at start.
  const std::string base = "tmplog_ts_prune_test";
  const std::string idle = base + ".thread31.log";
  auto cleanup = [&] {
    for (auto &path : {base, idle}) {
      for (auto suffix : {"", ".old", ".old.1", ".old.2", ".old.3", ".old.4", ".old.9"}) {
        td::unlink(path + suffix).ignore();
      }
    }
  };
  cleanup();
  // Gapped generations: .old.2 is missing.
  for (auto suffix : {".old", ".old.1", ".old.3", ".old.4", ".old.9"}) {
    td::write_file(idle + suffix, "x").ensure();
  }
  // Names that only look like another log's archives are left alone.
  const std::string foreign = base + "x.thread31.log.old.9";
  const std::string unparsable = idle + ".old.9x";
  td::write_file(foreign, "x").ensure();
  td::write_file(unparsable, "x").ensure();
  {
    auto log = td::TsFileLog::create(base, 1 << 20, false, 2).move_as_ok();
    log->append(td::CSlice("only the main thread writes\n"));
  }
  ASSERT_TRUE(td::stat(base).is_ok());
  ASSERT_TRUE(td::stat(idle).is_error());
  ASSERT_TRUE(td::stat(idle + ".old").is_ok());
  ASSERT_TRUE(td::stat(idle + ".old.1").is_ok());
  ASSERT_TRUE(td::stat(idle + ".old.3").is_error());
  ASSERT_TRUE(td::stat(idle + ".old.4").is_error());
  ASSERT_TRUE(td::stat(idle + ".old.9").is_error());
  ASSERT_TRUE(td::stat(foreign).is_ok());
  ASSERT_TRUE(td::stat(unparsable).is_ok());
  td::unlink(foreign).ignore();
  td::unlink(unparsable).ignore();
  cleanup();
}

#if TD_PORT_POSIX
TEST(Log, FileLogTellsAMissingFileFromOtherOsErrors) {
  // The rotation and prune code treat only a missing file as benign, by the
  // errno the OS error carries.
  const std::string base = "tmplog_errno_test";
  td::rmrf(base + ".dir").ignore();
  auto missing = td::rename(base + ".missing", base + ".other");
  ASSERT_TRUE(missing.is_error());
  ASSERT_EQ(ENOENT, missing.code());
  ASSERT_TRUE(td::FileLog::is_missing_file_error(missing));
  ASSERT_TRUE(td::FileLog::is_missing_file_error(td::unlink(base + ".missing")));

  td::mkdir(base + ".dir").ensure();
  td::write_file(base + ".dir/inside", "x").ensure();
  auto is_dir = td::unlink(base + ".dir");
  ASSERT_TRUE(is_dir.is_error());
  ASSERT_TRUE(is_dir.code() != 0);
  ASSERT_TRUE(!td::FileLog::is_missing_file_error(is_dir));
  ASSERT_TRUE(!td::FileLog::is_missing_file_error(td::Status::OK()));
  td::rmrf(base + ".dir").ensure();
}

TEST(Log, FileLogStopsShiftingWhenARenameFails) {
  // A rename that fails for any reason but a missing source must stop the
  // shift: going on would move newer generations over files that were never
  // moved out of the way. The current file still rotates into .old, so the
  // log keeps working and stays bounded, and the failure is counted.
  const std::string base = "tmplog_shift_fail_test";
  auto cleanup = [&] {
    td::rmrf(base + ".old.3").ignore();
    for (auto suffix : {"", ".old", ".old.1", ".old.2", ".old.3", ".old.4"}) {
      td::unlink(base + suffix).ignore();
    }
  };
  auto first_byte = [](std::string path) -> char {
    auto r = td::read_file_str(path);
    return r.is_ok() && !r.ok().empty() ? r.ok()[0] : '-';
  };
  cleanup();
  // A non-empty directory where the oldest kept generation goes: a file cannot
  // be renamed onto it.
  td::mkdir(base + ".old.3").ensure();
  td::write_file(base + ".old.3/inside", "x").ensure();

  auto rotation_failures = td::FileLog::rotation_failures();
  auto prune_failures = td::FileLog::prune_failures();
  {
    td::FileLog log;
    log.init(base, 100, false, 4).ensure();
    // A, B and C fill .old, .old.1 and .old.2. Every missing source on the way
    // is skipped without counting.
    for (char generation : std::string("ABC")) {
      log.append(td::CSlice(std::string(150, generation) + "\n"), VERBOSITY_NAME(INFO));
    }
    ASSERT_EQ(rotation_failures, td::FileLog::rotation_failures());
    ASSERT_EQ('C', first_byte(base + ".old"));
    ASSERT_EQ('B', first_byte(base + ".old.1"));
    ASSERT_EQ('A', first_byte(base + ".old.2"));

    // D cannot shift .old.2 into .old.3. Nothing older moves, and D replaces
    // only .old.
    log.append(td::CSlice(std::string(150, 'D') + "\n"), VERBOSITY_NAME(INFO));
    ASSERT_EQ(rotation_failures + 1, td::FileLog::rotation_failures());
    ASSERT_EQ('D', first_byte(base + ".old"));
    ASSERT_EQ('B', first_byte(base + ".old.1"));
    ASSERT_EQ('A', first_byte(base + ".old.2"));

    // Each later rotation fails the same way and is counted again; the log
    // still writes, and no file beyond the kept ones appears.
    log.append(td::CSlice(std::string(150, 'E') + "\n"), VERBOSITY_NAME(INFO));
    ASSERT_EQ(rotation_failures + 2, td::FileLog::rotation_failures());
    log.append(td::CSlice("still logging\n"), VERBOSITY_NAME(INFO));
    ASSERT_EQ('E', first_byte(base + ".old"));
    ASSERT_EQ('B', first_byte(base + ".old.1"));
    ASSERT_EQ('A', first_byte(base + ".old.2"));
    ASSERT_EQ('s', first_byte(base));
    ASSERT_TRUE(td::stat(base + ".old.3/inside").is_ok());
    ASSERT_TRUE(td::stat(base + ".old.4").is_error());
  }
  // The directory sits inside the kept range, so pruning never touched it.
  ASSERT_EQ(prune_failures, td::FileLog::prune_failures());
  cleanup();
}

TEST(Log, FileLogReportsAStaleFileItCannotRemove) {
  // A stale generation that cannot be removed is counted and reported, and
  // init still succeeds: a few files too many must not stop the engine. The
  // absent generations the scan also tries do not count.
  const std::string base = "tmplog_prune_fail_test";
  auto cleanup = [&] {
    td::rmrf(base + ".old.5").ignore();
    for (auto suffix : {"", ".old", ".old.1", ".old.2"}) {
      td::unlink(base + suffix).ignore();
    }
  };
  cleanup();
  auto prune_failures = td::FileLog::prune_failures();
  {
    td::FileLog log;
    log.init(base, 1 << 20, false, 2).ensure();
  }
  ASSERT_EQ(prune_failures, td::FileLog::prune_failures());

  td::mkdir(base + ".old.5").ensure();
  td::write_file(base + ".old.5/inside", "x").ensure();
  td::write_file(base + ".old.2", "x").ensure();
  {
    td::FileLog log;
    log.init(base, 1 << 20, false, 2).ensure();
    log.append(td::CSlice("logging\n"), VERBOSITY_NAME(INFO));
  }
  ASSERT_EQ(prune_failures + 1, td::FileLog::prune_failures());
  ASSERT_TRUE(td::stat(base + ".old.2").is_error());
  ASSERT_TRUE(td::stat(base + ".old.5/inside").is_ok());
  cleanup();
}

TEST(Log, TsFileLogReportsIdleArchivesItCannotRemove) {
  // The same at start for an idle thread's archives: an entry it cannot remove
  // and a directory it cannot scan are counted, and the log still starts.
  const std::string base = "tmplog_ts_prune_fail_test";
  const std::string idle = base + ".thread31.log";
  auto cleanup = [&] {
    td::rmrf(idle + ".old.5").ignore();
    for (auto suffix : {"", ".old", ".old.2", ".old.3"}) {
      td::unlink(base + suffix).ignore();
      td::unlink(idle + suffix).ignore();
    }
  };
  cleanup();
  auto prune_failures = td::FileLog::prune_failures();
  // Nothing stale on disk: nothing counts.
  {
    auto log = td::TsFileLog::create(base, 1 << 20, false, 2).move_as_ok();
    log->append(td::CSlice("first start\n"));
  }
  ASSERT_EQ(prune_failures, td::FileLog::prune_failures());

  td::mkdir(idle + ".old.5").ensure();
  td::write_file(idle + ".old.5/inside", "x").ensure();
  td::write_file(idle + ".old.3", "x").ensure();
  {
    auto r_log = td::TsFileLog::create(base, 1 << 20, false, 2);
    ASSERT_TRUE(r_log.is_ok());
    r_log.move_as_ok()->append(td::CSlice("second start\n"));
  }
  ASSERT_EQ(prune_failures + 1, td::FileLog::prune_failures());
  ASSERT_TRUE(td::stat(idle + ".old.3").is_error());
  ASSERT_TRUE(td::stat(idle + ".old.5/inside").is_ok());
  cleanup();

  // A log directory that can be written but not listed: the scan fails, which
  // counts, and the log still starts.
  const std::string dir = base + ".unlistable";
  const std::string inner = dir + "/log";
  td::unlink(inner).ignore();
  td::rmdir(dir).ignore();
  td::mkdir(dir, 0300).ensure();
  auto unlistable = td::WalkPath::run(dir, [](td::CSlice, td::WalkPath::Type) {});
  if (unlistable.is_error()) {
    // Not so when the test runs with the right to read any directory.
    prune_failures = td::FileLog::prune_failures();
    {
      auto r_log = td::TsFileLog::create(inner, 1 << 20, false, 2);
      ASSERT_TRUE(r_log.is_ok());
      r_log.move_as_ok()->append(td::CSlice("unlistable directory\n"));
    }
    ASSERT_EQ(prune_failures + 1, td::FileLog::prune_failures());
    ASSERT_TRUE(td::stat(inner).is_ok());
  }
  td::unlink(inner).ignore();
  td::rmdir(dir).ignore();
}

TEST(Log, TsFileLogFindsTheDirectoryOfItsLog) {
  // The idle-archive scan lists the log's own directory; a log directly under
  // the root lives in "/", not in the working directory.
  ASSERT_EQ("/", td::TsFileLog::log_directory("/validator.log"));
  ASSERT_EQ("/", td::TsFileLog::log_directory("//validator.log"));
  ASSERT_EQ(".", td::TsFileLog::log_directory("validator.log"));
  ASSERT_EQ("/var/log/tos", td::TsFileLog::log_directory("/var/log/tos/validator.log"));
  ASSERT_EQ("logs", td::TsFileLog::log_directory("logs/validator.log"));
  ASSERT_EQ("logs", td::TsFileLog::log_directory("logs//validator.log"));
  ASSERT_EQ(".", td::TsFileLog::log_directory("./validator.log"));
}

TEST(Log, TsFileLogPrunesBesideAnUnreadableDirectory) {
  // The log directory may hold other directories the engine cannot read. The
  // scan lists only the log directory's own entries, so such a neighbour
  // neither stops the pruning nor counts as a failure.
  const std::string base = "tmplog_ts_neighbour_test";
  const std::string idle = base + ".thread31.log";
  const std::string unreadable = base + ".unreadable";
  auto cleanup = [&] {
    for (auto suffix : {"", ".old", ".old.1", ".old.3"}) {
      td::unlink(base + suffix).ignore();
      td::unlink(idle + suffix).ignore();
    }
    td::rmdir(unreadable).ignore();
  };
  cleanup();
  td::mkdir(unreadable, 0).ensure();
  auto probe = td::WalkPath::run(unreadable, [](td::CSlice, td::WalkPath::Type) {});
  if (probe.is_error()) {
    // Not so when the test runs with the right to read any directory.
    td::write_file(idle + ".old.1", "x").ensure();
    td::write_file(idle + ".old.3", "x").ensure();
    auto prune_failures = td::FileLog::prune_failures();
    {
      auto r_log = td::TsFileLog::create(base, 1 << 20, false, 2);
      ASSERT_TRUE(r_log.is_ok());
      r_log.move_as_ok()->append(td::CSlice("beside an unreadable directory\n"));
    }
    ASSERT_EQ(prune_failures, td::FileLog::prune_failures());
    ASSERT_TRUE(td::stat(idle + ".old.1").is_ok());
    ASSERT_TRUE(td::stat(idle + ".old.3").is_error());
  }
  cleanup();
}
#endif
#endif
