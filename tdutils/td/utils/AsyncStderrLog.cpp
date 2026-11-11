#include <array>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "td/utils/AsyncStderrLog.h"
#include "td/utils/port/signals.h"

namespace td {
namespace {

std::atomic<uint64> dropped{0};
std::atomic<uint64> dropped_errors{0};
std::atomic<uint64> write_errors{0};
constexpr auto drain_timeout = std::chrono::milliseconds(250);

void count_drop(bool error) {
  dropped.fetch_add(1, std::memory_order_relaxed);
  if (error) {
    dropped_errors.fetch_add(1, std::memory_order_relaxed);
  }
}

struct Output {
  explicit Output(int source) : fd(fcntl(source, F_DUPFD_CLOEXEC, 3)) {
#ifdef F_SETNOSIGPIPE
    // Darwin delivers a broken-pipe signal process-wide. Its output-specific
    // flag suppresses that signal even when another thread is unmasked.
    if (fd >= 0) {
      const int original = fcntl(fd, F_GETNOSIGPIPE);
      if (original < 0 || (original == 0 && fcntl(fd, F_SETNOSIGPIPE, 1) < 0)) {
        close(fd);
        fd = -1;
      } else {
        restore_sigpipe = original == 0;
      }
    }
#endif
  }
  ~Output() {
    if (fd >= 0) {
#ifdef F_SETNOSIGPIPE
      if (restore_sigpipe) {
        fcntl(fd, F_SETNOSIGPIPE, 0);
      }
#endif
      close(fd);
    }
  }
  bool write_all(Slice data) const {
    while (!data.empty()) {
      auto n = write(fd, data.data(), data.size());
      if (n < 0 && errno == EINTR) {
        continue;
      }
      if (n <= 0) {
        return false;
      }
      data.remove_prefix(static_cast<size_t>(n));
    }
    return true;
  }
  int fd;
#ifdef F_SETNOSIGPIPE
  bool restore_sigpipe{false};
#endif
};

}  // namespace

struct AsyncStderrLog::State {
  struct Record {
    std::unique_ptr<char[]> bytes;
    size_t size{0};
    bool error{false};
  };

  explicit State(Sink output) : sink(std::move(output)) {
  }

  void run() {
    // EPIPE is a failure of this diagnostic record, never a process signal.
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    const bool can_write = pthread_sigmask(SIG_BLOCK, &mask, nullptr) == 0;
    std::unique_lock lock(mutex);
    for (;;) {
      work.wait(lock, [&] { return closing || count != 0; });
      if (count == 0) {
        return;
      }
      auto &record = queue[head];
      lock.unlock();
      const bool ok = can_write && sink(Slice(record.bytes.get(), record.size));
      lock.lock();
      if (!ok) {
        write_errors.fetch_add(1, std::memory_order_relaxed);
      }
      bytes -= record.size;
      record = {};
      head = (head + 1) % max_records;
      --count;
      ++completed;
      drained.notify_all();
    }
  }

  Sink sink;
  std::mutex mutex;
  std::condition_variable work, drained;
  std::array<Record, max_records> queue;
  size_t head{0}, count{0}, bytes{0};
  uint64 completed{0};
  bool closing{false};
};

AsyncStderrLog::AsyncStderrLog(int fd)
    : AsyncStderrLog([out = std::make_shared<Output>(fd)](Slice data) { return out->write_all(data); }) {
}

AsyncStderrLog::AsyncStderrLog(Sink sink)
    : state_(std::make_shared<State>(std::move(sink))), writer_([state = state_] { state->run(); }) {
}

AsyncStderrLog::~AsyncStderrLog() {
  std::unique_lock lock(state_->mutex);
  state_->closing = true;
  state_->work.notify_one();
  if (state_->drained.wait_for(lock, drain_timeout, [&] { return state_->count == 0; })) {
    lock.unlock();
    writer_.join();
    return;
  }
  // The head may be inside write(2). Its writer retains the state and fd
  // until the call returns or the process exits. Discard the waiting tail.
  while (state_->count > 1) {
    auto &record = state_->queue[(state_->head + state_->count - 1) % max_records];
    count_drop(record.error);
    state_->bytes -= record.size;
    record = {};
    --state_->count;
  }
  writer_.detach();
}

AnsiColor AsyncStderrLog::color_for(int level) {
  return default_log_interface->color_for(level);
}

void AsyncStderrLog::append(CSlice message, int level) {
  if (level == VERBOSITY_NAME(FATAL)) {
    set_failure_signal_message(message);
    process_fatal_error(message);
  }
  Slice line = message;
  if (!line.empty() && line.back() == '\n') {
    line.remove_suffix(1);
  }
  const auto color = color_for(level);
  const Slice prefix = ansi_color_to_str(color);
  const Slice reset = color == AnsiColor::Disallowed ? Slice() : ansi_color_to_str(AnsiColor::Empty);
  const bool error = level == VERBOSITY_NAME(ERROR);
  const size_t record_limit = error ? max_records : max_records - error_records;
  const size_t byte_limit = error ? max_bytes : max_bytes - error_bytes;
  const size_t framing = prefix.size() + reset.size() + 1;
  std::unique_lock lock(state_->mutex);
  if (state_->closing || state_->count >= record_limit || line.size() > byte_limit - framing ||
      state_->bytes > byte_limit - framing - line.size()) {
    count_drop(error);
    return;
  }
  auto &record = state_->queue[(state_->head + state_->count) % max_records];
  record.size = framing + line.size();
  record.bytes = std::make_unique_for_overwrite<char[]>(record.size);
  record.error = error;
  char *dest = record.bytes.get();
  for (Slice part : {prefix, line, reset}) {
    if (!part.empty()) {
      std::memcpy(dest, part.data(), part.size());
      dest += part.size();
    }
  }
  *dest = '\n';
  state_->bytes += record.size;
  ++state_->count;
  lock.unlock();
  state_->work.notify_one();
}

bool AsyncStderrLog::flush() {
  std::unique_lock lock(state_->mutex);
  const auto target = state_->completed + state_->count;
  return state_->drained.wait_for(lock, drain_timeout, [&] { return state_->completed >= target; });
}

AsyncStderrLog::Stats AsyncStderrLog::stats() {
  return {dropped.load(std::memory_order_relaxed), dropped_errors.load(std::memory_order_relaxed),
          write_errors.load(std::memory_order_relaxed)};
}

}  // namespace td
