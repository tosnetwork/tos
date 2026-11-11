#pragma once

#include <functional>
#include <memory>
#include <thread>

#include "td/utils/logging.h"

namespace td {

// Best-effort validator diagnostics. The writer owns a copy of every admitted
// record, including the one currently in I/O. Limits include the ANSI framing.
class AsyncStderrLog final : public LogInterface {
 public:
  static constexpr size_t max_records = 256;
  static constexpr size_t max_bytes = 1024 * 1024;
  static constexpr size_t error_records = 8;
  static constexpr size_t error_bytes = Logger::BUFFER_SIZE + 32;  // One full ERROR, with framing.

  struct Stats {
    uint64 dropped;
    uint64 dropped_errors;
    uint64 write_errors;
  };

  // Own a duplicate. Preserve O_NONBLOCK and the caller's descriptor lifetime.
  // Darwin requires suppressing SIGPIPE on the shared output description.
  explicit AsyncStderrLog(int fd);
  using Sink = std::function<bool(Slice)>;
  explicit AsyncStderrLog(Sink sink);
  ~AsyncStderrLog() override;

  void append(CSlice line, int level) override;
  AnsiColor color_for(int level) override;
  // Wait at most 250 ms for records admitted before this call.
  bool flush();
  static Stats stats();

 private:
  struct State;
  std::shared_ptr<State> state_;
  std::thread writer_;
};

}  // namespace td
