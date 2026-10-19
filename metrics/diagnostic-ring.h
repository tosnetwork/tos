#pragma once
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace tos::health {
// One process-wide ring can be shared by producers and an external-IPC pump.
// Contention drops only the diagnostic copy; there is no spin or file fallback.
class DiagnosticRing {
 public:
  static constexpr std::size_t capacity = 4096;
  static constexpr std::size_t record_bytes = 512;
  struct Record {
    std::uint64_t sequence = 0;
    std::uint16_t size = 0;
    std::array<char, record_bytes> bytes{};
  };
  bool push(const char *bytes, std::size_t size) noexcept {
    const auto sequence = next_.fetch_add(1, std::memory_order_relaxed);
    if (size > record_bytes || size == 0 || bytes == nullptr || sequence == UINT64_MAX) {
      dropped_.fetch_add(1, std::memory_order_relaxed);
      return false;
    }
    if (lock_.test_and_set(std::memory_order_acquire)) {
      dropped_.fetch_add(1, std::memory_order_relaxed);
      return false;
    }
    if (count_ == capacity) {
      lock_.clear(std::memory_order_release);
      dropped_.fetch_add(1, std::memory_order_relaxed);
      return false;
    }
    auto &record = records_[(head_ + count_) % capacity];
    record.sequence = sequence;
    record.size = static_cast<std::uint16_t>(size);
    std::memcpy(record.bytes.data(), bytes, size);
    ++count_;
    lock_.clear(std::memory_order_release);
    return true;
  }
  bool pop(Record &record) noexcept {
    if (lock_.test_and_set(std::memory_order_acquire)) {
      return false;
    }
    if (count_ == 0) {
      lock_.clear(std::memory_order_release);
      return false;
    }
    record = records_[head_];
    head_ = (head_ + 1) % capacity;
    --count_;
    lock_.clear(std::memory_order_release);
    return true;
  }
  std::uint64_t dropped() const {
    return dropped_.load(std::memory_order_relaxed);
  }

 private:
  std::array<Record, capacity> records_{};
  std::atomic_flag lock_ = ATOMIC_FLAG_INIT;
  std::atomic<std::uint64_t> next_{0}, dropped_{0};
  std::size_t head_ = 0, count_ = 0;
};
static_assert(sizeof(DiagnosticRing) < 4 * 1024 * 1024);
}  // namespace tos::health
