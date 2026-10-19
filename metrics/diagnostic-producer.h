#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>

#include "diagnostic-wire.h"
namespace tos::health {
// Only scalar copies cross this boundary. Admission precedes construction.
class DiagnosticProducer {
 public:
  static constexpr std::size_t capacity = 4096, record_bytes = 512;
  struct Packet {
    std::array<std::uint8_t, record_bytes> bytes{};
    std::uint16_t size = 0;
  };
  enum class Drop : std::size_t { Capacity, Contention, Sequence, Encoding, Socket, Shutdown, Count };
  struct Stats {
    std::atomic<std::uint64_t> dropped{0}, sampled_out{0}, records{0}, bytes{0}, sent{0}, enabled{0}, complete{1};
    std::array<std::atomic<std::uint64_t>, static_cast<std::size_t>(Drop::Count)> reasons{};
    void add(std::atomic<std::uint64_t> &counter, std::uint64_t amount = 1) noexcept {
      auto old = counter.load(std::memory_order_relaxed);
      for (unsigned i = 0; i < 8; ++i) {
        if (amount > UINT64_MAX - old) {
          complete.store(0, std::memory_order_relaxed);
          return;
        }
        if (counter.compare_exchange_weak(old, old + amount, std::memory_order_relaxed))
          return;
      }
      complete.store(0, std::memory_order_relaxed);
    }
    void drop(Drop reason) noexcept {
      add(dropped);
      add(reasons[static_cast<std::size_t>(reason)]);
    }
  };
  explicit DiagnosticProducer(Stats &stats, std::array<std::uint8_t, 16> epoch, std::uint32_t sample_every = 1) noexcept
      : stats_(stats), epoch_(epoch), sample_every_(sample_every == 0 ? 1 : sample_every) {
  }
  void enable() noexcept {
    stats_.enabled.store(1, std::memory_order_release);
  }
  void disable() noexcept {
    stats_.enabled.store(0, std::memory_order_release);
  }
  // Builders are internal fixed-size encoders, never caller-owned objects.
  template <class Builder>
  bool emit(Builder &&builder) noexcept {
    if (stats_.enabled.load(std::memory_order_acquire) == 0)
      return false;
    std::uint64_t ticket = 0;
    if (!take(sampling_, ticket)) {
      stats_.drop(Drop::Sequence);
      return false;
    }
    if (ticket % sample_every_ != 0) {
      stats_.add(stats_.sampled_out);
      return false;
    }
    std::uint64_t sequence = 0;
    if (!take(next_, sequence)) {
      stats_.drop(Drop::Sequence);
      return false;
    }
    if (lock_.test_and_set(std::memory_order_acquire)) {
      stats_.drop(Drop::Contention);
      return false;
    }
    if (count_ == capacity) {
      lock_.clear(std::memory_order_release);
      stats_.drop(Drop::Capacity);
      return false;
    }
    if (stats_.enabled.load(std::memory_order_acquire) == 0) {
      lock_.clear(std::memory_order_release);
      stats_.drop(Drop::Shutdown);
      return false;
    }
    auto &packet = packets_[(head_ + count_) % capacity];
    packet.size = builder(packet.bytes.data(), sequence, epoch_);
    if (packet.size < 64 || packet.size > record_bytes) {
      lock_.clear(std::memory_order_release);
      stats_.drop(Drop::Encoding);
      return false;
    }
    ++count_;
    bytes_ += packet.size;
    stats_.records.store(count_, std::memory_order_relaxed);
    stats_.bytes.store(bytes_, std::memory_order_relaxed);
    lock_.clear(std::memory_order_release);
    return true;
  }
  bool phase(std::uint8_t action, std::uint8_t origin, std::uint8_t phase) noexcept {
    return emit([=](std::uint8_t *out, std::uint64_t seq, const auto &epoch) noexcept -> std::uint16_t {
      if (action >= 4 || origin >= 3 || phase >= 22)
        return 0;
      for (std::size_t i = 0; i < 68; ++i)
        out[i] = 0;
      out[0] = 'T';
      out[1] = 'H';
      out[2] = 'D';
      out[3] = '1';
      wire_put(out + 4, 1, 2);
      wire_put(out + 6, 64, 2);
      wire_put(out + 8, 68, 2);
      wire_put(out + 10, 1, 2);
      wire_put(out + 12, 8, 4);
      for (std::size_t i = 0; i < 16; ++i)
        out[16 + i] = epoch[i];
      wire_put(out + 32, seq, 8);
      const auto ns =
          std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
              .count();
      wire_put(out + 40, static_cast<std::uint64_t>(ns), 8);
      wire_put(out + 56, 4, 2);
      const auto wall =
          std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
              .count();
      if (wall >= 0) {
        wire_put(out + 48, static_cast<std::uint64_t>(wall), 8);
        wire_put(out + 58, 1, 2);
      }
      out[64] = action;
      out[65] = origin;
      out[66] = phase;
      return 68;
    });
  }
  bool pop(Packet &packet) noexcept {
    if (lock_.test_and_set(std::memory_order_acquire))
      return false;
    if (count_ == 0) {
      lock_.clear(std::memory_order_release);
      return false;
    }
    packet = packets_[head_];
    head_ = (head_ + 1) % capacity;
    --count_;
    bytes_ -= packet.size;
    stats_.records.store(count_, std::memory_order_relaxed);
    stats_.bytes.store(bytes_, std::memory_order_relaxed);
    lock_.clear(std::memory_order_release);
    return true;
  }

 private:
  friend struct DiagnosticProducerTest;
  static bool take(std::atomic<std::uint64_t> &counter, std::uint64_t &value) noexcept {
    auto old = counter.load(std::memory_order_relaxed);
    for (unsigned i = 0; i < 8 && old != UINT64_MAX; ++i) {
      if (counter.compare_exchange_weak(old, old + 1, std::memory_order_relaxed)) {
        value = old;
        return true;
      }
    }
    return false;
  }
  Stats &stats_;
  const std::array<std::uint8_t, 16> epoch_;
  const std::uint32_t sample_every_;
  std::atomic<std::uint64_t> sampling_{0}, next_{0};
  std::atomic_flag lock_ = ATOMIC_FLAG_INIT;
  std::array<Packet, capacity> packets_{};
  std::size_t head_ = 0, count_ = 0, bytes_ = 0;
};
static_assert(sizeof(DiagnosticProducer) < 4 * 1024 * 1024);
static_assert(DiagnosticProducer::capacity * DiagnosticProducer::record_bytes <= 2 * 1024 * 1024);
inline DiagnosticProducer::Stats diagnostic_stats;
// Set once at startup; process lifetime storage avoids actor teardown races.
inline std::atomic<DiagnosticProducer *> diagnostic_producer{nullptr};
inline void diagnostic_phase(std::uint8_t action, std::uint8_t origin, std::uint8_t phase) noexcept {
  const auto producer = diagnostic_producer.load(std::memory_order_acquire);
  if (producer != nullptr)
    producer->phase(action, origin, phase);
}
}  // namespace tos::health
