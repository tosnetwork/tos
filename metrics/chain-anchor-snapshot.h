#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace tos::health {
struct ChainAnchorSnapshot {
  std::array<std::uint8_t, 32> network_hash{};
  struct Block {
    std::array<std::uint8_t, 32> file_hash{};
    std::array<std::uint8_t, 32> root_hash{};
    std::uint32_t seqno = 0;
  } applied, served;
  bool have_served = false;
  std::uint64_t applied_advanced_unix_seconds = 0;
  std::uint64_t observed_unix_seconds = 0;
  // Last known key block: the checkpoint persistent states and garbage
  // collection follow. Seqno 0 with the zero state's time means none yet.
  std::uint32_t key_block_seqno = 0;
  std::uint64_t key_block_unix_seconds = 0;
};

// One manager actor writes; exporter readers retry a bounded number of times.
// Every field is atomic so a concurrent read is never a C++ data race.
struct ChainAnchorState {
  std::array<std::atomic<std::uint8_t>, 32> network_hash{};
  struct Block {
    std::array<std::atomic<std::uint8_t>, 32> file_hash{};
    std::array<std::atomic<std::uint8_t>, 32> root_hash{};
    std::atomic<std::uint32_t> seqno{0};
  } applied, served;
  std::atomic<std::uint64_t> sequence{0}, observed_unix_seconds{0}, applied_advanced_unix_seconds{0};
  std::atomic<std::uint64_t> key_block_unix_seconds{0};
  std::atomic<std::uint32_t> key_block_seqno{0};
  std::atomic<bool> have_served{false};
  std::atomic_flag writing = ATOMIC_FLAG_INIT;

  static void copy(Block &to, const ChainAnchorSnapshot::Block &from) noexcept {
    for (std::size_t i = 0; i < 32; ++i) {
      to.file_hash[i].store(from.file_hash[i], std::memory_order_relaxed);
      to.root_hash[i].store(from.root_hash[i], std::memory_order_relaxed);
    }
    to.seqno.store(from.seqno, std::memory_order_relaxed);
  }
  static void copy(ChainAnchorSnapshot::Block &to, const Block &from) noexcept {
    for (std::size_t i = 0; i < 32; ++i) {
      to.file_hash[i] = from.file_hash[i].load(std::memory_order_relaxed);
      to.root_hash[i] = from.root_hash[i].load(std::memory_order_relaxed);
    }
    to.seqno = from.seqno.load(std::memory_order_relaxed);
  }
  void publish(const ChainAnchorSnapshot &value) noexcept {
    if (writing.test_and_set(std::memory_order_acquire)) return;
    sequence.fetch_add(1, std::memory_order_acq_rel);
    for (std::size_t i = 0; i < 32; ++i)
      network_hash[i].store(value.network_hash[i], std::memory_order_relaxed);
    copy(applied, value.applied);
    copy(served, value.served);
    have_served.store(value.have_served, std::memory_order_relaxed);
    applied_advanced_unix_seconds.store(value.applied_advanced_unix_seconds, std::memory_order_relaxed);
    observed_unix_seconds.store(value.observed_unix_seconds, std::memory_order_relaxed);
    key_block_seqno.store(value.key_block_seqno, std::memory_order_relaxed);
    key_block_unix_seconds.store(value.key_block_unix_seconds, std::memory_order_relaxed);
    sequence.fetch_add(1, std::memory_order_release);
    writing.clear(std::memory_order_release);
  }
  std::optional<ChainAnchorSnapshot> read() const noexcept {
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
      const auto before = sequence.load(std::memory_order_acquire);
      if (before == 0 || (before & 1)) continue;
      ChainAnchorSnapshot value;
      for (std::size_t i = 0; i < 32; ++i)
        value.network_hash[i] = network_hash[i].load(std::memory_order_relaxed);
      copy(value.applied, applied);
      copy(value.served, served);
      value.have_served = have_served.load(std::memory_order_relaxed);
      value.applied_advanced_unix_seconds = applied_advanced_unix_seconds.load(std::memory_order_relaxed);
      value.observed_unix_seconds = observed_unix_seconds.load(std::memory_order_relaxed);
      value.key_block_seqno = key_block_seqno.load(std::memory_order_relaxed);
      value.key_block_unix_seconds = key_block_unix_seconds.load(std::memory_order_relaxed);
      // The fence keeps the relaxed field loads above from moving past the
      // re-read of the sequence; an acquire load alone would not.
      std::atomic_thread_fence(std::memory_order_acquire);
      if (before == sequence.load(std::memory_order_relaxed)) return value;
    }
    return std::nullopt;
  }
};
inline ChainAnchorState chain_anchor_state;
}  // namespace tos::health
