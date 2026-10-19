#include <cassert>
#include <memory>
#include <thread>

#include "metrics/diagnostic-producer.h"

using tos::health::DiagnosticProducer;
namespace tos::health {
struct DiagnosticProducerTest {
  static void sequence(DiagnosticProducer &producer, std::uint64_t next) {
    producer.next_.store(next);
  }
};
}  // namespace tos::health
int main() {
  DiagnosticProducer::Stats stats;
  auto p = std::make_unique<DiagnosticProducer>(stats, std::array<std::uint8_t, 16>{}, 2);
  unsigned built = 0;
  auto builder = [&](auto *out, auto sequence, const auto &) noexcept -> std::uint16_t {
    ++built;
    tos::health::wire_put(out + 32, sequence, 8);
    return 64;
  };
  assert(!p->emit(builder) && built == 0);
  assert(stats.dropped == 0 && stats.sampled_out == 0 && stats.records == 0);
  p->enable();
  for (unsigned i = 0; i < 8192; ++i)
    p->emit(builder);
  assert(built == 4096 && stats.records == 4096 && stats.bytes == 262144 && stats.sampled_out == 4096);
  assert(!p->emit(builder) && built == 4096 && stats.dropped == 1);
  DiagnosticProducer::Packet packet;
  for (unsigned i = 0; i < 4096; ++i) {
    assert(p->pop(packet));
    assert(tos::health::wire_get(packet.bytes.data() + 32, 8) == i);
  }
  assert(!p->pop(packet) && stats.records == 0 && stats.bytes == 0);
  assert(!p->emit(builder));  // sample, no transport gap
  assert(p->emit(builder));
  assert(p->pop(packet) && tos::health::wire_get(packet.bytes.data() + 32, 8) == 4097);
  p->disable();
  assert(!p->emit(builder) && built == 4097);

  DiagnosticProducer::Stats contention;
  auto q = std::make_unique<DiagnosticProducer>(contention, std::array<std::uint8_t, 16>{});
  q->enable();
  std::atomic<bool> entered{false}, release{false};
  std::thread owner([&] {
    assert(q->emit([&](auto *, auto, const auto &) noexcept -> std::uint16_t {
      entered.store(true);
      while (!release.load())
        std::this_thread::yield();
      return 64;
    }));
  });
  while (!entered.load())
    std::this_thread::yield();
  bool contention_built = false;
  assert(!q->emit([&](auto *, auto, const auto &) noexcept -> std::uint16_t {
    contention_built = true;
    return 64;
  }));
  assert(!contention_built && contention.dropped == 1 && contention.reasons[1] == 1);
  release.store(true);
  owner.join();
  assert(q->phase(1, 2, 21));
  assert(q->pop(packet));
  assert(q->pop(packet));
  assert(packet.size == 68 && tos::health::wire_get(packet.bytes.data() + 12, 4) == 8 &&
         tos::health::wire_get(packet.bytes.data() + 32, 8) == 2 && packet.bytes[64] == 1 && packet.bytes[65] == 2 &&
         packet.bytes[66] == 21);
  assert(!q->phase(4, 0, 0) && contention.reasons[3] == 1);
  tos::health::DiagnosticProducerTest::sequence(*q, UINT64_MAX - 1);
  assert(q->phase(1, 0, 3));
  assert(q->pop(packet));
  assert(tos::health::wire_get(packet.bytes.data() + 32, 8) == UINT64_MAX - 1);
  assert(!q->phase(1, 0, 3) && contention.reasons[2] == 1);
  assert(!q->phase(1, 0, 3) && contention.reasons[2] == 2);
}
