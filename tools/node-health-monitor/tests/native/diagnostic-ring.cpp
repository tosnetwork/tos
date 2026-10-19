#include <cassert>
#include <memory>
#include <thread>

#include "metrics/diagnostic-ring.h"
int main() {
  auto ring = std::make_unique<tos::health::DiagnosticRing>();
  for (size_t i = 0; i < ring->capacity; ++i) {
    assert(ring->push("abc", 3));
  }
  assert(!ring->push("abc", 3));
  assert(!ring->push("abc", 513));
  assert(ring->dropped() == 2);
  tos::health::DiagnosticRing::Record record;
  for (size_t i = 0; i < ring->capacity; ++i) {
    assert(ring->pop(record));
    assert(record.size == 3);
    assert(record.sequence == i);
    assert(record.bytes[0] == 'a');
  }
  assert(!ring->pop(record));
  assert(ring->push("new", 3));
  assert(ring->pop(record));
  assert(record.sequence == ring->capacity + 2);
  std::thread a([&] {
    for (int i = 0; i < 10000; ++i)
      ring->push("a", 1);
  });
  std::thread b([&] {
    for (int i = 0; i < 10000; ++i)
      ring->push("b", 1);
  });
  a.join();
  b.join();
  size_t count = 0;
  while (ring->pop(record)) {
    ++count;
    assert(record.size == 1);
  }
  assert(count + ring->dropped() - 2 == 20000);
}
