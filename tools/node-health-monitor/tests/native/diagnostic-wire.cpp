#include <cassert>
#include <iomanip>
#include <iostream>

#include "metrics/diagnostic-wire.h"
int main() {
  tos::health::DiagnosticWireRecord r;
  r.epoch.fill(0x11);
  r.sequence = 9;
  r.monotonic_ns = 10;
  r.payload = {1, 2};
  auto out = tos::health::encode_diagnostic(r);
  assert(out);
  auto decoded = tos::health::decode_diagnostic(out->data(), out->size());
  assert(decoded && decoded->sequence == 9 && !decoded->wall_ns);
  for (auto offset : {4, 6, 8, 10, 12, 48, 56, 58, 60}) {
    auto bad = *out;
    bad[offset] = 255;
    assert(!tos::health::decode_diagnostic(bad.data(), bad.size()));
  }
  assert(!tos::health::decode_diagnostic(out->data(), 63));
  for (auto b : *out) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << int(b);
  }
  std::cout << '\n';
}
