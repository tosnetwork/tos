#include <cassert>
#include <limits>

#include "metrics/source-admission.h"
int main() {
  tos::metrics::SourceAdmission gate;
  assert(!gate.fresh(0));
  assert(!gate.begin(std::numeric_limits<double>::quiet_NaN()));
  assert(gate.begin(1));
  assert(!gate.begin(2));
  assert(gate.expired(4));
  assert(!gate.begin(100));  // a client timeout cannot release actual work
  assert(!gate.finish(100, true, 100));
  assert(!gate.fresh(100));
  assert(gate.begin(101));
  assert(gate.finish(102, true, 100));
  assert(gate.generation() == 1);
  assert(!gate.begin(110));
  assert(gate.fresh(120));
  assert(!gate.fresh(133));
  assert(!gate.fresh(101));
  assert(gate.begin(133));
  assert(!gate.finish(134, true, gate.max_snapshot_bytes + 1));
  assert(gate.generation() == 1);
  assert(!gate.fresh(134));
  assert(gate.begin(149));
  assert(gate.finish(150, true, gate.max_snapshot_bytes));
  assert(gate.generation() == 2);
  assert(!gate.finish(151, true, 1));
}
