/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

// A labelled metric keeps one entry per distinct label value, forever. That is
// fine for a label the node picks itself, and not fine for one taken from a
// request: the JSON-RPC server counts requests by method name, and a client
// chooses that name. Without a bound, a client that sends a fresh name each
// time grows the process until it dies -- no authentication needed on a public
// read-only listener.
//
// These tests pin that the map stops growing, that counting stays correct
// after it does, and that the values the node itself emits are all still
// visible, since a bound that hid real series would trade one problem for
// another.

#include "metrics/metrics-collectors.h"

#include "td/utils/tests.h"

#include <string>

namespace {
size_t count_occurrences(const std::string &haystack, const std::string &needle) {
  size_t found = 0;
  for (size_t at = haystack.find(needle); at != std::string::npos; at = haystack.find(needle, at + needle.size())) {
    ++found;
  }
  return found;
}
}  // namespace

namespace tos::metrics {
namespace {

using Counter = AtomicCounter<td::uint64>;
using ByName = Labeled<std::string, Counter>;

TEST(MetricsLabelBound, KeepsEveryLabelUpToTheLimit) {
  auto metric = ByName::make("method", "requests_total", "requests");
  for (size_t i = 0; i < ByName::MAX_LABELS; i++) {
    metric->label(PSTRING() << "method_" << i)->add(1);
  }
  auto rendered = metric->collect().render();
  // Each of them is its own series: a bound that started collapsing real
  // labels would be worse than none.
  ASSERT_EQ(ByName::MAX_LABELS, count_occurrences(rendered, "method=\""));
  ASSERT_EQ(0u, count_occurrences(rendered, ByName::overflow_label()));
}

TEST(MetricsLabelBound, LabelsPastTheLimitShareOneEntry) {
  auto metric = ByName::make("method", "requests_total", "requests");
  for (size_t i = 0; i < ByName::MAX_LABELS; i++) {
    metric->label(PSTRING() << "method_" << i)->add(1);
  }

  // The flood: every value distinct, none of them ever seen before.
  for (size_t i = 0; i < 100000; i++) {
    metric->label(PSTRING() << "attacker_" << i)->add(1);
  }

  auto rendered = metric->collect().render();
  // Not one of the flood's values was remembered: the map is still the size
  // it was, plus the single overflow series.
  ASSERT_EQ(0u, count_occurrences(rendered, "attacker_"));
  ASSERT_EQ(ByName::MAX_LABELS + 1, count_occurrences(rendered, "method=\""));
  // The flood was still counted, all of it, in that one series.
  ASSERT_TRUE(rendered.find(PSTRING() << "method=\"" << ByName::overflow_label() << "\"} 100000") !=
              std::string::npos);
  // And a real label from before the flood still carries its own count.
  ASSERT_TRUE(rendered.find("method=\"method_0\"} 1") != std::string::npos);
}

TEST(MetricsLabelBound, TheLimitIsAboveTheNodesOwnLabelSet) {
  // The largest label set the node emits is its JSON-RPC method list, in the
  // dozens. If the limit ever drops near that, real methods would start
  // collapsing into the overflow series.
  ASSERT_TRUE(ByName::MAX_LABELS >= 128);
}

}  // namespace
}  // namespace tos::metrics
