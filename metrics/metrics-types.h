#pragma once
#include <optional>
#include <string>
#include <vector>

namespace tos::metrics {
struct Label {
  std::string key, val;

  [[nodiscard]] std::string render() &&;
};

struct LabelSet {
  std::vector<Label> labels;

  [[nodiscard]] LabelSet join(LabelSet other) &&;
  [[nodiscard]] std::string render() &&;
};

struct Sample {
  LabelSet label_set;
  double value = 0;

  [[nodiscard]] std::string render(const std::string &metric_name, LabelSet metric_label_set) &&;
};

struct Metric {
  std::string suffix;
  LabelSet label_set;
  std::vector<Sample> samples;

  [[nodiscard]] std::string render(std::string family_name) &&;
  [[nodiscard]] Metric label(LabelSet extension) &&;
};

struct MetricFamily {
  std::string name;
  std::optional<std::string> type, help;
  std::vector<Metric> metrics;

  [[nodiscard]] std::string render() &&;
  [[nodiscard]] MetricFamily wrap(std::string prefix) &&;
  [[nodiscard]] MetricFamily label(const LabelSet &extension) &&;

  static MetricFamily make_scalar(std::string name, std::string type, double value,
                                  std::optional<std::string> help = std::nullopt);
};

// A string whose capacity is at most max_bytes, from a reservation that asks for
// max_bytes - allowance: a library may round a reservation up (libc++ by up to
// 15 bytes, libstdc++ not at all), and the allowance absorbs that rounding so
// the single allocation stays within the budget. Refuses when the granted
// capacity still exceeds max_bytes, or when allowance >= max_bytes. The
// terminator is outside max_bytes; callers account for it separately.
[[nodiscard]] std::optional<std::string> reserve_bounded(std::size_t max_bytes, std::size_t allowance);

struct MetricSet {
  std::vector<MetricFamily> families;

  [[nodiscard]] std::optional<std::string> render_bounded(std::size_t max_bytes) &&;
  [[nodiscard]] std::size_t resident_bytes() const;

  [[nodiscard]] MetricSet join(MetricSet other) &&;
  [[nodiscard]] std::string render() &&;
  [[nodiscard]] MetricSet wrap(const std::string &prefix) &&;
  [[nodiscard]] MetricSet label(const LabelSet &extension) &&;
};

struct Exposition {
  MetricSet main_set;

  [[nodiscard]] std::string render() &&;
};

}  // namespace tos::metrics
