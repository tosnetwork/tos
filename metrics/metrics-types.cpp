#include <unordered_map>
#include <charconv>
#include <cmath>
#include <limits>

#include "td/utils/logging.h"

#include "metrics-types.h"

namespace tos::metrics {

namespace {
std::string concat_names(std::string name1, std::string name2) {
  if (!name1.empty() && !name2.empty())
    return std::move(name1) + '_' + std::move(name2);
  return std::move(name1) + std::move(name2);
}
}  // namespace

std::string Label::render() && {
  auto k = std::move(key), v = std::move(val);
  return PSTRING() << k << '=' << '"' << v << '"';
}

LabelSet LabelSet::join(LabelSet other) && {
  auto all_labels = std::move(labels);
  all_labels.reserve(all_labels.size() + other.labels.size());
  for (auto &l : other.labels)
    all_labels.push_back(std::move(l));
  other.labels.resize(0);
  return {.labels = std::move(all_labels)};
}

std::string LabelSet::render() && {
  if (labels.empty())
    return "";
  std::string result = "{";
  for (auto &l : labels) {
    if (result.size() != 1)
      result += ',';
    result += std::move(l).render();
  }
  labels = {};
  result += '}';
  return result;
}

std::string Sample::render(const std::string &metric_name, LabelSet metric_label_set) && {
  return PSTRING() << metric_name << std::move(metric_label_set).join(std::move(label_set)).render() << ' ' << value
                   << '\n';
}

std::string Metric::render(std::string family_name) && {
  auto whole_name = concat_names(std::move(family_name), std::move(suffix));
  std::string result;
  for (auto &s : samples)
    result += std::move(s).render(whole_name, label_set);
  label_set = {};
  samples = {};
  return result;
}

Metric Metric::label(LabelSet extension) && {
  auto new_label_set = std::move(label_set);
  for (auto &l : extension.labels)
    new_label_set.labels.push_back(std::move(l));
  return {.suffix = std::move(suffix), .label_set = std::move(new_label_set), .samples = std::move(samples)};
}

std::string MetricFamily::render() && {
  const auto whole_name = std::move(name);
  std::string result;
  if (help.has_value())
    result += PSTRING() << "# HELP " << whole_name << ' ' << *help << '\n';
  if (type.has_value())
    result += PSTRING() << "# TYPE " << whole_name << ' ' << *type << '\n';
  for (auto &m : metrics)
    result += std::move(m).render(whole_name);
  metrics = {};
  return result;
}

MetricFamily MetricFamily::wrap(std::string prefix) && {
  return {.name = concat_names(std::move(prefix), std::move(name)),
          .type = std::move(type),
          .help = std::move(help),
          .metrics = std::move(metrics)};
}

MetricFamily MetricFamily::label(const LabelSet &extension) && {
  auto new_metrics = std::move(metrics);
  for (auto &m : new_metrics)
    m = std::move(m).label(extension);
  return {.name = std::move(name), .type = std::move(type), .help = std::move(help), .metrics = std::move(new_metrics)};
}

MetricFamily MetricFamily::make_scalar(std::string name, std::string type, double value,
                                       std::optional<std::string> help) {
  return MetricFamily{
      .name = name,
      .type = type,
      .help = help,
      .metrics = {Metric{.suffix = "", .label_set = {}, .samples = {Sample{.label_set = {}, .value = value}}}}};
}

MetricSet MetricSet::join(MetricSet other) && {
  std::unordered_map<std::string, MetricFamily> all_families;
  for (auto &f : families) {
    all_families.insert({f.name, std::move(f)});
  }
  families.resize(0);
  for (auto &f : other.families) {
    if (!all_families.contains(f.name)) {
      all_families.insert({f.name, std::move(f)});
    } else {
      auto &f0 = all_families.at(f.name);
      for (auto &m : f.metrics) {
        f0.metrics.push_back(std::move(m));
      }
    }
  }
  other.families.resize(0);

  std::vector<MetricFamily> all_families_vec;
  for (auto &[_, f] : all_families) {
    all_families_vec.push_back(std::move(f));
  }

  return {.families = std::move(all_families_vec)};
}

std::string MetricSet::render() && {
  std::string result;
  for (auto &f : families)
    result += std::move(f).render();
  families = {};
  return result;
}

std::size_t MetricSet::resident_bytes() const {
  std::size_t total = sizeof(*this);
  auto add = [&](std::size_t bytes) {
    if (total > std::numeric_limits<std::size_t>::max() - bytes) total = std::numeric_limits<std::size_t>::max();
    else total += bytes;
  };
  auto product = [&](std::size_t count, std::size_t bytes) {
    add(count > std::numeric_limits<std::size_t>::max() / bytes ? std::numeric_limits<std::size_t>::max() : count * bytes);
  };
  auto labels = [&](const LabelSet &set) {
    product(set.labels.capacity(), sizeof(Label));
    for (const auto &label : set.labels) { add(label.key.capacity()); add(1); add(label.val.capacity()); add(1); }
  };
  product(families.capacity(), sizeof(MetricFamily));
  for (const auto &family : families) {
    add(family.name.capacity()); add(1);
    if (family.type) { add(family.type->capacity()); add(1); }
    if (family.help) { add(family.help->capacity()); add(1); }
    product(family.metrics.capacity(), sizeof(Metric));
    for (const auto &metric : family.metrics) {
      add(metric.suffix.capacity()); add(1); labels(metric.label_set);
      product(metric.samples.capacity(), sizeof(Sample));
      for (const auto &sample : metric.samples) labels(sample.label_set);
    }
  }
  return total;
}

std::optional<std::string> MetricSet::render_bounded(std::size_t max_bytes) && {
  // Stream into one reserved body. Labels and HELP strings are appended from
  // existing storage; the only formatting scratch is a fixed numeric buffer.
  std::string result;
  if (max_bytes == std::numeric_limits<std::size_t>::max()) return std::nullopt;
  result.reserve(max_bytes);
  // The pinned standard library is checked too; a larger actual reservation
  // cannot silently escape the caller's remaining capacity budget.
  if (result.capacity() > max_bytes) return std::nullopt;
  auto append = [&](std::string_view part) {
    if (part.size() > max_bytes - result.size()) return false;
    result.append(part);
    return true;
  };
  for (auto &family : families) {
    if (family.help && (!append("# HELP ") || !append(family.name) || !append(" ") || !append(*family.help) || !append("\n"))) return std::nullopt;
    if (family.type && (!append("# TYPE ") || !append(family.name) || !append(" ") || !append(*family.type) || !append("\n"))) return std::nullopt;
    for (auto &metric : family.metrics) {
      for (auto &sample : metric.samples) {
        if (!append(family.name)) return std::nullopt;
        if (!metric.suffix.empty() && (!append("_") || !append(metric.suffix))) return std::nullopt;
        if (!metric.label_set.labels.empty() || !sample.label_set.labels.empty()) {
          if (!append("{")) return std::nullopt;
          bool first = true;
          auto labels = [&](const LabelSet &set) {
            for (const auto &label : set.labels) {
              if (!first && !append(",")) return false;
              first = false;
              if (!append(label.key) || !append("=\"") || !append(label.val) || !append("\"")) return false;
            }
            return true;
          };
          if (!labels(metric.label_set) || !labels(sample.label_set) || !append("}")) return std::nullopt;
        }
        char number[64];
        if (!std::isfinite(sample.value)) return std::nullopt;
        const auto converted = std::to_chars(std::begin(number), std::end(number), sample.value);
        if (converted.ec != std::errc{} || !append(" ") || !append(std::string_view(number, converted.ptr - number)) || !append("\n")) return std::nullopt;
      }
    }
  }
  if (!append("# EOF\n")) return std::nullopt;
  families = {};
  return result;
}

MetricSet MetricSet::wrap(const std::string &prefix) && {
  auto new_families = std::move(families);
  for (auto &f : new_families)
    f = std::move(f).wrap(prefix);
  return {.families = std::move(new_families)};
}

MetricSet MetricSet::label(const LabelSet &extension) && {
  auto new_families = std::move(families);
  for (auto &f : new_families)
    f = std::move(f).label(extension);
  return {.families = std::move(new_families)};
}

std::string Exposition::render() && {
  std::string result = std::move(main_set).render();
  result += "# EOF\n";
  return result;
}

}  // namespace tos::metrics
