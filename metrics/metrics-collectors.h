#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <limits>
#include <optional>
#include <type_traits>

#include "td/actor/ActorId.h"
#include "td/actor/PromiseFuture.h"
#include "td/actor/common.h"
#include "td/actor/coro_task.h"

#include "metrics-types.h"

namespace tos::metrics {

// What a collector will build, declared before it builds it. The bounded
// collection path compares this with the remaining budget and refuses the
// collector before any container is allocated; the result is still measured
// afterwards, so an understated reservation is caught, never trusted.
struct CollectionReservation {
  std::size_t resident_bytes = 0;
  std::size_t families = 0;
};

// Bytes one scalar family (one metric, one sample) occupies as `MetricSet::
// resident_bytes` counts it: the three containers at capacity one plus the
// strings, with a fixed allowance for the type string and allocator rounding.
inline std::size_t scalar_family_reservation_bytes(const std::string &name, const std::optional<std::string> &help) {
  return sizeof(MetricFamily) + sizeof(Metric) + sizeof(Sample) + name.capacity() + (help ? help->capacity() : 0) + 64;
}

// `count` scalar families whose names and helps fit the given capacities.
inline CollectionReservation scalar_families_reservation(std::size_t count, std::size_t name_capacity,
                                                         std::size_t help_capacity) {
  const auto per_family = sizeof(MetricFamily) + sizeof(Metric) + sizeof(Sample) + name_capacity + help_capacity + 64;
  return CollectionReservation{count * per_family, count};
}
// `families` families that together carry `metrics` labelled metrics of one
// sample each, `labels_per_metric` labels with the given total key+value
// capacity per label.
inline CollectionReservation labelled_metrics_reservation(std::size_t families, std::size_t metrics,
                                                          std::size_t labels_per_metric, std::size_t label_capacity,
                                                          std::size_t family_name_help_capacity) {
  const auto per_metric = sizeof(Metric) + sizeof(Sample) + labels_per_metric * (sizeof(Label) + label_capacity + 2);
  return CollectionReservation{families * (sizeof(MetricFamily) + family_name_help_capacity + 64) + metrics * per_metric,
                               families};
}

class Collector {
 public:
  virtual MetricSet collect() = 0;
  // nullopt: this collector cannot bound its result in advance. Under a
  // bounded budget it is then refused and recorded as shed, never run.
  virtual std::optional<CollectionReservation> reservation() const { return std::nullopt; }
  virtual ~Collector() = default;
};

using MetricsPromise = td::Promise<MetricSet>;

// Budget of one bounded collection. `max_resident_bytes` is what remains for
// the children's results after the exporter has already set aside the pieces
// that are alive at the same time during one collection: the resident
// consensus core snapshot, the diagnostic status response, the previous
// published snapshot and its typed prefix/suffix, the new rendered body and
// a fixed scratch allowance (`remaining_core_publication_bytes` in the
// exporter sums them). A child's result, the joined set and the rendered body
// overlap in time, so the figure handed down is the remainder, not the whole.
struct CollectionBudget {
  bool bounded = false;
  double deadline = 0;
  std::size_t max_resident_bytes = std::numeric_limits<std::size_t>::max();
  std::size_t max_families = 256;
  bool expired() const { return bounded && td::Timestamp::now().at() >= deadline; }
  // Whether a declared reservation fits what remains. Unbounded admits all.
  bool admits(const CollectionReservation &reservation) const {
    return !bounded || (reservation.resident_bytes <= max_resident_bytes && reservation.families <= max_families);
  }
};

// A collector refused before it ran. The reason travels as an error whose
// message carries this prefix, so a parent can tell a shed from a failure.
inline constexpr const char *kShedPrefix = "shed:";
inline constexpr const char *kShedUnbudgeted = "collector_unbudgeted";
inline constexpr const char *kShedOverBudget = "collector_over_budget";
inline td::Status shed_status(const char *reason) { return td::Status::Error(PSTRING() << kShedPrefix << reason); }
inline std::optional<std::string> shed_reason_of(const td::Status &status) {
  const auto message = status.message();
  const td::Slice prefix{kShedPrefix};
  if (message.size() > prefix.size() && message.substr(0, prefix.size()) == prefix) {
    return message.substr(prefix.size()).str();
  }
  return std::nullopt;
}
// Families a parent appends to a bounded result so a shed is visible in the
// output rather than silently missing: one `health_collection_shed` sample
// per refused child and a `health_collection_complete` gauge.
inline constexpr const char *kShedFamily = "health_collection_shed";
inline constexpr const char *kCompleteFamily = "health_collection_complete";
struct CollectionShed {
  std::string source;
  std::string reason;
};
MetricSet shed_families(const std::vector<CollectionShed> &sheds);

// Also implies inheritance from `td::actor::Actor`.
// However, we cannot inherit actor class right here,
// because this inheritance should be virtual (but it is not virtual in other places).
class AsyncCollector {
 public:
  virtual void collect(MetricsPromise P) = 0;
  // Bounded path. A child that cannot declare a reservation is refused before
  // it runs; one that fits runs `collect` and is measured afterwards. Only an
  // unbounded budget falls through to the unbounded collect.
  virtual std::optional<CollectionReservation> reservation() const { return std::nullopt; }
  virtual void collect_with_budget(MetricsPromise P, CollectionBudget budget) {
    if (!budget.bounded) {
      collect(std::move(P));
      return;
    }
    const auto declared = reservation();
    if (!declared) {
      P.set_error(shed_status(kShedUnbudgeted));
      return;
    }
    if (!budget.admits(*declared)) {
      P.set_error(shed_status(kShedOverBudget));
      return;
    }
    collect(std::move(P));
  }
  virtual ~AsyncCollector() = default;
};

using AsyncCollectorClosure = std::function<void(MetricsPromise, CollectionBudget)>;

class CollectorWrapper : public AsyncCollector {
 public:
  CollectorWrapper() = default;
  void collect(MetricsPromise P) final;
  void collect_with_budget(MetricsPromise P, CollectionBudget budget) final;

  template <typename A>
  void add_collector(std::string source_id, td::actor::ActorId<A> collector);

 private:
  struct SourceCollector {
    std::string source_id;
    AsyncCollectorClosure collect;
    double last_completed_at = 0;
    double last_success_at = 0;
    std::uint64_t failures = 0;
    bool last_result_ok = false;
  };
  td::actor::Task<MetricSet> collect_coro(CollectionBudget budget);

  bool collection_inflight_ = false;
  bool registration_overflow_ = false;
  std::vector<SourceCollector> source_collectors_;
};

// CRTP helper for all instruments (collector objects).
template <typename Derived>
class Instrument : public Collector {
 public:
  using Ptr = std::shared_ptr<Derived>;
  template <typename... Args>
  static Ptr make(Args &&...);
};

using SamplerLambda = std::function<std::vector<Sample>()>;

class LambdaGauge : public Instrument<LambdaGauge> {
 public:
  // A lambda's sample count is unknown to the framework; a caller that knows
  // the bound declares it, otherwise the collector is unbudgeted.
  LambdaGauge(std::string metric_name, SamplerLambda lambda, std::optional<std::string> help = std::nullopt,
        std::optional<CollectionReservation> reservation = std::nullopt);
  MetricSet collect() final;
  std::optional<CollectionReservation> reservation() const final { return reservation_; }

 private:
  std::string metric_name_;
  SamplerLambda lambda_;
  std::optional<std::string> help_;
  std::optional<CollectionReservation> reservation_;
};

class LambdaCounter : public Instrument<LambdaCounter> {
 public:
  // A lambda's sample count is unknown to the framework; a caller that knows
  // the bound declares it, otherwise the collector is unbudgeted.
  LambdaCounter(std::string metric_name, SamplerLambda lambda, std::optional<std::string> help = std::nullopt,
        std::optional<CollectionReservation> reservation = std::nullopt);
  MetricSet collect() final;
  std::optional<CollectionReservation> reservation() const final { return reservation_; }

 private:
  std::string metric_name_;
  SamplerLambda lambda_;
  std::optional<std::string> help_;
  std::optional<CollectionReservation> reservation_;
};

using CollectorLambda = std::function<std::vector<MetricFamily>()>;

class LambdaCollector : public Instrument<LambdaCollector> {
 public:
  // Same rule as the lambda instruments: declare the bound or be unbudgeted.
  explicit LambdaCollector(CollectorLambda lambda, std::optional<CollectionReservation> reservation = std::nullopt);
  MetricSet collect() final;
  std::optional<CollectionReservation> reservation() const final { return reservation_; }

 private:
  CollectorLambda lambda_;
  std::optional<CollectionReservation> reservation_;
};

class MultiCollector : public td::actor::Actor, public AsyncCollector {
 public:
  using Own = td::actor::ActorOwn<MultiCollector>;
  using Ptr = td::actor::ActorId<MultiCollector>;

  explicit MultiCollector(std::string prefix);
  void collect(MetricsPromise P) override;
  void collect_with_budget(MetricsPromise P, CollectionBudget budget) override;

  void add_sync_collector(std::shared_ptr<Collector> collector);

  template <std::derived_from<AsyncCollector> A>
  void add_async_collector(std::string source_id, td::actor::ActorId<A> collector);

  static td::actor::ActorOwn<MultiCollector> create(std::string prefix);

 private:
  bool collection_inflight_ = false;
  bool registration_overflow_ = false;
  void collection_completed(MetricSet whole_set, MetricsPromise promise, td::Result<MetricSet> result, CollectionBudget budget,
                            std::vector<CollectionShed> sheds);
  std::string prefix_;
  std::vector<std::shared_ptr<Collector>> sync_collectors_ = {};
  std::unique_ptr<CollectorWrapper> async_collector_ = std::make_unique<CollectorWrapper>();
};

template <typename ValueType>
class AtomicGauge : public Instrument<AtomicGauge<ValueType>> {
 public:
  explicit AtomicGauge(std::string name, std::optional<std::string> help = std::nullopt);
  MetricSet collect() final;
  std::optional<CollectionReservation> reservation() const final {
    return CollectionReservation{scalar_family_reservation_bytes(name_, help_), 1};
  }

  void set(ValueType value);
  void add(ValueType value);
  void sub(ValueType value);
  ValueType get() const {
    return value_.load(std::memory_order_relaxed);
  }

 private:
  const std::string name_;
  const std::optional<std::string> help_;
  std::atomic<ValueType> value_ = {ValueType()};
};

template <typename ValueType>
class AtomicCounter : public Instrument<AtomicCounter<ValueType>> {
 public:
  explicit AtomicCounter(std::string name, std::optional<std::string> help = std::nullopt);
  MetricSet collect() final;
  std::optional<CollectionReservation> reservation() const final {
    return CollectionReservation{scalar_family_reservation_bytes(name_, help_), 1};
  }

  void set(ValueType value);
  void add(ValueType value);

 private:
  const std::string name_;
  const std::optional<std::string> help_;
  std::atomic<ValueType> value_ = {ValueType()};
};

// A counter split by a label value. Each distinct value seen becomes a
// permanent entry, so a label fed from anything remote -- a method name a
// client chose, say -- would otherwise let that client grow the process by
// sending a fresh value each time. Past MAX_LABELS distinct values, everything
// further is counted under one overflow label: the totals stay right, and the
// series a well-behaved deployment produces are all still there, because real
// label sets are small and fixed by the code that emits them.
template <typename LabelType, typename InstrumentType>
class Labeled : public Instrument<Labeled<LabelType, InstrumentType>> {
 public:
  // Comfortably above any label set the node itself produces (the largest is
  // its JSON-RPC method list, in the dozens).
  static constexpr size_t MAX_LABELS = 256;

  template <typename... Args>
  explicit Labeled(std::string label_name, Args... args);
  MetricSet collect() override;
  // The table is bounded by MAX_LABELS, so the reservation is the sum of its
  // instruments' own reservations plus one label per metric; nullopt when
  // the instrument type cannot bound itself.
  std::optional<CollectionReservation> reservation() const override;

  std::shared_ptr<InstrumentType> label(LabelType label);

  // The value everything past MAX_LABELS is counted under.
  static LabelType overflow_label() {
    if constexpr (std::is_same_v<LabelType, std::string>) {
      return std::string{"<over-label-limit>"};
    } else {
      return LabelType{};
    }
  }

 private:
  const std::string label_name_;
  std::function<std::shared_ptr<InstrumentType>()> make_;
  std::unordered_map<LabelType, std::shared_ptr<InstrumentType>> instruments_;
  mutable std::mutex mutex_;
};

template <typename A>
void CollectorWrapper::add_collector(std::string source_id, td::actor::ActorId<A> collector) {
  CHECK(!collector.empty());
  const bool valid_source = !source_id.empty() && source_id.size() <= 64 && source_id[0] >= 'a' &&
                            source_id[0] <= 'z' && std::all_of(source_id.begin(), source_id.end(), [](char c) {
                              return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
                            });
  if (!valid_source || source_collectors_.size() >= 256 ||
      std::any_of(source_collectors_.begin(), source_collectors_.end(),
                  [&](const auto &item) { return item.source_id == source_id; })) {
    registration_overflow_ = true;
    return;
  }
  source_collectors_.push_back(
      {.source_id = std::move(source_id), .collect = [collector](MetricsPromise P, CollectionBudget budget) mutable {
         td::actor::send_lambda(collector, [P = std::move(P), budget, &collector = collector.get_actor_unsafe()]() mutable {
           collector.collect_with_budget(std::move(P), budget);
         });
       }});
}

template <typename Derived>
template <typename... Args>
Instrument<Derived>::Ptr Instrument<Derived>::make(Args &&...args) {
  return std::make_shared<Derived>(std::forward<Args>(args)...);
}

template <std::derived_from<AsyncCollector> A>
void MultiCollector::add_async_collector(std::string source_id, td::actor::ActorId<A> collector) {
  async_collector_->add_collector(std::move(source_id), std::move(collector));
}

template <typename ValueType>
AtomicGauge<ValueType>::AtomicGauge(std::string name, std::optional<std::string> help)
    : name_(std::move(name)), help_(std::move(help)) {
}

template <typename ValueType>
MetricSet AtomicGauge<ValueType>::collect() {
  auto value = value_.load();
  return {{MetricFamily::make_scalar(name_, "gauge", value, help_)}};
}

template <typename ValueType>
void AtomicGauge<ValueType>::set(ValueType value) {
  value_.store(value);
}

template <typename ValueType>
void AtomicGauge<ValueType>::add(ValueType value) {
  value_.fetch_add(value);
}

template <typename ValueType>
void AtomicGauge<ValueType>::sub(ValueType value) {
  value_.fetch_sub(value);
}

template <typename ValueType>
AtomicCounter<ValueType>::AtomicCounter(std::string name, std::optional<std::string> help)
    : name_(std::move(name)), help_(std::move(help)) {
}

template <typename ValueType>
MetricSet AtomicCounter<ValueType>::collect() {
  auto value = value_.load();
  return {{MetricFamily::make_scalar(name_, "counter", value, help_)}};
}

template <typename ValueType>
void AtomicCounter<ValueType>::set(ValueType value) {
  auto old = value_.exchange(value);
  CHECK(value >= old);
}

template <typename ValueType>
void AtomicCounter<ValueType>::add(ValueType value) {
  CHECK(value >= 0);
  value_.fetch_add(value);
}

template <typename LabelType, typename InstrumentType>
template <typename... Args>
Labeled<LabelType, InstrumentType>::Labeled(std::string label_name, Args... args) : label_name_(std::move(label_name)) {
  make_ = [t = std::make_tuple(std::move(args)...)]() mutable {
    return std::apply([](auto &&...xs) { return std::make_shared<InstrumentType>(std::forward<decltype(xs)>(xs)...); },
                      t);
  };
}

template <typename LabelType, typename InstrumentType>
MetricSet Labeled<LabelType, InstrumentType>::collect() {
  std::vector<std::pair<LabelType, std::shared_ptr<InstrumentType>>> tmp;
  {
    std::unique_lock lock(mutex_);
    for (auto e : instruments_) {
      tmp.push_back(std::move(e));
    }
  }
  MetricSet whole_set{{}};
  for (auto &[l, i] : tmp) {
    MetricSet metric_set = i->collect();
    std::string label_str = PSTRING() << l;
    whole_set = std::move(whole_set).join(std::move(metric_set).label({{{label_name_, label_str}}}));
  }
  return whole_set;
}

template <typename LabelType, typename InstrumentType>
std::optional<CollectionReservation> Labeled<LabelType, InstrumentType>::reservation() const {
  std::unique_lock lock(mutex_);
  CollectionReservation total;
  for (const auto &[l, instrument] : instruments_) {
    const auto inner = instrument->reservation();
    if (!inner) {
      return std::nullopt;
    }
    // One label (key and rendered value) per metric the instrument emits.
    const auto label_bytes = inner->families * (sizeof(Label) + label_name_.capacity() + 32);
    total.resident_bytes += inner->resident_bytes + label_bytes;
    total.families += inner->families;
  }
  return total;
}

template <typename LabelType, typename InstrumentType>
std::shared_ptr<InstrumentType> Labeled<LabelType, InstrumentType>::label(LabelType label) {
  std::unique_lock lock(mutex_);
  auto it = instruments_.find(label);
  if (it == instruments_.end()) {
    if (instruments_.size() >= MAX_LABELS) {
      // Count it, but do not remember the value: a new entry per value seen is
      // exactly how a remote caller would grow this map without limit.
      auto overflow = overflow_label();
      it = instruments_.find(overflow);
      if (it == instruments_.end()) {
        it = instruments_.emplace(std::move(overflow), make_()).first;
      }
      return it->second;
    }
    it = instruments_.emplace(std::move(label), make_()).first;
  }
  return it->second;
}

}  // namespace tos::metrics
