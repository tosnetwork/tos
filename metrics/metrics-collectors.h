#pragma once

#include <functional>
#include <type_traits>

#include "td/actor/ActorId.h"
#include "td/actor/PromiseFuture.h"
#include "td/actor/common.h"
#include "td/actor/coro_task.h"

#include "metrics-types.h"

namespace tos::metrics {

class Collector {
 public:
  virtual MetricSet collect() = 0;
  virtual ~Collector() = default;
};

using MetricsPromise = td::Promise<MetricSet>;

// Also implies inheritance from `td::actor::Actor`.
// However, we cannot inherit actor class right here,
// because this inheritance should be virtual (but it is not virtual in other places).
class AsyncCollector {
 public:
  virtual void collect(MetricsPromise P) = 0;
  virtual ~AsyncCollector() = default;
};

using AsyncCollectorClosure = std::function<void(MetricsPromise)>;

class CollectorWrapper : public AsyncCollector {
 public:
  CollectorWrapper() = default;
  void collect(MetricsPromise P) final;

  template <typename A>
  void add_collector(td::actor::ActorId<A> collector);

 private:
  td::actor::Task<MetricSet> collect_coro();

  std::vector<AsyncCollectorClosure> collector_closures_;
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
  LambdaGauge(std::string metric_name, SamplerLambda lambda, std::optional<std::string> help = std::nullopt);
  MetricSet collect() final;

 private:
  std::string metric_name_;
  SamplerLambda lambda_;
  std::optional<std::string> help_;
};

class LambdaCounter : public Instrument<LambdaCounter> {
 public:
  LambdaCounter(std::string metric_name, SamplerLambda lambda, std::optional<std::string> help = std::nullopt);
  MetricSet collect() final;

 private:
  std::string metric_name_;
  SamplerLambda lambda_;
  std::optional<std::string> help_;
};

using CollectorLambda = std::function<std::vector<MetricFamily>()>;

class LambdaCollector : public Instrument<LambdaCollector> {
 public:
  explicit LambdaCollector(CollectorLambda lambda);
  MetricSet collect() final;

 private:
  CollectorLambda lambda_;
};

class MultiCollector : public td::actor::Actor, public AsyncCollector {
 public:
  using Own = td::actor::ActorOwn<MultiCollector>;
  using Ptr = td::actor::ActorId<MultiCollector>;

  explicit MultiCollector(std::string prefix);
  void collect(MetricsPromise P) override;

  void add_sync_collector(std::shared_ptr<Collector> collector);

  template <std::derived_from<AsyncCollector> A>
  void add_async_collector(td::actor::ActorId<A> collector);

  static td::actor::ActorOwn<MultiCollector> create(std::string prefix);

 private:
  std::string prefix_;
  std::vector<std::shared_ptr<Collector>> sync_collectors_ = {};
  std::unique_ptr<CollectorWrapper> async_collector_ = std::make_unique<CollectorWrapper>();
};

template <typename ValueType>
class AtomicGauge : public Instrument<AtomicGauge<ValueType>> {
 public:
  explicit AtomicGauge(std::string name, std::optional<std::string> help = std::nullopt);
  MetricSet collect() final;

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
  std::mutex mutex_;
};

template <typename A>
void CollectorWrapper::add_collector(td::actor::ActorId<A> collector) {
  CHECK(!collector.empty());
  collector_closures_.push_back([collector](MetricsPromise P) mutable {
    td::actor::send_lambda(collector, [P = std::move(P), &collector = collector.get_actor_unsafe()]() mutable {
      collector.collect(std::move(P));
    });
  });
}

template <typename Derived>
template <typename... Args>
Instrument<Derived>::Ptr Instrument<Derived>::make(Args &&...args) {
  return std::make_shared<Derived>(std::forward<Args>(args)...);
}

template <std::derived_from<AsyncCollector> A>
void MultiCollector::add_async_collector(td::actor::ActorId<A> collector) {
  async_collector_->add_collector(std::move(collector));
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
