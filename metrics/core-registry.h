#pragma once

#include <array>
#include <algorithm>
#include <iterator>
#include <atomic>
#include <cstdint>
#include <limits>
#include <mutex>
#include <string>

#include "metrics-types.h"
#include "consensus-metric-catalog.h"

namespace tos::health {

// Registration is a bounded setup operation. Business-path updates only touch
// fixed atomics: no allocation, I/O, actor reference, or retry loop without a
// fixed progress bound.
class CoreRegistry {
 public:
  static constexpr std::size_t max_slots = 64;
  static constexpr std::size_t max_name_bytes = 95;
  static constexpr std::size_t max_update_attempts = 8;
  enum class RegistrationProfile : std::uint8_t { Production, TestOnly };

  explicit CoreRegistry(RegistrationProfile profile = RegistrationProfile::Production) : profile_(profile) {
  }

  enum class Kind : std::uint8_t { Counter, Gauge };
  struct Handle {
    std::uint16_t index = std::numeric_limits<std::uint16_t>::max();
    Kind kind = Kind::Counter;
    bool valid() const {
      return index < max_slots;
    }
  };

  Handle register_metric(const std::string &name, Kind kind) {
    std::lock_guard guard(registration_mutex_);
    // C01 ships the lifecycle skeleton, not C04 business hooks. The process-
    // global production registry therefore has an empty exact allowlist. Tests
    // must opt in explicitly; later stages add reviewed exact names here and to
    // the metric manifest before wiring any business update.
    if (!valid_name(name) || (profile_ == RegistrationProfile::Production && !approved_production_name(name))) {
      refuse_update();
      return {};
    }
    const auto registered = registered_.load(std::memory_order_acquire);
    for (std::size_t i = 0; i < registered; ++i) {
      if (slots_[i].name == name) {
        if (slots_[i].kind == kind) {
          return {static_cast<std::uint16_t>(i), kind};
        }
        refuse_update();
        return {};
      }
    }
    if (registered == max_slots) {
      refuse_update();
      return {};
    }
    const auto index = registered;
    slots_[index].name = name;
    slots_[index].kind = kind;
    slots_[index].published.store(true, std::memory_order_release);
    registered_.store(registered + 1, std::memory_order_release);
    return {static_cast<std::uint16_t>(index), kind};
  }

  void note_update_failure() noexcept { refuse_update(); }

  enum class UpdateResult : std::uint8_t { Updated, Saturated, Contended };
  static UpdateResult bounded_add(std::atomic<std::uint64_t> &counter, std::uint64_t amount = 1) noexcept {
    auto old = counter.load(std::memory_order_relaxed);
    for (std::size_t attempt = 0; attempt < max_update_attempts; ++attempt) {
      const bool overflow = amount > std::numeric_limits<std::uint64_t>::max() - old;
      const auto next = overflow ? std::numeric_limits<std::uint64_t>::max() : old + amount;
      if (counter.compare_exchange_weak(old, next, std::memory_order_relaxed))
        return overflow ? UpdateResult::Saturated : UpdateResult::Updated;
    }
    return UpdateResult::Contended;
  }

  // Only the frozen compiled tuple ID can select labels. Sources are static
  // process atomics, bound at exporter setup, never actor-owned state.
  bool register_fixed(std::size_t id, std::atomic<std::uint64_t> *source,
                      const std::atomic<bool> *available = nullptr) {
    std::lock_guard guard(registration_mutex_);
    if (id >= consensus_metric_catalog.size() || source == nullptr) { refuse_update(); return false; }
    auto &slot = fixed_[id];
    const auto existing = slot.source.load(std::memory_order_acquire);
    if (existing != nullptr) {
      if (existing != source || slot.available != available) { refuse_update(); return false; }
      return true;
    }
    slot.available = available;
    slot.source.store(source, std::memory_order_release);
    return true;
  }

  bool add(Handle handle, std::uint64_t amount = 1) noexcept {
    auto *slot = checked(handle, Kind::Counter);
    if (!slot) {
      refuse_update();
      return false;
    }
    const auto updated = bounded_add(slot->value, amount);
    if (updated == UpdateResult::Updated) return true;
    refuse_update();
    return false;
  }

  bool set_gauge(Handle handle, std::uint64_t value) noexcept {
    auto *slot = checked(handle, Kind::Gauge);
    if (!slot || !slot->owner_active.load(std::memory_order_relaxed)) {
      refuse_update();
      return false;
    }
    slot->value.store(value, std::memory_order_relaxed);
    return true;
  }

  class GaugeOwner {
   public:
    GaugeOwner() = default;
    GaugeOwner(CoreRegistry *registry, Handle handle) : registry_(registry), handle_(handle) {
    }
    GaugeOwner(GaugeOwner &&other) noexcept : registry_(other.registry_), handle_(other.handle_) {
      other.registry_ = nullptr;
    }
    GaugeOwner &operator=(GaugeOwner &&other) noexcept {
      if (this != &other) {
        reset();
        registry_ = other.registry_;
        handle_ = other.handle_;
        other.registry_ = nullptr;
      }
      return *this;
    }
    ~GaugeOwner() {
      reset();
    }
    bool set(std::uint64_t value) noexcept {
      return registry_ && registry_->set_gauge(handle_, value);
    }
    bool valid() const {
      return registry_ != nullptr;
    }
    GaugeOwner(const GaugeOwner &) = delete;
    GaugeOwner &operator=(const GaugeOwner &) = delete;

   private:
    void reset() noexcept {
      if (registry_) {
        registry_->release_gauge(handle_);
        registry_ = nullptr;
      }
    }
    CoreRegistry *registry_ = nullptr;
    Handle handle_{};
  };

  GaugeOwner acquire_gauge(Handle handle) noexcept {
    auto *slot = checked(handle, Kind::Gauge);
    bool inactive = false;
    if (!slot || !slot->owner_active.compare_exchange_strong(inactive, true, std::memory_order_relaxed)) {
      refuse_update();
      return {};
    }
    slot->value.store(0, std::memory_order_relaxed);
    return GaugeOwner(this, handle);
  }

  metrics::MetricSet collect(bool include_fixed = true) const {
    metrics::MetricSet result;
    for (const auto &slot : slots_) {
      if (!slot.published.load(std::memory_order_acquire)) {
        continue;
      }
      result.families.push_back(
          metrics::MetricFamily::make_scalar(slot.name, slot.kind == Kind::Counter ? "counter" : "gauge",
                                             static_cast<double>(slot.value.load(std::memory_order_relaxed))));
    }
    for (std::size_t id = 0; include_fixed && id < fixed_.size(); ++id) {
      const auto &slot = fixed_[id];
      const auto source = slot.source.load(std::memory_order_acquire);
      if (source == nullptr || (slot.available != nullptr && !slot.available->load(std::memory_order_relaxed))) continue;
      const auto &descriptor = consensus_metric_catalog[id];
      auto family = std::find_if(result.families.begin(), result.families.end(),
          [&](const auto &item) { return item.name == descriptor.name; });
      if (family == result.families.end()) {
        result.families.push_back({.name = descriptor.name, .type = descriptor.type,
            .help = "Fixed C04 native observations; concurrent bounded snapshot.", .metrics = {}});
        family = std::prev(result.families.end());
      }
      metrics::LabelSet labels;
      for (std::size_t label = 0; label < descriptor.label_count; ++label)
        labels.labels.push_back({descriptor.labels[label][0], descriptor.labels[label][1]});
      family->metrics.push_back({.suffix = descriptor.suffix, .label_set = std::move(labels),
          .samples = {{.label_set = {}, .value = static_cast<double>(source->load(std::memory_order_relaxed)) * descriptor.scale}}});
    }
    result.families.push_back(metrics::MetricFamily::make_scalar("tos_health_core_registry_instrumentation_complete",
                                                                 "gauge",
                                                                 complete_.load(std::memory_order_relaxed) ? 1 : 0));
    result.families.push_back(
        metrics::MetricFamily::make_scalar("tos_health_core_registry_dropped_updates_total", "counter",
                                           static_cast<double>(dropped_updates_.load(std::memory_order_relaxed))));
    return result;
  }

  bool complete() const noexcept {
    return complete_.load(std::memory_order_relaxed);
  }
  std::uint64_t dropped_updates() const noexcept {
    return dropped_updates_.load(std::memory_order_relaxed);
  }
  std::size_t registered() const noexcept {
    return registered_.load(std::memory_order_acquire);
  }

 private:
  struct FixedSlot {
    std::atomic<std::atomic<std::uint64_t> *> source{nullptr};
    const std::atomic<bool> *available = nullptr;
  };
  std::array<FixedSlot, consensus_metric_catalog.size()> fixed_{};

  struct Slot {
    std::string name;
    Kind kind = Kind::Counter;
    std::atomic<std::uint64_t> value{0};
    std::atomic<bool> owner_active{false};
    std::atomic<bool> published{false};
  };

  static bool valid_name(const std::string &name) {
    if (name.empty() || name.size() > max_name_bytes || name[0] < 'a' || name[0] > 'z') {
      return false;
    }
    for (char value : name) {
      if (!((value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '_')) {
        return false;
      }
    }
    return true;
  }
  static bool approved_production_name(const std::string &) {
    return false;
  }
  Slot *checked(Handle handle, Kind expected) noexcept {
    if (!handle.valid() || handle.kind != expected) {
      return nullptr;
    }
    auto &slot = slots_[handle.index];
    if (!slot.published.load(std::memory_order_acquire) || slot.kind != expected) {
      return nullptr;
    }
    return &slot;
  }
  void release_gauge(Handle handle) noexcept {
    if (auto *slot = checked(handle, Kind::Gauge)) {
      slot->value.store(0, std::memory_order_relaxed);
      slot->owner_active.store(false, std::memory_order_release);
    }
  }
  void refuse_update() noexcept {
    complete_.store(false, std::memory_order_relaxed);
    auto old = dropped_updates_.load(std::memory_order_relaxed);
    for (std::size_t attempt = 0; attempt < max_update_attempts; ++attempt) {
      if (old == std::numeric_limits<std::uint64_t>::max() ||
          dropped_updates_.compare_exchange_weak(old, old + 1, std::memory_order_relaxed)) {
        return;
      }
    }
    // Preserve monotonicity even when the accounting counter itself is highly
    // contended; saturation is an explicit lower bound, never a wraparound.
    dropped_updates_.store(std::numeric_limits<std::uint64_t>::max(), std::memory_order_relaxed);
  }

  std::array<Slot, max_slots> slots_{};
  RegistrationProfile profile_ = RegistrationProfile::Production;
  mutable std::mutex registration_mutex_;
  std::atomic<std::size_t> registered_{0};
  std::atomic<bool> complete_{true};
  std::atomic<std::uint64_t> dropped_updates_{0};
};

inline CoreRegistry core_registry;
static_assert(sizeof(CoreRegistry) < 16 * 1024);

}  // namespace tos::health
