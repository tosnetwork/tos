#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <limits>
#include <mutex>
#include <string>

#include "metrics-types.h"

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

  bool add(Handle handle, std::uint64_t amount = 1) noexcept {
    auto *slot = checked(handle, Kind::Counter);
    if (!slot) {
      refuse_update();
      return false;
    }
    auto old = slot->value.load(std::memory_order_relaxed);
    for (std::size_t attempt = 0; attempt < max_update_attempts; ++attempt) {
      if (amount > std::numeric_limits<std::uint64_t>::max() - old) {
        slot->value.store(std::numeric_limits<std::uint64_t>::max(), std::memory_order_relaxed);
        refuse_update();
        return false;
      }
      if (slot->value.compare_exchange_weak(old, old + amount, std::memory_order_relaxed)) {
        return true;
      }
    }
    // A business-path update has a fixed progress bound. Losing an update is
    // explicit in the publisher's quality signal rather than hidden in an
    // unbounded retry loop.
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

  metrics::MetricSet collect() const {
    metrics::MetricSet result;
    for (const auto &slot : slots_) {
      if (!slot.published.load(std::memory_order_acquire)) {
        continue;
      }
      result.families.push_back(
          metrics::MetricFamily::make_scalar(slot.name, slot.kind == Kind::Counter ? "counter" : "gauge",
                                             static_cast<double>(slot.value.load(std::memory_order_relaxed))));
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
