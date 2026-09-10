#pragma once

#include "block/workchain-execution-dispatch.h"

namespace block {

// Publish ownership of the binding and adapter as one object. A caller cannot
// independently own or replace either half, or move the binding out from under
// the adapter. Accessor borrows remain valid only while this owner is retained;
// they must not cross release, including release during coroutine cancellation.
// This owns configuration, not the registered engine or execution permission.
class WorkchainAccountBindingOwner final {
 public:
  static td::Result<std::unique_ptr<WorkchainAccountBindingOwner>> bind(
      ResolvedWorkchainAccountBinding binding) {
    TRY_RESULT(adapter, ConfiguredWorkchainAccountEngine::bind(binding));
    try {
      return std::unique_ptr<WorkchainAccountBindingOwner>(
          new WorkchainAccountBindingOwner(std::move(binding), std::move(adapter)));
    } catch (const std::bad_alloc&) {
      return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                               "cannot allocate account binding owner");
    }
  }

  WorkchainAccountBindingOwner(const WorkchainAccountBindingOwner&) = delete;
  WorkchainAccountBindingOwner& operator=(const WorkchainAccountBindingOwner&) = delete;
  WorkchainAccountBindingOwner(WorkchainAccountBindingOwner&&) = delete;
  WorkchainAccountBindingOwner& operator=(WorkchainAccountBindingOwner&&) = delete;

  const ResolvedWorkchainAccountBinding& binding() const { return binding_; }
  const ConfiguredWorkchainAccountEngine& adapter() const { return *adapter_; }

  // Consume the sole owner. The temporary half-released state cannot escape
  // this function; the binding dies before the returned diagnostic is exposed.
  // Null is an already-released owner, not a partially initialized binding.
  static long release(std::unique_ptr<WorkchainAccountBindingOwner> owner) {
    if (!owner) return 0;
    owner->adapter_.reset();
    return owner->binding_.engine_config.use_count();
  }

 private:
  WorkchainAccountBindingOwner(ResolvedWorkchainAccountBinding binding,
                               std::unique_ptr<ConfiguredWorkchainAccountEngine> adapter)
      : binding_(std::move(binding)), adapter_(std::move(adapter)) {}
  ResolvedWorkchainAccountBinding binding_;
  // Keep the existing intermediate configuration-count sampling order. The
  // adapter owns its own configuration reference, so this ordering is not a
  // memory-safety dependency between the two fields.
  std::unique_ptr<ConfiguredWorkchainAccountEngine> adapter_;
};

}  // namespace block
