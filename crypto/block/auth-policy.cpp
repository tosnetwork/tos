#include "block/auth-policy.h"
#include "td/utils/crypto.h"
#include "vm/dict.h"

namespace block {
namespace {
td::Status invalid() {
  return td::Status::Error("invalid or missing AUTH policy (ConfigParam 48)");
}
}  // namespace

td::Result<AuthPolicy> unpack_auth_policy(td::Ref<vm::Cell> value) {
  try {
    if (value.is_null() || value->get_level() != 0) {
      return invalid();
    }
    bool special = false;
    auto cs = vm::load_cell_slice_special(value, special);
    if (special || cs.size() != 601 || cs.fetch_ulong(8) != 0xa1) {
      return invalid();
    }
    AuthPolicy result;
    if (!cs.fetch_bits_to(result.network)) {
      return invalid();
    }
    result.sequence = cs.fetch_ulong(64);
    result.retired = static_cast<td::uint16>(cs.fetch_ulong(16));
    if (result.retired & ~2) {
      return invalid();
    }
    const bool present = cs.fetch_ulong(1) != 0;
    if (cs.size_refs() != (present ? 1u : 0u)) {
      return invalid();
    }
    auto schedule = present ? cs.fetch_ref() : td::Ref<vm::Cell>{};
    td::Bits256 spec, expected;
    td::sha256(auth_policy_profile, expected.as_slice());
    if (!cs.fetch_bits_to(spec) || spec != expected || !cs.empty_ext()) {
      return invalid();
    }
    if (present) {
      if (schedule->get_level() != 0) {
        return invalid();
      }
      vm::load_cell_slice_special(schedule, special);
      if (special) {
        return invalid();
      }
      vm::Dictionary deadlines{schedule, 8};
      bool seen = false;
      if (!deadlines.check_for_each([&](td::Ref<vm::CellSlice> entry, td::ConstBitPtr key, int bits) {
            if (seen || bits != 8 || key.get_uint(8) != 1 || entry->size() != 32 || entry->size_refs() != 0) {
              return false;
            }
            seen = true;
            result.deadline = static_cast<td::uint32>(entry->prefetch_ulong(32));
            return result.deadline != 0;
          }) ||
          !seen) {
        return invalid();
      }
    }
    return result;
  } catch (vm::VmError&) {
    return invalid();
  } catch (vm::VmVirtError&) {
    return invalid();
  }
}

td::Status validate_auth_policy_config(td::Ref<vm::Cell> config) {
  try {
    if (config.is_null()) {
      return invalid();
    }
    vm::Dictionary dictionary{config, 32};
    auto value = dictionary.lookup_ref(td::BitArray<32>{48});
    auto version_cell = dictionary.lookup_ref(td::BitArray<32>{8});
    bool required = false;
    if (version_cell.not_null()) {
      auto version = vm::load_cell_slice(version_cell);
      if (version.size() != 104 || version.size_refs() != 0 || version.fetch_ulong(8) != 0xc4) {
        return invalid();
      }
      required = version.fetch_ulong(32) >= 17;
    }
    if (value.is_null() && !required) {
      return td::Status::OK();
    }
    auto policy = unpack_auth_policy(value);
    if (policy.is_error()) {
      return policy.move_as_error();
    }
    // The node pins mandatory/critical membership, not merely the current value.
    if (value.not_null()) {
      for (int parameter : {9, 10}) {
        auto list = dictionary.lookup_ref(td::BitArray<32>{parameter});
        if (list.is_null() || !vm::Dictionary{list, 32}.int_key_exists(48)) {
          return td::Status::Error("AUTH policy must be mandatory and critical");
        }
      }
    }
    return td::Status::OK();
  } catch (vm::VmError&) {
    return invalid();
  } catch (vm::VmVirtError&) {
    return invalid();
  }
}

td::Status validate_auth_policy_transition(td::Ref<vm::Cell> old_config, td::Ref<vm::Cell> new_config) {
  TRY_STATUS(validate_auth_policy_config(new_config));
  try {
    vm::Dictionary old_dict{old_config, 32}, new_dict{new_config, 32};
    auto old_cell = old_dict.lookup_ref(td::BitArray<32>{48});
    auto new_cell = new_dict.lookup_ref(td::BitArray<32>{48});
    if (old_cell.is_null() && new_cell.is_null()) {
      return td::Status::OK();
    }
    TRY_RESULT(next, unpack_auth_policy(new_cell));
    if (old_cell.is_null()) {
      return next.sequence == 0 ? td::Status::OK() : invalid();
    }
    TRY_RESULT(previous, unpack_auth_policy(old_cell));
    if (old_cell->get_hash() == new_cell->get_hash()) {
      return td::Status::OK();
    }
    if (previous.network != next.network || next.sequence <= previous.sequence ||
        (next.retired & previous.retired) != previous.retired ||
        (previous.deadline != 0 && (next.deadline == 0 || next.deadline > previous.deadline))) {
      return td::Status::Error("AUTH retirement policy cannot roll back");
    }
    return td::Status::OK();
  } catch (vm::VmError&) {
    return invalid();
  } catch (vm::VmVirtError&) {
    return invalid();
  }
}
}  // namespace block
