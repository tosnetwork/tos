#include "validator/auth/native-session-id-core.h"

#include <algorithm>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <utility>

using namespace tos::auth;

namespace {
struct AssertionFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};
void require(bool condition, const std::string& assertion) {
  if (!condition)
    throw AssertionFailure(assertion);
}
Hash h(std::uint8_t byte) {
  Hash result{};
  result.fill(byte);
  return result;
}
Hash transcript_hash(NativeSessionIdForm form, std::int32_t workchain,
                     std::uint64_t shard, std::uint32_t vertical,
                     std::uint32_t key_block, std::uint32_t catchain,
                     const Hash& options,
                     std::span<const NativeSessionIdMember> members) {
  Writer writer;
  writer.integer(static_cast<std::uint8_t>(form));
  writer.integer(workchain);
  writer.integer(shard);
  writer.integer(vertical);
  writer.integer(key_block);
  writer.integer(catchain);
  writer.bytes(options);
  writer.length(members.size(), 2);
  for (const auto& member : members) {
    writer.bytes(member.short_id);
    writer.bytes(member.adnl_id);
    writer.integer(member.weight);
  }
  require(writer.ok(), "transcript_hash");
  Hash result{};
  std::uint32_t state = 2166136261u;
  for (std::size_t i = 0; i < writer.data.size(); ++i) {
    state ^= writer.data[i];
    state *= 16777619u;
    result[i % result.size()] ^= static_cast<std::uint8_t>(state >> ((i % 4) * 8));
  }
  if (result == Hash{})
    result[0] = 1;
  return result;
}
NativeSessionIdEncoder encoder() {
  return [](NativeSessionIdForm form, std::int32_t workchain,
            std::uint64_t shard, std::uint32_t vertical,
            std::uint32_t key_block, std::uint32_t catchain,
            const Hash& options,
            std::span<const NativeSessionIdMember> members) -> Result<Hash> {
    return transcript_hash(form, workchain, shard, vertical, key_block,
                           catchain, options, members);
  };
}
std::vector<NativeSessionIdMember> members() {
  return {{h(11), h(21), 5}, {h(12), h(22), 7}, {h(13), {}, 9}};
}
NativeSessionIdInput input(NativeSessionIdForm form) {
  NativeSessionIdInput value;
  value.native_options_hash = h(31);
  value.workchain = -1;
  value.shard = std::uint64_t{1} << 63;
  value.maximal_vertical_seqno = form == NativeSessionIdForm::group ? 0 : 17;
  value.last_key_block_seqno = 41;
  value.form = form;
  return value;
}
Hash manager_group_oracle(const NativeSessionIdInput& value,
                          std::uint32_t catchain,
                          std::span<const NativeSessionIdMember> roster) {
  return transcript_hash(NativeSessionIdForm::group, value.workchain,
                         value.shard, 0, 0, catchain,
                         value.native_options_hash, roster);
}
Hash manager_group_ex_oracle(const NativeSessionIdInput& value,
                             std::uint32_t catchain,
                             std::span<const NativeSessionIdMember> roster) {
  return transcript_hash(NativeSessionIdForm::group_ex, value.workchain,
                         value.shard, value.maximal_vertical_seqno, 0,
                         catchain, value.native_options_hash, roster);
}
Hash manager_group_new_oracle(const NativeSessionIdInput& value,
                              std::uint32_t catchain,
                              std::span<const NativeSessionIdMember> roster) {
  return transcript_hash(NativeSessionIdForm::group_new, value.workchain,
                         value.shard, value.maximal_vertical_seqno,
                         value.last_key_block_seqno, catchain,
                         value.native_options_hash, roster);
}
void expect_error(const auto& result, std::string_view error,
                  const std::string& assertion) {
  require(!result.ok() && result.error().code == error, assertion);
}
void setup() {
  const auto roster = members();
  auto result = derive_native_session_identity_core(
      input(NativeSessionIdForm::group), 19, roster, encoder());
  require(result.ok(), "fixture_accepts");
}

using Test = std::pair<std::string, std::function<void()>>;
std::vector<Test> tests() {
  std::vector<Test> result;
  auto add = [&](std::string name, std::function<void()> fn) {
    result.emplace_back(std::move(name), std::move(fn));
  };
  add("group_matches_manager_bytes", [] {
    const auto roster = members();
    const auto value = input(NativeSessionIdForm::group);
    auto actual = derive_native_session_identity_core(value, 19, roster, encoder());
    require(actual.ok(), "group_matches_manager_bytes");
    const NativeSessionIdentity expected{manager_group_oracle(value, 19, roster),
                                         value.native_options_hash,
                                         value.workchain,
                                         value.shard,
                                         19,
                                         0,
                                         0,
                                         NativeSessionIdForm::group};
    require(actual.value() == expected, "group_matches_manager_bytes");
  });
  add("group_ex_matches_manager_bytes", [] {
    const auto roster = members();
    const auto value = input(NativeSessionIdForm::group_ex);
    auto actual = derive_native_session_identity_core(value, 19, roster, encoder());
    require(actual.ok(), "group_ex_matches_manager_bytes");
    const NativeSessionIdentity expected{manager_group_ex_oracle(value, 19, roster),
                                         value.native_options_hash,
                                         value.workchain,
                                         value.shard,
                                         19,
                                         17,
                                         0,
                                         NativeSessionIdForm::group_ex};
    require(actual.value() == expected, "group_ex_matches_manager_bytes");
  });
  add("group_new_matches_manager_bytes", [] {
    const auto roster = members();
    const auto value = input(NativeSessionIdForm::group_new);
    auto actual = derive_native_session_identity_core(value, 19, roster, encoder());
    require(actual.ok(), "group_new_matches_manager_bytes");
    const NativeSessionIdentity expected{manager_group_new_oracle(value, 19, roster),
                                         value.native_options_hash,
                                         value.workchain,
                                         value.shard,
                                         19,
                                         17,
                                         41,
                                         NativeSessionIdForm::group_new};
    require(actual.value() == expected, "group_new_matches_manager_bytes");
  });
  add("nonzero_catchain_is_committed", [] {
    const auto roster = members();
    const auto value = input(NativeSessionIdForm::group_new);
    auto a = derive_native_session_identity_core(value, 19, roster, encoder());
    auto b = derive_native_session_identity_core(value, 20, roster, encoder());
    require(a.ok() && b.ok() && a.value().catchain == 19,
            "nonzero_catchain_is_committed");
    require(a.value().native_session_id != b.value().native_session_id,
            "nonzero_catchain_is_committed");
  });
  add("legacy_key_block_is_normalized", [] {
    const auto roster = members();
    auto a = input(NativeSessionIdForm::group_ex);
    auto b = a;
    a.last_key_block_seqno = 41;
    b.last_key_block_seqno = 99;
    auto left = derive_native_session_identity_core(a, 19, roster, encoder());
    auto right = derive_native_session_identity_core(b, 19, roster, encoder());
    require(left.ok() && right.ok(), "legacy_key_block_is_normalized");
    require(left.value().key_block_seqno == 0 && right.value().key_block_seqno == 0,
            "legacy_key_block_is_normalized");
    require(left.value().native_session_id == right.value().native_session_id,
            "legacy_key_block_is_normalized");
  });
  add("new_key_block_is_committed", [] {
    const auto roster = members();
    auto a = input(NativeSessionIdForm::group_new);
    auto b = a;
    b.last_key_block_seqno = 99;
    auto left = derive_native_session_identity_core(a, 19, roster, encoder());
    auto right = derive_native_session_identity_core(b, 19, roster, encoder());
    require(left.ok() && right.ok() &&
                left.value().native_session_id != right.value().native_session_id,
            "new_key_block_is_committed");
  });
  add("options_hash_is_committed", [] {
    const auto roster = members();
    auto a = input(NativeSessionIdForm::group);
    auto b = a;
    b.native_options_hash = h(32);
    auto left = derive_native_session_identity_core(a, 19, roster, encoder());
    auto right = derive_native_session_identity_core(b, 19, roster, encoder());
    require(left.ok() && right.ok() &&
                left.value().native_session_id != right.value().native_session_id,
            "options_hash_is_committed");
  });
  add("vertical_sequence_is_committed", [] {
    const auto roster = members();
    auto a = input(NativeSessionIdForm::group_ex);
    auto b = a;
    b.maximal_vertical_seqno = 18;
    auto left = derive_native_session_identity_core(a, 19, roster, encoder());
    auto right = derive_native_session_identity_core(b, 19, roster, encoder());
    require(left.ok() && right.ok() &&
                left.value().native_session_id != right.value().native_session_id,
            "vertical_sequence_is_committed");
  });
  add("member_order_is_committed", [] {
    auto roster = members();
    auto reversed = roster;
    std::reverse(reversed.begin(), reversed.end());
    const auto value = input(NativeSessionIdForm::group);
    auto left = derive_native_session_identity_core(value, 19, roster, encoder());
    auto right = derive_native_session_identity_core(value, 19, reversed, encoder());
    require(left.ok() && right.ok() &&
                left.value().native_session_id != right.value().native_session_id,
            "member_order_is_committed");
  });
  add("member_address_is_committed", [] {
    auto roster = members();
    auto changed = roster;
    changed[1].adnl_id = h(33);
    const auto value = input(NativeSessionIdForm::group);
    auto left = derive_native_session_identity_core(value, 19, roster, encoder());
    auto right = derive_native_session_identity_core(value, 19, changed, encoder());
    require(left.ok() && right.ok() &&
                left.value().native_session_id != right.value().native_session_id,
            "member_address_is_committed");
  });
  add("member_weight_is_committed", [] {
    auto roster = members();
    auto changed = roster;
    changed[1].weight = 8;
    const auto value = input(NativeSessionIdForm::group);
    auto left = derive_native_session_identity_core(value, 19, roster, encoder());
    auto right = derive_native_session_identity_core(value, 19, changed, encoder());
    require(left.ok() && right.ok() &&
                left.value().native_session_id != right.value().native_session_id,
            "member_weight_is_committed");
  });
  add("zero_options_are_refused", [] {
    const auto roster = members();
    auto value = input(NativeSessionIdForm::group);
    value.native_options_hash = {};
    expect_error(derive_native_session_identity_core(value, 19, roster, encoder()),
                 "native-session-options", "zero_options_are_refused");
  });
  add("constructor_form_must_match_vertical", [] {
    const auto roster = members();
    auto simple = input(NativeSessionIdForm::group);
    simple.maximal_vertical_seqno = 1;
    expect_error(derive_native_session_identity_core(simple, 19, roster, encoder()),
                 "native-session-form", "constructor_form_must_match_vertical");
    auto extended = input(NativeSessionIdForm::group_ex);
    extended.maximal_vertical_seqno = 0;
    expect_error(derive_native_session_identity_core(extended, 19, roster, encoder()),
                 "native-session-form", "constructor_form_must_match_vertical");
  });
  add("invalid_coordinate_is_refused", [] {
    const auto roster = members();
    auto invalid_workchain = input(NativeSessionIdForm::group);
    invalid_workchain.workchain = -2;
    expect_error(derive_native_session_identity_core(invalid_workchain, 19, roster, encoder()),
                 "native-session-coordinate", "invalid_coordinate_is_refused");
    auto invalid_shard = input(NativeSessionIdForm::group);
    invalid_shard.shard = 0;
    expect_error(derive_native_session_identity_core(invalid_shard, 19, roster, encoder()),
                 "native-session-coordinate", "invalid_coordinate_is_refused");
  });
  add("missing_encoder_is_refused", [] {
    const auto roster = members();
    expect_error(derive_native_session_identity_core(
                     input(NativeSessionIdForm::group), 19, roster, {}),
                 "native-session-encoder", "missing_encoder_is_refused");
  });
  add("empty_roster_is_refused", [] {
    const std::vector<NativeSessionIdMember> roster;
    expect_error(derive_native_session_identity_core(
                     input(NativeSessionIdForm::group), 19, roster, encoder()),
                 "native-session-members", "empty_roster_is_refused");
  });
  add("invalid_member_is_refused", [] {
    auto roster = members();
    roster[0].weight = 0;
    expect_error(derive_native_session_identity_core(
                     input(NativeSessionIdForm::group), 19, roster, encoder()),
                 "native-session-member", "invalid_member_is_refused");
  });
  add("encoder_failure_has_no_fallback", [] {
    const auto roster = members();
    NativeSessionIdEncoder failed = [](auto...) -> Result<Hash> {
      return Error{"native-encoder-failed"};
    };
    expect_error(derive_native_session_identity_core(
                     input(NativeSessionIdForm::group), 19, roster, failed),
                 "native-encoder-failed", "encoder_failure_has_no_fallback");
  });
  add("zero_encoded_id_is_refused", [] {
    const auto roster = members();
    NativeSessionIdEncoder zero = [](auto...) -> Result<Hash> { return Hash{}; };
    expect_error(derive_native_session_identity_core(
                     input(NativeSessionIdForm::group), 19, roster, zero),
                 "native-session-id", "zero_encoded_id_is_refused");
  });
  return result;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc > 2) {
    std::cerr << "USAGE: test-p0-native-session-id [case-name|--list]\n";
    return 2;
  }
  const auto all = tests();
  if (argc == 2 && std::string_view(argv[1]) == "--list") {
    for (const auto& test : all)
      std::cout << test.first << '\n';
    return 0;
  }
  std::size_t ran = 0;
  for (const auto& [name, fn] : all) {
    if (argc == 2 && name != argv[1])
      continue;
    try {
      setup();
      std::cout << "SETUP_OK " << name << '\n';
      fn();
      std::cout << "CASE_PASS " << name << '\n';
      ++ran;
    } catch (const AssertionFailure& error) {
      std::cerr << "ASSERTION_FAILED " << error.what() << '\n';
      return 1;
    } catch (const std::exception& error) {
      std::cerr << "UNEXPECTED_EXCEPTION " << name << ": " << error.what() << '\n';
      return 2;
    }
  }
  if (ran == 0) {
    std::cerr << "UNKNOWN_CASE\n";
    return 2;
  }
  std::cout << "SUMMARY cases=" << ran << " passed=" << ran << '\n';
  return 0;
}
