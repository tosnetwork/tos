/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// Conformance model for the validator authentication phases described in
// TIP-0002, evaluated against the corpus in test/validator-auth-policy.
//
// What this is: a check that the weight arithmetic a future phased policy
// would rely on is the arithmetic this build actually implements, and a
// pinned statement of the authorization rules that implementation must obey
// -- AND is not OR, a shadow result carries no authority, an absent validator
// does not shrink the denominator.
//
// What this is NOT: a signature verifier, a post-quantum implementation, or
// evidence that any of TIP-0002 is implemented. `ed_valid`/`pq_valid` in the
// corpus are supplied outcomes, not signatures. None of the phases beyond the
// classical one exists in this codebase; see doc/tip-0002-p0-readiness.md.
//
// The quorum, weight-cap and zero-weight decisions below are delegated to
// tos/quorum.h rather than restated, so that changing the real predicate
// changes this test's verdicts. The Python model in test/validator-auth-policy
// evaluates the same corpus independently; the two must agree.

#include <map>
#include <set>
#include <string>
#include <vector>

#include "td/utils/JsonBuilder.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"
#include "tos/quorum.h"

namespace {

struct Signer {
  std::string validator;
  bool ed_valid{false};
  bool pq_valid{false};
  bool registered{false};
  bool context_matches{true};
};

struct Case {
  std::string id;
  std::string phase;
  std::vector<Signer> signers;
  std::map<std::string, td::uint64> registry;
  bool well_formed{true};
  bool policy_matches{true};
  bool mandatory_suite_supported{true};
  std::string expected;
};

bool is_known_phase(const std::string& phase) {
  return phase == "classical" || phase == "shadow" || phase == "hybrid_required" || phase == "pq_required";
}

// The modeled outcome. Registry admission and the quorum decision come from
// tos/quorum.h; everything else is the phase rule TIP-0002 requires.
std::string evaluate(const Case& c) {
  if (!is_known_phase(c.phase)) {
    return "reject_phase";
  }
  if (!c.well_formed) {
    return "reject_encoding";
  }
  if (!c.policy_matches) {
    return "reject_policy";
  }
  if (!c.mandatory_suite_supported) {
    return "reject_suite";
  }
  if (c.registry.empty()) {
    return "reject_registry";
  }
  // checked_add_validator_weight is the production guard: it rejects a
  // zero-weight validator and any set whose total breaks the UINT64_MAX/3
  // invariant the quorum helpers depend on.
  tos::ValidatorWeight total = 0;
  for (const auto& [identity, weight] : c.registry) {
    if (!tos::checked_add_validator_weight(total, weight)) {
      return "reject_registry";
    }
  }

  std::set<std::string> seen;
  tos::ValidatorWeight signed_weight = 0;
  for (const auto& signer : c.signers) {
    auto entry = c.registry.find(signer.validator);
    if (entry == c.registry.end()) {
      return "reject_unknown_signer";
    }
    if (!seen.insert(signer.validator).second) {
      return "reject_duplicate_signer";
    }
    // Key, role, network, committee and statement bindings must all match.
    if (!signer.context_matches) {
      return "reject_context";
    }
    if (c.phase == "hybrid_required" || c.phase == "pq_required") {
      if (!signer.registered) {
        return "reject_registration";
      }
    }
    bool authorized;
    if (c.phase == "classical" || c.phase == "shadow") {
      // A shadow result never rescues or invalidates a classical vote.
      authorized = signer.ed_valid;
    } else if (c.phase == "hybrid_required") {
      authorized = signer.ed_valid && signer.pq_valid;  // AND, never OR
    } else {
      authorized = signer.pq_valid;
    }
    if (!authorized) {
      return "reject_authentication";
    }
    if (!tos::checked_add_validator_weight(signed_weight, entry->second)) {
      return "reject_registry";
    }
  }
  return tos::has_quorum(signed_weight, total) ? "accept" : "reject_quorum";
}

bool get_bool(td::JsonObject& object, td::Slice name, bool fallback) {
  auto field = object.extract_field(name);
  if (field.type() == td::JsonValue::Type::Null) {
    return fallback;
  }
  CHECK(field.type() == td::JsonValue::Type::Boolean);
  return field.get_boolean();
}

std::map<std::string, td::uint64> parse_registry(td::JsonValue&& value) {
  CHECK(value.type() == td::JsonValue::Type::Object);
  std::map<std::string, td::uint64> registry;
  for (auto& field : value.get_object().field_values_) {
    CHECK(field.second.type() == td::JsonValue::Type::Number);
    auto parsed = td::to_integer_safe<td::uint64>(field.second.get_number());
    parsed.ensure();
    registry.emplace(field.first.str(), parsed.move_as_ok());
  }
  return registry;
}

std::vector<Case> load_cases(const std::string& path) {
  auto data = td::read_file_str(path);
  data.ensure();
  auto text = data.move_as_ok();
  auto decoded = td::json_decode(td::MutableSlice(text));
  decoded.ensure();
  auto root = decoded.move_as_ok();
  CHECK(root.type() == td::JsonValue::Type::Object);
  auto& root_object = root.get_object();

  auto default_registry = parse_registry(root_object.extract_field("default_registry"));

  auto raw_cases = root_object.extract_field("cases");
  CHECK(raw_cases.type() == td::JsonValue::Type::Array);
  std::vector<Case> cases;
  for (auto& element : raw_cases.get_array()) {
    CHECK(element.type() == td::JsonValue::Type::Object);
    auto& object = element.get_object();
    Case parsed;
    parsed.id = object.extract_field("id").get_string().str();
    parsed.phase = object.extract_field("phase").get_string().str();
    parsed.expected = object.extract_field("expected").get_string().str();
    parsed.well_formed = get_bool(object, "well_formed", true);
    parsed.policy_matches = get_bool(object, "policy_matches", true);
    parsed.mandatory_suite_supported = get_bool(object, "mandatory_suite_supported", true);

    auto registry_field = object.extract_field("registry");
    parsed.registry =
        registry_field.type() == td::JsonValue::Type::Null ? default_registry : parse_registry(std::move(registry_field));

    auto signers = object.extract_field("signers");
    CHECK(signers.type() == td::JsonValue::Type::Array);
    for (auto& raw_signer : signers.get_array()) {
      CHECK(raw_signer.type() == td::JsonValue::Type::Object);
      auto& signer_object = raw_signer.get_object();
      Signer signer;
      signer.validator = signer_object.extract_field("validator").get_string().str();
      signer.ed_valid = get_bool(signer_object, "ed_valid", false);
      signer.pq_valid = get_bool(signer_object, "pq_valid", false);
      signer.registered = get_bool(signer_object, "registered", false);
      signer.context_matches = get_bool(signer_object, "context_matches", true);
      parsed.signers.push_back(std::move(signer));
    }
    cases.push_back(std::move(parsed));
  }
  return cases;
}

std::string corpus_path;

}  // namespace

TEST(ValidatorAuthPolicy, CorpusIsNonEmptyAndUniquelyIdentified) {
  auto cases = load_cases(corpus_path);
  ASSERT_TRUE(!cases.empty());
  std::set<std::string> ids;
  for (const auto& c : cases) {
    ASSERT_TRUE(ids.insert(c.id).second);
  }
}

TEST(ValidatorAuthPolicy, EveryCaseMatchesItsExpectedOutcome) {
  for (const auto& c : load_cases(corpus_path)) {
    auto actual = evaluate(c);
    LOG_CHECK(actual == c.expected) << c.id << ": expected " << c.expected << ", got " << actual;
  }
}

// The corpus is only meaningful while it still discriminates. If the AND in
// the hybrid phase were relaxed to OR, these cases must stop matching; a
// corpus that passes either way would be measuring nothing.
TEST(ValidatorAuthPolicy, HybridCorpusDistinguishesAndFromOr) {
  int discriminating = 0;
  for (const auto& c : load_cases(corpus_path)) {
    if (c.phase != "hybrid_required" || c.expected != "reject_authentication") {
      continue;
    }
    bool every_signer_has_one_component = true;
    for (const auto& signer : c.signers) {
      if (!(signer.ed_valid || signer.pq_valid)) {
        every_signer_has_one_component = false;
        break;
      }
    }
    if (every_signer_has_one_component) {
      ++discriminating;
    }
  }
  ASSERT_TRUE(discriminating > 0);
}

// The weight arithmetic the model uses is the production arithmetic. This
// pins the two facts the corpus depends on rather than trusting a comment.
TEST(ValidatorAuthPolicy, ArithmeticComesFromTheProductionQuorumHelpers) {
  // Two of three equal-weight validators reach the >= 2/3 threshold.
  ASSERT_TRUE(tos::has_quorum(2, 3));
  ASSERT_TRUE(!tos::has_quorum(1, 3));
  // A zero-weight validator is inadmissible, and the cap is the value the
  // corpus overflow case is built on.
  tos::ValidatorWeight acc = 0;
  ASSERT_TRUE(!tos::checked_add_validator_weight(acc, 0));
  acc = 0;
  ASSERT_TRUE(tos::checked_add_validator_weight(acc, tos::kMaxTotalValidatorWeight));
  ASSERT_TRUE(!tos::checked_add_validator_weight(acc, 1));
}

int main(int argc, char** argv) {
  if (argc < 2) {
    LOG(FATAL) << "usage: " << argv[0] << " <policy-cases.json>";
  }
  corpus_path = argv[1];
  td::TestsRunner::get_default().run_all();
  return 0;
}
