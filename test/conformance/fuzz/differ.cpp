// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
#include <dlfcn.h>
#include <filesystem>
#include <fstream>
#include <system_error>

#include "differ.h"

namespace conformance::fuzz {
namespace {

bool is_refusal(const Json &effects) {
  return effects.is(Json::Type::Object) && effects.fields().size() == 1 && effects.has("harness_error");
}

Json parse_or_raw(const std::string &text) {
  auto parsed = parse_json(text);
  if (parsed.value) {
    return std::move(*parsed.value);
  }
  return Json::string(text);
}

}  // namespace

Library::~Library() {
  if (handle_ != nullptr) {
    dlclose(handle_);
  }
}

std::string Library::open(const std::string &path) {
  path_ = path;
  int flags = RTLD_NOW | RTLD_LOCAL;
#if defined(RTLD_DEEPBIND) && !defined(CONFORMANCE_FUZZ_NO_DEEPBIND)
  flags |= RTLD_DEEPBIND;
#endif
  handle_ = dlopen(path.c_str(), flags);
  if (handle_ == nullptr) {
    const char *why = dlerror();
    return "cannot load " + path + ": " + (why != nullptr ? why : "unknown error");
  }
  run_ = reinterpret_cast<RunFn>(dlsym(handle_, "conformance_run_v1"));
  has_ = reinterpret_cast<HasFn>(dlsym(handle_, "conformance_has_harness"));
  info_ = reinterpret_cast<InfoFn>(dlsym(handle_, "conformance_reference_info"));
  free_ = reinterpret_cast<FreeFn>(dlsym(handle_, "conformance_free"));
  if (run_ == nullptr || free_ == nullptr) {
    return path + ": conformance_run_v1 and conformance_free are required";
  }
  return {};
}

std::string Library::take(const char *text) const {
  if (text == nullptr) {
    return {};
  }
  std::string out{text};
  free_(text);
  return out;
}

bool Library::has_harness(const std::string &harness) const {
  // A library without the query is assumed to provide every harness; run reports otherwise.
  return has_ == nullptr || has_(harness.c_str()) != 0;
}

std::string Library::info() const {
  return info_ == nullptr ? std::string("{}") : take(info_());
}

std::string Library::run(const std::string &harness, const std::string &context) const {
  const char *out = run_(harness.c_str(), context.c_str());
  if (out == nullptr) {
    return "{\"harness_error\":\"no response\"}";
  }
  return take(out);
}

Comparison compare_effects(const std::string &reference, const std::string &target) {
  Comparison result;
  result.reference = parse_or_raw(reference);
  result.target = parse_or_raw(target);
  const bool ref_refused = is_refusal(result.reference);
  const bool target_refused = is_refusal(result.target);
  if (ref_refused && target_refused) {
    result.verdict = Verdict::BothRefused;
  } else if (ref_refused || target_refused) {
    result.verdict = Verdict::Mismatch;
  } else {
    result.verdict = result.reference == result.target ? Verdict::Equal : Verdict::Mismatch;
  }
  return result;
}

std::string mismatch_text(const MismatchRecord &record) {
  Json doc = Json::object();
  doc.set("format", Json::string("fuzz-mismatch-v1"));
  doc.set("harness", Json::string(record.harness));
  doc.set("lineage", Json::string(record.lineage));
  doc.set("seed", Json::integer(static_cast<std::int64_t>(record.seed)));
  doc.set("index", Json::integer(static_cast<std::int64_t>(record.index)));
  doc.set("reference", Json::string(record.reference_name));
  doc.set("target", Json::string(record.target_name));
  doc.set("context", record.context != nullptr ? *record.context : Json::null());
  Json effects = Json::object();
  if (record.comparison != nullptr) {
    effects.set("reference", record.comparison->reference);
    effects.set("target", record.comparison->target);
  }
  doc.set("effects", std::move(effects));
  return doc.dump() + "\n";
}

std::string write_mismatch(const std::string &root, const MismatchRecord &record, std::string &error) {
  const auto dir = std::filesystem::path(root) / record.harness / "inputs" / "fuzz-mismatches" / record.lineage;
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    error = "cannot create " + dir.string() + ": " + ec.message();
    return {};
  }
  const auto path = dir / (context_digest(record.canonical_context) + ".json");
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out << mismatch_text(record);
  if (!out) {
    error = "cannot write " + path.string();
    return {};
  }
  return path.string();
}

void Tally::count_outcome(const Json &effects) {
  std::string key = "other";
  if (is_refusal(effects)) {
    key = "refused";
  } else if (const Json *code = effects.find("exit_code"); code != nullptr && code->is(Json::Type::Int)) {
    key = "exit_code=" + std::to_string(code->as_int());
  } else if (const Json *outcome = effects.find("outcome"); outcome != nullptr && outcome->is(Json::Type::String)) {
    key = outcome->as_string();
  }
  ++reference_outcomes[key];
}

std::string Tally::summary_json(const std::string &harness, std::uint64_t seed) const {
  Json doc = Json::object();
  doc.set("harness", Json::string(harness));
  doc.set("seed", Json::integer(static_cast<std::int64_t>(seed)));
  doc.set("cases", Json::integer(static_cast<std::int64_t>(cases)));
  doc.set("equal", Json::integer(static_cast<std::int64_t>(equal)));
  doc.set("both_refused", Json::integer(static_cast<std::int64_t>(both_refused)));
  doc.set("mismatched", Json::integer(static_cast<std::int64_t>(mismatched)));
  doc.set("generator_errors", Json::integer(static_cast<std::int64_t>(generator_errors)));
  doc.set("files_written", Json::integer(static_cast<std::int64_t>(files_written)));
  Json by_lineage = Json::object();
  for (const auto &[lineage, count] : cases_by_lineage) {
    Json entry = Json::object();
    entry.set("cases", Json::integer(static_cast<std::int64_t>(count)));
    auto it = mismatches_by_lineage.find(lineage);
    entry.set("mismatched",
              Json::integer(static_cast<std::int64_t>(it == mismatches_by_lineage.end() ? 0 : it->second)));
    by_lineage.set(lineage, std::move(entry));
  }
  doc.set("lineages", std::move(by_lineage));
  Json outcomes = Json::object();
  for (const auto &[key, count] : reference_outcomes) {
    outcomes.set(key, Json::integer(static_cast<std::int64_t>(count)));
  }
  doc.set("reference_outcomes", std::move(outcomes));
  // Milliseconds and cases per second as integers keep the summary free of float formatting.
  doc.set("milliseconds", Json::integer(static_cast<std::int64_t>(seconds * 1000)));
  doc.set("cases_per_second",
          Json::integer(seconds > 0 ? static_cast<std::int64_t>(static_cast<double>(cases) / seconds) : 0));
  return doc.dump();
}

}  // namespace conformance::fuzz
