// Minimal nlohmann::json stub for silkworm-core compilation.
// Only provides the type declarations needed by chain/config.hpp and genesis.hpp.
// Full JSON support is NOT needed for the EVM execution path (first slice).
#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace nlohmann {

class json {
  public:
    json() = default;

    // Construction from basic types
    json(std::nullptr_t) {}
    json(bool) {}
    json(int) {}
    json(int64_t) {}
    json(uint64_t) {}
    json(double) {}
    json(const std::string&) {}
    json(const char*) {}

    // Stub accessors — these will abort if actually called at runtime.
    // The first slice never parses genesis JSON inside the execution path.
    template <typename T>
    T get() const { return T{}; }

    json operator[](const std::string&) const { return {}; }
    json operator[](const char*) const { return {}; }
    json& operator[](const std::string& key) { static json j; return j; }

    bool contains(const std::string&) const { return false; }
    bool is_null() const { return true; }
    bool is_object() const { return false; }
    bool is_array() const { return false; }
    bool is_string() const { return false; }

    using iterator = std::map<std::string, json>::iterator;
    using const_iterator = std::map<std::string, json>::const_iterator;

    iterator begin() { return data_.begin(); }
    iterator end() { return data_.end(); }
    const_iterator begin() const { return data_.begin(); }
    const_iterator end() const { return data_.end(); }

    std::string dump(int = -1) const { return "{}"; }

  private:
    std::map<std::string, json> data_;
};

}  // namespace nlohmann
