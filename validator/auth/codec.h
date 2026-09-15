#pragma once
#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

namespace tos::auth {
using Bytes = std::vector<std::uint8_t>;
using Hash = std::array<std::uint8_t, 32>;
inline constexpr std::size_t max_object_bytes = 33554432;
struct Error {
  std::string code;
};
template <class T>
class Result {
  std::variant<T, Error> data_;

 public:
  Result(T value) : data_(std::move(value)) {
  }
  Result(Error error) : data_(std::move(error)) {
  }
  bool ok() const {
    return std::holds_alternative<T>(data_);
  }
  const T& value() const {
    return std::get<T>(data_);
  }
  T& value() {
    return std::get<T>(data_);
  }
  const Error& error() const {
    return std::get<Error>(data_);
  }
};
struct ParseBudget {
  std::size_t bytes = max_object_bytes;
  std::size_t allocated = 2 * max_object_bytes;
};
class Reader;
void read(Reader&, Hash&);
class Reader {
  std::span<const std::uint8_t> input_;
  std::size_t offset_ = 0, allocation_;

 public:
  std::string error;
  explicit Reader(std::span<const std::uint8_t> input, ParseBudget budget = {})
      : input_(input), allocation_(budget.allocated) {
    if (input.size() > budget.bytes || budget.bytes > max_object_bytes || budget.allocated > 2 * max_object_bytes)
      fail("object-bound");
  }
  void fail(const char* code) {
    if (error.empty())
      error = code;
  }
  bool ok() const {
    return error.empty();
  }
  std::size_t remaining() const {
    return input_.size() - offset_;
  }
  std::span<const std::uint8_t> take(std::size_t size) {
    if (!ok())
      return {};
    if (size > remaining()) {
      fail("truncated");
      return {};
    }
    auto out = input_.subspan(offset_, size);
    offset_ += size;
    return out;
  }
  bool allocate(std::size_t size) {
    if (!ok())
      return false;
    if (size > allocation_) {
      fail("allocation-bound");
      return false;
    }
    allocation_ -= size;
    return true;
  }
  template <class T>
  void integer(T& value) {
    auto b = take(sizeof(T));
    if (!ok())
      return;
    using U = std::make_unsigned_t<T>;
    U bits = 0;
    for (auto x : b)
      bits = static_cast<U>((bits << 8) | x);
    value = std::bit_cast<T>(bits);
  }
  std::uint64_t length(unsigned width) {
    auto b = take(width);
    std::uint64_t n = 0;
    for (auto x : b)
      n = (n << 8) | x;
    return n;
  }
  void header(const char* tag) {
    auto b = take(8);
    if (!ok())
      return;
    for (unsigned i = 0; i < 4; ++i)
      if (b[i] != static_cast<std::uint8_t>(tag[i]))
        fail("tag");
    if (b[4] != 0 || b[5] != 1)
      fail("version");
    if (b[6] != 0 || b[7] != 0)
      fail("flags");
  }
  void hash(Hash& value) {
    auto b = take(32);
    if (ok())
      std::copy(b.begin(), b.end(), value.begin());
  }
  void blob(Bytes& value, std::size_t limit) {
    auto n = length(4);
    if (!ok())
      return;
    if (n > limit) {
      fail("blob-bound");
      return;
    }
    auto b = take(n);
    if (!ok() || !allocate(n))
      return;
    value.assign(b.begin(), b.end());
  }
  template <class T>
  void list(std::vector<T>& value, unsigned width, std::size_t limit, std::size_t minimum) {
    auto n = length(width);
    if (!ok())
      return;
    if (n > limit) {
      fail("list-bound");
      return;
    }
    if (minimum && n > remaining() / minimum) {
      fail("truncated");
      return;
    }
    if (n > allocation_ / sizeof(T) || !allocate(n * sizeof(T))) {
      fail("allocation-bound");
      return;
    }
    value.resize(n);
    for (auto& item : value) {
      read(*this, item);
      if (!ok())
        return;
    }
  }
};
inline void read(Reader& r, Hash& v) {
  r.hash(v);
}
class Writer;
void write(Writer&, const Hash&);
class Writer {
 public:
  Bytes data;
  std::string error;
  bool ok() const {
    return error.empty();
  }
  void fail(const char* code) {
    if (ok())
      error = code;
  }
  void bytes(std::span<const std::uint8_t> value) {
    if (!ok())
      return;
    if (value.size() > max_object_bytes - data.size()) {
      fail("object-bound");
      return;
    }
    data.insert(data.end(), value.begin(), value.end());
  }
  void length(std::uint64_t value, unsigned width) {
    std::array<std::uint8_t, 8> b{};
    for (unsigned i = 0; i < width; ++i)
      b[width - i - 1] = static_cast<std::uint8_t>(value >> (8 * i));
    bytes(std::span(b).first(width));
  }
  template <class T>
  void integer(T value) {
    length(static_cast<std::make_unsigned_t<T>>(value), sizeof(T));
  }
  void header(const char* tag) {
    std::array<std::uint8_t, 8> b{0, 0, 0, 0, 0, 1, 0, 0};
    for (unsigned i = 0; i < 4; ++i)
      b[i] = static_cast<std::uint8_t>(tag[i]);
    bytes(b);
  }
  void blob(const Bytes& value, std::size_t limit) {
    if (value.size() > limit) {
      fail("blob-bound");
      return;
    }
    length(value.size(), 4);
    bytes(value);
  }
  template <class T>
  void list(const std::vector<T>& value, unsigned width, std::size_t limit) {
    if (value.size() > limit) {
      fail("list-bound");
      return;
    }
    length(value.size(), width);
    for (const auto& item : value) {
      write(*this, item);
      if (!ok())
        return;
    }
  }
};
inline void write(Writer& w, const Hash& v) {
  w.bytes(v);
}
template <class T>
Result<T> decode(std::span<const std::uint8_t> bytes, ParseBudget budget = {}) {
  Reader r(bytes, budget);
  T value{};
  read(r, value);
  if (r.ok() && r.remaining())
    r.fail("trailing");
  if (!r.ok())
    return Error{r.error};
  return value;
}
template <class T>
Result<Bytes> encode(const T& value) {
  Writer w;
  write(w, value);
  if (!w.ok())
    return Error{w.error};
  return std::move(w.data);
}
}  // namespace tos::auth
