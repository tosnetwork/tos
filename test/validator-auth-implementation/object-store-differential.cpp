#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "validator/auth/object-store.h"

using namespace tos::auth;

namespace {
Hash hash(std::uint32_t value) {
  Hash out{};
  out[28] = static_cast<std::uint8_t>(value >> 24);
  out[29] = static_cast<std::uint8_t>(value >> 16);
  out[30] = static_cast<std::uint8_t>(value >> 8);
  out[31] = static_cast<std::uint8_t>(value);
  return out;
}

Anchor anchor(std::uint32_t seqno) {
  return {seqno, hash(1), hash(2), hash(3)};
}

template <class T>
T take(Result<T> result) {
  if (!result.ok())
    throw std::runtime_error(result.error().code);
  return std::move(result.value());
}

std::pair<Bytes, ObjectRef> manifest(std::uint8_t fill, std::size_t length) {
  Bytes raw(length, fill);
  auto carrier = take(object_value(5, raw));
  if (carrier.reference_.size() != 1)
    throw std::runtime_error("script");
  return {std::move(raw), carrier.reference_[0]};
}

std::pair<ObjectRef, Bytes> large_manifest(std::uint8_t fill, std::uint32_t length) {
  auto count = (static_cast<std::size_t>(length) + chunk_bytes - 1) / chunk_bytes;
  if (count == 0 || count > 64)
    throw std::runtime_error("script");
  auto object_id = hash(100000u + fill);
  Bytes chunk(std::min<std::size_t>(length, chunk_bytes), fill);
  Bytes preimage(object_id.begin(), object_id.end());
  preimage.push_back(0);
  preimage.insert(preimage.end(), chunk.begin(), chunk.end());
  auto first = take(digest("object-chunk", preimage));
  ObjectRef reference{5, length, object_id, std::vector<Hash>(count, hash(999))};
  reference.chunk_hashes_[0] = first;
  return {std::move(reference), std::move(chunk)};
}

template <class T, class Detail>
void emit(std::ostream& out, const std::string& operation, Result<T> result,
          std::size_t reserved, Detail detail) {
  if (result.ok())
    out << "OK " << operation << ' ' << detail(std::move(result.value())) << ' ' << reserved << '\n';
  else
    out << "ERR " << operation << ' ' << result.error().code << ' ' << reserved << '\n';
}

template <class T>
T number(std::istringstream& line) {
  unsigned long long raw = 0;
  if (!(line >> raw) || raw > static_cast<unsigned long long>(std::numeric_limits<T>::max()))
    throw std::runtime_error("script");
  return static_cast<T>(raw);
}
}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc != 3)
      throw std::runtime_error("arguments");

    std::ifstream input(argv[1]);
    std::ofstream output(argv[2]);
    if (!input.good() || !output.good())
      throw std::runtime_error("file");

    std::optional<ScopedObjectStore> store;
    std::string raw_line;
    while (std::getline(input, raw_line)) {
      if (raw_line.empty() || raw_line[0] == '#')
        continue;
      std::istringstream line(raw_line);
      std::string operation;
      if (!(line >> operation))
        continue;

      if (operation == "config") {
        auto global = number<std::size_t>(line);
        auto ttl = number<std::uint64_t>(line);
        std::string extra;
        if (line >> extra)
          throw std::runtime_error("script");
        store.emplace(global, ttl);
        output << "OK config - 0\n";
        continue;
      }

      if (!store)
        throw std::runtime_error("script");

      if (operation == "publish" || operation == "publish_bad") {
        auto principal = hash(number<std::uint32_t>(line));
        auto seqno = number<std::uint32_t>(line);
        auto fill = number<std::uint8_t>(line);
        auto length = number<std::size_t>(line);
        auto now = number<std::uint64_t>(line);
        std::string extra;
        if (line >> extra)
          throw std::runtime_error("script");
        auto [raw, reference] = manifest(fill, length);
        if (operation == "publish_bad") {
          if (raw.empty())
            throw std::runtime_error("script");
          raw[0] ^= 1;
        }
        auto result = store->publish(principal, anchor(seqno), reference, raw, now);
        emit(output, operation, std::move(result), store->reserved(),
             [](bool) { return std::string("-"); });
        continue;
      }

      if (operation == "put_large") {
        auto principal = hash(number<std::uint32_t>(line));
        auto seqno = number<std::uint32_t>(line);
        auto length = number<std::uint32_t>(line);
        auto fill = number<std::uint8_t>(line);
        auto now = number<std::uint64_t>(line);
        std::string extra;
        if (line >> extra)
          throw std::runtime_error("script");
        auto [reference, chunk] = large_manifest(fill, length);
        auto result = store->put(principal, anchor(seqno), reference, 0, chunk, now);
        emit(output, operation, std::move(result), store->reserved(),
             [](const Hash&) { return std::string("-"); });
        continue;
      }

      if (operation == "get") {
        auto principal = hash(number<std::uint32_t>(line));
        auto seqno = number<std::uint32_t>(line);
        auto fill = number<std::uint8_t>(line);
        auto length = number<std::size_t>(line);
        auto index = number<std::uint8_t>(line);
        auto now = number<std::uint64_t>(line);
        std::string extra;
        if (line >> extra)
          throw std::runtime_error("script");
        auto [ignored, reference] = manifest(fill, length);
        auto result = store->get(principal, anchor(seqno), reference, index, now);
        emit(output, operation, std::move(result), store->reserved(),
             [](const Bytes& bytes) { return std::to_string(bytes.size()); });
        continue;
      }

      if (operation == "reserved") {
        std::string extra;
        if (line >> extra)
          throw std::runtime_error("script");
        output << "STATE reserved " << store->reserved() << '\n';
        continue;
      }

      throw std::runtime_error("script");
    }

    return output.good() ? 0 : 2;
  } catch (const std::exception& error) {
    std::cerr << "DRIVER_FAILURE " << error.what() << '\n';
    return 2;
  }
}
