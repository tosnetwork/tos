#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace tos::health {
// Catalog 7/type 1 is a synthetic interoperability fixture, not a trace producer.
struct DiagnosticWireRecord {
  std::uint16_t type{1};
  std::uint32_t catalog{7};
  std::array<std::uint8_t, 16> epoch{};
  std::uint64_t sequence{0}, monotonic_ns{0};
  std::optional<std::uint64_t> wall_ns;
  std::array<std::uint8_t, 2> payload{};
};
inline void wire_put(std::uint8_t *out, std::uint64_t value, std::size_t size) {
  for (std::size_t i = 0; i < size; ++i) { out[i] = static_cast<std::uint8_t>(value >> (i * 8)); }
}
inline std::uint64_t wire_get(const std::uint8_t *in, std::size_t size) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < size; ++i) { value |= std::uint64_t(in[i]) << (i * 8); }
  return value;
}
inline std::optional<std::array<std::uint8_t, 66>> encode_diagnostic(const DiagnosticWireRecord &r) {
  if (r.type != 1 || r.catalog != 7) { return std::nullopt; }
  std::array<std::uint8_t, 66> out{};
  out[0]='T'; out[1]='H'; out[2]='D'; out[3]='1';
  wire_put(out.data()+4,1,2); wire_put(out.data()+6,64,2); wire_put(out.data()+8,66,2);
  wire_put(out.data()+10,r.type,2); wire_put(out.data()+12,r.catalog,4);
  for (std::size_t i=0;i<16;++i) {out[16+i]=r.epoch[i];}
  wire_put(out.data()+32,r.sequence,8); wire_put(out.data()+40,r.monotonic_ns,8);
  wire_put(out.data()+48,r.wall_ns.value_or(0),8); wire_put(out.data()+56,2,2);
  wire_put(out.data()+58,r.wall_ns.has_value()?1:0,2);
  out[64]=r.payload[0]; out[65]=r.payload[1]; return out;
}
inline std::optional<DiagnosticWireRecord> decode_diagnostic(const std::uint8_t *in, std::size_t size) {
  if (size!=66 || in[0]!='T' || in[1]!='H' || in[2]!='D' || in[3]!='1') {return std::nullopt;}
  const auto flags=wire_get(in+58,2);
  if (wire_get(in+4,2)!=1 || wire_get(in+6,2)!=64 || wire_get(in+8,2)!=size
      || wire_get(in+10,2)!=1 || wire_get(in+12,4)!=7 || wire_get(in+56,2)!=2
      || flags>1 || wire_get(in+60,4)!=0 || (flags==0 && wire_get(in+48,8)!=0)) {return std::nullopt;}
  DiagnosticWireRecord r;
  for (std::size_t i=0;i<16;++i) {r.epoch[i]=in[16+i];}
  r.sequence=wire_get(in+32,8); r.monotonic_ns=wire_get(in+40,8);
  if (flags==1) {r.wall_ns=wire_get(in+48,8);}
  r.payload={in[64],in[65]}; return r;
}
}  // namespace tos::health
