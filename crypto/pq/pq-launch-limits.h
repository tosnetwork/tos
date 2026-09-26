#pragma once

#include <cstddef>

namespace tos::pq::launch_limits {

inline constexpr std::size_t max_total_validators = 21;
inline constexpr std::size_t max_masterchain_committee = 21;
inline constexpr std::size_t max_shard_committee = 21;

}  // namespace tos::pq::launch_limits
