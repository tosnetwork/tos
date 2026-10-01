set(OVERLAY_SOURCE
  broadcast-fec.cpp
  broadcast-plumtree-stats.cpp
  broadcast-plumtree.cpp
  broadcast-simple.cpp
  broadcast-twostep.cpp
  overlay-manager.cpp
  overlay.cpp
  overlay-peers.cpp

  broadcast-fec.hpp
  broadcast-plumtree-stats.hpp
  broadcast-plumtree.hpp
  broadcast-simple.hpp
  broadcast-twostep.hpp
  overlay-manager.h
  overlay.h
  overlay.hpp
  overlays.h
)

add_library(overlay STATIC ${OVERLAY_SOURCE})

target_include_directories(overlay PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/..
  ${OPENSSL_INCLUDE_DIR}
)
# `metrics`, not only `metrics-core`: the overlay's budgeted traffic collection calls
# `collect_traffic_with_budget`, which is defined with the collectors.
target_link_libraries(overlay PRIVATE tdutils tdactor adnl tl_api dht fec metrics)

