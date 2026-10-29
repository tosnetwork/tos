add_library(tos-service-common STATIC service-common.cpp service-common.h)
target_include_directories(tos-service-common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(tos-service-common PUBLIC validator-engine-json-rpc lite-client-common toshttp)

add_executable(tos-rpc rpc-main.cpp)
target_link_libraries(tos-rpc PRIVATE tos-service-common)
install(TARGETS tos-rpc RUNTIME DESTINATION bin)

add_executable(tos-wallet-index index-main.cpp index-progress.cpp index-progress.h index-reader.cpp index-reader.h
  index-replay.h index-source.cpp index-source.h index-prefetch.cpp index-prefetch.h index-replay-loop.h)
target_link_libraries(tos-wallet-index PRIVATE tos-service-common validator-db validator-common)
install(TARGETS tos-wallet-index RUNTIME DESTINATION bin)

# Comparison tool for replay equivalence: prints a stopped index's logical
# content. Not installed.
add_executable(tos-wallet-index-dump index-dump.cpp)
target_link_libraries(tos-wallet-index-dump PRIVATE tddb tdutils)
