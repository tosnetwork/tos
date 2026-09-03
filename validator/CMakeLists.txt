#add_subdirectory(dummy0)
add_subdirectory(impl)

set(VALIDATOR_DB_SOURCE
  db/archiver.cpp
  db/archiver.hpp
  db/archive-manager.cpp
  db/archive-manager.hpp
  db/archive-slice.cpp
  db/archive-slice.hpp
  db/celldb.cpp
  db/celldb.hpp
  db/permanent-celldb/permanent-celldb-utils.cpp
  db/permanent-celldb/permanent-celldb-utils.h
  db/files-async.hpp
  db/fileref.hpp
  db/fileref.cpp
  db/rootdb.cpp
  db/rootdb.hpp
  db/statedb.hpp
  db/statedb.cpp
  db/staticfilesdb.cpp
  db/staticfilesdb.hpp
  db/db-utils.cpp
  db/db-utils.h
  db/db-event-publisher.cpp
  db/db-event-publisher.hpp

  db/package.hpp
  db/package.cpp
)

set(VALIDATOR_HEADERS
  types.h
  block-handle.hpp
  get-next-key-blocks.h

  downloaders/download-state.hpp
  downloaders/wait-block-data-disk.hpp
  downloaders/wait-block-data.hpp
  downloaders/wait-block-state-merge.hpp
  downloaders/wait-block-state.hpp

  fabric.h
  interfaces/db.h
  interfaces/external-message.h
  interfaces/liteserver.h
  interfaces/out-msg-queue-proof.h
  interfaces/proof.h
  interfaces/shard.h
  interfaces/validator-full-id.h
  interfaces/validator-manager.h
  invariants.hpp

  import-db-slice.hpp
  import-db-slice-local.hpp
  queue-size-counter.hpp
  validator-telemetry.hpp
  weak-ptr-registry.hpp
  storage-stat-cache.hpp
  shard-block-verifier.hpp
  shard-block-retainer.hpp

  collation-manager.hpp
  collator-node/collator-node.hpp
  collator-node/collator-node-session.hpp
  collator-node/utils.hpp
  manager-disk.h
  manager-disk.hpp
  manager-init.h
  manager-init.hpp
  manager.h
  manager.hpp
  shard-client.hpp
  state-download-buffer.h
  validate-broadcast.hpp
  validator-group.hpp
  validator-options.hpp
  validator.h
)
set(VALIDATOR_SOURCE
  collation-manager.cpp
  collator-node/collator-node.cpp
  collator-node/collator-node-session.cpp
  collator-node/utils.cpp
  downloaders/wait-block-data.cpp
  get-next-key-blocks.cpp
  import-db-slice.cpp
  import-db-slice-local.cpp
  state-serializer.cpp
  token-manager.cpp
  validate-broadcast.cpp
  validator-telemetry.cpp
  storage-stat-cache.cpp
  shard-block-verifier.cpp
  shard-block-retainer.cpp
  impl/applied-ext-message-cleanup.cpp

  manager.cpp

  consensus/simplex/bus.cpp
  consensus/simplex/candidate-resolver.cpp
  consensus/simplex/certificate.cpp
  consensus/simplex/collator-schedule.cpp
  consensus/simplex/consensus.cpp
  consensus/simplex/db.cpp
  consensus/simplex/metric-collector.cpp
  consensus/simplex/pool.cpp
  consensus/simplex/state-resolver.cpp
  consensus/simplex/stats.cpp
  consensus/simplex/votes.cpp
  consensus/block-accepter.cpp
  consensus/candidate-codec.cpp
  consensus/candidate-codec.h
  consensus/block-producer.cpp
  consensus/block-sync-overlay.cpp
  consensus/block-validator.cpp
  consensus/bridge.cpp
  consensus/bus.cpp
  consensus/chain-state.cpp
  consensus/misbehavior-reporter.cpp
  consensus/payload.cpp
  consensus/private-overlay.cpp
  consensus/session-compat.cpp
  consensus/session-compat.h
  consensus/trace-collector.cpp
  consensus/stats.cpp
  consensus/types.cpp
  consensus/utils.cpp

  ${VALIDATOR_HEADERS}
)

set(DISK_VALIDATOR_SOURCE
  downloaders/wait-block-data-disk.cpp
  manager-disk.cpp
)

set(HARDFORK_VALIDATOR_SOURCE
  downloaders/wait-block-data-disk.cpp
  manager-hardfork.cpp
)

set(FULL_NODE_SOURCE
  full-node.h
  full-node.hpp
  full-node.cpp
  full-node-shard.h
  full-node-shard.hpp
  full-node-shard.cpp
  full-node-master.h
  full-node-master.hpp
  full-node-master.cpp
  full-node-custom-overlays.hpp
  full-node-custom-overlays.cpp
  full-node-serializer.hpp
  full-node-serializer.cpp
  full-node-fast-sync-overlays.hpp
  full-node-fast-sync-overlays.cpp

  net/download-block-new.hpp
  net/download-block-new.cpp
  net/download-next-blocks.hpp
  net/download-next-blocks.cpp
  net/download-archive-slice.hpp
  net/download-archive-slice.cpp
  net/download-state.hpp
  net/download-state.cpp
  net/download-proof.hpp
  net/download-proof.cpp
  net/get-next-key-blocks.hpp
  net/get-next-key-blocks.cpp
)

# Persistent-state download/processing budget primitives. Lives in its own
# static library so the budget destructor / reservation API live in exactly
# ONE translation unit; both validator-common (where downloaders/ link) and
# full-node (where the actor implementation links) PUBLIC link this so they
# pick up the same set of symbols regardless of link order.
add_library(validator-state-download-budget STATIC
  state-download-buffer.cpp
  state-download-buffer.h
)
target_include_directories(validator-state-download-budget PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/..
)
target_link_libraries(validator-state-download-budget PUBLIC tdutils tos_crypto)

add_library(validator-db OBJECT ${VALIDATOR_DB_SOURCE})
target_include_directories(validator-db PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(validator-db PUBLIC tdactor adnl tl_api dht tdfec overlay tos_db
                      validator-state-download-budget)

add_library(validator-common OBJECT
  downloaders/download-state.cpp
  downloaders/wait-block-state-merge.cpp
  downloaders/wait-block-state.cpp
  apply-block.cpp
  wc0-block-hook.cpp
  block-handle.cpp
  manager-init.cpp
  queue-size-counter.cpp
  shard-client.cpp
  validator-full-id.cpp
  validator-options.cpp
)
target_link_libraries(validator-common PUBLIC validator-db validator-state-download-budget)

add_library(validator STATIC ${VALIDATOR_SOURCE})
add_library(validator-disk STATIC ${DISK_VALIDATOR_SOURCE})
add_library(validator-hardfork STATIC ${HARDFORK_VALIDATOR_SOURCE})
add_library(full-node STATIC ${FULL_NODE_SOURCE})

if (MSVC)
  # Work around MSVC ICE in consensus/simplex/consensus.cpp by disabling optimizer passes for this TU.
  # Newer MSVC (17.11 / 19.41+) ICEs with the old workaround, so only apply it to older toolsets.
  if (MSVC_VERSION LESS 1941)
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("/d2ssaoptimizer-" TOS_MSVC_HAS_D2SSAOPT)
    set(TOS_MSVC_CONSENSUS_OPTS "/Od" "/GL-")
    if (TOS_MSVC_HAS_D2SSAOPT)
      list(APPEND TOS_MSVC_CONSENSUS_OPTS "/d2ssaoptimizer-")
    endif()
    set_source_files_properties(consensus/simplex/consensus.cpp PROPERTIES
      COMPILE_OPTIONS "${TOS_MSVC_CONSENSUS_OPTS}")
  endif()
endif()

target_include_directories(validator PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/..
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/../crypto
  ${OPENSSL_INCLUDE_DIR}
)

target_include_directories(validator-disk PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/..
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/../crypto
  ${OPENSSL_INCLUDE_DIR}
  )

target_include_directories(validator-hardfork PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/..
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/../crypto
  ${OPENSSL_INCLUDE_DIR}
  )

target_include_directories(full-node PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/..
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/../crypto
  ${OPENSSL_INCLUDE_DIR}
  )

target_link_libraries(validator PRIVATE validator-common validator-db tos_validator)

target_link_libraries(validator-disk PRIVATE validator-common validator-db)

target_link_libraries(validator-hardfork PRIVATE validator-common validator-db)

target_link_libraries(full-node PUBLIC validator-state-download-budget)
target_link_libraries(full-node PRIVATE tdactor adnl rldp2 tl_api dht tdfec overlay tos_db)
