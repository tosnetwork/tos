# Aggregate explicit inclusion only; no default build or activation changes.
include("${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/workchain-construction-isolation.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/workchain-execution-ledger.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/crypto/test/workchain-batch-scan.cmake")
