set(TOS_CRYPTO_CORE_SOURCE
  Ed25519.cpp
  common/bigint.cpp
  common/refcnt.cpp
  common/refint.cpp
  common/bigexp.cpp
  common/bitstring.cpp
  common/util.cpp
  openssl/bignum.cpp
  openssl/residue.cpp
  openssl/rand.cpp
  vm/boc.cpp
  vm/large-boc-serializer.cpp
  tl/tlblib.cpp

  Ed25519.h
  common/AtomicRef.h
  common/bigint.hpp
  common/bitstring.h
  common/refcnt.hpp
  common/refint.h
  common/bigexp.h
  common/util.h
  common/linalloc.hpp
  common/promiseop.hpp

  openssl/bignum.h
  openssl/digest.hpp
  openssl/rand.hpp
  openssl/residue.h

  tl/tlbc-aux.h
  tl/tlbc-data.h
  tl/tlblib.hpp

  keccak/keccak.h
  keccak/keccak.cpp

  vm/dict.cpp
  vm/cells/Cell.cpp
  vm/cells/CellBuilder.cpp
  vm/cells/CellHash.cpp
  vm/cells/CellSlice.cpp
  vm/cells/CellString.cpp
  vm/cells/CellTraits.cpp
  vm/cells/CellUsageTree.cpp
  vm/cells/DataCell.cpp
  vm/cells/LevelMask.cpp
  vm/cells/MerkleProof.cpp
  vm/cells/MerkleUpdate.cpp

  vm/dict.h
  vm/cells/Cell.h
  vm/cells/CellBuilder.h
  vm/cells/CellHash.h
  vm/cells/CellSlice.h
  vm/cells/CellString.h
  vm/cells/CellTraits.h
  vm/cells/CellUsageTree.h
  vm/cells/DataCell.h
  vm/cells/ExtCell.h
  vm/cells/LevelMask.h
  vm/cells/MerkleProof.h
  vm/cells/MerkleUpdate.h
  vm/cells/PrunnedCell.h
  vm/cells/UsageCell.h
  vm/cells/VirtualCell.h

  vm/cells.h
  vm/cellslice.h

  vm/db/StaticBagOfCellsDb.h
  vm/db/StaticBagOfCellsDb.cpp

  vm/Hasher.h
  vm/Hasher.cpp

  ellcurve/secp256k1.h
  ellcurve/secp256k1.cpp
  ellcurve/p256.h
  ellcurve/p256.cpp)

set(TOS_CRYPTO_SOURCE
  vm/boc-compression.cpp
  vm/stack.cpp
  vm/atom.cpp
  vm/continuation.cpp
  vm/memo.cpp
  vm/dispatch.cpp
  vm/opctable.cpp
  vm/cp0.cpp
  vm/stackops.cpp
  vm/tupleops.cpp
  vm/arithops.cpp
  vm/cellops.cpp
  vm/contops.cpp
  vm/dictops.cpp
  vm/debugops.cpp
  vm/tosops.cpp
  vm/utils.cpp
  vm/vm.cpp
  vm/bls.cpp

  vm/arithops.h
  vm/atom.h
  vm/boc.h
  vm/boc-compression.h
  vm/boc-writers.h
  vm/box.hpp
  vm/cellops.h
  vm/continuation.h
  vm/contops.h
  vm/cp0.h
  vm/debugops.h
  vm/dictops.h
  vm/excno.hpp
  vm/fmt.hpp
  vm/log.h
  vm/memo.h
  vm/opctable.h
  vm/stack.hpp
  vm/stackops.h
  vm/tupleops.h
  vm/tosops.h
  vm/vmstate.h
  vm/utils.h
  vm/vm.h
  vm/bls.h)

set(TOS_DB_SOURCE
  vm/db/CellDbExtCell.cpp
  vm/db/DynamicBagOfCellsDb.cpp
  vm/db/DynamicBagOfCellsDbV2.cpp
  vm/db/CellStorage.cpp
  vm/db/TosDb.cpp

  vm/db/CellDbExtCell.h
  vm/db/DynamicBagOfCellsDb.h
  vm/db/CellHashTable.h
  vm/db/CellStorage.h
  vm/db/TosDb.h
  vm/db/InMemoryBagOfCellsDb.cpp
)

set(FIFT_SOURCE
  fift/Dictionary.cpp
  fift/Fift.cpp
  fift/IntCtx.cpp
  fift/HashMap.cpp
  fift/Continuation.cpp
  fift/SourceLookup.cpp
  fift/utils.cpp
  fift/words.cpp

  fift/Dictionary.h
  fift/Fift.h
  fift/IntCtx.h
  fift/HashMap.h
  fift/Continuation.h
  fift/SourceLookup.h
  fift/utils.h
  fift/words.h
)

set(PARSER_SOURCE
  parser/srcread.cpp
  parser/lexer.cpp
  parser/symtable.cpp

  parser/srcread.h
  parser/lexer.h
  parser/symtable.h
)

set(FUNC_LIB_SOURCE
  func/keywords.cpp
  func/unify-types.cpp
  func/parse-func.cpp
  func/abscode.cpp
  func/gen-abscode.cpp
  func/analyzer.cpp
  func/asmops.cpp
  func/builtins.cpp
  func/stack-transform.cpp
  func/optimize.cpp
  func/codegen.cpp
  func/func.cpp
)

set(TLB_BLOCK_AUTO
  ${CMAKE_CURRENT_SOURCE_DIR}/block/block-auto.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/block/block-auto.h
)

set(BLOCK_SOURCE
  block/Binlog.h
  block/Binlog.cpp
  block/aipow.h
  block/aipow.cpp
  block/block.cpp
  block/block-db.cpp
  block/block-parse.cpp
  block/check-proof.cpp
  block/mc-config.cpp
  block/output-queue-merger.cpp
  block/transaction.cpp
  block/account-storage-stat.h
  block/account-storage-stat.cpp
  block/precompiled-smc/PrecompiledSmartContract.cpp
  block/workchain-execution-dispatch.cpp
  block/workchain-execution-dispatch.h
  ${TLB_BLOCK_AUTO}

  block/block-binlog.h
  block/block-db-impl.h
  block/block-db.h
  block/block.h
  block/block-parse.h
  block/check-proof.h
  block/output-queue-merger.h
  block/transaction.h
  block/precompiled-smc/PrecompiledSmartContract.h
  block/precompiled-smc/common.h

  block/validator-set.h
  block/validator-set.cpp
  block/signature-set.h
  block/signature-set.cpp

  common/stats.cpp
)

set(SMC_ENVELOPE_SOURCE
  smc-envelope/GenericAccount.cpp
  smc-envelope/HighloadWallet.cpp
  smc-envelope/HighloadWalletV2.cpp
  smc-envelope/ManualDns.cpp
  smc-envelope/MultisigWallet.cpp
  smc-envelope/PaymentChannel.cpp
  smc-envelope/SmartContract.cpp
  smc-envelope/SmartContractCode.cpp
  smc-envelope/WalletInterface.cpp
  smc-envelope/WalletV3.cpp
  smc-envelope/WalletV4.cpp

  smc-envelope/GenericAccount.h
  smc-envelope/HighloadWallet.h
  smc-envelope/HighloadWalletV2.h
  smc-envelope/ManualDns.h
  smc-envelope/MultisigWallet.h
  smc-envelope/SmartContract.h
  smc-envelope/SmartContractCode.h
  smc-envelope/WalletInterface.h
  smc-envelope/WalletV3.h
  smc-envelope/WalletV4.h
)

set(ED25519_TEST_SOURCE
  ${CMAKE_CURRENT_SOURCE_DIR}/test/Ed25519.cpp
  PARENT_SCOPE
)

set(TOSDB_TEST_SOURCE
  ${CMAKE_CURRENT_SOURCE_DIR}/test/test-db.cpp
  PARENT_SCOPE
)

set(CELLS_TEST_SOURCE
  ${CMAKE_CURRENT_SOURCE_DIR}/test/test-cells.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/test/test-aipow.cpp
  PARENT_SCOPE
)

set(TOSVM_TEST_SOURCE
  ${CMAKE_CURRENT_SOURCE_DIR}/test/vm.cpp
  PARENT_SCOPE
)

set(SMARTCONT_TEST_SOURCE
  ${CMAKE_CURRENT_SOURCE_DIR}/test/test-smartcont.cpp
  PARENT_SCOPE
)

set(FIFT_TEST_SOURCE
  ${CMAKE_CURRENT_SOURCE_DIR}/test/fift.cpp
  PARENT_SCOPE
)

set(BIGINT_TEST_SOURCE
  ${CMAKE_CURRENT_SOURCE_DIR}/test/test-bigint.cpp
  PARENT_SCOPE
)

set(USE_EMSCRIPTEN ${USE_EMSCRIPTEN} PARENT_SCOPE)

add_library(tos_crypto_core STATIC ${TOS_CRYPTO_CORE_SOURCE})
target_include_directories(tos_crypto_core PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>)
target_link_libraries(tos_crypto_core PUBLIC ${OPENSSL_CRYPTO_LIBRARY} tdutils tddb_utils)
if (NOT WIN32)
  target_link_libraries(tos_crypto_core PUBLIC ${CMAKE_DL_LIBS} ${ZLIB_LIBRARIES})
endif()
target_include_directories(tos_crypto_core SYSTEM PUBLIC $<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIR}>)
# Ensure OpenSSL is built before tos_crypto_core
if (TARGET OpenSSL)
  add_dependencies(tos_crypto_core OpenSSL)
endif()

add_library(tos_crypto STATIC ${TOS_CRYPTO_SOURCE})
target_include_directories(tos_crypto PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>)
target_link_libraries(tos_crypto PUBLIC ${OPENSSL_CRYPTO_LIBRARY} tos_crypto_core tos_block)
# Ensure OpenSSL is built before tos_crypto
if (TARGET OpenSSL)
  add_dependencies(tos_crypto OpenSSL)
endif()
if (USE_EMSCRIPTEN)
  target_link_options(tos_crypto PRIVATE -fexceptions)
  target_compile_options(tos_crypto PRIVATE -fexceptions)
endif()
if (NOT WIN32)
  if (CMAKE_DL_LIBS)
    target_link_libraries(tos_crypto PUBLIC ${CMAKE_DL_LIBS})
  endif()
  if (ZLIB_LIBRARIES)
    target_link_libraries(tos_crypto PUBLIC ${ZLIB_LIBRARIES})
  endif()
endif()
target_include_directories(tos_crypto SYSTEM PUBLIC $<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIR}>)

add_dependencies(tos_crypto blst)
add_dependencies(tos_crypto_core secp256k1)
if (TARGET zlib)
  add_dependencies(tos_crypto zlib)
  add_dependencies(tos_crypto_core zlib)
endif()
if (TARGET sodium)
  add_dependencies(tos_crypto sodium)
  add_dependencies(tos_crypto_core sodium)
endif()

target_include_directories(tos_crypto PRIVATE ${BLST_INCLUDE_DIR})
target_link_libraries(tos_crypto PRIVATE ${BLST_LIB})

target_include_directories(tos_crypto_core PUBLIC $<BUILD_INTERFACE:${SECP256K1_INCLUDE_DIR}>)

if (MSVC)
  find_package(Sodium REQUIRED)
  target_compile_definitions(tos_crypto PUBLIC SODIUM_STATIC)
  target_link_libraries(tos_crypto_core PUBLIC ${SECP256K1_LIBRARY})
  target_link_libraries(tos_crypto PUBLIC ${SECP256K1_LIBRARY})
elseif (EMSCRIPTEN)
  target_link_libraries(tos_crypto_core PUBLIC $<BUILD_INTERFACE:${SECP256K1_LIBRARY}>)
  target_link_libraries(tos_crypto PUBLIC $<BUILD_INTERFACE:${SECP256K1_LIBRARY}>)
else()
  if (NOT SODIUM_FOUND)
    find_package(Sodium REQUIRED)
  else()
    message(STATUS "Using Sodium ${SODIUM_LIBRARY_RELEASE}")
  endif()
  target_compile_definitions(tos_crypto PUBLIC SODIUM_STATIC)
  target_link_libraries(tos_crypto_core PUBLIC ${SECP256K1_LIBRARY})
  target_link_libraries(tos_crypto PUBLIC ${SECP256K1_LIBRARY})
endif()

target_include_directories(tos_crypto_core PUBLIC $<BUILD_INTERFACE:${SODIUM_INCLUDE_DIR}>)
target_link_libraries(tos_crypto PUBLIC ${SODIUM_LIBRARY_RELEASE})

add_library(tos_db STATIC ${TOS_DB_SOURCE})
target_include_directories(tos_db PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>)
target_link_libraries(tos_db PUBLIC tdutils tddb tos_crypto)

add_library(fift-lib STATIC ${FIFT_SOURCE})
target_include_directories(fift-lib PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(fift-lib PUBLIC tos_crypto)

if (USE_EMSCRIPTEN)
  target_link_options(fift-lib PRIVATE -fexceptions)
  target_compile_options(fift-lib PRIVATE -fexceptions)
endif()
set_target_properties(fift-lib PROPERTIES OUTPUT_NAME fift)

add_executable(fift fift/fift-main.cpp)
target_link_libraries(fift PUBLIC fift-lib git)
if (WINGETOPT_FOUND)
  target_link_libraries_system(fift wingetopt)
endif()

add_library(src_parser ${PARSER_SOURCE})
target_include_directories(src_parser PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(src_parser PUBLIC tos_crypto_core)

add_library(tos_block STATIC ${BLOCK_SOURCE})
target_include_directories(tos_block PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/block> $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>)
target_link_libraries(tos_block PUBLIC tos_crypto_core tdactor tl_api)
if (MINGW)
  # Resolve circular static linking between tos_block and tos_crypto on MinGW.
  target_link_libraries(tos_block PUBLIC tos_crypto)
endif()
if (USE_EMSCRIPTEN)
  target_link_options(tos_block PRIVATE -fexceptions)
  target_compile_options(tos_block PRIVATE -fexceptions)
endif()

add_executable(func func/func-main.cpp ${FUNC_LIB_SOURCE})
target_include_directories(func PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(func PUBLIC tos_crypto src_parser git)
if (MINGW)
  # Ensure tos_crypto appears after tos_block in link order to resolve VM symbols.
  target_link_libraries(func PRIVATE tos_crypto)
endif()
if (WINGETOPT_FOUND)
  target_link_libraries_system(func wingetopt)
endif()

if (USE_EMSCRIPTEN)
  add_executable(funcfiftlib funcfiftlib/funcfiftlib.cpp ${FUNC_LIB_SOURCE})
  target_include_directories(funcfiftlib PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
  target_link_libraries(funcfiftlib PUBLIC fift-lib src_parser git)
  target_link_options(funcfiftlib PRIVATE -sEXPORTED_RUNTIME_METHODS=FS,ccall,cwrap,UTF8ToString,stringToUTF8,lengthBytesUTF8,addFunction,removeFunction,setValue)
  target_link_options(funcfiftlib PRIVATE -sEXPORTED_FUNCTIONS=_func_compile,_version,_malloc,_free,_setThrew)
  target_link_options(funcfiftlib PRIVATE -sEXPORT_NAME=CompilerModule)
  target_link_options(funcfiftlib PRIVATE -sERROR_ON_UNDEFINED_SYMBOLS=0)
  target_link_options(funcfiftlib PRIVATE -sFILESYSTEM=1 -lnodefs.js)
  target_link_options(funcfiftlib PRIVATE -Oz)
  target_link_options(funcfiftlib PRIVATE -sIGNORE_MISSING_MAIN=1)
  target_link_options(funcfiftlib PRIVATE -sAUTO_NATIVE_LIBRARIES=0)
  target_link_options(funcfiftlib PRIVATE -sMODULARIZE=1)
  target_link_options(funcfiftlib PRIVATE -sTOTAL_MEMORY=33554432)
  target_link_options(funcfiftlib PRIVATE -sALLOW_MEMORY_GROWTH=1)
  target_link_options(funcfiftlib PRIVATE -sALLOW_TABLE_GROWTH=1)
  target_link_options(funcfiftlib PRIVATE --embed-file ${CMAKE_CURRENT_SOURCE_DIR}/fift/lib@/fiftlib)
  target_link_options(funcfiftlib PRIVATE --pre-js ${CMAKE_CURRENT_SOURCE_DIR}/funcfiftlib/funcfiftlib-prejs.js)
  target_link_options(funcfiftlib PRIVATE -fexceptions)
  target_compile_options(funcfiftlib PRIVATE -fexceptions -fno-stack-protector)
endif()

add_executable(tlbc tl/tlbc.cpp)
target_include_directories(tlbc PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(tlbc PUBLIC src_parser)
if (WINGETOPT_FOUND)
  target_link_libraries_system(tlbc wingetopt)
endif()

if (WINGETOPT_FOUND)
  target_link_libraries_system(fift wingetopt)
endif()

add_executable(mintless-proof-generator util/mintless-proof-generator.cpp)
target_link_libraries(mintless-proof-generator PRIVATE tos_crypto git ${JEMALLOC_LIBRARIES})

if (JEMALLOC_FOUND)
  target_include_directories(mintless-proof-generator PRIVATE ${JEMALLOC_INCLUDE_DIR})
  target_compile_definitions(mintless-proof-generator PRIVATE -DTOS_USE_JEMALLOC=1)
endif()

set(SMARTCONT_AUTO_DIR "${CMAKE_CURRENT_BINARY_DIR}/smartcont/auto")
file(MAKE_DIRECTORY "${SMARTCONT_AUTO_DIR}")
if (NOT CMAKE_CROSSCOMPILING OR USE_EMSCRIPTEN)
  set(GENERATE_TLB_CMD tlbc)
  if (NOT USE_EMSCRIPTEN)
    add_custom_command(
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/block
      COMMAND ${GENERATE_TLB_CMD} -o block-auto -n block::gen -z block.tlb
      COMMENT "Generate block tlb source files"
      OUTPUT ${TLB_BLOCK_AUTO}
      DEPENDS tlbc block/block.tlb
    )
  else()
    add_custom_command(
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/block
      COMMENT "Generate block tlb source files"
      OUTPUT ${TLB_BLOCK_AUTO}
      DEPENDS tlbc block/block.tlb
    )
  endif()
  add_custom_target(tlb_generate_block DEPENDS ${TLB_BLOCK_AUTO})
  add_dependencies(tos_block tlb_generate_block)

  add_custom_target(gen_fif ALL)

  set(STDLIB_V6_FEES_TEST_FIF "${SMARTCONT_AUTO_DIR}/stdlib-v6-fees-test.fif")
  add_custom_command(
    COMMENT "Compile FunC stdlib TVM v6 fee primitive coverage"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND $<TARGET_FILE:func> -PS -o ${STDLIB_V6_FEES_TEST_FIF}
      smartcont/stdlib.fc smartcont/tests/stdlib-v6-fees-test.fc
    DEPENDS func smartcont/stdlib.fc smartcont/tests/stdlib-v6-fees-test.fc
    OUTPUT ${STDLIB_V6_FEES_TEST_FIF}
  )
  add_custom_target(test_func_stdlib_v6_fees DEPENDS ${STDLIB_V6_FEES_TEST_FIF})
  add_dependencies(gen_fif test_func_stdlib_v6_fees)

  function(GenFif)
    set(options )
    set(oneValueArgs DEST NAME)
    set(multiValueArgs SOURCE)
    set(FUNC_LIB_SOURCE smartcont/stdlib.fc)
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN} )
    string(REGEX REPLACE "[^0-9a-zA-Z_]" "_" ID ${ARG_DEST})
    get_filename_component(ARG_DEST_NAME "${ARG_DEST}" NAME)
    set(ARG_DEST_FIF "${SMARTCONT_AUTO_DIR}/${ARG_DEST_NAME}.fif")
    add_custom_command(
      COMMENT "Generate ${ARG_DEST_FIF}"
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      COMMAND $<TARGET_FILE:func> -PS -o ${ARG_DEST_FIF} ${FUNC_LIB_SOURCE} ${ARG_SOURCE}
      MAIN_DEPENDENCY ${ARG_SOURCE}
      DEPENDS func ${FUNC_LIB_SOURCE}
      OUTPUT ${ARG_DEST_FIF}
    )
    set(ARG_DEST_CPP "${SMARTCONT_AUTO_DIR}/${ARG_DEST_NAME}.cpp")

    if (WIN32)
      set(ARG_LIB_DIR "fift/lib@smartcont")
    else()
      set(ARG_LIB_DIR "fift/lib:smartcont")
    endif()

    add_custom_command(
      COMMENT "Generate ${ARG_DEST_CPP}"
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      COMMAND $<TARGET_FILE:fift> -I${ARG_LIB_DIR} -s asm-to-cpp.fif ${ARG_DEST_FIF} ${ARG_DEST_CPP} ${ARG_NAME}
      MAIN_DEPENDENCY ${ARG_SOURCE}
      DEPENDS fift ${ARG_DEST_FIF} smartcont/asm-to-cpp.fif fift/lib/Asm.fif
      OUTPUT ${ARG_DEST_CPP}
    )
    add_custom_target(gen_fif_${ID} DEPENDS ${ARG_DEST_FIF} ${ARG_DEST_CPP})
    add_dependencies(gen_fif gen_fif_${ID})
  endfunction()

  GenFif(DEST smartcont/auto/config-code SOURCE smartcont/config-code.fc NAME config)
  GenFif(DEST smartcont/auto/wallet-code SOURCE smartcont/wallet-code.fc NAME wallet)
  GenFif(DEST smartcont/auto/wallet3-code SOURCE smartcont/wallet3-code.fc NAME wallet3)
  GenFif(DEST smartcont/auto/wallet-v4-code SOURCE smartcont/wallet-v4-code.fc NAME wallet_v4)
  GenFif(DEST smartcont/auto/wallet-v5-code SOURCE smartcont/wallet-v5-code.fc NAME wallet_v5)
  GenFif(DEST smartcont/auto/simple-wallet-code SOURCE smartcont/simple-wallet-code.fc NAME simple-wallet)
  GenFif(DEST smartcont/auto/highload-wallet-code SOURCE smartcont/highload-wallet-code.fc NAME highload-wallet)
  GenFif(DEST smartcont/auto/highload-wallet-v2-code SOURCE smartcont/highload-wallet-v2-code.fc NAME highload-wallet-v2)
  GenFif(DEST smartcont/auto/elector-code SOURCE smartcont/elector-code.fc NAME elector-code)
  GenFif(DEST smartcont/auto/multisig-code SOURCE smartcont/multisig-code.fc NAME multisig)
  GenFif(DEST smartcont/auto/restricted-wallet-code SOURCE smartcont/restricted-wallet-code.fc NAME restricted-wallet)
  GenFif(DEST smartcont/auto/restricted-wallet2-code SOURCE smartcont/restricted-wallet2-code.fc NAME restricted-wallet2)
  GenFif(DEST smartcont/auto/restricted-wallet3-code SOURCE smartcont/restricted-wallet3-code.fc NAME restricted-wallet3)
  GenFif(DEST smartcont/auto/session-wallet-code SOURCE smartcont/session-wallet-code.fc NAME session-wallet)
  GenFif(DEST smartcont/auto/task-escrow-code SOURCE smartcont/task-escrow-code.fc NAME task-escrow)
  set(NATIVE_REGISTRY_CPP "${SMARTCONT_AUTO_DIR}/native-registry-code.cpp")
  add_custom_command(
    COMMENT "Verify and embed the frozen TOS Native Service Registry BOC"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMAND ${CMAKE_SOURCE_DIR}/scripts/embed-tos-service-native-registry-v1.sh
      ${NATIVE_REGISTRY_CPP} native-registry
    MAIN_DEPENDENCY smartcont/native-registry-code.fc
    DEPENDS func fift smartcont/stdlib.fc
      smartcont/tos-service-native-registry-v1.boc.base64
      smartcont/tos-service-native-registry-v1.release.json
      ${CMAKE_SOURCE_DIR}/scripts/build-tos-service-native-registry-v1.sh
      ${CMAKE_SOURCE_DIR}/scripts/test-tos-service-native-registry-v1.sh
      ${CMAKE_SOURCE_DIR}/scripts/embed-tos-service-native-registry-v1.sh
    OUTPUT ${NATIVE_REGISTRY_CPP}
  )
  add_custom_target(gen_fif_smartcont_auto_native_registry_code DEPENDS ${NATIVE_REGISTRY_CPP})
  add_dependencies(gen_fif gen_fif_smartcont_auto_native_registry_code)
  set(TOS_SERVICE_STABLECOIN_ESCROW_CPP "${SMARTCONT_AUTO_DIR}/tos-service-stablecoin-escrow-v1.cpp")
  add_custom_command(
    COMMENT "Verify and embed the frozen TOS Service Protocol stablecoin escrow v1 BOC"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMAND ${CMAKE_SOURCE_DIR}/scripts/embed-tos-service-stablecoin-escrow-v1.sh
      ${TOS_SERVICE_STABLECOIN_ESCROW_CPP} tos-service-stablecoin-escrow-v1
    MAIN_DEPENDENCY smartcont/tos-service-stablecoin-escrow-v1.fc
    DEPENDS func fift smartcont/stdlib.fc
      smartcont/tos-service-stablecoin-escrow-v1.boc.base64
      smartcont/tos-service-stablecoin-escrow-v1.release.json
      ${CMAKE_SOURCE_DIR}/scripts/build-tos-service-stablecoin-escrow-v1.sh
      ${CMAKE_SOURCE_DIR}/scripts/test-tos-service-stablecoin-escrow-v1.sh
      ${CMAKE_SOURCE_DIR}/scripts/embed-tos-service-stablecoin-escrow-v1.sh
    OUTPUT ${TOS_SERVICE_STABLECOIN_ESCROW_CPP}
  )
  add_custom_target(gen_fif_smartcont_auto_tos_service_stablecoin_escrow_v1
    DEPENDS ${TOS_SERVICE_STABLECOIN_ESCROW_CPP})
  add_dependencies(gen_fif gen_fif_smartcont_auto_tos_service_stablecoin_escrow_v1)
  GenFif(DEST smartcont/auto/agent-account-code SOURCE smartcont/agent-account-code.fc NAME agent-account)
  GenFif(DEST smartcont/auto/pow-testgiver-code SOURCE smartcont/pow-testgiver-code.fc NAME pow-testgiver)

  GenFif(DEST smartcont/auto/dns-manual-code SOURCE smartcont/dns-manual-code.fc NAME dns-manual)
  GenFif(DEST smartcont/auto/dns-auto-code SOURCE smartcont/dns-auto-code.fc NAME dns-auto)

  GenFif(DEST smartcont/auto/payment-channel-code SOURCE smartcont/payment-channel-code.fc NAME payment-channel)

  GenFif(DEST smartcont/auto/simple-wallet-ext-code SOURCE smartcont/simple-wallet-ext-code.fc NAME simple-wallet-ext)
endif()

add_library(smc-envelope STATIC ${SMC_ENVELOPE_SOURCE})
target_include_directories(smc-envelope BEFORE PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)
target_include_directories(smc-envelope PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
target_link_libraries(smc-envelope PUBLIC tos_crypto PRIVATE tdutils tos_block)
if (NOT CMAKE_CROSSCOMPILING)
  add_dependencies(smc-envelope gen_fif)
endif()

add_executable(create-state block/create-state.cpp)
target_include_directories(create-state PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>)
if (NOT CMAKE_CROSSCOMPILING OR USE_EMSCRIPTEN)
  # CreateState.fif preloads these generated contracts.  Keep create-state
  # independently buildable instead of relying on the default ALL target to
  # have populated the build-tree smartcont/auto directory first.
  add_dependencies(create-state
    gen_fif_smartcont_auto_wallet_code
    gen_fif_smartcont_auto_restricted_wallet_code
    gen_fif_smartcont_auto_restricted_wallet2_code
    gen_fif_smartcont_auto_restricted_wallet3_code)
endif()
if (INTERNAL_COMPILE)
  target_link_libraries(create-state PUBLIC tos_crypto fift-lib toslib git)
else()
  if (TOSLIB_COMPILE)
    target_link_libraries(create-state PUBLIC tos_crypto fift-lib toslib git)
  else()
    target_link_libraries(create-state PUBLIC tos_crypto fift-lib git)
  endif()
endif()
if (WINGETOPT_FOUND)
  target_link_libraries_system(create-state wingetopt)
endif()

add_executable(dump-block block/dump-block.cpp)
target_include_directories(dump-block PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>)
target_link_libraries(dump-block PUBLIC tos_crypto fift-lib git)
if (WINGETOPT_FOUND)
  target_link_libraries_system(dump-block wingetopt)
endif()

add_executable(adjust-block block/adjust-block.cpp)
target_include_directories(adjust-block PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>)
target_link_libraries(adjust-block PUBLIC tos_crypto fift-lib git)
if (WINGETOPT_FOUND)
  target_link_libraries_system(dump-block wingetopt)
  target_link_libraries_system(adjust-block wingetopt)
endif()

add_executable(test-weight-distr block/test-weight-distr.cpp)
target_include_directories(test-weight-distr PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>)
target_link_libraries(test-weight-distr PUBLIC tos_crypto fift-lib git)
if (WINGETOPT_FOUND)
  target_link_libraries_system(test-weight-distr wingetopt)
endif()

install(TARGETS fift func create-state tlbc RUNTIME DESTINATION bin)
install(DIRECTORY fift/lib/ DESTINATION lib/fift)
install(DIRECTORY smartcont DESTINATION share/tos)
