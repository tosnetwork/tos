/* TOS Network - Avata contract execution ABI. */

#ifndef AVATA_CONTRACT_H
#define AVATA_CONTRACT_H

#include <stdint.h>

#if defined(_WIN32) || defined(__CYGWIN__)
#define AVATA_CONTRACT_EXPORT __declspec(dllexport)
#else
#define AVATA_CONTRACT_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AvataThread AvataThread;
typedef uintptr_t AvataContractMethod;

enum {
  AVATA_CONTRACT_OK = 0,
  AVATA_CONTRACT_BAD_ARGUMENT = 1,
  AVATA_CONTRACT_OUT_OF_GAS = 2,
  AVATA_CONTRACT_OUT_OF_MEMORY = 3,
  AVATA_CONTRACT_EXCEPTION = 4,
  AVATA_CONTRACT_OPCODE_COUNT = 256
};

enum {
  AVATA_CONTRACT_ARG_BOOL = 1,
  AVATA_CONTRACT_ARG_INT32 = 2,
  AVATA_CONTRACT_ARG_INT64 = 3,
  AVATA_CONTRACT_ARG_BYTES = 4,
  AVATA_CONTRACT_ARG_ADDRESS = 5,
  AVATA_CONTRACT_ARG_UINT256 = 6,
  AVATA_CONTRACT_ARG_BYTES32 = 7,
  AVATA_CONTRACT_ARG_BYTES4 = 8,
  AVATA_CONTRACT_ARG_COUNT_LIMIT = 64
};

typedef struct AvataContractArg {
  uint8_t type;
  const uint8_t* bytes;
  uint32_t bytes_length;
} AvataContractArg;

enum {
  AVATA_CONTRACT_HELPER_STORAGE_LOAD = 0,
  AVATA_CONTRACT_HELPER_STORAGE_STORE_BASE = 1,
  AVATA_CONTRACT_HELPER_STORAGE_STORE_BYTE = 2,
  AVATA_CONTRACT_HELPER_STORAGE_CLEAR = 3,
  AVATA_CONTRACT_HELPER_ALLOCATION_OBJECT_WORD = 4,
  AVATA_CONTRACT_HELPER_ALLOCATION_ARRAY_BASE = 5,
  AVATA_CONTRACT_HELPER_ALLOCATION_ARRAY_ELEMENT = 6,
  AVATA_CONTRACT_HELPER_ARRAYCOPY_BASE = 7,
  AVATA_CONTRACT_HELPER_ARRAYCOPY_ELEMENT = 8,
  AVATA_CONTRACT_HELPER_NATIVE_CALL = 9,
  AVATA_CONTRACT_HELPER_EVENT_BASE = 10,
  AVATA_CONTRACT_HELPER_EVENT_TOPIC = 11,
  AVATA_CONTRACT_HELPER_EVENT_BYTE = 12,
  // Round 53 MEDIUM fix: per-byte cost charged on Storage.load after
  // the host returns the decoded value's size.  Pre-fix `Storage.load`
  // charged only the fixed `STORAGE_LOAD` (~20 gas) but the host
  // decoded + malloc'd + memcpy'd a value chain up to
  // `kJvmStorageValueMaxBytes` (1 MiB) — validators did O(N) work
  // for O(1) gas, a CPU-DoS vector once a contract had seeded a
  // large slot.  Now mirrored to STORAGE_STORE_BYTE so load and
  // store bill symmetrically per byte.
  AVATA_CONTRACT_HELPER_STORAGE_LOAD_BYTE = 13,
  /* Per Phase A of the rt.jar gap plan: each java.lang.Context getter
     charges one unit of CONTEXT_READ. Reads are O(1) constant-bytes
     snapshots, so we bill a single small fixed cost per call rather
     than per-byte.  Position 14 is the first free slot after the
     pre-existing 0..13 helpers; ConfigParam 85's helper-gas table
     grows by appending. */
  AVATA_CONTRACT_HELPER_CONTEXT_READ = 14,
  /* Phase B of the rt.jar gap plan: signature + hash primitives. */
  AVATA_CONTRACT_HELPER_CRYPTO_SHA256_BASE = 15,
  AVATA_CONTRACT_HELPER_CRYPTO_SHA256_BYTE = 16,
  AVATA_CONTRACT_HELPER_CRYPTO_SECP256K1_RECOVER = 17,
  AVATA_CONTRACT_HELPER_CRYPTO_SECP256K1_VERIFY = 18,
  AVATA_CONTRACT_HELPER_CRYPTO_ED25519_VERIFY = 19,
  AVATA_CONTRACT_HELPER_CRYPTO_BLS12381_VERIFY = 20,
  /* Final TODO closure: outbound message primitive (System.sendMessage).
     MESSAGE_BASE charges the fixed per-call cost (high enough to
     discourage spam), MESSAGE_BYTE charges the body bandwidth. */
  AVATA_CONTRACT_HELPER_MESSAGE_BASE = 21,
  AVATA_CONTRACT_HELPER_MESSAGE_BYTE = 22,
  AVATA_CONTRACT_HELPER_GAS_COST_COUNT = 23
};

AVATA_CONTRACT_EXPORT int avata_begin_contract_transaction(
    AvataThread* thread,
    uint64_t gas_limit);

AVATA_CONTRACT_EXPORT int avata_begin_contract_transaction_with_limits(
    AvataThread* thread,
    uint64_t gas_limit,
    uint64_t memory_limit);

AVATA_CONTRACT_EXPORT int avata_end_contract_transaction(AvataThread* thread);

AVATA_CONTRACT_EXPORT int avata_resolve_contract_static_void(
    AvataThread* thread,
    const char* class_name,
    const char* method_name,
    const char* method_spec,
    AvataContractMethod* resolved_method);

AVATA_CONTRACT_EXPORT int avata_define_contract_class(
    AvataThread* thread,
    const char* class_name,
    const uint8_t* class_bytes,
    uint32_t class_bytes_length);

AVATA_CONTRACT_EXPORT int avata_invoke_contract_static_void(
    AvataThread* thread,
    AvataContractMethod resolved_method);

AVATA_CONTRACT_EXPORT int avata_invoke_contract_static_void_args(
    AvataThread* thread,
    AvataContractMethod resolved_method,
    const AvataContractArg* args,
    uint32_t arg_count);

AVATA_CONTRACT_EXPORT int avata_contract_remaining_gas(
    AvataThread* thread,
    uint64_t* remaining_gas);

AVATA_CONTRACT_EXPORT int avata_contract_memory_used(
    AvataThread* thread,
    uint64_t* used_bytes);

AVATA_CONTRACT_EXPORT int avata_contract_memory_remaining(
    AvataThread* thread,
    uint64_t* remaining_bytes);

AVATA_CONTRACT_EXPORT int avata_contract_memory_limit(
    AvataThread* thread,
    uint64_t* limit_bytes);

AVATA_CONTRACT_EXPORT int avata_charge_contract_gas(
    AvataThread* thread,
    uint64_t gas_cost);

AVATA_CONTRACT_EXPORT int avata_charge_contract_helper_gas(
    AvataThread* thread,
    uint16_t helper,
    uint64_t units);

AVATA_CONTRACT_EXPORT int avata_reset_opcode_gas_costs(AvataThread* thread);

AVATA_CONTRACT_EXPORT int avata_set_opcode_gas_cost(
    AvataThread* thread,
    uint8_t opcode,
    uint64_t gas_cost);

AVATA_CONTRACT_EXPORT int avata_set_opcode_gas_costs(
    AvataThread* thread,
    const uint64_t* gas_costs,
    uint32_t gas_cost_count);

AVATA_CONTRACT_EXPORT int avata_get_opcode_gas_cost(
    AvataThread* thread,
    uint8_t opcode,
    uint64_t* gas_cost);

AVATA_CONTRACT_EXPORT int avata_reset_contract_helper_gas_costs(
    AvataThread* thread);

AVATA_CONTRACT_EXPORT int avata_set_contract_helper_gas_cost(
    AvataThread* thread,
    uint16_t helper,
    uint64_t gas_cost);

AVATA_CONTRACT_EXPORT int avata_set_contract_helper_gas_costs(
    AvataThread* thread,
    const uint64_t* gas_costs,
    uint32_t gas_cost_count);

AVATA_CONTRACT_EXPORT int avata_get_contract_helper_gas_cost(
    AvataThread* thread,
    uint16_t helper,
    uint64_t* gas_cost);

#ifdef __cplusplus
}
#endif

#endif  // AVATA_CONTRACT_H
