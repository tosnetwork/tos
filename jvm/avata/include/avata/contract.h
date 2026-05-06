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

enum {
  AVATA_CONTRACT_OK = 0,
  AVATA_CONTRACT_BAD_ARGUMENT = 1,
  AVATA_CONTRACT_OUT_OF_GAS = 2,
  AVATA_CONTRACT_OPCODE_COUNT = 256
};

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
  AVATA_CONTRACT_HELPER_GAS_COST_COUNT = 10
};

AVATA_CONTRACT_EXPORT int avata_begin_contract_transaction(
    AvataThread* thread,
    uint64_t gas_limit);

AVATA_CONTRACT_EXPORT int avata_end_contract_transaction(AvataThread* thread);

AVATA_CONTRACT_EXPORT int avata_contract_remaining_gas(
    AvataThread* thread,
    uint64_t* remaining_gas);

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
