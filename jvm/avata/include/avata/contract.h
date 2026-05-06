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
  AVATA_CONTRACT_BAD_ARGUMENT = 1
};

AVATA_CONTRACT_EXPORT int avata_begin_contract_transaction(
    AvataThread* thread,
    uint64_t gas_limit);

AVATA_CONTRACT_EXPORT int avata_end_contract_transaction(AvataThread* thread);

AVATA_CONTRACT_EXPORT int avata_contract_remaining_gas(
    AvataThread* thread,
    uint64_t* remaining_gas);

#ifdef __cplusplus
}
#endif

#endif  // AVATA_CONTRACT_H
