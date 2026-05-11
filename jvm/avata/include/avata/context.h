/* TOS Network - Avata JVM contract context interface.

   Per-call read-only chain context (caller, callee, value, block, chain id)
   plumbed by the workchain runtime before invoking Java contract code. Unlike
   storage/event, the context has no side effects and does not need host
   callbacks — values are captured by value into Avata thread-local state and
   read back through Java_java_lang_Context_* JNI getters. */

#ifndef AVATA_CONTEXT_H
#define AVATA_CONTEXT_H

#include <stddef.h>
#include <stdint.h>

#if defined(PLATFORM_WINDOWS) || defined(_WIN32)
#define AVATA_CONTEXT_EXPORT __declspec(dllexport)
#else
#define AVATA_CONTEXT_EXPORT \
  __attribute__((visibility("default"))) __attribute__((used))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define AVATA_CONTEXT_OK 0
#define AVATA_CONTEXT_ERROR 1

#define AVATA_CONTEXT_ADDRESS_SIZE 32
#define AVATA_CONTEXT_VALUE_SIZE 32

/* Sentinel `caller_present=0` is set on the first activation external entry
   if no inbound src is available (the engine rejects this case today, so the
   sentinel is defensive). Java side surfaces it as Address.ZERO + workchain
   sentinel `AVATA_CONTEXT_NO_CALLER`. */
#define AVATA_CONTEXT_NO_CALLER 0x7fffffff

/* Read-only snapshot of the per-call chain context. value_be is the attached
   TOMIS as a 32-byte big-endian unsigned integer (matches Uint256 wire form).
   block_seqno is the masterchain-binding block height; block_timestamp is the
   block's `now` field. chain_id comes from ConfigParam 85. */
typedef struct AvataContractContext {
  int32_t contract_workchain;
  uint8_t contract_addr[AVATA_CONTEXT_ADDRESS_SIZE];
  int32_t caller_workchain;
  uint8_t caller_addr[AVATA_CONTEXT_ADDRESS_SIZE];
  uint8_t caller_present;
  uint8_t value_be[AVATA_CONTEXT_VALUE_SIZE];
  uint64_t block_seqno;
  uint64_t block_timestamp;
  uint64_t chain_id;
  uint8_t is_static_call;
} AvataContractContext;

/* Install the context for the next contract invocation on `thread`. The
   contents are copied; the caller may release `ctx` immediately after. */
AVATA_CONTEXT_EXPORT void avata_set_contract_context(
    const AvataContractContext* ctx);

/* Clear any previously installed context. Subsequent Java Context getters
   throw java.lang.ContractViolationError until set again. */
AVATA_CONTEXT_EXPORT void avata_clear_contract_context(void);

/* True iff a context has been installed for the current call. */
AVATA_CONTEXT_EXPORT int avata_has_contract_context(void);

#ifdef __cplusplus
}
#endif

#endif  // AVATA_CONTEXT_H
