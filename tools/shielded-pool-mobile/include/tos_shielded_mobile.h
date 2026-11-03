#ifndef TOS_SHIELDED_MOBILE_H
#define TOS_SHIELDED_MOBILE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Every pointer must designate a live allocation of at least the stated length.
 * Seed is exactly the protocol's 32-byte TOS seed, not mnemonic UTF-8 bytes.
 * Calls are synchronous, do not retain input, and perform no networking.
 * Limit application concurrency; a call may perform expensive PQ cryptography.
 * Response contents may contain private note material: never log them.
 */
typedef struct TosShieldedResponse TosShieldedResponse;
/* Issue: domain is a canonical 32-byte big-endian field element.
 * The caller MUST durably reserve note_index before publishing this descriptor.
 * Success payload is the 2573-byte descriptor; failure payload is empty.
 */
TosShieldedResponse *tos_shielded_descriptor(const uint8_t *seed, size_t seed_len, const uint8_t *domain,
                                             size_t domain_len, uint64_t note_index);
/* Scan a bounded JSON batch. Chain slots/nullifiers must come from verified
 * state. This function authenticates no chain and asserts no balance freshness.
 * Success payload is UTF-8 JSON, failure payload empty. See README.md.
 */
TosShieldedResponse *tos_shielded_scan(const uint8_t *seed, size_t seed_len, const uint8_t *request,
                                       size_t request_len);
/* Decode a single-root generic BOC, max 2 MiB, 32768 cells, depth 128.
 * Success is layout validation only, not proof authentication. Bind data_hash
 * to the account proof before using the result as a pool observation.
 */
TosShieldedResponse *tos_shielded_pool_state(const uint8_t *data, size_t length);
/* Bind/decode one transaction. JSON expectations originate in an account proof
 * or a previously checked newer link. Does not establish freshness or replay
 * completeness. Request max 2 MiB; same response ownership as the other calls.
 */
TosShieldedResponse *tos_shielded_history_transaction(const uint8_t *request, size_t length);
/* Replay owns bounded provisional public history, never a seed. Creation hashes
 * and head metadata MUST come from one verified observation; see request schema.
 * Serialize every call/free. Create returns NULL on error. Mutators return
 * 0 success, 1 error, 2 contained panic; any failed mutator poisons the session.
 * Only after successful finish can info/scan/summary read the completed ledger.
 */
typedef struct TosShieldedReplay TosShieldedReplay;
TosShieldedReplay *tos_shielded_replay_create(const uint8_t *request, size_t length);
int32_t tos_shielded_replay_push(TosShieldedReplay *session, const uint8_t *boc, size_t length);
int32_t tos_shielded_replay_finish(TosShieldedReplay *session);
TosShieldedResponse *tos_shielded_replay_info(const TosShieldedReplay *session);
/* Scan at most 512 outputs against the completed ledger's FULL nullifier set.
 * A page is not a complete private balance. Merge by note body, cover all pages,
 * preserve issued-index high water and recheck proof freshness before publishing.
 */
TosShieldedResponse *tos_shielded_replay_scan(const TosShieldedReplay *session, const uint8_t *seed, size_t seed_length,
                                              size_t offset, size_t count);
void tos_shielded_replay_free(TosShieldedReplay *session);
/* Complete Ready-ledger summary: globally deduplicates note bodies and reconciles
 * all published nullifiers. No note secrets/nullifiers are returned. Freshness
 * still belongs to the proof layer; scan_next_index excludes durable reservations.
 */
TosShieldedResponse *tos_shielded_replay_summary(const TosShieldedReplay *session, const uint8_t *seed,
                                                 size_t seed_length);
/* status: 0 success; 1 invalid input/crypto failure; 2 contained panic.
 * Pointer is valid until free; free once, on the same library that allocated it.
 * The response buffer is zeroized on free. Accessors require a live handle.
 */
int32_t tos_shielded_response_status(const TosShieldedResponse *response);
const uint8_t *tos_shielded_response_data(const TosShieldedResponse *response);
size_t tos_shielded_response_size(const TosShieldedResponse *response);
void tos_shielded_response_free(TosShieldedResponse *response);
#ifdef __cplusplus
}
#endif
#endif
