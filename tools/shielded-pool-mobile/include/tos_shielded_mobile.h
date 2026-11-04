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

/* Validates one binary recipient descriptor against a Ready replay's pool.
 * The response has an empty payload. This does not authorize a payment. */
TosShieldedResponse *tos_shielded_replay_validate_recipient(const TosShieldedReplay *session, const uint8_t *descriptor,
                                                            size_t descriptor_len);
/* Returns one byte. 1 means the Ready ledger observed the exact intent.
 * 0 means absent from this observation and cannot authorize a replacement. */
TosShieldedResponse *tos_shielded_replay_intent_accepted(const TosShieldedReplay *session, const uint8_t *digest,
                                                         size_t digest_len);
/* Scan at most 512 outputs against the completed ledger's FULL nullifier set.
 * A page is not a complete private balance. Merge by note body, cover all pages,
 * preserve issued-index high water and recheck proof freshness before publishing.
 */
TosShieldedResponse *tos_shielded_replay_scan(const TosShieldedReplay *session, const uint8_t *seed, size_t seed_length,
                                              size_t offset, size_t count);
/* Returns 1 when local payment proving and BR1 are compiled in. */
uint8_t tos_shielded_payment_supported(void);

/* Load is synchronous and returns NULL on failure or in a read-only build. Paths must be absolute UTF-8 byte strings. */
typedef struct PaymentProver TosShieldedPaymentProver;
TosShieldedPaymentProver *tos_shielded_payment_prover_load(const TosShieldedReplay *session, const uint8_t *phase1,
                                                           size_t phase1_len, const uint8_t *ceremony,
                                                           size_t ceremony_len);
void tos_shielded_payment_prover_free(TosShieldedPaymentProver *prover);

/* Requires proving support. The request call uses loopback Tor and blocks.
 * The caller must verify current on-chain Bond eligibility before calling. */
typedef struct RelayOffer TosShieldedRelayOffer;
TosShieldedRelayOffer *tos_shielded_relay_offer_request(const TosShieldedReplay *session, const uint8_t *request,
                                                        size_t length);
TosShieldedResponse *tos_shielded_relay_offer_info(const TosShieldedRelayOffer *offer);
void tos_shielded_relay_offer_free(TosShieldedRelayOffer *offer);

/* Requires proving support. Stage consumes the offer, even on failure. All calls
 * are synchronous. Submit uses Tor and reports an unverified relay status. */
typedef struct RecoveredRelaySubmission TosShieldedPaymentSubmission;
TosShieldedPaymentSubmission *tos_shielded_payment_stage(const TosShieldedReplay *session,
                                                         const TosShieldedPaymentProver *prover,
                                                         TosShieldedRelayOffer *offer, const uint8_t *seed,
                                                         size_t seed_len, const uint8_t *request, size_t request_len);
/* Returns 0 on success (NULL output if none is pending), 1 on error. */
uint8_t tos_shielded_payment_recover(const TosShieldedReplay *session, const uint8_t *seed, size_t seed_len,
                                     const uint8_t *request, size_t request_len, TosShieldedPaymentSubmission **output);
TosShieldedResponse *tos_shielded_payment_submit(const TosShieldedPaymentSubmission *submission);
void tos_shielded_payment_free(TosShieldedPaymentSubmission *submission);

void tos_shielded_replay_free(TosShieldedReplay *session);
/* Complete Ready-ledger summary: globally deduplicates note bodies and reconciles
 * all published nullifiers. No note secrets/nullifiers are returned. Freshness
 * still belongs to the proof layer; scan_next_index excludes durable reservations.
 */
TosShieldedResponse *tos_shielded_replay_summary(const TosShieldedReplay *session, const uint8_t *seed,
                                                 size_t seed_length);
#if defined(__unix__) || defined(__APPLE__)
/* Ready replay and original master are required. Authenticate freshness and all
 * binding fields against the same observation before calling. Root is the UTF-8
 * absolute common app-private directory. Binding is big-endian i32 global ID
 * followed by seven 32-byte fields: pool account, genesis root, genesis file,
 * code hash, profile hash, manifest hash, verifying-key hash.
 * Replay creation JSON must contain these same bytes as hex in receive_binding.
 * Success returns one descriptor after durable reservation. An error after
 * reservation can burn the index. Serialize all access to the replay. */
TosShieldedResponse *tos_shielded_replay_receive(const TosShieldedReplay *session, const uint8_t *seed,
                                                 size_t seed_length, const uint8_t *root, size_t root_length,
                                                 const uint8_t *binding, size_t binding_length);
/* Ready replay; decimal minimum attached nanoTOS, excluding wallet fees. */
TosShieldedResponse *tos_shielded_replay_deposit_value(const TosShieldedReplay *session, uint64_t amount);
/* Same authenticated replay and index reservation as receive. Returns body BOC. */
TosShieldedResponse *tos_shielded_replay_self_deposit(
    const TosShieldedReplay *session, const uint8_t *seed, size_t seed_length,
    const uint8_t *root, size_t root_length, const uint8_t *binding, size_t binding_length,
    uint64_t amount, uint64_t query_id);

/* Read the unresolved payment against the same wallet-bound Ready replay.
 * Payload: 0 no record, 1 intent absent, 2 intent accepted. Keeps the record. */
TosShieldedResponse *tos_shielded_replay_pending_status(const TosShieldedReplay *session, const uint8_t *seed,
                                                        size_t seed_length, const uint8_t *root, size_t root_length,
                                                        const uint8_t *binding, size_t binding_length);

#endif

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
