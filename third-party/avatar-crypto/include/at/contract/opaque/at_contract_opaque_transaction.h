#ifndef HEADER_at_contract_opaque_at_contract_opaque_transaction_h
#define HEADER_at_contract_opaque_at_contract_opaque_transaction_h

#include "at/contract/opaque/at_contract_opaque_mod.h"
#include "at/transaction/at_txn.h"

AT_PROTOTYPES_BEGIN

typedef struct {
  at_txn_t const *            txn;
  uchar const *               raw;
  at_contract_opaque_hash_t   hash;
  int                         has_hash;
} at_contract_opaque_transaction_t;

int
at_contract_opaque_transaction_init( at_contract_opaque_transaction_t *      out,
                                     at_txn_t const *                         txn,
                                     uchar const *                            raw,
                                     at_contract_opaque_hash_t const *        hash_opt );

int
at_contract_opaque_transaction_nonce( at_contract_opaque_transaction_t const * tx,
                                      ulong *                                  nonce_out );

int
at_contract_opaque_transaction_hash( at_contract_opaque_transaction_t const * tx,
                                     at_contract_opaque_hash_t *              hash_out );

int
at_contract_opaque_transaction_source( at_contract_opaque_transaction_t const * tx,
                                       int                                      mainnet,
                                       at_contract_opaque_address_t *           address_out );

int
at_contract_opaque_transaction_fee( at_contract_opaque_transaction_t const * tx,
                                    ulong *                                  fee_out );

int
at_contract_opaque_transaction_signature( at_contract_opaque_transaction_t const * tx,
                                          at_contract_opaque_signature_t *         signature_out );

AT_PROTOTYPES_END

#endif /* HEADER_at_contract_opaque_at_contract_opaque_transaction_h */
