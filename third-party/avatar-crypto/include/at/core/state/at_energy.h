#ifndef HEADER_at_core_state_at_energy_h
#define HEADER_at_core_state_at_energy_h

#include "at/infra/at_util_base.h"

/* TOS common/src/error.rs :: EnergyError parity */
typedef enum at_energy_error {
  AT_ENERGY_ERR_OVERFLOW             = 1,
  AT_ENERGY_ERR_DIVISION_BY_ZERO     = 2,
  AT_ENERGY_ERR_INVALID_RECORD_AMOUNT= 3
} at_energy_error_t;

AT_PROTOTYPES_BEGIN

static inline char const *
at_energy_error_str( at_energy_error_t err ) {
  switch( err ) {
    case AT_ENERGY_ERR_OVERFLOW:              return "Energy overflow";
    case AT_ENERGY_ERR_DIVISION_BY_ZERO:      return "Energy division by zero";
    case AT_ENERGY_ERR_INVALID_RECORD_AMOUNT: return "Invalid freeze record amount";
    default:                                  return "Unknown energy error";
  }
}

AT_PROTOTYPES_END

#endif /* HEADER_at_core_state_at_energy_h */
