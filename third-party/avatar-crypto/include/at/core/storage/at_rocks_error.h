#ifndef HEADER_at_rocks_at_rocks_error_h
#define HEADER_at_rocks_at_rocks_error_h

/* at_rocks_error.h - Error codes for at_rocks module */

#include "at/infra/at_util_base.h"

/* Error codes returned by at_rocks APIs */
typedef enum {
  AT_ROCKS_OK             =  0,  /* Success */
  AT_ROCKS_ERR_NOT_FOUND  = -1,  /* Key not found (distinct from IO error) */
  AT_ROCKS_ERR_IO         = -2,  /* RocksDB IO error */
  AT_ROCKS_ERR_CORRUPTION = -3,  /* Data corruption detected */
  AT_ROCKS_ERR_INVALID    = -4,  /* Invalid argument */
  AT_ROCKS_ERR_FULL       = -5,  /* Buffer too small */
  AT_ROCKS_ERR_EXISTS     = -6,  /* Key already exists (for create ops) */
  AT_ROCKS_ERR_BUSY       = -7,  /* Resource busy */
} at_rocks_err_t;

#endif /* HEADER_at_rocks_at_rocks_error_h */