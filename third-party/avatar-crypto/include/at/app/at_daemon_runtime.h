#ifndef HEADER_at_app_at_daemon_runtime_h
#define HEADER_at_app_at_daemon_runtime_h

#include "at/app/at_daemon_config.h"

/* Run the Avatar daemon runtime using the provided configuration.
   Returns 0 on success, non-zero on failure with err populated. */
int
at_daemon_run( at_cli_config_t const * cfg,
               char *                  err,
               unsigned long           err_sz );

#endif /* HEADER_at_app_at_daemon_runtime_h */
