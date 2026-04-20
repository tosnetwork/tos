#ifndef HEADER_at_src_waltz_http_at_url_h
#define HEADER_at_src_waltz_http_at_url_h

/* at_url.h provides an API for handling URLs.

   This API is by no means compliant.  Works only for basic strings.  */

#include "at/infra/at_util_base.h"

/* at_url_t holds a bunch of pointers into an URL string. */

struct at_url {
  char const * scheme;
  ulong        scheme_len;

  char const * host;
  ulong        host_len; /* <=255 */

  char const * port;
  ulong        port_len;

  char const * tail; /* path, query, fragment */
  ulong        tail_len;
};

typedef struct at_url at_url_t;

#define AT_URL_SUCCESS         0
#define AT_URL_ERR_SCHEME      1
#define AT_URL_ERR_HOST_OVERSZ 2
#define AT_URL_ERR_USERINFO    3

AT_PROTOTYPES_BEGIN

/* at_url_parse_cstr is a basic URL parser.  It is not RFC compliant.

   Non-exhaustive list of what this function cannot do:
   - Schemes other than http and https are not supported
   - userinfo (e.g. 'user:pass@') is not supported
   - Anything after the authority is ignored

   If opt_err!=NULL, on return *opt_err holds an AT_URL_ERR_{...} code. */

at_url_t *
at_url_parse_cstr( at_url_t *   url,
                   char const * url_str,
                   ulong        url_str_len,
                   int *        opt_err );

/* at_url_unescape undoes % escapes in-place. */

ulong
at_url_unescape( char * const msg,
                 ulong  const len );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_waltz_http_at_url_h */