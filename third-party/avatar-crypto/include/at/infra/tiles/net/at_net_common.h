/* at_net_common.h - Common network definitions

   TODO: Implement based on TOS requirements */

#ifndef HEADER_at_disco_net_at_net_common_h
#define HEADER_at_disco_net_at_net_common_h

#include "at/infra/at_util_base.h"

/* Network MTU definitions
   TODO: Implement based on TOS requirements - these may need adjustment */

#define AT_NET_MTU (2048UL)

/* Chunk alignment for network buffers */
#define AT_CHUNK_ALIGN (64UL)

#endif /* HEADER_at_disco_net_at_net_common_h */