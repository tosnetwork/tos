#ifndef HEADER_at_src_ballet_json_cJSON_alloc_h
#define HEADER_at_src_ballet_json_cJSON_alloc_h

#include "at/infra/alloc/at_alloc.h"

#ifdef __cplusplus
extern "C" {
#endif

void
cJSON_alloc_install( at_alloc_t * alloc );

#ifdef __cplusplus
}
#endif

#endif /* HEADER_at_src_ballet_json_cJSON_alloc_h */