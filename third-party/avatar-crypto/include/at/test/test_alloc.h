#ifndef HEADER_at_test_alloc_h
#define HEADER_at_test_alloc_h

#include "at/infra/at_wksp.h"
#include "at/infra/alloc/at_alloc.h"
#include "at/infra/at_util_base.h"
#include "at/infra/cstr/at_cstr.h"

#include <stdio.h>
#include <unistd.h>

typedef struct {
  at_wksp_t * wksp;
  void *     alloc_shmem;
  at_alloc_t * alloc;
  ulong      alloc_gaddr;
  ulong      wksp_footprint;
  char       name[ AT_SHMEM_NAME_MAX ];
} at_test_alloc_t;

static inline void
at_test_alloc_fini( at_test_alloc_t * ctx );

static inline int
at_test_alloc_init( at_test_alloc_t * ctx,
                    char const *      name,
                    ulong             wksp_tag,
                    ulong             cgroup_hint,
                    ulong             part_max,
                    ulong             data_max ) {
  static int shmem_booted = 0;
  if( !shmem_booted ) {
    int argc = 1;
    char * argv_local[] = { (char *)"test", NULL };
    char ** argv = argv_local;
    at_shmem_private_boot( &argc, &argv );
    shmem_booted = 1;
  }
  if( !ctx ) return -1;
  at_memset( ctx, 0, sizeof(*ctx) );

  if( !name ) name = "test_wksp";
  {
    static ulong ctr = 0UL;
    ulong id = ++ctr;
    int pid = (int)getpid();
    at_cstr_printf( ctx->name, sizeof(ctx->name), NULL, "%s_%d_%lu", name, pid, id );
  }

  ulong footprint = at_wksp_footprint( part_max, data_max );
  if( !footprint ) return -1;
  ctx->wksp_footprint = footprint;

  ulong page_sz  = AT_SHMEM_NORMAL_PAGE_SZ;
  ulong page_cnt = (footprint + page_sz - 1UL) / page_sz;
  ulong cpu_idx  = 0UL;

  at_wksp_t * wksp = at_wksp_new_anon( ctx->name, page_sz, 1UL, &page_cnt, &cpu_idx, 0U, part_max );
  if( !wksp ) {
    fprintf( stderr, "test_alloc: at_wksp_new_anon failed (name=%s)\n", ctx->name );
    goto fail;
  }

  ctx->wksp = wksp;

  ulong gaddr = at_wksp_alloc( wksp, at_alloc_align(), at_alloc_footprint(), wksp_tag );
  if( !gaddr ) goto fail;
  ctx->alloc_gaddr = gaddr;

  void * shalloc = at_wksp_laddr( wksp, gaddr );
  if( !shalloc ) goto fail;
  ctx->alloc_shmem = shalloc;

  if( !at_wksp_containing( shalloc ) ) {
    fprintf( stderr, "test_alloc: laddr not in wksp (name=%s)\n", ctx->name );
    goto fail;
  }

  if( !at_alloc_new( shalloc, wksp_tag ) ) {
    fprintf( stderr, "test_alloc: at_alloc_new failed (wksp=%p laddr=%p wksp_containing=%p)\n",
             (void *)wksp, shalloc, (void *)at_wksp_containing( shalloc ) );
    goto fail;
  }

  at_alloc_t * alloc = at_alloc_join( shalloc, cgroup_hint );
  if( !alloc ) goto fail;
  ctx->alloc = alloc;

  return 0;

fail:
  at_test_alloc_fini( ctx );
  return -1;
}

static inline void
at_test_alloc_fini( at_test_alloc_t * ctx ) {
  if( !ctx ) return;

  if( ctx->alloc ) {
    void * shalloc = at_alloc_leave( ctx->alloc );
    if( shalloc ) at_alloc_delete( shalloc );
    ctx->alloc = NULL;
  }

  if( ctx->wksp && ctx->alloc_gaddr ) {
    at_wksp_free( ctx->wksp, ctx->alloc_gaddr );
    ctx->alloc_gaddr = 0;
  }

  if( ctx->wksp ) {
    at_wksp_delete_anon( ctx->wksp );
    ctx->wksp = NULL;
  }
  ctx->name[0] = '\0';
  ctx->alloc_shmem = NULL;
}

#endif /* HEADER_at_test_alloc_h */