#ifndef HEADER_at_disco_topob_h
#define HEADER_at_disco_topob_h

/* at_topob is a builder for at_topo, providing convenience
   functions for creating a topology. */

#include "at_topo.h"

/* A link in the topology is either unpolled or polled.  Almost all
   links are polled, which means a tile which has this link as an in
   will read fragments from it and pass them to the tile handling
   code.  An unpolled link will not read off the link by default and
   the user code will need to specifically read it as needed. */

#define AT_TOPOB_UNPOLLED 0
#define AT_TOPOB_POLLED 1

/* A reliable link is a flow controlled one, where the producer will
   not send fragments if any downstream consumer does not have enough
   capacity (credits) to handle it. */

#define AT_TOPOB_UNRELIABLE 0
#define AT_TOPOB_RELIABLE 1

AT_PROTOTYPES_BEGIN

/* Configure default bank tile DB backend used by at_topob_tile(). */
void at_topob_set_bank_db_backend( uint backend );
uint at_topob_get_bank_db_backend( void );

/* Initialize a new at_topo_t with the given app name and at the memory address
   provided.  Returns the topology at given address.  The topology will be empty
   with no tiles, objects, links. */

at_topo_t *
at_topob_new( void * mem,
              char const * app_name );

/* Add a workspace with the given name to the topology.  Workspace names
   must be unique and adding the same workspace twice will produce an
   error. */

at_topo_wksp_t *
at_topob_wksp( at_topo_t *  topo,
               char const * name );

/* Add an object with the given type to the toplogy.  An object is
   something that takes up space in memory, in a workspace. */

at_topo_obj_t *
at_topob_obj( at_topo_t *  topo,
              char const * obj_type,
              char const * wksp_name );

/* Same as at_topo_obj, but labels the object. */

at_topo_obj_t *
at_topob_obj_named( at_topo_t *  topo,
                    char const * obj_type,
                    char const * wksp_name,
                    char const * label );

/* Add a relationship saying that a certain tile uses a given object.
   mode should be one of AT_SHMEM_JOIN_MODE_READ_ONLY or
   AT_SHMEM_JOIN_MODE_READ_WRITE. */

void
at_topob_tile_uses( at_topo_t *           topo,
                    at_topo_tile_t *      tile,
                    at_topo_obj_t const * obj,
                    int                   mode );

/* Add a link to the toplogy.  The link will not have any producer or
   consumer(s) by default. */

at_topo_link_t *
at_topob_link( at_topo_t *  topo,
               char const * link_name,
               char const * wksp_name,
               ulong        depth,
               ulong        mtu,
               ulong        burst );

/* Add a tile to the topology. */

at_topo_tile_t *
at_topob_tile( at_topo_t *    topo,
               char const *   tile_name,
               char const *   tile_wksp,
               char const *   metrics_wksp,
               ulong          cpu_idx,
               int            is_tosrust,
               int            uses_keyswitch );

/* Add an input link to the tile. */

void
at_topob_tile_in( at_topo_t *  topo,
                  char const * tile_name,
                  ulong        tile_kind_id,
                  char const * fseq_wksp,
                  char const * link_name,
                  ulong        link_kind_id,
                  int          reliable,
                  int          polled );

/* Add an output link to the tile. */

void
at_topob_tile_out( at_topo_t *  topo,
                   char const * tile_name,
                   ulong        tile_kind_id,
                   char const * link_name,
                   ulong        link_kind_id );

/* Automatically layout the tiles onto CPUs. */

void
at_topob_auto_layout( at_topo_t * topo,
                      int         reserve_tosrust_cores );

/* Finish creating the topology.  Lays out all the objects in the
   given workspaces, and sizes everything correctly. */

int
at_topob_finish( at_topo_t *                topo,
                 at_topo_obj_callbacks_t ** callbacks );

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_topob_h */
