#ifndef HEADER_at_src_p2p_net_mib_at_netdev_tbl_h
#define HEADER_at_src_p2p_net_mib_at_netdev_tbl_h

/* at_netdev_tbl.h provides a network interface table.
   The entrypoint of this API is at_netlink_tbl_t. */

#include "at/infra/at_util_base.h"

/* AT_OPER_STATUS_* give the operational state of a network interface.
   See RFC 2863 Section 3.1.14. */

#define AT_OPER_STATUS_INVALID          (0)
#define AT_OPER_STATUS_UP               (1)  /* ready to pass packets */
#define AT_OPER_STATUS_DOWN             (2)
#define AT_OPER_STATUS_TESTING          (3)  /* in some test mode */
#define AT_OPER_STATUS_UNKNOWN          (4)  /* status can not be determined */
#define AT_OPER_STATUS_DORMANT          (5)
#define AT_OPER_STATUS_NOT_PRESENT      (6)  /* some component is missing */
#define AT_OPER_STATUS_LOWER_LAYER_DOWN (7)  /* down due to state of lower-layer interface(s) */

/* at_netdev_t holds basic configuration of a network device. */

struct at_netdev {
  ushort mtu;            /* Largest layer-3 payload that fits in a packet */
  uchar  mac_addr[6];    /* MAC address */
  uint   if_idx;         /* Interface index */
  short  slave_tbl_idx;  /* index to bond slave table, -1 if not a bond master */
  int    master_idx;     /* index of bond master, -1 if not a bond slave */
  char   name[16];       /* cstr interface name (max 15 length) */
  uchar  oper_status;    /* one of AT_OPER_STATUS_{...} */
  ushort dev_type;       /* one of ARPHRD_ETHER/_LOOPBACK_/IPGRE */
  uint   gre_dst_ip;
  uint   gre_src_ip;
};

typedef struct at_netdev at_netdev_t;

/* AT_NETDEV_BOND_SLAVE_MAX is the max supported number of bond slaves. */

#define AT_NETDEV_BOND_SLAVE_MAX (16)

/* at_netdev_bond_t lists active slaves of a bond device. */

struct at_netdev_bond {
  uchar  slave_cnt;
  ushort slave_idx[ AT_NETDEV_BOND_SLAVE_MAX ];
};

typedef struct at_netdev_bond at_netdev_bond_t;

/* at_netdev_tbl_t provides an interface table. */

struct at_netdev_tbl_private;
typedef struct at_netdev_tbl_private at_netdev_tbl_t;

struct at_netdev_tbl_hdr {
  ushort dev_max;
  ushort bond_max;
  ushort dev_cnt;
  ushort bond_cnt;
};
typedef struct at_netdev_tbl_hdr at_netdev_tbl_hdr_t;

struct at_netdev_tbl_join {
  at_netdev_tbl_hdr_t * hdr;
  at_netdev_t *         dev_tbl;
  at_netdev_bond_t *    bond_tbl;
};
typedef struct at_netdev_tbl_join at_netdev_tbl_join_t;

#define AT_NETDEV_TBL_MAGIC (0xd5f9ba2710d6bf0aUL) /* random */

/* AT_NETDEV_TBL_ALIGN is the return value of at_netdev_tbl_align(). */

#define AT_NETDEV_TBL_ALIGN (16UL)

AT_PROTOTYPES_BEGIN

/* at_netdev_tbl_{align,footprint} describe a memory region suitable to
   back a netdev_tbl with dev_max interfaces and bond_max bond masters. */

AT_FN_CONST ulong
at_netdev_tbl_align( void );

AT_FN_CONST ulong
at_netdev_tbl_footprint( ulong dev_max,
                         ulong bond_max );

/* at_netdev_tbl_new formats a memory region as an empty netdev_tbl.
   Returns shmem on success.  On failure returns NULL and logs reason for
   failure. */

void *
at_netdev_tbl_new( void * shmem,
                   ulong  dev_max,
                   ulong  bond_max );

/* at_netdev_tbl_join joins a netdev_tbl at shtbl.  ljoin points to a
   at_netdev_tbl_join_t[1] to which object information is written to.
   Returns ljoin on success.  On failure, returns NULL and logs reason for
   failure. */

at_netdev_tbl_join_t *
at_netdev_tbl_join( void * ljoin,
                    void * shtbl );

/* at_netdev_tbl_leave undoes a at_netdev_tbl_join.  Returns ownership
   of the region backing join to the caller.  (Warning: This returns ljoin,
   not shtbl) */

void *
at_netdev_tbl_leave( at_netdev_tbl_join_t * join );

/* at_netdev_tbl_delete unformats the memory region backing a netdev_tbl
   and returns ownership of the region back to the caller. */

void *
at_netdev_tbl_delete( void * shtbl );

/* at_netdev_tbl_reset resets the table to the state of a newly constructed
   empty object (clears all devices and bonds). */

void
at_netdev_tbl_reset( at_netdev_tbl_join_t * tbl );

/* at_netdev_tbl_query queries the netdev table for a device with idx if_idx.
   Returns pointer to the device object if found, otherwise NULL. */

static inline at_netdev_t *
at_netdev_tbl_query( at_netdev_tbl_join_t * tbl,
                     uint                   if_idx ) {
  at_netdev_t * dev = tbl->dev_tbl;
  ulong j;
#define UNROLL_FACTOR 8
  for( j = 0UL; j+UNROLL_FACTOR < tbl->hdr->dev_cnt; j+=UNROLL_FACTOR ) {
    if( AT_UNLIKELY( dev[j+0].if_idx==if_idx ) ) return dev+j+0;
    if( AT_UNLIKELY( dev[j+1].if_idx==if_idx ) ) return dev+j+1;
    if( AT_UNLIKELY( dev[j+2].if_idx==if_idx ) ) return dev+j+2;
    if( AT_UNLIKELY( dev[j+3].if_idx==if_idx ) ) return dev+j+3;
    if( AT_UNLIKELY( dev[j+4].if_idx==if_idx ) ) return dev+j+4;
    if( AT_UNLIKELY( dev[j+5].if_idx==if_idx ) ) return dev+j+5;
    if( AT_UNLIKELY( dev[j+6].if_idx==if_idx ) ) return dev+j+6;
    if( AT_UNLIKELY( dev[j+7].if_idx==if_idx ) ) return dev+j+7;
  }
#undef UNROLL_FACTOR

  for( ; j<tbl->hdr->dev_cnt; j++ ) {
    if( dev[j].if_idx==if_idx ) return dev+j;
  }
  return NULL;
}

#if AT_HAS_HOSTED

/* at_netdev_tbl_fprintf prints the interface table to the given FILE *
   pointer (or target equivalent).  Outputs ASCII encoding with LF
   newlines.  Returns errno on failure and 0 on success. */

int
at_netdev_tbl_fprintf( at_netdev_tbl_join_t const * tbl,
                       void *                       file );

#endif /* AT_HAS_HOSTED */

AT_PROTOTYPES_END

char const *
at_oper_status_cstr( uint oper_status );

#endif /* HEADER_at_src_p2p_net_mib_at_netdev_tbl_h */
