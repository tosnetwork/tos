#ifndef HEADER_at_src_util_net_at_pcapng_private_h
#define HEADER_at_src_util_net_at_pcapng_private_h

#include "at_pcapng.h"

/* AT_PCAPNG_BLOCK_SZ: max size of serialized block
   (including packet content) */
#define AT_PCAPNG_BLOCK_SZ (32768UL)

/* AT_PCAPNG_BLOCK_TYPE_*: Block type identifiers */

#define AT_PCAPNG_BLOCK_TYPE_SHB (0x0A0D0D0AU) /* Section Header Block        */
#define AT_PCAPNG_BLOCK_TYPE_IDB (0x00000001U) /* Interface Description Block */
#define AT_PCAPNG_BLOCK_TYPE_SPB (0x00000003U) /* Simple Packet Block         */
#define AT_PCAPNG_BLOCK_TYPE_EPB (0x00000006U) /* Enhanced Packet Block       */
#define AT_PCAPNG_BLOCK_TYPE_DSB (0x0000000AU) /* Decryption Secrets Block    */

/* AT_PCAPNG_BYTE_ORDER_MAGIC: BOM in logical order */

#define AT_PCAPNG_BYTE_ORDER_MAGIC (0x1A2B3C4D)

/* at_pcapng_option_t points to a variable-length option value.
   Kind of option value depends on option type.  Strings (char *) are
   UTF-8 encoded and are not zero terminated. */

struct at_pcapng_option {
  ushort type;  /* AT_PCAPNG_*_OPT_* */
  ushort sz;    /* byte size of option data at value */
  void * value; /* points to first byte of option data */
};
typedef struct at_pcapng_option at_pcapng_option_t;

/* Common option codes */

#define AT_PCAPNG_OPT_END     ((ushort)0) /* end of options */
#define AT_PCAPNG_OPT_COMMENT ((ushort)1)

#define AT_PCAPNG_MAX_OPT_CNT 256

/* at_pcapng_hdr_t: Common block header */

struct __attribute__((packed)) at_pcapng_block_hdr {
  uint block_type;
  uint block_sz;
};
typedef struct at_pcapng_block_hdr at_pcapng_block_hdr_t;

/* at_pcapng_shb_t: Section Header Block */

#define AT_PCAPNG_SHB_OPT_HARDWARE ((ushort)2)  /* char * hardware; max once */
#define AT_PCAPNG_SHB_OPT_OS       ((ushort)3)  /* char * os_name ; max once */
#define AT_PCAPNG_SHB_OPT_USERAPPL ((ushort)4)  /* char * app_name; max once */

struct __attribute__((packed)) at_pcapng_shb {
  uint   block_type;       /* ==AT_PCAPNG_BLOCK_TYPE_SHB */
  uint   block_sz;         /* ==sizeof(at_pcapng_shb_t) */
  uint   byte_order_magic; /* ==AT_PCAPNG_BYTE_ORDER_MAGIC */
  ushort version_major;    /* ==1 */
  ushort version_minor;    /* ==0 */
  ulong  section_sz;       /* ==ULONG_MAX (undefined) */
};
typedef struct at_pcapng_shb at_pcapng_shb_t;

/* at_pcapng_idb_t: Interface Description Block */

#define AT_PCAPNG_IDB_OPT_NAME      ((ushort) 2) /* char * if_name;        max once */
#define AT_PCAPNG_IDB_OPT_IPV4_ADDR ((ushort) 4) /* uint   ip4;            multiple */
#define AT_PCAPNG_IDB_OPT_MAC_ADDR  ((ushort) 6) /* char   hwaddr[6];      max once */
#define AT_PCAPNG_IDB_OPT_TSRESOL   ((ushort) 9) /* uchar  tsresol;        max once */
#define AT_PCAPNG_IDB_OPT_HARDWARE  ((ushort)15) /* char * device_name;    max once */

struct __attribute__((packed)) at_pcapng_idb {
  uint   block_type; /* ==AT_PCAPNG_BLOCK_TYPE_IDB */
  uint   block_sz;   /* ==sizeof(at_pcapng_idb_t) */
  ushort link_type;  /* ==AT_PCAPNG_LINKTYPE_ETHERNET */
  ushort _pad_0a;    /* ==0 */
  uint   snap_len;   /* packet payload sz limit, 0==unlim */
};
typedef struct at_pcapng_idb at_pcapng_idb_t;

/* at_pcapng_spb_t: Simple Packet Block */

struct __attribute__((packed)) at_pcapng_spb {
  uint   block_type; /* ==AT_PCAPNG_BLOCK_TYPE_SPB      */
  uint   block_sz;   /* >=sizeof(at_pcapng_spb_t)       */
  uint   orig_len;   /* Original packet size (bytes)    */
};
typedef struct at_pcapng_spb at_pcapng_spb_t;

/* at_pcapng_epb_t: Enhanced Packet Block */

struct __attribute__((packed)) at_pcapng_epb {
  uint   block_type; /* ==AT_PCAPNG_BLOCK_TYPE_EPB      */
  uint   block_sz;   /* >=sizeof(at_pcapng_epb_t)       */
  uint   if_idx;     /* Index of related IDB in section */
  uint   ts_hi;      /* High 32 bits of timestamp       */
  uint   ts_lo;      /* Low 32 bits of timestamp        */
  uint   cap_len;    /* Captured packet size (bytes)    */
  uint   orig_len;   /* Original packet size (bytes)    */
};
typedef struct at_pcapng_epb at_pcapng_epb_t;

/* at_pcapng_dsb_t: Decryption Secrets Block */

#define AT_PCAPNG_SECRET_TYPE_TLS (0x544c534bU)

struct __attribute__((packed)) at_pcapng_dsb {
  uint   block_type;  /* ==AT_PCAPNG_BLOCK_TYPE_DSB */
  uint   block_sz;    /* >=sizeof(at_pcapng_dsb_t)  */
  uint   secret_type; /* ==AT_PCAPNG_SECRET_TYPE_*  */
  uint   secret_sz;   /* byte sz of secrets data    */
};
typedef struct at_pcapng_dsb at_pcapng_dsb_t;

struct __attribute__((aligned(AT_PCAPNG_ITER_ALIGN))) at_pcapng_iter {
  void * stream;
  int    error;
  uint   empty : 1;

  at_pcapng_frame_t pkt;

# define AT_PCAPNG_IFACE_CNT 16
  at_pcapng_idb_desc_t iface[ AT_PCAPNG_IFACE_CNT ];
  uint                 iface_cnt;

  uchar  block_buf[ AT_PCAPNG_BLOCK_SZ ];
  ulong  block_buf_sz;
  ulong  block_buf_pos;
};

#endif /* HEADER_at_src_util_net_at_pcapng_private_h */
