#ifndef HEADER_at_src_util_net_at_pcapng_h
#define HEADER_at_src_util_net_at_pcapng_h

/* pcapng is a file format for packet captures. Incompatible with
   classic "tcpdump" pcap as in at_pcap.h but supports additional
   features such as embedded encryption secrets.

   Spec: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/

   at_pcapng only supports little-endian files.  All strings in this API
   are formatted as UTF-8 (superset of ASCII) and max not exceed 200
   char length.  All values in "opt" structs are optional, absence
   implied by zero unless otherwise stated.

   This library is not optimized for high performance and is thus not
   suitable for packet capture at line rate.  Parsing API is hardened
   against malicious inputs. */

#include "../at_util_base.h"

/* Opaque handle of a pcapng iterator */

struct at_pcapng_iter;
typedef struct at_pcapng_iter at_pcapng_iter_t;

#define AT_PCAPNG_ITER_ALIGN (32UL)

/* Section Header Block options */

struct at_pcapng_shb_opts {
  char const * hardware; /* Generic name of machine performing capture
                            e.g. "x86_64 Server" */
  char const * os;       /* Operating system or distro name */
  char const * userappl; /* Name of this program (e.g. "Reference") */
};
typedef struct at_pcapng_shb_opts at_pcapng_shb_opts_t;

/* Interface Description Block options */

struct at_pcapng_idb_opts {
  char  name[16];     /* Name of network interface in OS */
  uchar ip4_addr[4];  /* IPv4 address in big endian order -- todo support multiple */
  uchar mac_addr[6];  /* MAC address */
  uchar tsresol;      /* See AT_PCAPNG_TSRESOL_* */
  char  hardware[64]; /* Name of network interface hardware */
};
typedef struct at_pcapng_idb_opts at_pcapng_idb_opts_t;

/* Generalized frame read from a pcapng.
   Usually a packet but can also be metadata */

struct at_pcapng_idb_desc {
  uint                 link_type;
  at_pcapng_idb_opts_t opts;
};
typedef struct at_pcapng_idb_desc at_pcapng_idb_desc_t;

struct at_pcapng_frame {
  long ts;      /* Time in ns (matches at_log_wallclock) */
  uint type;    /* Packet type */
  uint data_sz; /* Size of data array */
  uint orig_sz; /* Original packet size (>=data_sz) */
  uint if_idx;  /* Index of interface */
  at_pcapng_idb_desc_t const * idb;  /* Associated interface (nullable) */
  uchar * data;
};
typedef struct at_pcapng_frame at_pcapng_frame_t;

/* AT_PCAPNG_TSRESOL_* sets the resolution of a timestamp. */

#define AT_PCAPNG_TSRESOL_NS ((uchar)0x09)

/* at_pcapng_iter iter frame types */

#define AT_PCAPNG_FRAME_SIMPLE   (1U) /* Simple packet type (data only) */
#define AT_PCAPNG_FRAME_ENHANCED (3U) /* Packet with metadata */
#define AT_PCAPNG_FRAME_TLSKEYS  (4U) /* TLS keys */

AT_PROTOTYPES_BEGIN

/* Read API ***********************************************************/

/* at_pcap_iter_{align,footprint} return alignment and footprint
   requirements of an at_pcap_iter_t memory region. */

AT_FN_CONST ulong
at_pcapng_iter_align( void );

AT_FN_CONST ulong
at_pcapng_iter_footprint( void );

/* at_pcapng_iter_new creates an iterator suitable for reading a pcapng
   file.  mem is a non-NULL pointer to a memory region matching align
   and footprint requirements.  file should be non-NULL handle of a
   stream seeked to the first byte of a pcapng section header block
   (e.g. on a hosted platform a FILE * of the fopen'd file).  Returns
   pointer to iter on success (not just a cast of mem) and NULL on
   failure (an indeterminant number of bytes in the stream might have
   been consumed on failure). */

at_pcapng_iter_t *
at_pcapng_iter_new( void * mem,
                    void * file );

/* at_pcapng_iter_delete destroys an at_pcap_iter_t.  Returns the
   underlying memory region (not just a cast of iter).  The caller
   regains ownership of the memory region and stream handle. */

void *
at_pcapng_iter_delete( at_pcapng_iter_t * iter );

/* at_pcapng_iter_next extracts the next frame from the pcapng stream.
   Returns a pointer to the frame descriptor on success and NULL on
   failure.  Failure reasons include normal end of section (or file),
   fread failures, or file corruption.  Details of all failures except
   normal end-of-file are logged with a warning.  Last error code can
   be retrieved with at_pcapng_iter_err.

   On successful return, the return value itself and the frame data
   are backed by a thread-local memory region that is valid until delete
   or next iter_next. */

at_pcapng_frame_t *
at_pcapng_iter_next( at_pcapng_iter_t * iter );

/* at_pcapng_iter_ele returns the current iterator element. */

at_pcapng_frame_t *
at_pcapng_iter_ele( at_pcapng_iter_t * iter );

/* at_pcapng_is_pkt returns 1 if given frame (non-NULL) is a regular
   captured packet and 0 if it is metadata (such as decryption secrets). */

AT_FN_UNUSED AT_FN_PURE static inline int
at_pcapng_is_pkt( at_pcapng_frame_t const * frame ) {
  uint ty = frame->type;
  return (ty==AT_PCAPNG_FRAME_SIMPLE) | (ty==AT_PCAPNG_FRAME_ENHANCED);
}

/* at_pcapng_iter_err returns the last encountered error.  Uses at_io
   error codes. */

AT_FN_PURE int
at_pcapng_iter_err( at_pcapng_iter_t const * iter );

/* Write API **********************************************************/

/* at_pcapng_shb_defaults stores default options for an SHB based on the
   system environment into opt.  Given opt must be initialized prior to
   call. */

void
at_pcapng_shb_defaults( at_pcapng_shb_opts_t * opt );

/* at_pcapng_fwrite_shb writes a little endian pcapng SHB v1.0 (Section
   Header Block) to the stream pointed to by file.  Same semantics as
   fwrite (returns the number of headers written, which should be 1 on
   success and 0 on failure). opt contains options embedded into SHB
   and may be NULL.

   The PCAPNG spec requires an SHB v1.0 at the beginning of the file.
   Multiple SHBs per file are permitted.  An SHB clears any side effects
   induced by blocks (such as the timestamp resolution of an IDB).  It
   is the caller's responsibility to maintain 4 byte alignment for
   stream pointer of file. (all functions in this API will write
   multiples of 4).

   If SHB is not first of file, this function currently makes no attempt
   to fix up the length field of the preceding SHB (may change in the
   future). */

ulong
at_pcapng_fwrite_shb( at_pcapng_shb_opts_t const * opt,
                      void *                       file );

#if AT_HAS_HOSTED

/* at_pcapng_idb_defaults stores default options for an IDB based on the
   system environment into opt.  if_idx is the operating system's
   interface index. (THIS IS UNRELATED TO THE PCAPNG INTERFACE INDEX).
   Returns 0 on success and -1 on failure.  Reasons for failure are
   written to log.  On failure, partially writes opt. */

int
at_pcapng_idb_defaults( at_pcapng_idb_opts_t * opt,
                        uint                   if_idx );

#endif /* AT_HAS_HOSTED */

/* at_pcapng_fwrite_idb writes an IDB (Interface Description Block) to
   the stream pointed to by file.  Usually a successor of an SHB.  Refer
   to at_pcapng_fwrite_shb for use of opt, file args. link_type is one
   of AT_PCAPNG_LINKTYPE_*.  opt->tsresol is ignored.  at_pcapng always
   writes TSRESOL==9 (nanoseconds). */

/* AT_PCAPNG_LINKTYPE_*: Link types (currently only Ethernet supported) */

#define AT_PCAPNG_LINKTYPE_ETHERNET   (1U) /* IEEE 802.3 Ethernet */
#define AT_PCAPNG_LINKTYPE_RAW      (101U) /* IPv4 or IPv6 */
#define AT_PCAPNG_LINKTYPE_COOKED   (113U) /* Linux "cooked" capture */
#define AT_PCAPNG_LINKTYPE_USER0    (147U) /* DLT_USER0 */
#define AT_PCAPNG_LINKTYPE_IPV4     (228U) /* IPv4 */

ulong
at_pcapng_fwrite_idb( uint                         link_type,
                      at_pcapng_idb_opts_t const * opt,
                      void *                       file );

/* at_pcapng_fwrite_pkt writes an EPB (Enhanced Packet Block) containing
   an ethernet frame at time ts (in nanos). Same semantics as fwrite
   (returns the number of packets written, which should be 1 on success
   and 0 on failure). */

ulong
at_pcapng_fwrite_pkt1( void *       file,
                       void const * payload,
                       ulong        payload_sz,
                       void const * options,
                       ulong        options_sz,
                       uint         if_idx,
                       long         ts );

static inline ulong
at_pcapng_fwrite_pkt( long         ts,
                      void const * payload,
                      ulong        payload_sz,
                      void *       file ) {
  return at_pcapng_fwrite_pkt1( file, payload, payload_sz, NULL, 0UL, 0U, ts );
}

/* at_pcapng_fwrite_tls_key_log writes TLS key log info to a PCAPNG via
   a DSB (Decryption Secrets Block).  Similar semantics to fwrite
   (returns 1 on success and 0 on failure, but will dispatch multiple
   fwrite calls internally).  log points to first byte of NSS key log
   in ASCII format.  log_sz is byte size of log. */

ulong
at_pcapng_fwrite_tls_key_log( uchar const * log,
                              uint          log_sz,
                              void *        file );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_net_at_pcapng_h */