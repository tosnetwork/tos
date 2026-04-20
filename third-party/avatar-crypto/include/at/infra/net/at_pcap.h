#ifndef HEADER_at_src_util_net_at_pcap_h
#define HEADER_at_src_util_net_at_pcap_h

#include "../log/at_log.h"
#include "at_eth.h"

#define AT_PCAP_ITER_TYPE_ETHERNET (0UL)
#define AT_PCAP_ITER_TYPE_COOKED   (1UL)

#define AT_PCAP_LINK_LAYER_ETHERNET (  1U)
#define AT_PCAP_LINK_LAYER_USER0    (147U)

/* Opaque handle of a pcap iterator */

struct at_pcap_iter;
typedef struct at_pcap_iter at_pcap_iter_t;

AT_PROTOTYPES_BEGIN

/* at_pcap_iter_new creates an iterator suitable for reading a pcap
   file.  file should be non-NULL handle of a stream seeked to the first
   byte of the pcap file (e.g. on a hosted platform a FILE * of the
   fopen'd file).  Returns file on success (the pcap_iter will have
   ownership of the file stream) and NULL on failure (an indeterminant
   number of bytes in the stream might have been consumed on failure). */

at_pcap_iter_t *
at_pcap_iter_new( void * file );

/* at_pcap_iter_file returns the file stream of the pcap file being
   iterated over.  at_pcap_iter_type returns the type of pcap file being
   iterated over (return value will be a AT_PCAP_ITER_TYPE_*).  Assumes
   iter is a current iterator and the iterator is unchanged.  No bytes
   in the underlying stream are consumed. */

AT_FN_CONST static inline void * at_pcap_iter_file( at_pcap_iter_t * iter ) { return (void *)(((ulong)iter) & ~1UL); }
AT_FN_CONST static inline ulong  at_pcap_iter_type( at_pcap_iter_t * iter ) { return          ((ulong)iter) &  1UL;  }

/* at_pcap_iter_delete destroys a at_pcap_iter_t.  Returns the handle of
   the underlying stream; the caller has ownership of the stream. */

AT_FN_CONST static inline void * at_pcap_iter_delete( at_pcap_iter_t * iter ) { return at_pcap_iter_file( iter ); }

/* at_pcap_iter_next extracts the next packet from the pcap stream.
   Returns pkt_sz the number of bytes in the packet on success and 0 on
   on failure.  Failure reasons include normal end-of-file, fread
   failures, pcap file corruption, pcap file contains truncated packets
   and pkt_max is too small for pkt_sz.  Details of all failures except
   normal end-of-file are logged with a warning.

   On a successful return, the memory region pointed to by pkt will
   contain the pkt_sz bytes of the extracted packet starting from the
   first byte of Ethernet header to the last byte of whatever was
   captured for that packet (e.g. the last byte of the Ethernet payload,
   the last byte of the Ethernet FCS, etc).  *_pkt_ts will contain the
   packet timestamp (assumes that the pcap captured at nanosecond
   resolution).  The iterator's underlying stream pointer will be
   advanced exactly on pcap pkt (and the underlying stream will have
   consumed bytes up to the next pkt).  If iterating over over a cooked
   capture, pkt will have use a phony Ethernet header with no VLAN
   tagging that mangles cooked sll dir/ha_type/ha_len fields into the
   dst mac and the ha into the src mac).

   On a failed return, pkt and pkt_ts are untouched.  If not a normal
   EOF, the iterator's underlying stream may have consumed an
   indeterminant number of bytes. */

ulong
at_pcap_iter_next( at_pcap_iter_t * iter,
                   void *           pkt,
                   ulong            pkt_max,
                   long *           _pkt_ts );

/* at_pcap_iter_next extracts the next packet from the pcap stream,
   placing the packet headers in one output buffer and the packet
   payload in another output buffer.  Returns 1 on success and 0 on
   failure.  Failure reasons include normal end-of-file, fread failures,
   pcap file corruption, pcap file contains truncated packets,
   hdr_sz is too small for the packet's headers, and pld_sz is too small
   for the packet's payload.  Details of all failures except normal
   end-of-file are logged with a warning.

   For the purposes of this function, Ethernet, IPv4 and UDP headers are
   the only ones that are recognized as headers.  This function
   considers all bytes not part of one of the listed header types as
   payload.

   When the function is called, hdr_buf must point the first byte of a
   *hdr_sz byte-sized region of writable memory, and pld_buf must point
   to the first byte of a *pld_sz byte-sized region of writable memory.

   On successful return, the memory regions pointed to by hdr_buf and
   pld_buf will respectively contain the packet's headers (starting with
   the first byte of the Ethernet header) and the packet's payload
   (ending with whatever was captured for that packet, which could
   potentially include the Ethernet FCS).  The iterator's underlying
   stream will advance one packet.
   The ulongs pointed to by hdr_sz and pld_sz will be updated with the
   number of bytes written to hdr_buf and pld_buf, respectively.
   *_pkt_ts will contain the packet timestamp (assumes that the pcap
   captured at nanosecond resolution).


   If the underlying stream is at EOF when this function is called, it
   will return 0, but not modify the contents of hdr_buf or pld_buf.  In
   other failure cases, an indeterminate number of bytes between 0 and
   *{hdr,pld}_sz bytes, inclusive, may be written to {hdr,pld}_buf,
   respectively. */
int
at_pcap_iter_next_split( at_pcap_iter_t * iter,
                         void *           hdr_buf,
                         ulong *          hdr_sz,
                         void *           pld_buf,
                         ulong *          pld_sz,
                         long *           _pkt_ts );

/* at_pcap_fwrite_hdr write a little endian 2.4 pcap header to the
   stream pointed to by file.  link_layer_type should be one of the
   AT_PCAP_LINK_LAYER_* values defined above.  Same semantics as fwrite
   (returns number of headers written, which should be 1 on success and
   0 on failure). */

ulong
at_pcap_fwrite_hdr( void * file,
                    uint   link_layer_type );

/* at_pcap_ostream_hdr behaves exactly like at_pcap_fwrite_hdr except
   that the data is written to a at_io_buffered_ostream_t stream.
   Returns nonzero on failure. */

int
at_pcap_ostream_hdr( at_io_buffered_ostream_t * out,
                     uint                       link_layer_type );

/* at_pcap_pkt_sz returns the number of bytes needed to write a pcap
   entry for the given hdr_sz + payload_sz.  Returns a negative number
   if the given hdr/payload are too large for the pcap file. */

long
at_pcap_pkt_sz( ulong hdr_sz,
                ulong payload_sz );

/* at_pcap_pkt writes the pcap ethernet frame formed by concatenating
   hdr/payload/fcs as appropriate for a pcap file at time ts (will be
   encoded with ns resolution).  hdr should start on the first byte of
   the Ethernet header and payload should end on the last byte of the
   Ethernet payload.  For normal (uncorrupted) frames:

     _fcs = at_eth_fcs_append( at_eth_fcs( _hdr, hdr_sz ), _payload, _payload_sz )

   The resulting pcap entry is written to the given pointer, which must
   have at least at_pcap_pkt_sz( hdr_sz, payload_sz ) bytes of free
   space to write into.  Returns pcap entry size on success and negative
   on failure. */

long
at_pcap_pkt( void *       out,
             long         ts,
             void const * _hdr,
             ulong        hdr_sz,
             void const * _payload,
             ulong        payload_sz,
             uint         _fcs );

/* at_pcap_fwrite_pkt behaves like at_pcap_pkt except that it writes
   data to the stream pointed to by file.

   Same semantics as fwrite: returns number of packets written -> 1 on
   success and 0 on failure (logs details on failure). */

ulong
at_pcap_fwrite_pkt( long         ts,
                    void const * _hdr,
                    ulong        hdr_sz,
                    void const * _payload,
                    ulong        payload_sz,
                    uint         _fcs,
                    void *       file );

/* at_pcap_ostream_pkt behaves like at_pcap_pkt except that it writes
   data to a at_io_buffered_ostream_t stream.  Returns nonzero on
   failure. */

int
at_pcap_ostream_pkt( at_io_buffered_ostream_t * out,
                     long                       ts,
                     void const *               _hdr,
                     ulong                      hdr_sz,
                     void const *               _payload,
                     ulong                      payload_sz,
                     uint                       _fcs );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_net_at_pcap_h */
