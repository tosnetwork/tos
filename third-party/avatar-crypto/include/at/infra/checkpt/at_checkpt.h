#ifndef HEADER_at_src_util_checkpt_at_checkpt_h
#define HEADER_at_src_util_checkpt_at_checkpt_h

/* APIs for fast parallel compressed checkpoint and restore.  Concepts:

   - A checkpoint contains of zero or more frames.

   - Each frame resides in a disjoint contiguous sequence of bytes in
     the checkpoint and contains a sequence of zero of more data
     buffers.

   - Data buffers can have (up to physical limitation) arbitrary
     variable byte size.

   - A frame has a style that specifies how data buffers have been
     encoded into it.

   - Buffers in a RAW frame are stored verbatim with no gaps.  As such,
     the space needed for a raw frame and the location of buffers in a
     raw frame can computed exactly up front.

   - Buffers in a LZ4 frame are stored via LZ4 streaming compression.  A
     worst case upper bound for the space needed for a LZ4 frame can be
     computed up front, roughly:

       (256/255) total_sz_all_buffers + 19 buffer_count.

     The location of buffers in LZ4 frame is not practically computable
     in advance and decompression of a buffer in a frame depends on
     previous buffers in that frame.

   - Checkpoints can be read and written in a streaming IO mode or in a
     memory IO mode with the exact same APIs (i.e. no changes to the
     calling code outside of specifying the mode when starting a
     checkpoint or a restore).  The checkpoint and restore processes
     will produce bit-level identical results regardless of mode.

   - Frames are independent such that different frames can be generated
     in parallel.  Each frame generated will be bit-level identical
     regardless how generation is distributed over threads.

   - Similarly, frames can restored in parallel.  The restored results
     will be bit-level identical regardles how restoration is
     distributed over threads.

   - As such, arbitrary streaming/mmio serial/parallel operation is fine
     (e.g. have a single thread write a checkpoint file with streaming
     I/O and then use multiple threads to restore from that checkpoint
     file with memory mapped I/O). */

#include "../log/at_log.h"

/* AT_CHECKPT_SUCCESS / AT_CHECKPT_ERR_* are return values from various
   at_checkpt APIs.  SUCCESS is zero and ERR_* are negative integers. */

#define AT_CHECKPT_SUCCESS   (0)  /* operation was successful */
#define AT_CHECKPT_ERR_INVAL (-1) /* operation failed because bad input arguments */
#define AT_CHECKPT_ERR_UNSUP (-2) /* operation failed because it is unsupported on this target */
#define AT_CHECKPT_ERR_IO    (-3) /* operation failed because an I/O error occurred */
#define AT_CHECKPT_ERR_COMP  (-4) /* operation failed because a compressor/decompressor error occurred */

/* AT_CHECKPT_FRAME_STYLE_* specify a checkpoint frame style.  These are
   positive integers. */

#define AT_CHECKPT_FRAME_STYLE_RAW (1) /* uncompressed   frame */
#define AT_CHECKPT_FRAME_STYLE_LZ4 (2) /* lz4 compressed frame */

#define AT_CHECKPT_FRAME_STYLE_DEFAULT AT_CHECKPT_FRAME_STYLE_RAW

/* AT_CHECKPT_META_MAX is the maximum size buffer supported by
   at_checkpt_meta.  64 KiB is recommended. */

#define AT_CHECKPT_META_MAX (65536UL)

/* AT_CHECKPT_WBUF_MIN is the minimum write buffer size needed by a
   at_checkpt_t in streaming mode.  Must be at least 65813 ~
     AT_CHECKPT_PRIVATE_CSZ_MAX( AT_CHECKPT_PRIVATE_CHUNK_USZ_MAX ) */

#define AT_CHECKPT_WBUF_MIN (69632UL) /* 68 KiB */

/* AT_CHECKPT_{ALIGN,FOOTPRINT} give the required {alignment,footprint}
   of a memory region suitable for use as a at_checkpt_t. */

#define AT_CHECKPT_ALIGN     alignof( at_checkpt_t )
#define AT_CHECKPT_FOOTPRINT sizeof(  at_checkpt_t )

/* A at_checkpt_t is a semi-opaque handle for an in-progress checkpoint
   (a stack or global declaration of an at_checkpt_t is sufficient to
   get the correct alignment and footprint). */

struct at_checkpt_private;
typedef struct at_checkpt_private at_checkpt_t;

/* AT_RESTORE_META_MAX is the maximum size buffer supported by
   at_restore_meta.  Must match AT_CHECKPT_META_MAX currently. */

#define AT_RESTORE_META_MAX AT_CHECKPT_META_MAX

/* AT_RESTORE_RBUF_MIN is the minimum read buffer size needed by a
   at_restore_t in streaming mode.  Must be at least
   AT_CHECKPT_WBUF_MIN. */

#define AT_RESTORE_RBUF_MIN AT_CHECKPT_WBUF_MIN

/* AT_RESTORE_{ALIGN,FOOTPRINT} give the required {alignment,footprint}
   of a memory region suitable for use as a at_restore_t. */

#define AT_RESTORE_ALIGN     alignof( at_restore_t )
#define AT_RESTORE_FOOTPRINT sizeof(  at_restore_t )

/* A at_restore_t is a semi-opaque handle of an in-progress restore (a
   stack or global declaration of an at_restore_t is sufficient to get
   the correct alignment and footprint). */

struct at_restore_private;
typedef struct at_restore_private at_restore_t;

/* Internal use only **************************************************/

/* These are exposed to facilitate things like stack declaration */

/* AT_CHECKPT_PRIVATE_CHUNK_USZ_MAX is the maximum amount of checkpt
   data fed into the underlying compressor at a time.  Should be much
   less than LZ4_MAX_INPUT_SIZE (and probably much less than 2^24-1).
   Must be at least AT_CHECKPT_BUF_META_MAX.  64 KiB recommended. */

#define AT_CHECKPT_PRIVATE_CHUNK_USZ_MAX (65536UL)

/* AT_CHECKPT_PRIVATE_CSZ_MAX returns a reasonably tight upper bound to
   the number of compressed output bytes generated given usz
   uncompressed input bytes.  Assumes usz is safe against multiple
   evaluation and usz<=AT_CHECKPT_PRIVATE_CHUNK_USZ_MAX.  (This is the
   same as LZ4_COMPRESSBOUND plus 3 extra bytes for checkpt related
   metadata plus ulong typing usz and the usz limit.) */

#define AT_CHECKPT_PRIVATE_CSZ_MAX(usz) ((usz) + ((usz)/255UL) + 19UL)

AT_STATIC_ASSERT( AT_CHECKPT_PRIVATE_CHUNK_USZ_MAX <= (1UL<<30), adjust_buf_limits );
AT_STATIC_ASSERT( AT_CHECKPT_WBUF_MIN >= AT_CHECKPT_PRIVATE_CSZ_MAX( AT_CHECKPT_PRIVATE_CHUNK_USZ_MAX ), adjust_buf_limits );
AT_STATIC_ASSERT( AT_RESTORE_RBUF_MIN >= AT_CHECKPT_WBUF_MIN, adjust_buf_limits );

/* AT_CHECKPT_PRIVATE_GBUF_SZ is the size of the checkpt gather buffer.
   Must be at least 2*META_MAX + 65536 - 1 (the 64KiB is from LZ4). */

#define AT_CHECKPT_PRIVATE_GBUF_SZ (2UL*AT_CHECKPT_META_MAX + 65536UL)

AT_STATIC_ASSERT( AT_CHECKPT_META_MAX        <= AT_CHECKPT_PRIVATE_CHUNK_USZ_MAX,  adjust_buf_limits );
AT_STATIC_ASSERT( AT_CHECKPT_PRIVATE_GBUF_SZ >= 2UL*AT_CHECKPT_META_MAX + 65535UL, adjust_buf_limits );

/* AT_RESTORE_PRIVATE_SBUF_SZ similarly gives the configuration for
   restore scatter optimizations.  This currently need to match the
   gather configuration. */

#define AT_RESTORE_PRIVATE_SBUF_SZ AT_CHECKPT_PRIVATE_GBUF_SZ

/* at_checkpt_t internals */

struct at_checkpt_private_wbuf { /* very similar to at_io_buffered_ostream */
  uchar * mem;  /* Buffer of compressed bytes not yet written to fd, byte indexed [0,wbuf_sz) */
  ulong   sz;   /* Buffer size in bytes, >=AT_CHECKPT_WBUF_MIN */
  ulong   used; /* Buffer bytes [0,wbuf_used) are not yet written to fd,
                   buffer bytes [wbuf_used,wbuf_sz) are free */
};

typedef struct at_checkpt_private_wbuf at_checkpt_private_wbuf_t;

struct at_checkpt_private_mmio {
  uchar * mem; /* Checkpoint memory region, indexed [0,sz) */
  ulong   sz;  /* Checkpoint memory region size in bytes */
};

typedef struct at_checkpt_private_mmio at_checkpt_private_mmio_t;

struct at_checkpt_private {
  int    fd;          /* (stream) File descriptor for the checkpt (>=0), (mmio) -1 */
  int    frame_style; /* AT_CHECKPT_FRAME_STYLE_* (>0), 0: not in frame (valid), -1: not in frame (failed) */
  void * lz4;         /* Handle of the underlying compressor */
  ulong  gbuf_cursor; /* Cursor for small buffer gather optimizations, in [0,AT_CHECKPT_PRIVATE_GBUF_SZ] */
  ulong  off;         /* Offset of the next byte to write (relative to the checkpoint first byte), in [0,mmio_sz) in mmio mode */
  union {
    at_checkpt_private_wbuf_t wbuf; /* used in streaming mode */
    at_checkpt_private_mmio_t mmio; /* used in mmio mode */
  };
  uchar gbuf[ AT_CHECKPT_PRIVATE_GBUF_SZ ]; /* gather optimization buffer */
};

/* at_restore_t internals */

struct at_restore_private_rbuf { /* very similar to at_io_buffered_istream */
  uchar * mem;   /* Buffer of compressed bytes read from fd, byte indexed [0,rbuf_sz) */
  ulong   sz;    /* Buffer size in bytes, >=AT_RESTORE_RBUF_MIN */
  ulong   lo;    /* Buffer bytes [0,rbuf_lo) have been read and restored */
  ulong   ready; /* Number of compressed bytes that haven't been processed, 0<=rbuf_lo<=(rbuf_lo+rbuf_ready)<=rbuf_sz */
};

typedef struct at_restore_private_rbuf at_restore_private_rbuf_t;

struct at_restore_private_mmio {
  uchar const * mem; /* Checkpoint memory region, indexed [0,sz) */
};

typedef struct at_restore_private_mmio at_restore_private_mmio_t;

struct at_restore_private {
  int    fd;          /* (stream) File descriptor for the restore (>=0), (mmio) -1 */
  int    frame_style; /* AT_CHECKPT_FRAME_STYLE_* (>0), 0: not in frame (valid), -1: not in frame (failed) */
  void * lz4;         /* Handle of the underlying decompressor used */
  ulong  sbuf_cursor; /* Cursor for small buffer scatter optimizations, in [0,AT_RESTORE_PRIVATE_SBUF_SZ] */
  ulong  sz;          /* (stream) if seekable, file size, otherwise ULONG_MAX, (mmio) mmio region size */
  ulong  off;         /* Offset of the next byte to read.  In [0,sz].  Relative to:
                         (stream) first byte of file if seekable, fd position when initialized otherwise,
                         (mmio) first byte of mmio region. */
  union {
    at_restore_private_rbuf_t rbuf; /* used in streaming mode */
    at_restore_private_mmio_t mmio; /* used in mmio mode */
  };
  uchar sbuf[ AT_RESTORE_PRIVATE_SBUF_SZ ]; /* scatter optimization buffer */
};

/* End internal use only **********************************************/

AT_PROTOTYPES_BEGIN

/* Checkpt APIs *******************************************************/

/* at_checkpt_init_stream formats a memory region, mem, with suitable
   alignment and footprint into a at_checkpt_t (a pointer to a stack
   declared at_checkpt_t is fine).  fd is an open normal-ish file
   descriptor where the checkpoint should be streamed out.  wbuf points
   to the first byte in the caller's address space to an unused wbuf_sz
   byte size memory region to use for write buffering.  wbuf_sz should
   be at least AT_CHECKPT_WBUF_MIN.

   On success, returns mem formatted as a at_checkpt_t in streaming
   mode.  On return, the at_checkpt_t will be valid, not in a frame and
   will have ownership of mem, fd, and wbuf.

   On failure, returns NULL (logs details).  No ownership changed. */

at_checkpt_t *
at_checkpt_init_stream( void * mem,
                        int    fd,
                        void * wbuf,
                        ulong  wbuf_sz );

/* at_checkpt_init_mmio is the same as at_checkpt_init_stream but
   checkpoints frames into a mmio_sz byte sized memory region whose
   first byte in the caller's local address space is pointed to by mmio. */

at_checkpt_t *
at_checkpt_init_mmio( void * mem,
                      void * mmio,
                      ulong  mmio_sz );

/* at_checkpt_fini finishes a checkpoint.  checkpt should be valid and
   not in a frame.

   On success, returns mem.  On return, checkpt is no longer valid and
   the caller will have ownership of mem, fd and wbuf (streaming mode)
   or mem and mmio (mmio mode).

   On failure, returns NULL (logs details).  Reasons for failure include
   NULL checkpt and checkpt in a frame.  The checkpt (and underlying fd
   in streaming mode) should be considered failed (i.e. checkpt no
   longer has any interest in checkpointed data and the user should only
   fini checkpt, close fd in streaming mode and discard the failed
   checkpoint). */

void *
at_checkpt_fini( at_checkpt_t * checkpt );

/* at_checkpt_is_mmio returns 0/1 if checkpt is in streaming/mmio mode.
   Assumes checkpt is valid. */

AT_FN_PURE static inline int at_checkpt_is_mmio( at_checkpt_t const * checkpt ) { return checkpt->fd<0; }

/* at_checkpt_{fd,wbuf,wbuf_sz} return the values used to initialize a
   streaming checkpt.  Assumes checkpt is valid and in streaming mode.  */

AT_FN_PURE static inline int    at_checkpt_fd     ( at_checkpt_t const * checkpt ) { return checkpt->fd;       }
AT_FN_PURE static inline void * at_checkpt_wbuf   ( at_checkpt_t       * checkpt ) { return checkpt->wbuf.mem; }
AT_FN_PURE static inline ulong  at_checkpt_wbuf_sz( at_checkpt_t const * checkpt ) { return checkpt->wbuf.sz;  }

/* at_checkpt_{mmio,mmio_sz} return the values used to initialzie a
   mmio checkpt.  Assumes checkpt is valid and in mmio mode. */

AT_FN_PURE static inline void * at_checkpt_mmio   ( at_checkpt_t       * checkpt ) { return checkpt->mmio.mem; }
AT_FN_PURE static inline ulong  at_checkpt_mmio_sz( at_checkpt_t const * checkpt ) { return checkpt->mmio.sz;  }

/* at_checkpt_{can_open,in_frame} returns 1 if {a frame can be
   opened,the checkpt is in a frame} and 0 otherwise.  A failed checkpt
   is not in a frame but cannot open a new frame.  Assumes checkpt is
   valid. */

AT_FN_PURE static inline int at_checkpt_can_open( at_checkpt_t const * checkpt ) { return !checkpt->frame_style; }
AT_FN_PURE static inline int at_checkpt_in_frame( at_checkpt_t const * checkpt ) { return checkpt->frame_style>0; }

/* at_checkpt_open_advanced opens a new frame.  Different frames in a
   checkpoint can be restored in parallel.  frame_style is a
   AT_CHECKPT_FRAME_STYLE_* that specifies the style of frame to write
   (0 indicates to use AT_CHECKPT_FRAME_STYLE_DEFAULT).  checkpt should
   be valid and openable (not currently in a frame or failed).

   On success, returns AT_CHECKPT_SUCCESS (0).  On return, *_off will
   contain the offset of this frame from the beginning of the
   checkpoint.  This is to allow parallel restore threads to jump to
   frames they are assigned to restore.  Retains no interest in _off.

   On failure, logs details and returns a AT_CHECKPT_ERR (negative).
   *_off will be untouched.  Retains no interest in _off.  Reasons for
   failure include INVAL (NULL checkpt, in a frame, failed), UNSUP
   (unsupported frame style on this target), IO (an i/o error) and COMP
   (a compressor error).  The checkpt (and underlying fd in streaming
   mode) should be considered failed (i.e. the checkpt no longer has
   any interest in checkpointed data and the user should only fini
   checkpt, close fd in streaming mode and discard the failed
   checkpoint).

   IMPORTANT SAFETY TIP!  The returned offset is relative to the start
   of the _checkpoint_, _not_ the start of the _file_.  These are often
   the same but do not have to be (e.g. writing a checkpoint to an
   unseekable file descriptor like stdout, the caller has already
   written other data to the file descriptor before starting the
   checkpoint, etc).

   IMPORTANT SAFETY TIP!  Compression ratios for compressed frames can
   be optimized by putting similar items into the same frame and then
   putting more similar items near each other sequentially.

   at_checkpt_open is a convenience for when the frame offset isn't
   needed. */

int
at_checkpt_open_advanced( at_checkpt_t * checkpt,
                          int            frame_style,
                          ulong *        _off );

static inline int
at_checkpt_open( at_checkpt_t * checkpt,
                 int            frame_style ) {
  ulong off;
  return at_checkpt_open_advanced( checkpt, frame_style, &off );
}

/* at_checkpt_close_advanced closes the current frame.  checkpt should
   be valid and in a frame.

   On success, returns AT_CHECKPT_SUCCESS (0).  On return, *_off will
   contain the offset of one past the last byte of the just closed
   frame.  That is, [off_open,off_close) specify the range of bytes
   relative to the start of the checkpoint used by this frame and
   off_close-off_open is the frame byte size.  This is to facilitate
   parallel checkpoint writing and then concatentating results from
   different threads into a compact checkpoint.  checkpt will no longer
   have any interest in checkpointed data or in _off.

   On failure, logs details and returns a AT_CHECKPT_ERR (negative).  On
   return, *_off will be untouched and checkpoint will have no interest
   in _off.  Reasons for failure include INVAL (NULL checkpt, not in a
   frame), IO (write failed, too many bytes written) and COMP (a
   compressor error).  The checkpt (and underlying fd in streaming mode)
   should be considered failed (i.e. the checkpt no longer has any
   interest in checkpointed data and the user should only fini checkpt,
   close fd in streaming mode and discard the failed checkpoint).

   at_checkpt_close is a convenience for when the frame offset isn't
   needed. */

int
at_checkpt_close_advanced( at_checkpt_t * checkpt,
                           ulong *        _off );

static inline int
at_checkpt_close( at_checkpt_t * checkpt ) {
  ulong off;
  return at_checkpt_close_advanced( checkpt, &off );
}

/* at_checkpt_meta checkpoints the sz byte memory region whose first
   byte in the caller's local address space is pointed to by buf.
   checkpt should be valid and in a frame.  sz should be at most
   AT_CHECKPT_META_MAX.  sz==0 is fine (and buf==NULL if sz==0 is also
   fine).

   On success, returns AT_CHECKPT_SUCCESS (0).  On return, checkpt
   retains no interest in buf.

   On failure, logs details and returns a AT_CHECKPT_ERR (negative).
   Reasons for failure include INVAL (NULL checkpt, not in a frame, NULL
   buf with a non-zero sz, too large sz), IO (write failed, too many
   bytes written) and COMP (compressor error).  The checkpt (and
   underlying fd in streaming mode) should be considered failed (i.e.
   should only fini checkpt, close fd in streaming mode and discard the
   failed checkpoint). */

int
at_checkpt_meta( at_checkpt_t * checkpt,
                 void const *   buf,
                 ulong          sz );

/* at_checkpt_data checkpoints the sz byte memory region whose first
   byte in the caller's local address space is pointed to by buf.
   checkpt should be valid and in a frame.  There is no practical limit
   on sz.  sz==0 is fine (and buf==NULL if sz==0 is also fine).

   On success, returns AT_CHECKPT_SUCCESS (0).  On return, checkpt
   retains an interest in buf until the frame is closed (e.g. buf should
   continue to exist unchanged until the frame is closed).  IMPORTANT
   SAFETY TIP!  AMONG OTHER THINGS, THIS MEANS IT IS UNSAFE TO GATHER
   DATA INTO A TEMP BUFFER, CHECKPT THE TEMP BUFFER AND THEN FREE /
   REUSE THAT TEMP BUFFER BEFORE THE FRAME IS CLOSED!  USE
   AT_CHECKPT_META FOR THAT.

   On failure, logs details and returns a AT_CHECKPT_ERR (negative).
   Reasons for failure include INVAL (NULL checkpt, not in a frame, NULL
   buf with a non-zero sz), IO (write failed, too many bytes written)
   and COMP (compressor error).  The checkpt (and underlying fd in
   streaming mode) should be considered failed (i.e. should only fini
   checkpt, close fd in streaming mode and discard the failed
   checkpoint). */

int
at_checkpt_data( at_checkpt_t * checkpt,
                 void const *   buf,
                 ulong          sz );

/* Restore APIs *******************************************************/

/* at_restore_init_stream formats a memory region, mem, with suitable
   alignment and footprint into a at_restore_t in streaming mode (a
   pointer to a stack declared at_restore_t is fine).  fd is an open
   normal-ish file descriptor usually positioned at the start of the
   first checkpoint frame to read.  rbuf points to the first byte in the
   caller's address space of an unused rbuf_sz byte size memory region
   to use for read buffering.  rbuf_sz should be at least
   AT_RESTORE_RBUF_MIN (it does _not_ need to match the wbuf_sz used to
   make the checkpoint).

   On success, returns mem formatted as a at_restore_t.  On return, the
   at_restore_t will be valid, not in a frame and will have ownership of
   mem, fd, and rbuf.

   On failure, returns NULL (logs details).  No ownership changed. */

at_restore_t *
at_restore_init_stream( void * mem,
                        int    fd,
                        void * rbuf,
                        ulong  rbuf_sz );

/* at_restore_init_mmio is the same as at_restore_init_stream but the
   frames to restore have been memory mapped into the mmio_sz byte
   memory region whose first byte in the caller's local address space is
   pointed to by mmio. */

at_restore_t *
at_restore_init_mmio( void *       mem,
                      void const * mmio,
                      ulong        mmio_sz );

/* at_restore_fini finishes restoring from a checkpoint.  restore should
   be valid and not in a frame.

   On success, returns mem.  On return, restore is no longer valid and
   the caller will have ownership of mem, fd and rbuf (streaming mode)
   or mem and mmio (mmio mode).

   On failure, returns NULL (logs details).  Reasons for failure include
   NULL restore and restore in a frame.  The restore (and underlying fd
   in streaming mode) should be considered failed (i.e. the restore no
   longer has any interest in restored data and the user should only
   fini restore and close fd in streaming mode). */

void *
at_restore_fini( at_restore_t * restore );

/* at_restore_is_mmio returns 0/1 if restore is in streaming/mmio mode.
   Assumes restore is valid. */

AT_FN_PURE static inline int at_restore_is_mmio( at_restore_t const * restore ) { return restore->fd<0; }

/* at_restore_{fd,rbuf,rbuf_sz} return the values used to initialize a
   streaming restore.  Assumes restore is valid and in streaming mode.  */

AT_FN_PURE static inline int    at_restore_fd     ( at_restore_t const * restore ) { return restore->fd;       }
AT_FN_PURE static inline void * at_restore_rbuf   ( at_restore_t       * restore ) { return restore->rbuf.mem; }
AT_FN_PURE static inline ulong  at_restore_rbuf_sz( at_restore_t const * restore ) { return restore->rbuf.sz;  }

/* at_restore_{mmio,mmio_sz} return the values used to initialzie a
   mmio restore.  Assumes restore is valid and in mmio mode. */

AT_FN_PURE static inline void const * at_restore_mmio   ( at_restore_t const * restore ) { return restore->mmio.mem; }
AT_FN_PURE static inline ulong        at_restore_mmio_sz( at_restore_t const * restore ) { return restore->sz;       }

/* at_restore_{can_open,in_frame} returns 1 if {a frame can be
   opened,the restore is in a frame} and 0 otherwise.  A failed restore
   is not in a frame but cannot open a new frame.  Assumes restore is
   valid. */

AT_FN_PURE static inline int at_restore_can_open( at_restore_t const * restore ) { return !restore->frame_style; }
AT_FN_PURE static inline int at_restore_in_frame( at_restore_t const * restore ) { return restore->frame_style>0; }

/* at_restore_sz returns the size of the checkpt (mmio mode == mmio_sz
   <= LONG_MAX, streaming mode with seekable file == at_io_sz <=
   LONG_MAX, streaming mode with a non-seekable file == ULONG_MAX).
   Assumes restore is valid. */

AT_FN_PURE static inline ulong at_restore_sz( at_restore_t const * restore ) { return restore->sz; }

/* at_restore_open_advanced opens a new frame.  Different frames in a
   checkpoint can be restored in parallel.  frame_style is a
   AT_CHECKPT_FRAME_STYLE_* that specifies the style of frame to read (0
   indicates to use AT_CHECKPT_FRAME_STYLE_DEFAULT).  restore should be
   valid and openable (not currently in a frame or failed).

   On success, returns AT_CHECKPT_SUCCESS (0).  On return, *_off will
   contain the offset of this frame from the beginning of the
   checkpoint.  Retains no interest in _off.

   On failure, logs details and returns a AT_CHECKPT_ERR (negative).
   *_off will be untouched.  Retains no interest in _off.  Reasons for
   failure include INVAL (NULL restore, in a frame, failed), UNSUP
   (unsupported frame style on this target), IO (an i/o error) and COMP
   (a decompressor error).  The restore (and underlying fd in streaming
   mode) should be considered failed (i.e. the restore no longer has any
   interest in restored data and the user should only fini restore and
   close fd in streaming mode).

   IMPORTANT SAFETY TIP!  The returned offset is relative to the start
   first byte of the mmio region (mmio mode), first byte of the file
   (seekable file descriptor) or the stream position when the restore
   was initialized (unseekable file descriptor).  These are often the
   same as the first byte of the checkpt but do not have to be (e.g.
   restoring from a file where data was prepended to the file).

   IMPORTANT SAFETY TIP!  frame_style should match the frame_style used
   when the frame was written.

   IMPORTANT SAFETY TIP!  The sequence of restore_open / restore_meta /
   restore_data / restore_close calls should _exactly_ match the
   sequence of checkpt_open / checkpt_meta / checkpt_data /
   checkpt_close used when the frame was created.

   at_restore_open is a convenience for when the frame offset isn't
   needed. */

int
at_restore_open_advanced( at_restore_t * restore,
                          int            frame_style,
                          ulong *        _off );

static inline int
at_restore_open( at_restore_t * restore,
                 int            frame_style ) {
  ulong off;
  return at_restore_open_advanced( restore, frame_style, &off );
}

/* at_restore_close_advanced closes the current frame.  restore should
   be valid and in a frame.

   On success, returns AT_CHECKPT_SUCCESS (0).  On return, *_off will
   contain the offset of one past the last byte of the just closed
   frame.  That is, [off_open,off_close) specify the range of bytes
   relative to the first byte of the mmio region (mmio mode), file
   (streaming mode with a seekable file descriptor) or stream when the
   restore was initialized (streaming mode with unseekable file
   descriptor).  The restore will no longer have any interest in
   restored data or in _off.

   On failure, logs details and returns a AT_CHECKPT_ERR (negative).
   Reasons for failure include INVAL (NULL restore, not in a frame), IO
   (an i/o error) and COMP (a decompressor error).  The restore (and
   underlying fd in streaming mode) should be considered failed (i.e.
   the restore no longer has any interest in restored data or _off and
   the user should only fini restore and close fd in streaming mode).

   IMPORTANT SAFETY TIP!  The sequence of restore_open / restore_meta /
   restore_data / restore_close calls should _exactly_ match the
   sequence of checkpt_open / checkpt_meta / checkpt_data /
   checkpt_close used when the frame was created.

   at_restore_close is a convenience for when the frame offset isn't
   needed. */

int
at_restore_close_advanced( at_restore_t * restore,
                           ulong *        _off );

static inline int
at_restore_close( at_restore_t * restore ) {
  ulong off;
  return at_restore_close_advanced( restore, &off );
}

/* at_restore_seek sets the restore to the position offset.  restore
   should be valid, openable and seekable, offset should be in [0,sz].
   In streaming mode, seeking may flush underlying read-ahead-buffering
   and thus should be minimized.

   On success, returns AT_CHECKPT_SUCCESS (0).  On return, the restore
   will be ready to open the frame at off.

   On failure, logs details and returns a AT_CHECKPT_ERR (negative).
   Reasons for failure include INVAL (NULL restore, not openable, not
   seekable, offset past end of file), IO (underlying error seeking the
   descriptor) The restore (and underlying fd in streaming mode) should
   be considered failed (i.e. the restore no longer has any interest in
   restored data and the user should only fini restore and close fd in
   streaming mode).

   IMPORTANT SAFETY TIP!  This offset is relative to the first byte of
   the mmio region (mmio mode) or the file (streaming mode with a
   seekable file descriptor). */

int
at_restore_seek( at_restore_t * restore,
                 ulong          off );

/* at_restore_meta restores sz bytes to the memory region whose first
   byte in the caller's local address space is pointed to by buf.
   restore should be valid and in a frame.  sz should be at most
   AT_RESTORE_META_MAX.  sz==0 is fine (and buf==NULL if sz==0 is also
   fine).

   On success, returns AT_CHECKPT_SUCCESS (0).  On return, the restored
   data will be in buf and the restore retains no interest in buf.

   On failure, logs details and returns a AT_CHECKPT_ERR (negative).
   Reasons for failure include INVAL (NULL restore, not in a frame, NULL
   buf with a non-zero sz, too large sz), IO (read failed, too many
   bytes read) and COMP (a decompressor error).  The restore (and
   underlying fd in streaming mode) should be considered failed (i.e.
   the restore no longer has any interest in restored data and the user
   should only fini restore and close fd in streaming mode).

   IMPORTANT SAFETY TIP!  The sequence of restore_open / restore_meta /
   restore_data / restore_close calls should _exactly_ match the
   sequence of checkpt_open / checkpt_meta / checkpt_data /
   checkpt_close used when the frame was created. */

int
at_restore_meta( at_restore_t * restore,
                 void *         buf,
                 ulong          sz );

/* at_restore_data restores sz bytes to the memory region whose first
   byte in the caller's local address space is pointed to by buf.
   restore should be valid and in a frame.  There is no practical
   limitation on sz.  sz==0 is fine (and buf==NULL if sz==0 is also
   fine).

   On success, returns AT_CHECKPT_SUCCESS (0).  On return, the restore
   retains an interest in buf until the frame close (e.g. buf should
   continue to exist and be untouched until the frame close) and the
   data in it may not be available until frame close.  IMPORTANT SAFETY
   TIP!  AMONG OTHER THINGS, THIS IMPLIES RESTORED DATA REGIONS SHOULD
   NOT OVERLAP AND THAT IT IS UNSAFE TO RESTORE DATA TO A TEMP BUFFER,
   SCATTER DATA FROM THE TEMP BUFFER AND THEN FREE / REUSE THAT TEMP
   BUFFER BEFORE THE FRAME IS CLOSED!  USE AT_RESTORE_META FOR THIS
   CASE.

   On failure, logs details and returns a AT_CHECKPT_ERR (negative).
   Reasons for failure include INVAL (NULL restore, not in a frame, NULL
   buf with a non-zero sz), IO (read failed, too many bytes read) and
   COMP (a decompressor error).  The restore (and underlying fd in
   streaming mode) should be considered failed (i.e. the restore no
   longer has any interest in restored data and the user should only
   fini restore and close fd in streaming mode).

   IMPORTANT SAFETY TIP!  The sequence of restore_open / restore_meta /
   restore_data / restore_close calls should _exactly_ match the
   sequence of checkpt_open / checkpt_meta / checkpt_data /
   checkpt_close used when the frame was created. */

int
at_restore_data( at_restore_t * restore,
                 void *         buf,
                 ulong          sz );

/* Misc APIs **********************************************************/

/* at_checkpt_frame_style_is_supported returns 1 if the given
   frame_style is supported on this target and 0 otherwise. */

AT_FN_CONST int at_checkpt_frame_style_is_supported( int frame_style );

/* at_checkpt_strerror converts a AT_CHECKPT_SUCCESS / AT_CHECKPT_ERR_*
   code into a human readable cstr.  The lifetime of the returned
   pointer is infinite.  The returned pointer is always to a non-NULL
   cstr. */

char const *
at_checkpt_strerror( int err );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_checkpt_at_checkpt_h */