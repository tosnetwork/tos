#ifndef HEADER_at_disco_keyguard_at_keyload_h
#define HEADER_at_disco_keyguard_at_keyload_h

/* at_keyload.h - Secure key loading utilities

   Provides secure key loading with protected memory pages that:
   - Will not appear in core dumps
   - Will not be paged out to disk
   - Are protected by guard pages
   - Are wiped on fork */

#include "at/infra/tiles/at_disco_base.h"

AT_PROTOTYPES_BEGIN

/* at_keyload_read() reads a JSON encoded keypair from the provided file
   descriptor. The key_path is not opened or read from, it is only used
   to output diagnostic error messages if reading the key fails.

   The keypair provided must be a full page (4096) bytes, not just 64
   bytes, as additional metadata will be temporarily stored in it while
   reading and parsing the key.

   If the key data from the file descriptor is not parsable, or any IO
   or other error is encountered while reading it, the process will be
   terminated with an error message. */

uchar * AT_FN_SENSITIVE
at_keyload_read( int          key_fd,
                 char const * key_path,
                 uchar *      keypair );

/* at_keyload_load() reads the key file from disk and stores the parsed
   contents in a specially mapped page in memory that will not appear in
   core dumps, will not be paged out to disk, is readonly, and is
   protected by guard pages that cannot be accessed.

   key_path must point to the first letter in a NUL-terminated cstr that
   is the path on disk of the key file. The key file must exist, be
   readable, and have the form of a keypair (64 element JSON array of
   bytes). If public_key_only is non-zero, zeros out the private part
   of the key and returns a pointer to the first byte (of 32) of the
   public part of the key in binary format. If public_key_only is zero,
   returns a pointer to the first byte (of 64) of the key in binary
   format.

   If the key file is not found, is not parsable, or any IO or other
   error is encountered while reading it, the process will be terminated
   with an error message. */

uchar * AT_FN_SENSITIVE
at_keyload_load( char const * key_path,
                 int          public_key_only );

/* at_keyload_unload() unloads a key from shared memory that was loaded
   with at_keyload_load. The argument public_key_only must match the
   one provided when the key was loaded. The key should not be accessed
   once this function returns and the memory is no longer valid. */

void AT_FN_SENSITIVE
at_keyload_unload( uchar const * key,
                   int           public_key_only );

/* at_keyload_alloc_protected_pages allocates `page_cnt` regular (4 kB)
   pages of memory protected by `guard_page_cnt` pages of unreadable and
   unwritable memory on each side. Additionally the OS is configured so
   that the page_cnt pages in the middle will not be paged out to disk
   in a swap file, appear in core dumps, and will be wiped on fork so it
   is not readable by any child process forked off from this process.
   Terminates the calling process with AT_LOG_ERR with details if the
   operation fails. Returns a pointer to the first byte of the
   protected memory. Precisely, if ptr is the returned pointer, then
   ptr[i] for i in [0, 4096*page_cnt) is readable and writable, but
   ptr[i] for i in [-4096*guard_page_cnt, 0) U [4096*page_cnt,
   4096*(page_cnt+guard_page_cnt) ) will cause a SIGSEGV. For current
   use cases, there's no use in freeing the pages allocated by this
   function, so no free function is provided. */

void * AT_FN_SENSITIVE
at_keyload_alloc_protected_pages( ulong page_cnt,
                                  ulong guard_page_cnt );

AT_PROTOTYPES_END

#endif /* HEADER_at_disco_keyguard_at_keyload_h */