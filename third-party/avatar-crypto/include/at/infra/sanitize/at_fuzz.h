#ifndef HEADER_at_src_util_sanitize_at_fuzz_h
#define HEADER_at_src_util_sanitize_at_fuzz_h

#include "../at_util_base.h"

#if AT_HAS_COVERAGE
#define AT_FUZZ_MUST_BE_COVERED ((void) 0)
#else
#define AT_FUZZ_MUST_BE_COVERED
#endif

AT_PROTOTYPES_BEGIN

ulong
LLVMFuzzerMutate( uchar * data,
                  ulong   data_sz,
                  ulong   max_sz );

AT_PROTOTYPES_END

#endif /* HEADER_at_src_util_sanitize_at_fuzz_h */