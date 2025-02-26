#include "cache_flush.h"

#include <stdlib.h>

#if defined __aarch64__

// Data chosen for a Raspberry pi 4.
#define CACHE_MULTIPLIER 2
#define CACHE_SIZE ((32 + 1024) * 1024 * CACHE_MULTIPLIER)
#define CACHE_LINE_SIZE 64

#elif defined __x86_64__

// Data chosen for an I7 8700K.
#define CACHE_MULTIPLIER 2
#define CACHE_SIZE ((32 + 256) * 1024 * CACHE_MULTIPLIER)
#define CACHE_LINE_SIZE 64

#else

// Fall back cache values
#define CACHE_MULTIPLIER 2
#define CACHE_SIZE (32 * 1024 * CACHE_MULTIPLIER)
#define CACHE_LINE_SIZE 32

#endif

static volatile char cache[CACHE_SIZE];
void flush_cache()
{
    static size_t dummy_value = 0;
    // You can use this pragma to control how many times a loop should be unrolled. It must be
    // placed immediately before a for, while or do loop or a #pragma GCC ivdep, and applies only to
    // the loop that follows. n is an integer constant expression specifying the unrolling factor.
    // The values of 0 and 1 block any unrolling of the loop.
    // Reference:
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#index-pragma-GCC-unroll-n
#if defined __aarch64__
#pragma GCC unroll((64 + 1024) * 1024 * 2 / 64)
#elif defined __x86_64__
#pragma GCC unroll((32 + 256) * 1024 * 2 / 64)
#else
#pragma GCC unroll((32 * 1024 * 2) / 32)
#endif
    for (size_t cache_line_start = 0; cache_line_start < CACHE_SIZE;
         cache_line_start += CACHE_LINE_SIZE)
    {
        // Writing to the middle-ish of the cache line. It might not be necessary, but it could
        // help ensure that a whole new cache line will be copied to the cache;
        size_t index = cache_line_start + CACHE_LINE_SIZE / 2;
        cache[index] = (char)(dummy_value++);
    }
}
