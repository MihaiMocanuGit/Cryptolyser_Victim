#include "cache_flush.h"

#include <stdlib.h>

#if defined __aarch64__

#define RASPBERRY_CACHE_MULTIPLIER 4
#define RASPBERRY_CACHE_SIZE ((64 + 512) * 1024 * RASPBERRY_CACHE_MULTIPLIER)
#define RASPBERRY_CACHE_LINE_SIZE 64

void flush_cache()
{
    void *ptr = NULL; // temporary non-volatile ptr just for posix_memalign.
    // aligns the requested heap memory to 64 bytes.
    if (posix_memalign(&ptr, RASPBERRY_CACHE_LINE_SIZE, RASPBERRY_CACHE_SIZE) != 0)
        return;
    // forcing the memory to be volatile now.
    volatile char *cache_flush = (volatile char *)ptr;

    static size_t dummy_value = 0;
    // You can use this pragma to control how many times a loop should be unrolled. It must be
    // placed immediately before a for, while or do loop or a #pragma GCC ivdep, and applies only to
    // the loop that follows. n is an integer constant expression specifying the unrolling factor.
    // The values of 0 and 1 block any unrolling of the loop.
    // Reference:
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#index-pragma-GCC-unroll-n
#pragma GCC unroll((64 + 512) * 1024 * 4 / 64)
    for (size_t cache_line_start = 0; cache_line_start < RASPBERRY_CACHE_SIZE;
         cache_line_start += RASPBERRY_CACHE_LINE_SIZE)
    {
        // Writing to the middle-ish of the cache line. It might not be necessary, but it could
        // help ensure that a whole new cache line will be copied to the cache;
        size_t index = cache_line_start + RASPBERRY_CACHE_LINE_SIZE / 2;
        cache_flush[index] = (char)(dummy_value++);
    }

    free((void *)cache_flush);
}

#elif defined __x86_64__

#define X64_CACHE_MULTIPLIER 2
// data chosen for an I7 8700K.
#define X64_CACHE_SIZE ((32 + 256) * 1024 * X64_CACHE_MULTIPLIER)
#define X64_CACHE_LINE_SIZE 64

void flush_cache()
{
    void *ptr = NULL; // temporary non-volatile ptr just for posix_memalign.
    // aligns the requested heap memory to 64 bytes
    if (posix_memalign(&ptr, X64_CACHE_LINE_SIZE, X64_CACHE_SIZE) != 0)
        return;
    // forcing the memory to be volatile now.
    volatile char *cache_flush = (volatile char *)ptr;

    static size_t dummy_value = 0;
    // You can use this pragma to control how many times a loop should be unrolled. It must be
    // placed immediately before a for, while or do loop or a #pragma GCC ivdep, and applies only to
    // the loop that follows. n is an integer constant expression specifying the unrolling factor.
    // The values of 0 and 1 block any unrolling of the loop.
    // Reference:
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#index-pragma-GCC-unroll-n
#pragma GCC unroll((32 + 256) * 1024 * 2 / 64)
    for (size_t cache_line_start = 0; cache_line_start < X64_CACHE_SIZE;
         cache_line_start += X64_CACHE_LINE_SIZE)
    {
        // Writing to the middle-ish of the cache line. It might not be necessary, but it could
        // help ensure that a whole new cache line will be copied to the cache;
        size_t index = cache_line_start + X64_CACHE_LINE_SIZE / 2;
        cache_flush[index] = (char)(dummy_value++);
    }

    free((void *)cache_flush);
}

#else

// Fall back cache values
#define UNKNOWN_CACHE_MULTIPLIER 2
#define UNKNOWN_CACHE_SIZE (32 * 1024 * X64_CACHE_MULTIPLIER)
#define UNKNOWN_CACHE_LINE_SIZE 32

void flush_cache()
{
    void *ptr = NULL; // temporary non-volatile ptr just for posix_memalign.
    // aligns the requested heap memory to UNKNOWN_CACHE_LINE_SIZE bytes
    if (posix_memalign(&ptr, UNKNOWN_CACHE_LINE_SIZE, UNKNOWN_CACHE_SIZE) != 0)
        return;
    // forcing the memory to be volatile now.
    volatile char *cache_flush = (volatile char *)ptr;

    static size_t dummy_value = 0;
    // You can use this pragma to control how many times a loop should be unrolled. It must be
    // placed immediately before a for, while or do loop or a #pragma GCC ivdep, and applies only to
    // the loop that follows. n is an integer constant expression specifying the unrolling factor.
    // The values of 0 and 1 block any unrolling of the loop.
    // Reference:
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#index-pragma-GCC-unroll-n
#pragma GCC unroll((32 * 1024 * 2) / 32)
    for (size_t cache_line_start = 0; cache_line_start < UNKNOWN_CACHE_SIZE;
         cache_line_start += UNKNOWN_CACHE_LINE_SIZE)
    {
        // Writing to the middle-ish of the cache line. It might not be necessary, but it could
        // help ensure that a whole new cache line will be copied to the cache;
        size_t index = cache_line_start + UNKNOWN_CACHE_LINE_SIZE / 2;
        cache_flush[index] = (char)(dummy_value++);
    }

    free((void *)cache_flush);
}

#endif
