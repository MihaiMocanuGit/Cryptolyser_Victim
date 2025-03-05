#include "cache_flush.h"

#include <stdatomic.h>
#include <stdlib.h>

#if defined __aarch64__

// Data chosen for a Raspberry pi 4.
#define CACHE_MULTIPLIER 2
#define CACHE_SIZE ((32 + 1024) * 1024 * CACHE_MULTIPLIER)
#define CACHE_LINE_SIZE 64
#define HEAP_CACHE_LINES 16

#elif defined __x86_64__

// Data chosen for an I7 8700K.
#define CACHE_MULTIPLIER 2
#define CACHE_SIZE ((32 + 256) * 1024 * CACHE_MULTIPLIER)
#define CACHE_LINE_SIZE 64
#define HEAP_CACHE_LINES 16

#else

// Fall back cache values
#define CACHE_MULTIPLIER 2
#define CACHE_SIZE (32 * 1024 * CACHE_MULTIPLIER)
#define CACHE_LINE_SIZE 32
#define HEAP_CACHE_LINES 16

#endif

static volatile char cache[CACHE_SIZE];
void flush_cache()
{
    atomic_thread_fence(memory_order_seq_cst);
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
    // Allocating some cache line arrays in order to hopefully touch a few different memory
    // regions (set associative cache).
    volatile char **cache_lines = calloc(HEAP_CACHE_LINES, sizeof(char *));
    for (int i = 0; i < HEAP_CACHE_LINES; ++i)
    {
        cache_lines[i] = malloc(CACHE_LINE_SIZE);
        if (!cache_lines[i])
            goto cleanup;
        cache_lines[i][CACHE_LINE_SIZE / 2] = cache[i * CACHE_LINE_SIZE + CACHE_LINE_SIZE / 2];
    }
// Freeing after all the malloc calls have been executed as we don't want the OS to reuse the
// same memory addresses. This is the main reason behind the memory barrier.
cleanup:
    for (int i = 0; i < HEAP_CACHE_LINES; ++i)
    {
        free((char *)cache_lines[i]);
    }
    free(cache_lines);
    atomic_thread_fence(memory_order_seq_cst);
}
