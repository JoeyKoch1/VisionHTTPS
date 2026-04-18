#ifndef VISION_MEM_ARENA_H
#define VISION_MEM_ARENA_H

#include "vision/platform.h"

/*
 * Arena allocator — bump pointer, O(1) alloc, O(1) free-all.
 * Perfect for per-request scratch memory: allocate freely during
 * request lifetime, reset the entire arena when the request is done.
 *
 * No free() of individual allocations. Reset via vision_arena_reset().
 */

typedef struct VisionArena {
    u8*   base;      /* start of the backing buffer                */
    usize size;      /* total capacity in bytes                    */
    usize offset;    /* current bump pointer offset                */
    usize peak;      /* high-water mark (for diagnostics)          */
} VisionArena;

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize an arena over a pre-allocated buffer (no OS call here) */
void  vision_arena_init(VisionArena* a, void* buf, usize size);

/* Allocate `n` bytes aligned to `align` (must be power of 2) */
void* vision_arena_alloc(VisionArena* a, usize n, usize align);

/* Convenience: allocate zeroed */
void* vision_arena_calloc(VisionArena* a, usize n, usize align);

/* Reset offset to 0 — all previous allocations invalidated */
void  vision_arena_reset(VisionArena* a);

/* How many bytes are still available */
usize vision_arena_remaining(const VisionArena* a);

#ifdef __cplusplus
}
#endif

#endif /* VISION_MEM_ARENA_H */
