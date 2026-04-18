#ifndef VISION_MEM_SLAB_H
#define VISION_MEM_SLAB_H

#include "vision/platform.h"

/*
 * Slab allocator — fixed-size object pool.
 * O(1) alloc and free via a freelist embedded in the objects themselves.
 *
 * Use case: connection structs, TLS sessions, HTTP streams — anything
 * that gets created and destroyed at high frequency with a known size.
 *
 * The slab does NOT call the OS. You give it a backing buffer at init time.
 */

typedef struct VisionSlabFree {
    struct VisionSlabFree* next;   /* intrusive freelist pointer */
} VisionSlabFree;

typedef struct VisionSlab {
    u8*            base;           /* backing buffer                    */
    usize          obj_size;       /* size of each object (bytes)       */
    usize          capacity;       /* total number of objects           */
    usize          in_use;         /* currently allocated objects       */
    VisionSlabFree* freelist;      /* head of the free chain            */
} VisionSlab;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize slab over `buf` for `capacity` objects of `obj_size` bytes.
 * obj_size must be >= sizeof(pointer) so the freelist node fits.
 */
void  vision_slab_init(VisionSlab* s, void* buf, usize obj_size, usize capacity);

/* Grab one object. Returns NULL if pool is exhausted. */
void* vision_slab_alloc(VisionSlab* s);

/* Return one object to the pool. ptr MUST have come from this slab. */
void  vision_slab_free(VisionSlab* s, void* ptr);

#ifdef __cplusplus
}
#endif

#endif /* VISION_MEM_SLAB_H */
