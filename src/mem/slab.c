/*
 * src/mem/slab.c
 * Fixed-size object pool with O(1) alloc/free via embedded freelist.
 */
#include "slab.h"
#include "vision/platform.h"

void vision_slab_init(VisionSlab* s, void* buf, usize obj_size, usize capacity) {
    /* obj_size must hold at least a pointer for the freelist node */
    if (obj_size < sizeof(VisionSlabFree)) {
        obj_size = sizeof(VisionSlabFree);
    }

    s->base      = (u8*)buf;
    s->obj_size  = obj_size;
    s->capacity  = capacity;
    s->in_use    = 0;
    s->freelist  = VISION_NULL;

    /* Chain all slots into the freelist */
    for (usize i = 0; i < capacity; i++) {
        VisionSlabFree* node = (VisionSlabFree*)(s->base + i * obj_size);
        node->next  = s->freelist;
        s->freelist = node;
    }
}

void* vision_slab_alloc(VisionSlab* s) {
    if (!s->freelist) return VISION_NULL;

    VisionSlabFree* node = s->freelist;
    s->freelist = node->next;
    s->in_use++;

    /* Zero the object before handing it out — no stale data leaks */
    vision_memset(node, 0, s->obj_size);
    return (void*)node;
}

void vision_slab_free(VisionSlab* s, void* ptr) {
    if (!ptr) return;
    VisionSlabFree* node = (VisionSlabFree*)ptr;
    node->next  = s->freelist;
    s->freelist = node;
    s->in_use--;
}
