#ifndef VISION_MEM_SLAB_H
#define VISION_MEM_SLAB_H

#include "vision/platform.h"

typedef struct VisionSlabFree {
    struct VisionSlabFree* next;
} VisionSlabFree;

typedef struct VisionSlab {
    u8*            base;
    usize          obj_size;
    usize          capacity;
    usize          in_use;
    VisionSlabFree* freelist;
} VisionSlab;

#ifdef __cplusplus
extern "C" {
#endif

void  vision_slab_init(VisionSlab* s, void* buf, usize obj_size, usize capacity);

void* vision_slab_alloc(VisionSlab* s);

void  vision_slab_free(VisionSlab* s, void* ptr);

#ifdef __cplusplus
}
#endif

#endif
