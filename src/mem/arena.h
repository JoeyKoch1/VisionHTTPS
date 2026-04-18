#ifndef VISION_MEM_ARENA_H
#define VISION_MEM_ARENA_H

#include "vision/platform.h"

typedef struct VisionArena {
    u8*   base;
    usize size;
    usize offset;
    usize peak;
} VisionArena;

#ifdef __cplusplus
extern "C" {
#endif

void  vision_arena_init(VisionArena* a, void* buf, usize size);

void* vision_arena_alloc(VisionArena* a, usize n, usize align);

void* vision_arena_calloc(VisionArena* a, usize n, usize align);

void  vision_arena_reset(VisionArena* a);

usize vision_arena_remaining(const VisionArena* a);

#ifdef __cplusplus
}
#endif

#endif
