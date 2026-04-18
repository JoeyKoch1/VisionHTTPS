#include "arena.h"
#include "vision/platform.h"

void vision_arena_init(VisionArena* a, void* buf, usize size) {
    a->base   = (u8*)buf;
    a->size   = size;
    a->offset = 0;
    a->peak   = 0;
}

void* vision_arena_alloc(VisionArena* a, usize n, usize align) {
    usize cur     = (usize)(a->base + a->offset);
    usize aligned = (cur + (align - 1)) & ~(align - 1);
    usize new_off = (aligned - (usize)a->base) + n;

    if (new_off > a->size) {
        return VISION_NULL;
    }

    a->offset = new_off;
    if (a->offset > a->peak) a->peak = a->offset;

    return (void*)aligned;
}

void* vision_arena_calloc(VisionArena* a, usize n, usize align) {
    void* ptr = vision_arena_alloc(a, n, align);
    if (ptr) vision_memset(ptr, 0, n);
    return ptr;
}

void vision_arena_reset(VisionArena* a) {
    a->offset = 0;
}

usize vision_arena_remaining(const VisionArena* a) {
    return a->size - a->offset;
}
