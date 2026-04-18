/*
 * tests/test_mem.c
 * Arena and slab allocator unit tests.
 */
#include "../src/mem/arena.h"
#include "../src/mem/slab.h"
#include "vision/platform.h"

int test_mem(void) {
    /* ── Arena tests ──────────────────────────────────────────────── */
    u8 backing[1024];
    VisionArena arena;
    vision_arena_init(&arena, backing, sizeof(backing));

    /* Basic alloc */
    void* p1 = vision_arena_alloc(&arena, 64, 8);
    if (!p1) return 1;
    if ((usize)p1 % 8 != 0) return 2;   /* alignment check */

    /* Second alloc — must be after first */
    void* p2 = vision_arena_alloc(&arena, 128, 16);
    if (!p2) return 3;
    if ((usize)p2 % 16 != 0) return 4;
    if ((u8*)p2 <= (u8*)p1) return 5;   /* must advance */

    /* Calloc must be zeroed */
    u8* p3 = (u8*)vision_arena_calloc(&arena, 32, 8);
    if (!p3) return 6;
    for (i32 i = 0; i < 32; i++) if (p3[i] != 0) return 7;

    /* Reset — offset should go back to 0 */
    vision_arena_reset(&arena);
    if (arena.offset != 0) return 8;
    if (arena.peak < 64 + 128 + 32) return 9; /* peak preserved */

    /* Overflow detection — asking for more than backing allows */
    void* huge = vision_arena_alloc(&arena, 2000, 1);
    if (huge != VISION_NULL) return 10;  /* must return NULL */

    /* ── Slab tests ───────────────────────────────────────────────── */
    typedef struct { u64 a; u64 b; } Obj;
    u8 slab_buf[sizeof(Obj) * 8];
    VisionSlab slab;
    vision_slab_init(&slab, slab_buf, sizeof(Obj), 8);

    if (slab.in_use != 0) return 20;

    Obj* objs[8];
    for (i32 i = 0; i < 8; i++) {
        objs[i] = (Obj*)vision_slab_alloc(&slab);
        if (!objs[i]) return 21;
        if (objs[i]->a != 0 || objs[i]->b != 0) return 22; /* zeroed */
        objs[i]->a = (u64)i;
    }
    if (slab.in_use != 8) return 23;

    /* Pool exhausted — next alloc must return NULL */
    Obj* overflow = (Obj*)vision_slab_alloc(&slab);
    if (overflow != VISION_NULL) return 24;

    /* Free one — must be reclaimable */
    vision_slab_free(&slab, objs[3]);
    if (slab.in_use != 7) return 25;

    Obj* reused = (Obj*)vision_slab_alloc(&slab);
    if (!reused) return 26;
    if (slab.in_use != 8) return 27;

    return 0;
}
