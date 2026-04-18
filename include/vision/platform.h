#ifndef VISION_PLATFORM_H
#define VISION_PLATFORM_H

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed   char      i8;
typedef signed   short     i16;
typedef signed   int       i32;
typedef signed   long long i64;
typedef u64                usize;
typedef i64                isize;
typedef u8                 bool8;

#define VISION_TRUE  ((bool8)1)
#define VISION_FALSE ((bool8)0)
#define VISION_NULL  ((void*)0)
#if defined(VISION_OS_WIN32)
#  define VISION_API   __declspec(dllexport)
#  define VISION_CALL  __cdecl
#else
#  define VISION_API   __attribute__((visibility("default")))
#  define VISION_CALL
#endif

#if defined(_MSC_VER)
#  define VISION_INLINE __forceinline
#else
#  define VISION_INLINE __attribute__((always_inline)) inline
#endif

#if defined(_MSC_VER)
#  define VISION_UNREACHABLE() __assume(0)
#else
#  define VISION_UNREACHABLE() __builtin_unreachable()
#endif

#if defined(VISION_OS_WIN32)
   typedef u64 vision_socket_t;
#  define VISION_INVALID_SOCKET ((vision_socket_t)(~0ULL))
#else
   typedef i32 vision_socket_t;
#  define VISION_INVALID_SOCKET ((vision_socket_t)(-1))
#endif

#ifdef __cplusplus
extern "C" {
#endif

vision_socket_t vision_socket_create(i32 af, i32 type, i32 proto);
i32             vision_socket_bind(vision_socket_t s, const void* addr, u32 addrlen);
i32             vision_socket_listen(vision_socket_t s, i32 backlog);
vision_socket_t vision_socket_accept(vision_socket_t s, void* addr, u32* addrlen);
isize           vision_socket_read(vision_socket_t s, void* buf, usize len);
isize           vision_socket_write(vision_socket_t s, const void* buf, usize len);
i32             vision_socket_close(vision_socket_t s);
i32             vision_socket_setnonblock(vision_socket_t s);

void            vision_exit(i32 code);

void*           vision_memset(void* dst, i32 val, usize n);
void*           vision_memcpy(void* dst, const void* src, usize n);
i32             vision_memcmp(const void* a, const void* b, usize n);

#ifdef __cplusplus
}
#endif

#endif
