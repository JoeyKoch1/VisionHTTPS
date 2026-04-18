#ifndef VISION_ROUTER_H
#define VISION_ROUTER_H

#include "vision/platform.h"
#include "../http/parser.h"

typedef isize (*VisionRouteHandler)(const HttpRequest* req,
                                    u8* out, usize out_cap);

typedef i32 (*VisionMiddlewareFn)(const HttpRequest* req);

#ifdef __cplusplus
extern "C" {
#endif

i32   vision_router_init(void);

i32   vision_router_add(HttpMethod method, const char* path,
                         VisionRouteHandler handler);

void  vision_router_use(VisionMiddlewareFn fn);

isize vision_router_dispatch(const HttpRequest* req, u8* out, usize out_cap);

#ifdef __cplusplus
}
#endif

#endif
