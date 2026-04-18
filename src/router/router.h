#ifndef VISION_ROUTER_H
#define VISION_ROUTER_H

#include "vision/platform.h"
#include "../http/parser.h"

/*
 * Route handler function signature.
 * Returns bytes written to out, or -1 on error.
 */
typedef isize (*VisionRouteHandler)(const HttpRequest* req,
                                    u8* out, usize out_cap);

/*
 * Middleware function.
 * Return 0 to continue the chain, nonzero to abort (triggers 403).
 */
typedef i32 (*VisionMiddlewareFn)(const HttpRequest* req);

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize router (clears trie + middleware chain) */
i32   vision_router_init(void);

/* Register a route: e.g. vision_router_add(HTTP_METHOD_GET, "/api/health", handler) */
i32   vision_router_add(HttpMethod method, const char* path,
                         VisionRouteHandler handler);

/* Add a middleware to the chain (executed before handler) */
void  vision_router_use(VisionMiddlewareFn fn);

/* Dispatch a parsed request to the matching handler */
isize vision_router_dispatch(const HttpRequest* req, u8* out, usize out_cap);

#ifdef __cplusplus
}
#endif

#endif /* VISION_ROUTER_H */
