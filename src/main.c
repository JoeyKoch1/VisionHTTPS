#include "vision/platform.h"
#include "config.h"
#include "net/connection.h"
#include "router/router.h"
#include "http/parser.h"

extern void vision_cpu_detect(void);

extern int  vision_net_init(u16 port);
extern void vision_net_run(void);

static isize handle_health(const HttpRequest* req, u8* out, usize cap) {
    (void)req;
    return vision_http_respond_text(200, "{\"status\":\"ok\",\"server\":\"Vision/0.1\"}\r\n", out, cap);
}

static isize handle_echo(const HttpRequest* req, u8* out, usize cap) {
    static const char prefix[] = "{\"echo\":\"";
    static const char suffix[] = "\"}\r\n";
    u8 body[1024];
    usize off = 0;
    usize pl = sizeof(prefix) - 1;
    usize sl = sizeof(suffix) - 1;
    vision_memcpy(body, prefix, pl); off += pl;
    usize bl = req->body_len < (sizeof(body) - pl - sl - 1)
               ? req->body_len : (sizeof(body) - pl - sl - 1);
    vision_memcpy(body + off, req->body, bl); off += bl;
    vision_memcpy(body + off, suffix, sl);    off += sl;

    HttpResponse resp;
    vision_memset(&resp, 0, sizeof(resp));
    resp.status_code = 200;
    resp.reason      = "OK";
    const char* ct = "Content-Type: application/json\r\n";
    usize ctl = 32;
    vision_memcpy(resp.headers_buf, ct, ctl);
    resp.headers_len = ctl;
    resp.body     = body;
    resp.body_len = off;
    return vision_http_respond(&resp, out, cap);
}

static isize handle_index(const HttpRequest* req, u8* out, usize cap) {
    (void)req;
    static const char html[] =
        "<!DOCTYPE html><html><head><title>Vision HTTPS</title></head>"
        "<body><h1>Vision HTTPS is running</h1>"
        "<p>Zero extern. Pure assembly + C. No libc.</p>"
        "</body></html>\r\n";
    return vision_http_respond_text(200, html, out, cap);
}

static VisionConfig g_config;

static int vision_init(void) {
    vision_cpu_detect();
    if (vision_config_load("vision.conf", &g_config) != 0) {
        g_config.port            = 8443;
        g_config.backlog         = 128;
        g_config.max_connections = 4096;
    }
    vision_config_load_certs(&g_config);

    vision_router_init();
    vision_router_add(HTTP_METHOD_GET,  "/",            handle_index);
    vision_router_add(HTTP_METHOD_GET,  "/health",      handle_health);
    vision_router_add(HTTP_METHOD_POST, "/echo",        handle_echo);

    int rc = vision_net_init(g_config.port);
    if (rc != 0) return rc;

    return 0;
}

void vision_main(void) {
    if (vision_init() != 0) vision_exit(1);
    vision_net_run();   /* blocks forever */
    vision_exit(0);
}

#if defined(VISION_OS_LINUX) || defined(VISION_OS_MACOS)
void _start(void) {
    vision_main();
}
#endif

#if defined(VISION_OS_WIN32)
void __stdcall vision_winmain(void) {
    vision_main();
}
#endif
