#ifndef VISION_HTTP_PARSER_H
#define VISION_HTTP_PARSER_H

#include "vision/platform.h"

#define HTTP_MAX_HEADERS     64
#define HTTP_MAX_METHOD_LEN  16
#define HTTP_MAX_PATH_LEN    2048
#define HTTP_MAX_HEADER_NAME 256
#define HTTP_MAX_HEADER_VAL  4096

typedef enum {
    HTTP_METHOD_GET     = 0,
    HTTP_METHOD_POST    = 1,
    HTTP_METHOD_PUT     = 2,
    HTTP_METHOD_DELETE  = 3,
    HTTP_METHOD_HEAD    = 4,
    HTTP_METHOD_OPTIONS = 5,
    HTTP_METHOD_PATCH   = 6,
    HTTP_METHOD_UNKNOWN = 7,
} HttpMethod;

typedef struct {
    const u8* name;   /* pointer into raw buffer — NOT null-terminated */
    usize     name_len;
    const u8* value;
    usize     value_len;
} HttpHeader;

typedef enum {
    HTTP_PARSE_INCOMPLETE = 0,   /* need more data        */
    HTTP_PARSE_COMPLETE   = 1,   /* full request parsed   */
    HTTP_PARSE_ERROR      = -1,  /* malformed request     */
} HttpParseResult;

typedef struct {
    /* Request line */
    HttpMethod method;
    const u8*  path;
    usize      path_len;
    u8         version_minor;    /* 0 = HTTP/1.0, 1 = HTTP/1.1 */

    /* Headers (pointers into the raw buffer) */
    HttpHeader headers[HTTP_MAX_HEADERS];
    u32        header_count;

    /* Body */
    const u8*  body;
    usize      body_len;
    usize      content_length;   /* from Content-Length header, 0 if none */
    bool8      chunked;          /* Transfer-Encoding: chunked */

    /* Bytes consumed from the input buffer */
    usize      consumed;
} HttpRequest;

typedef struct {
    u8    status_code_str[4];    /* "200", "404", etc. */
    u16   status_code;
    const char* reason;

    u8    headers_buf[4096];
    usize headers_len;

    const u8* body;
    usize     body_len;
} HttpResponse;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Zero-copy HTTP/1.1 request parser.
 * Operates directly on the raw network buffer — no allocations.
 * All string fields in HttpRequest point into buf[0..len].
 */
HttpParseResult vision_http_parse(const u8* buf, usize len, HttpRequest* req);

/*
 * Serialize an HTTP response into dst.
 * Returns bytes written or -1 if dst_cap insufficient.
 */
isize vision_http_respond(const HttpResponse* resp, u8* dst, usize dst_cap);

/* Quick response builders */
isize vision_http_respond_text(u16 code, const char* body,
                                u8* dst, usize dst_cap);
isize vision_http_respond_404(u8* dst, usize dst_cap);
isize vision_http_respond_400(u8* dst, usize dst_cap);

/* Find a header value by name (case-insensitive). Returns NULL if missing. */
const HttpHeader* vision_http_find_header(const HttpRequest* req,
                                           const char* name);

#ifdef __cplusplus
}
#endif

#endif /* VISION_HTTP_PARSER_H */
