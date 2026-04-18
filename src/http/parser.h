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
    const u8* name;
    usize     name_len;
    const u8* value;
    usize     value_len;
} HttpHeader;

typedef enum {
    HTTP_PARSE_INCOMPLETE = 0,
    HTTP_PARSE_COMPLETE   = 1,
    HTTP_PARSE_ERROR      = -1,
} HttpParseResult;

typedef struct {
    HttpMethod method;
    const u8*  path;
    usize      path_len;
    u8         version_minor;

    HttpHeader headers[HTTP_MAX_HEADERS];
    u32        header_count;

    const u8*  body;
    usize      body_len;
    usize      content_length;
    bool8      chunked;

    usize      consumed;
} HttpRequest;

typedef struct {
    u8    status_code_str[4];
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

HttpParseResult vision_http_parse(const u8* buf, usize len, HttpRequest* req);

isize vision_http_respond(const HttpResponse* resp, u8* dst, usize dst_cap);

isize vision_http_respond_text(u16 code, const char* body,
                                u8* dst, usize dst_cap);
isize vision_http_respond_404(u8* dst, usize dst_cap);
isize vision_http_respond_400(u8* dst, usize dst_cap);

const HttpHeader* vision_http_find_header(const HttpRequest* req,
                                           const char* name);

#ifdef __cplusplus
}
#endif

#endif
