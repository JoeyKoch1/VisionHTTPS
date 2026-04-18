#include "../src/http/parser.h"
#include "vision/platform.h"

int test_http(void) {
    static const u8 req1[] =
        "GET /api/health HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Connection: keep-alive\r\n"
        "User-Agent: TestClient/1.0\r\n"
        "\r\n";

    HttpRequest r;
    HttpParseResult res = vision_http_parse(req1, sizeof(req1) - 1, &r);
    if (res != HTTP_PARSE_COMPLETE) return 1;
    if (r.method != HTTP_METHOD_GET) return 2;
    if (r.path_len != 12) return 3;
    if (vision_memcmp(r.path, "/api/health", 11) != 0) return 4;
    if (r.version_minor != 1) return 5;
    if (r.header_count < 3) return 6;
    if (r.body_len != 0) return 7;

    static const u8 req2[] =
        "POST /echo HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "{\"hello\":\"world\"}";

    res = vision_http_parse(req2, sizeof(req2) - 1, &r);
    if (res != HTTP_PARSE_COMPLETE) return 10;
    if (r.method != HTTP_METHOD_POST) return 11;
    if (r.content_length != 15) return 12;
    if (r.body_len != 15) return 13;

    const HttpHeader* ct = vision_http_find_header(&r, "content-type");
    if (!ct) return 20;
    if (vision_memcmp(ct->value, "application/json", 16) != 0) return 21;

    const HttpHeader* ct2 = vision_http_find_header(&r, "Content-Type");
    if (!ct2) return 22;

    static const u8 partial[] = "GET /foo HTTP/1.1\r\nHo";
    res = vision_http_parse(partial, sizeof(partial) - 1, &r);
    if (res != HTTP_PARSE_INCOMPLETE) return 30;

    static const u8 bad[] = "BADVERB /foo ZTTP/9.9\r\n\r\n";
    res = vision_http_parse(bad, sizeof(bad) - 1, &r);
    if (res != HTTP_PARSE_ERROR) return 40;

    static const u8 traversal[] =
        "GET /../../../etc/passwd HTTP/1.1\r\n\r\n";
    res = vision_http_parse(traversal, sizeof(traversal) - 1, &r);
    if (res != HTTP_PARSE_COMPLETE) return 50;
    // Path contains '..' — serve_static should reject but parser accepts

    return 0;
}
