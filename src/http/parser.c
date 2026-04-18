#include "parser.h"
#include "vision/platform.h"

static VISION_INLINE bool8 is_sp(u8 c)     { return c == ' ' || c == '\t'; }
static VISION_INLINE bool8 is_digit(u8 c)  { return c >= '0' && c <= '9'; }
static VISION_INLINE bool8 is_alpha(u8 c)  { return (c|32) >= 'a' && (c|32) <= 'z'; }
static VISION_INLINE bool8 is_vchar(u8 c)  { return c >= 0x21 && c <= 0x7e; }
static VISION_INLINE bool8 is_token(u8 c)  {
    static const u8 tbl[16] = {
        0x00,0x00,0x00,0x00, 0xfa,0x73,0xff,0x03,
        0xfe,0xff,0xff,0x87, 0xfe,0xff,0xff,0x07
    };
    return (c < 128) && ((tbl[c >> 3] >> (c & 7)) & 1);
}

static bool8 ascii_iequal(const u8* a, usize alen, const char* b) {
    usize i = 0;
    for (; i < alen && b[i]; i++)
        if ((a[i] | 32) != (((u8)b[i]) | 32)) return VISION_FALSE;
    return (i == alen && b[i] == 0) ? VISION_TRUE : VISION_FALSE;
}

static usize parse_decimal(const u8* p, usize len) {
    usize n = 0;
    for (usize i = 0; i < len && is_digit(p[i]); i++)
        n = n * 10 + (p[i] - '0');
    return n;
}

static const u8* find_crlf(const u8* p, const u8* end) {
    for (; p + 1 < end; p++)
        if (p[0] == '\r' && p[1] == '\n') return p;
    return VISION_NULL;
}

static HttpMethod parse_method(const u8* p, usize len) {
    if (len == 3 && vision_memcmp(p, "GET",    3) == 0) return HTTP_METHOD_GET;
    if (len == 4 && vision_memcmp(p, "POST",   4) == 0) return HTTP_METHOD_POST;
    if (len == 3 && vision_memcmp(p, "PUT",    3) == 0) return HTTP_METHOD_PUT;
    if (len == 6 && vision_memcmp(p, "DELETE", 6) == 0) return HTTP_METHOD_DELETE;
    if (len == 4 && vision_memcmp(p, "HEAD",   4) == 0) return HTTP_METHOD_HEAD;
    if (len == 7 && vision_memcmp(p, "OPTIONS",7) == 0) return HTTP_METHOD_OPTIONS;
    if (len == 5 && vision_memcmp(p, "PATCH",  5) == 0) return HTTP_METHOD_PATCH;
    return HTTP_METHOD_UNKNOWN;
}

HttpParseResult vision_http_parse(const u8* buf, usize len, HttpRequest* req) {
    vision_memset(req, 0, sizeof(*req));

    const u8* p   = buf;
    const u8* end = buf + len;

    const u8* rl_end = find_crlf(p, end);
    if (!rl_end) return HTTP_PARSE_INCOMPLETE;

    const u8* method_start = p;
    while (p < rl_end && !is_sp(*p)) p++;
    if (p == rl_end) return HTTP_PARSE_ERROR;
    req->method = parse_method(method_start, (usize)(p - method_start));
    if (req->method == HTTP_METHOD_UNKNOWN) return HTTP_PARSE_ERROR;
    p++;

    req->path = p;
    while (p < rl_end && !is_sp(*p)) p++;
    if (p == rl_end) return HTTP_PARSE_ERROR;
    req->path_len = (usize)(p - req->path);
    if (req->path_len == 0 || req->path_len > HTTP_MAX_PATH_LEN) return HTTP_PARSE_ERROR;
    p++;

    if (rl_end - p < 8) return HTTP_PARSE_ERROR;
    if (vision_memcmp(p, "HTTP/1.", 7) != 0) return HTTP_PARSE_ERROR;
    req->version_minor = p[7] - '0';
    p = rl_end + 2;

    while (p + 1 < end) {
        if (p[0] == '\r' && p[1] == '\n') { p += 2; break; }

        const u8* hdr_end = find_crlf(p, end);
        if (!hdr_end) return HTTP_PARSE_INCOMPLETE;

        const u8* name_start = p;
        while (p < hdr_end && *p != ':') p++;
        if (p == hdr_end) return HTTP_PARSE_ERROR;
        usize name_len = (usize)(p - name_start);
        p++;

        while (p < hdr_end && is_sp(*p)) p++;

        const u8* val_start = p;
        const u8* val_end   = hdr_end;
        while (val_end > val_start && is_sp(*(val_end - 1))) val_end--;
        usize val_len = (usize)(val_end - val_start);

        if (req->header_count < HTTP_MAX_HEADERS) {
            HttpHeader* hdr = &req->headers[req->header_count++];
            hdr->name      = name_start;
            hdr->name_len  = name_len;
            hdr->value     = val_start;
            hdr->value_len = val_len;

            if (ascii_iequal(name_start, name_len, "content-length")) {
                req->content_length = parse_decimal(val_start, val_len);
            } else if (ascii_iequal(name_start, name_len, "transfer-encoding")) {
                if (val_len >= 7 && ascii_iequal(val_start, 7, "chunked"))
                    req->chunked = VISION_TRUE;
            }
        }
        p = hdr_end + 2;
    }

    usize header_bytes = (usize)(p - buf);
    usize remaining    = len - header_bytes;

    if (req->content_length > 0) {
        if (remaining < req->content_length) return HTTP_PARSE_INCOMPLETE;
        req->body     = p;
        req->body_len = req->content_length;
        req->consumed = header_bytes + req->content_length;
    } else if (req->chunked) {
        // Simple chunked decode for now improve later - Joey
        req->body     = p;
        req->body_len = 0;
        const u8* cp  = p;
        while (cp < end) {
            const u8* chunk_crlf = find_crlf(cp, end);
            if (!chunk_crlf) return HTTP_PARSE_INCOMPLETE;
            usize chunk_size = 0;
            for (const u8* hp = cp; hp < chunk_crlf; hp++) {
                u8 c = *hp;
                if      (c >= '0' && c <= '9') chunk_size = chunk_size*16 + (c-'0');
                else if ((c|32) >= 'a' && (c|32) <= 'f') chunk_size = chunk_size*16 + ((c|32)-'a'+10);
                else break;
            }
            cp = chunk_crlf + 2;
            if (chunk_size == 0) { cp += 2; break; }
            if (cp + chunk_size + 2 > end) return HTTP_PARSE_INCOMPLETE;
            req->body_len += chunk_size;
            cp += chunk_size + 2;
        }
        req->consumed = (usize)(cp - buf);
    } else {
        req->consumed = header_bytes;
    }

    return HTTP_PARSE_COMPLETE;
}

const HttpHeader* vision_http_find_header(const HttpRequest* req,
                                           const char* name) {
    for (u32 i = 0; i < req->header_count; i++) {
        const HttpHeader* h = &req->headers[i];
        if (ascii_iequal(h->name, h->name_len, name)) return h;
    }
    return VISION_NULL;
}

static usize str_len(const char* s) { usize n=0; while(s[n]) n++; return n; }

static usize append(u8* dst, usize off, usize cap, const u8* src, usize n) {
    if (off + n > cap) return off;
    vision_memcpy(dst + off, src, n);
    return off + n;
}
static usize appendz(u8* dst, usize off, usize cap, const char* s) {
    return append(dst, off, cap, (const u8*)s, str_len(s));
}

static const char* status_reason(u16 code) {
    switch (code) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 503: return "Service Unavailable";
        default:  return "Unknown";
    }
}

isize vision_http_respond(const HttpResponse* resp, u8* dst, usize cap) {
    usize off = 0;
    off = appendz(dst, off, cap, "HTTP/1.1 ");
    u8 code_str[4];
    u16 c = resp->status_code;
    code_str[0] = (u8)('0' + c / 100);
    code_str[1] = (u8)('0' + (c / 10) % 10);
    code_str[2] = (u8)('0' + c % 10);
    code_str[3] = ' ';
    off = append(dst, off, cap, code_str, 4);
    off = appendz(dst, off, cap, resp->reason ? resp->reason : status_reason(resp->status_code));
    off = appendz(dst, off, cap, "\r\n");

    if (resp->headers_len)
        off = append(dst, off, cap, resp->headers_buf, resp->headers_len);

    if (resp->body_len) {
        off = appendz(dst, off, cap, "Content-Length: ");
        u8 cl[20]; i32 ci = 20; usize bl = resp->body_len;
        do { cl[--ci] = (u8)('0' + bl % 10); bl /= 10; } while (bl);
        off = append(dst, off, cap, cl + ci, (usize)(20 - ci));
        off = appendz(dst, off, cap, "\r\n");
    }
    off = appendz(dst, off, cap, "Server: Vision/0.1\r\n\r\n");

    if (resp->body && resp->body_len)
        off = append(dst, off, cap, resp->body, resp->body_len);

    if (off > cap) return -1;
    return (isize)off;
}

isize vision_http_respond_text(u16 code, const char* body,
                                u8* dst, usize dst_cap) {
    HttpResponse resp;
    vision_memset(&resp, 0, sizeof(resp));
    resp.status_code = code;
    resp.reason      = status_reason(code);
    usize hlen = 0;
    const char* ct = "Content-Type: text/plain\r\n";
    usize ctlen = str_len(ct);
    vision_memcpy(resp.headers_buf, ct, ctlen);
    hlen = ctlen;
    resp.headers_len = hlen;
    resp.body        = (const u8*)body;
    resp.body_len    = str_len(body);
    return vision_http_respond(&resp, dst, dst_cap);
}

isize vision_http_respond_404(u8* dst, usize dst_cap) {
    return vision_http_respond_text(404, "Not Found\r\n", dst, dst_cap);
}
isize vision_http_respond_400(u8* dst, usize dst_cap) {
    return vision_http_respond_text(400, "Bad Request\r\n", dst, dst_cap);
}
