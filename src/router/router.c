#include "router.h"
#include "../http/parser.h"
#include "vision/platform.h"

#define ROUTER_MAX_NODES    512
#define ROUTER_MAX_CHILDREN  32
#define ROUTER_MAX_ROUTES   128
#define ROUTER_SEG_MAX       64

typedef struct RouterNode {
    u8  segment[ROUTER_SEG_MAX];
    u8  seg_len;
    bool8 wildcard;

    struct RouterNode* children[ROUTER_MAX_CHILDREN];
    u8                 child_count;

    VisionRouteHandler handlers[8];
} RouterNode;

static RouterNode s_node_pool[ROUTER_MAX_NODES];
static u32        s_node_count = 0;

static RouterNode* alloc_node(void) {
    if (s_node_count >= ROUTER_MAX_NODES) return VISION_NULL;
    RouterNode* n = &s_node_pool[s_node_count++];
    vision_memset(n, 0, sizeof(*n));
    return n;
}

static RouterNode* s_root = VISION_NULL;

#define MIDDLEWARE_MAX 16
static VisionMiddlewareFn s_middleware[MIDDLEWARE_MAX];
static u8                 s_mw_count = 0;

void vision_router_use(VisionMiddlewareFn fn) {
    if (s_mw_count < MIDDLEWARE_MAX) s_middleware[s_mw_count++] = fn;
}

typedef struct {
    const u8* path;
    usize     path_len;
    usize     pos;
} PathIter;

static bool8 path_next_segment(PathIter* it, const u8** seg, usize* seg_len) {
    while (it->pos < it->path_len && it->path[it->pos] == '/') it->pos++;
    if (it->pos >= it->path_len) return VISION_FALSE;
    usize start = it->pos;
    while (it->pos < it->path_len && it->path[it->pos] != '/') it->pos++;
    *seg     = it->path + start;
    *seg_len = it->pos - start;
    return VISION_TRUE;
}
static RouterNode* get_or_create_root(void) {
    if (!s_root) s_root = alloc_node();
    return s_root;
}

i32 vision_router_add(HttpMethod method, const char* path,
                       VisionRouteHandler handler) {
    RouterNode* node = get_or_create_root();
    if (!node) return -1;

    PathIter it;
    it.path     = (const u8*)path;
    it.path_len = 0;
    while (path[it.path_len]) it.path_len++;
    it.pos      = 0;

    const u8* seg; usize seg_len;
    while (path_next_segment(&it, &seg, &seg_len)) {
        bool8 is_wildcard = (seg_len > 0 && (seg[0] == ':' || seg[0] == '*'));
        RouterNode* child = VISION_NULL;
        for (u8 i = 0; i < node->child_count; i++) {
            RouterNode* c = node->children[i];
            if (c->wildcard == is_wildcard &&
                c->seg_len == seg_len &&
                vision_memcmp(c->segment, seg, seg_len) == 0) {
                child = c; break;
            }
        }
        if (!child) {
            child = alloc_node();
            if (!child) return -1;
            usize copy_len = seg_len < ROUTER_SEG_MAX ? seg_len : ROUTER_SEG_MAX - 1;
            vision_memcpy(child->segment, seg, copy_len);
            child->seg_len  = (u8)copy_len;
            child->wildcard = is_wildcard;
            if (node->child_count < ROUTER_MAX_CHILDREN)
                node->children[node->child_count++] = child;
        }
        node = child;
    }

    if (method < 8) node->handlers[method] = handler;
    return 0;
}

static RouterNode* trie_match(RouterNode* node, PathIter* it) {
    const u8* seg; usize seg_len;
    if (!path_next_segment(it, &seg, &seg_len)) {
        return node;
    }

    RouterNode* wc = VISION_NULL;
    for (u8 i = 0; i < node->child_count; i++) {
        RouterNode* c = node->children[i];
        if (c->wildcard) { wc = c; continue; }
        if (c->seg_len == seg_len &&
            vision_memcmp(c->segment, seg, seg_len) == 0) {
            PathIter saved = *it;
            RouterNode* found = trie_match(c, it);
            if (found) return found;
            *it = saved;
        }
    }
    if (wc) {
        PathIter saved = *it;
        RouterNode* found = trie_match(wc, it);
        if (found) return found;
        *it = saved;
    }
    return VISION_NULL;
}

static isize default_404(const HttpRequest* req, u8* out, usize cap) {
    (void)req;
    return vision_http_respond_404(out, cap);
}
static isize default_405(const HttpRequest* req, u8* out, usize cap) {
    (void)req;
    return vision_http_respond_text(405, "Method Not Allowed\r\n", out, cap);
}

static i32 mw_logger(const HttpRequest* req) {
    (void)req;
    return 0;
}

i32 vision_router_init(void) {
    s_node_count = 0;
    s_mw_count   = 0;
    s_root       = VISION_NULL;
    vision_router_use(mw_logger);
    return 0;
}

isize vision_router_dispatch(const HttpRequest* req, u8* out, usize out_cap) {
    for (u8 i = 0; i < s_mw_count; i++) {
        i32 rc = s_middleware[i](req);
        if (rc != 0) {
            return vision_http_respond_text(403, "Forbidden\r\n", out, out_cap);
        }
    }

    if (!s_root) return default_404(req, out, out_cap);

    PathIter it;
    it.path     = req->path;
    it.path_len = req->path_len;
    it.pos      = 0;

    RouterNode* node = trie_match(s_root, &it);
    if (!node) return default_404(req, out, out_cap);

    VisionRouteHandler handler = VISION_NULL;
    if (req->method < 8) handler = node->handlers[req->method];
    if (!handler) return default_405(req, out, out_cap);

    return handler(req, out, out_cap);
}
