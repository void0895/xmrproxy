/* proxy.c -- Epoll-based single-threaded stratum proxy.
 *
 * Architecture
 * ------------
 * Single epoll event loop with per-connection state machines.
 * No threads -- all I/O is non-blocking, driven by EPOLLIN/EPOLLOUT.
 *
 * Session lifecycle
 * -----------------
 * 1. handle_accept() accepts a new TCP connection, creates a session_t,
 *    starts non-blocking upstream connect, and enters the down conn
 *    into the appropriate handshake state (TLS, WS, or READY).
 * 2. Upstream connect completion is detected via EPOLLOUT on the
 *    CONN_CONNECTING state, then handle_connect_done() kicks off
 *    upstream TLS/WS handshake or goes straight to CONN_READY.
 * 3. CONN_READY: data arrives on either side, relay_data() parses
 *    WS frames (if WS) and forwards to the other side via
 *    build_and_send_ws() or conn_write().
 * 4. On error or EOF the session is marked closing, both conns cleaned
 *    up, and the session freed on the next cleanup_list pass.
 *
 * Key differences from the old thread-per-connection version
 * ----------------------------------------------------------
 * - Single epoll_wait loop instead of one pthread per session.
 * - All DNS, connect, TLS handshake, WS handshake are non-blocking
 *   state machines rather than synchronous calls.
 * - Write buffering: conn_write() buffers in wbuf and arms EPOLLOUT;
 *   conn_flush_write() drains on EPOLLOUT.
 * - WS frames parsed inline by ws_frame_parse() (called from relay_data)
 *   rather than by the blocking ws_recv() in websocket.c.
 * - Session lookup via back-pointer (O(1)) instead of linked list scan (O(N)).
 */

#define _GNU_SOURCE
#include "proxy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define MAX_EVENTS 256

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void init_conn_ws(conn_t *c)
{
    memset(&c->ws, 0, sizeof(c->ws));
    c->ws.fd = -1;
    c->wlen = 0;
    c->hlen = 0;
    c->state = CONN_INIT;
    c->epoll_events = 0;
    c->session = NULL;
}

static void fd_add(int epoll_fd, int fd, uint32_t events, conn_t *c)
{
    struct epoll_event ev = { .events = events, .data.ptr = c };
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
    c->epoll_events = events;
}

static void fd_mod(int epoll_fd, int fd, uint32_t events, conn_t *c)
{
    if (events == c->epoll_events) return;
    struct epoll_event ev = { .events = events, .data.ptr = c };
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
    c->epoll_events = events;
}

static void fd_del(int epoll_fd, int fd)
{
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
}

static int ssl_want(int ret, SSL *ssl)
{
    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ) return EPOLLIN;
    if (err == SSL_ERROR_WANT_WRITE) return EPOLLOUT;
    return -1;
}

static int do_ssl_accept(conn_t *c, int epoll_fd)
{
    int ret = SSL_accept(c->ws.ssl);
    if (ret == 1) return 1;
    int w = ssl_want(ret, c->ws.ssl);
    if (w > 0) { fd_mod(epoll_fd, c->ws.fd, w, c); return 0; }
    return -1;
}

static int do_ssl_connect(conn_t *c, int epoll_fd)
{
    int ret = SSL_connect(c->ws.ssl);
    if (ret == 1) return 1;
    int w = ssl_want(ret, c->ws.ssl);
    if (w > 0) { fd_mod(epoll_fd, c->ws.fd, w, c); return 0; }
    return -1;
}

/* ---- DNS + non-blocking connect ---- */

static int resolve_connect(const endpoint_t *ep, conn_t *c)
{
    struct addrinfo hints, *res;
    char port_str[16];
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%d", ep->port);
    if (getaddrinfo(ep->host, port_str, &hints, &res) != 0) return -1;

    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        int nodelay = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
        set_nonblock(fd);
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0 || errno == EINPROGRESS) {
            memcpy(&c->addr, p->ai_addr, p->ai_addrlen);
            c->addrlen = p->ai_addrlen;
            c->ws.fd = fd;
            freeaddrinfo(res);
            return 0;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return -1;
}

static int tls_connect_async(conn_t *c, int epoll_fd, const endpoint_t *ep, SSL_CTX *client_ctx)
{
    snprintf(c->ws.host, sizeof(c->ws.host), "%s", ep->host);
    c->ws.ctx = NULL;  /* shared context, not owned by connection */
    c->ws.ssl = SSL_new(client_ctx);
    SSL_set_fd(c->ws.ssl, c->ws.fd);
    SSL_set_tlsext_host_name(c->ws.ssl, ep->host);
    c->ws.use_tls = 1;
    int ret = SSL_connect(c->ws.ssl);
    if (ret == 1) return 1;
    int w = ssl_want(ret, c->ws.ssl);
    if (w > 0) { c->state = CONN_SSL_CONNECT; fd_mod(epoll_fd, c->ws.fd, w, c); return 0; }
    return -1;
}

/* ---- WS frame parser ---- */

static int ws_frame_parse(conn_t *c)
{
    uint8_t *buf = c->ws.read_buf;
    size_t len = c->ws.read_len;

    while (len >= 2) {
        uint8_t b0 = buf[0];
        uint8_t b1 = buf[1];
        uint8_t opcode = b0 & 0x0F;
        bool masked = (b1 & 0x80) != 0;
        size_t hdr_sz = 2;
        size_t payload_len = b1 & 0x7F;

        if (payload_len == 126) {
            if (len < 4) return 0;
            payload_len = ((size_t)buf[2] << 8) | buf[3];
            hdr_sz = 4;
        } else if (payload_len == 127) {
            if (len < 10) return 0;
            payload_len = 0;
            for (int i = 0; i < 8; i++)
                payload_len = (payload_len << 8) | buf[2 + i];
            hdr_sz = 10;
        }

        uint8_t mask_key[4];
        if (masked) {
            if (len < hdr_sz + 4) return 0;
            memcpy(mask_key, buf + hdr_sz, 4);
            hdr_sz += 4;
        }

        size_t frame_end = hdr_sz + payload_len;
        if (len < frame_end) return 0;

        if (opcode == 0x08) return -1;

        uint8_t *payload = buf + hdr_sz;
        if (masked)
            for (size_t i = 0; i < payload_len; i++)
                payload[i] ^= mask_key[i % 4];

        /* ping/pong: skip and continue */
        if (opcode == 0x09 || opcode == 0x0A) {
            len -= frame_end;
            memmove(buf, buf + frame_end, len);
            c->ws.read_len = len;
            continue;
        }

        /* Move payload to front, keep rest after it */
        memmove(buf, payload, payload_len);
        size_t rest = len - frame_end;
        if (rest > 0)
            memmove(buf + payload_len, buf + frame_end, rest);
        c->ws.read_len = payload_len + rest;
        return (int)payload_len;
    }
    return 0;
}

/* ---- conn I/O ---- */

static int conn_read_raw(conn_t *c)
{
    uint8_t *buf = c->ws.read_buf + c->ws.read_len;
    size_t cap = sizeof(c->ws.read_buf) - c->ws.read_len;
    if (cap == 0) return -1;
    int n;
    if (c->ws.use_tls) {
        n = SSL_read(c->ws.ssl, buf, cap);
        if (n <= 0) {
            int e = SSL_get_error(c->ws.ssl, n);
            if (e == SSL_ERROR_WANT_READ) return 0;
            return -1;
        }
    } else {
        n = read(c->ws.fd, buf, cap);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        if (n == 0) return -1;
    }
    c->ws.read_len += n;
    return n;
}

static int conn_flush_write(conn_t *c)
{
    if (c->wlen == 0) return 1;
    int n;
    if (c->ws.use_tls) {
        n = SSL_write(c->ws.ssl, c->wbuf, c->wlen);
        if (n <= 0) {
            int e = SSL_get_error(c->ws.ssl, n);
            if (e == SSL_ERROR_WANT_WRITE) return 0;
            return -1;
        }
    } else {
        n = write(c->ws.fd, c->wbuf, c->wlen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
    }
    if ((size_t)n < c->wlen) {
        memmove(c->wbuf, c->wbuf + n, c->wlen - n);
        c->wlen -= n;
        return 0;
    }
    c->wlen = 0;
    return 1;
}

static int conn_write(conn_t *c, const uint8_t *data, size_t len, int epoll_fd)
{
    if (c->wlen > 0) {
        size_t space = sizeof(c->wbuf) - c->wlen;
        if (space < len) return -1;
        memcpy(c->wbuf + c->wlen, data, len);
        c->wlen += len;
        fd_mod(epoll_fd, c->ws.fd, c->epoll_events | EPOLLOUT, c);
        return 0;
    }

    int n;
    if (c->ws.use_tls) {
        n = SSL_write(c->ws.ssl, data, len);
        if (n <= 0) {
            int e = SSL_get_error(c->ws.ssl, n);
            if (e == SSL_ERROR_WANT_WRITE) {
                if (len > sizeof(c->wbuf)) return -1;
                memcpy(c->wbuf, data, len);
                c->wlen = len;
                fd_mod(epoll_fd, c->ws.fd, c->epoll_events | EPOLLOUT, c);
                return 0;
            }
            return -1;
        }
    } else {
        n = write(c->ws.fd, data, len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (len > sizeof(c->wbuf)) return -1;
                memcpy(c->wbuf, data, len);
                c->wlen = len;
                fd_mod(epoll_fd, c->ws.fd, c->epoll_events | EPOLLOUT, c);
                return 0;
            }
            return -1;
        }
    }

    if ((size_t)n < len) {
        memcpy(c->wbuf, data + n, len - n);
        c->wlen = len - n;
        fd_mod(epoll_fd, c->ws.fd, c->epoll_events | EPOLLOUT, c);
    }
    return 0;
}

static int build_and_send_ws(conn_t *c, const uint8_t *data, size_t len, int epoll_fd, bool masked)
{
    uint8_t hdr[14 + 4];
    int hlen;
    hdr[0] = 0x81;
    if (len < 126) { hdr[1] = masked ? (0x80 | (uint8_t)len) : (uint8_t)len; hlen = 2; }
    else if (len < 65536) {
        hdr[1] = masked ? 0x80 | 126 : 126;
        hdr[2] = (len >> 8) & 0xFF; hdr[3] = len & 0xFF; hlen = 4;
    } else {
        hdr[1] = masked ? 0x80 | 127 : 127;
        for (int i = 0; i < 8; i++) hdr[2 + i] = (len >> (56 - i * 8)) & 0xFF; hlen = 10;
    }

    if (masked) {
        RAND_bytes(hdr + hlen, 4);
        if (conn_write(c, hdr, hlen + 4, epoll_fd) != 0) return -1;
        uint8_t stack_tmp[4096];
        uint8_t *tmp = (len <= sizeof(stack_tmp)) ? stack_tmp : malloc(len);
        if (!tmp) return -1;
        for (size_t i = 0; i < len; i++)
            tmp[i] = data[i] ^ (hdr[hlen + (i % 4)]);
        int ret = conn_write(c, tmp, len, epoll_fd);
        if (tmp != stack_tmp) free(tmp);
        return ret;
    }

    return conn_write(c, hdr, hlen, epoll_fd) == 0 ? conn_write(c, data, len, epoll_fd) : -1;
}

/* ---- WS handshake helpers ---- */

static void base64_encode(char *out, const uint8_t *in, size_t len)
{
    const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, j;
    for (i = 0, j = 0; i < len; i += 3) {
        uint32_t val = (uint32_t)in[i] << 16;
        if (i + 1 < len) val |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < len) val |= (uint32_t)in[i + 2];
        out[j++] = table[(val >> 18) & 0x3F];
        out[j++] = table[(val >> 12) & 0x3F];
        out[j++] = (i + 1 < len) ? table[(val >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < len) ? table[val & 0x3F] : '=';
    }
    out[j] = '\0';
}

static int hread(conn_t *c)
{
    char *buf = c->hbuf + c->hlen;
    size_t cap = sizeof(c->hbuf) - c->hlen - 1;
    if (cap == 0) return -1;
    int n;
    if (c->ws.use_tls) {
        n = SSL_read(c->ws.ssl, buf, cap);
        if (n <= 0) {
            int e = SSL_get_error(c->ws.ssl, n);
            if (e == SSL_ERROR_WANT_READ) return 0;
            return -1;
        }
    } else {
        n = read(c->ws.fd, buf, cap);
        if (n < 0) { if (errno == EAGAIN) return 0; return -1; }
        if (n == 0) return -1;
    }
    c->hlen += n;
    buf[n] = '\0';
    return n;
}

static int do_ws_accept(conn_t *c, int epoll_fd)
{
    char *end = strstr(c->hbuf, "\r\n\r\n");
    if (!end) {
        if (c->hlen >= sizeof(c->hbuf) - 1) return -1;
        return 0;
    }

    char *key = strstr(c->hbuf, "Sec-WebSocket-Key: ");
    if (!key) return -1;
    key += 19;
    char *knl = strstr(key, "\r\n");
    if (!knl) return -1;
    size_t klen = knl - key;
    if (klen > 255) klen = 255;
    char kbuf[256];
    memcpy(kbuf, key, klen); kbuf[klen] = '\0';

    char concat[512];
    snprintf(concat, sizeof(concat), "%s258EAFA5-E914-47DA-95CA-5AB9DC11B85B", kbuf);
    unsigned char sha[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)concat, strlen(concat), sha);
    char accept_key[64];
    base64_encode(accept_key, sha, SHA_DIGEST_LENGTH);

    char resp[1024];
    int rlen = snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n", accept_key);

    if (conn_write(c, (const uint8_t *)resp, rlen, epoll_fd) != 0) return -1;
    c->state = CONN_WS_WRITE_RESP;
    fd_mod(epoll_fd, c->ws.fd, EPOLLOUT, c);
    return 0;
}

static int do_ws_connect_req(conn_t *c, int epoll_fd, const char *host, int port)
{
    uint8_t key[16];
    RAND_bytes(key, sizeof(key));
    char key_b64[64];
    base64_encode(key_b64, key, sizeof(key));

    char req[2048];
    int reqlen = snprintf(req, sizeof(req),
        "GET / HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        host, port, key_b64);

    if (conn_write(c, (const uint8_t *)req, reqlen, epoll_fd) != 0) return -1;
    c->state = CONN_WS_READ_RESP;
    fd_mod(epoll_fd, c->ws.fd, c->epoll_events | EPOLLOUT | EPOLLIN, c);
    return 0;
}

static int do_ws_connect_resp(conn_t *c)
{
    if (!strstr(c->hbuf, "\r\n\r\n")) {
        if (c->hlen >= sizeof(c->hbuf) - 1) return -1;
        return 0;
    }
    if (!strstr(c->hbuf, "101")) return -1;
    return 1;
}

/* ---- JSON pretty-print ---- */

static void json_print(const uint8_t *data, size_t len)
{
    int indent = 0;
    for (size_t i = 0; i < len; i++) {
        char c = (char)data[i];
        if (c == '{' || c == '[') {
            putchar(c); putchar('\n');
            indent++;
            for (int j = 0; j < indent; j++) fputs("  ", stdout);
        } else if (c == '}' || c == ']') {
            putchar('\n');
            indent--;
            for (int j = 0; j < indent; j++) fputs("  ", stdout);
            putchar(c);
        } else if (c == ',') {
            putchar(c); putchar('\n');
            for (int j = 0; j < indent; j++) fputs("  ", stdout);
        } else if (c == ':') {
            fputs(": ", stdout);
        } else if (c == '"') {
            putchar(c);
            i++;
            while (i < len && (uint8_t)data[i] != '"') {
                if ((uint8_t)data[i] == '\\') { putchar('\\'); i++; if (i < len) putchar((char)data[i]); }
                else putchar((char)data[i]);
                i++;
            }
            if (i < len) putchar((char)data[i]);
        } else if (c > 32) {
            putchar(c);
        }
    }
    putchar('\n');
}

/* ---- relay ---- */

static int relay_data(session_t *s, conn_t *src, conn_t *dst, int epoll_fd)
{
    bool src_is_ws = (src == &s->down) ? s->down_is_ws : s->up_is_ws;

    if (src_is_ws) {
        int plen = ws_frame_parse(src);
        if (plen < 0) return -1;
        if (plen == 0) return 0;

        uint8_t *payload = src->ws.read_buf;
        size_t payload_len = (size_t)plen;

        s->last_active = time(NULL);
        printf("[proxy:%d] %s→%s (%zu bytes)\n", s->id,
               src->is_down ? "down" : "up",
               src->is_down ? "up" : "down", payload_len);
        json_print(payload, payload_len);

        bool dst_is_ws = (dst == &s->down) ? s->down_is_ws : s->up_is_ws;
        int ret;
        if (dst_is_ws) {
            ret = build_and_send_ws(dst, payload, payload_len, epoll_fd, dst == &s->up);
        } else {
            uint8_t stack_tmp[4096];
            uint8_t *tmp = (payload_len + 1 <= sizeof(stack_tmp)) ? stack_tmp : malloc(payload_len + 1);
            if (!tmp) return -1;
            memcpy(tmp, payload, payload_len);
            tmp[payload_len] = '\n';
            ret = conn_write(dst, tmp, payload_len + 1, epoll_fd);
            if (tmp != stack_tmp) free(tmp);
        }
        if (ret == 0) {
            size_t rest = src->ws.read_len - (size_t)plen;
            if (rest > 0)
                memmove(src->ws.read_buf, src->ws.read_buf + plen, rest);
            src->ws.read_len = rest;
            return (int)payload_len;
        }
        return -1;
    }

    ssize_t total = (ssize_t)src->ws.read_len;
    if (total == 0) return 0;

    s->last_active = time(NULL);
    printf("[proxy:%d] %s→%s (%zu bytes)\n", s->id,
           src->is_down ? "down" : "up",
           src->is_down ? "up" : "down", total);
    json_print(src->ws.read_buf, (size_t)total);

    bool dst_is_ws = (dst == &s->down) ? s->down_is_ws : s->up_is_ws;
    int ret;
    if (dst_is_ws)
        ret = build_and_send_ws(dst, src->ws.read_buf, total, epoll_fd, dst == &s->up);
    else
        ret = conn_write(dst, src->ws.read_buf, total, epoll_fd);
    if (ret == 0) { src->ws.read_len = 0; return (int)total; }
    return -1;
}

/* ---- session management ---- */

static void conn_cleanup(conn_t *c, int epoll_fd)
{
    if (c->ws.fd >= 0) {
        fd_del(epoll_fd, c->ws.fd);
        if (c->ws.ssl) { SSL_shutdown(c->ws.ssl); SSL_free(c->ws.ssl); c->ws.ssl = NULL; }
        if (c->ws.ctx) { SSL_CTX_free(c->ws.ctx); c->ws.ctx = NULL; }
        close(c->ws.fd);
        c->ws.fd = -1;
    }
    c->state = CONN_CLOSED;
}

static void session_close(session_t *s, int epoll_fd)
{
    if (s->closing) return;
    s->closing = true;
    conn_cleanup(&s->down, epoll_fd);
    conn_cleanup(&s->up, epoll_fd);
}

static void session_cleanup_list(session_t **list)
{
    while (*list) {
        session_t *s = *list;
        if (!s->closing) { list = &s->next; continue; }
        *list = s->next;
        free(s);
    }
}

/* ---- handle upstream connect completion ---- */

static void handle_connect_done(session_t *s, conn_t *c, int epoll_fd)
{
    int so_err = 0;
    socklen_t slen = sizeof(so_err);
    getsockopt(c->ws.fd, SOL_SOCKET, SO_ERROR, &so_err, &slen);
    if (so_err != 0) { session_close(s, epoll_fd); return; }

    if (s->ctx->up.proto == PROTO_WSS || s->ctx->up.proto == PROTO_TLS) {
        int r = tls_connect_async(c, epoll_fd, &s->ctx->up, s->ctx->client_ctx);
        if (r == 1) {
            if (s->ctx->up.proto == PROTO_WSS) {
                c->state = CONN_WS_WRITE_REQ;
                do_ws_connect_req(c, epoll_fd, s->ctx->up.host, s->ctx->up.port);
            } else {
                goto upstream_ready;
            }
        } else if (r < 0) {
            session_close(s, epoll_fd);
        }
    } else if (s->ctx->up.proto == PROTO_WS) {
        c->state = CONN_WS_WRITE_REQ;
        do_ws_connect_req(c, epoll_fd, s->ctx->up.host, s->ctx->up.port);
    } else {
upstream_ready:
        c->state = CONN_READY;
        fd_mod(epoll_fd, c->ws.fd, EPOLLIN | (c->wlen > 0 ? EPOLLOUT : 0), c);
    }
}

/* ---- accept ---- */

static void handle_accept(proxy_ctx_t *ctx, int epoll_fd, session_t **slist)
{
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    int fd = accept(ctx->listen_fd, (struct sockaddr *)&addr, &addrlen);
    if (fd < 0) return;

    int nodelay = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    set_nonblock(fd);

    session_t *s = calloc(1, sizeof(session_t));
    if (!s) { close(fd); return; }

    static int next_id = 1;
    s->id = next_id++;
    s->ctx = ctx;
    s->down_is_ws = (ctx->down.proto == PROTO_WS || ctx->down.proto == PROTO_WSS);
    s->up_is_ws = (ctx->up.proto == PROTO_WS || ctx->up.proto == PROTO_WSS);
    s->timeout = ctx->timeout;
    s->last_active = time(NULL);

    init_conn_ws(&s->down);
    s->down.ws.fd = fd;
    s->down.is_down = true;
    s->down.session = s;  /* Set back-pointer for O(1) lookup */

    init_conn_ws(&s->up);
    s->up.is_down = false;
    s->up.session = s;    /* Set back-pointer for O(1) lookup */

    s->next = *slist;
    *slist = s;

    if (ctx->down.proto == PROTO_WSS) {
        s->down.ws.ssl = SSL_new(ctx->server_ctx);
        SSL_set_fd(s->down.ws.ssl, fd);
        s->down.ws.use_tls = 1;
        s->down.state = CONN_SSL_ACCEPT;
        fd_add(epoll_fd, fd, EPOLLIN, &s->down);
        int r = do_ssl_accept(&s->down, epoll_fd);
        if (r == 1) {
            s->down.state = CONN_WS_READ_REQ;
            fd_mod(epoll_fd, fd, EPOLLIN, &s->down);
        } else if (r < 0) {
            session_close(s, epoll_fd); return;
        }
    } else if (ctx->down.proto == PROTO_WS) {
        s->down.state = CONN_WS_READ_REQ;
        fd_add(epoll_fd, fd, EPOLLIN, &s->down);
    } else if (ctx->down.proto == PROTO_TLS) {
        s->down.ws.ssl = SSL_new(ctx->server_ctx);
        SSL_set_fd(s->down.ws.ssl, fd);
        s->down.ws.use_tls = 1;
        s->down.state = CONN_SSL_ACCEPT;
        fd_add(epoll_fd, fd, EPOLLIN, &s->down);
        int r = do_ssl_accept(&s->down, epoll_fd);
        if (r == 1) {
            s->down.state = CONN_READY;
            fd_mod(epoll_fd, fd, EPOLLIN, &s->down);
        } else if (r < 0) {
            session_close(s, epoll_fd); return;
        }
    } else {
        s->down.state = CONN_READY;
        fd_add(epoll_fd, fd, EPOLLIN, &s->down);
    }

    if (resolve_connect(&ctx->up, &s->up) != 0) {
        if (ctx->verbosity)
            fprintf(stderr, "[session:%d] upstream DNS/connect failed\n", s->id);
        session_close(s, epoll_fd); return;
    }

    s->up.state = CONN_CONNECTING;
    fd_add(epoll_fd, s->up.ws.fd, EPOLLOUT, &s->up);

    printf("[proxy] session:%d connected (down=%s up=%s)\n", s->id,
           s->down_is_ws ? "ws" : "tcp", s->up_is_ws ? "ws" : "tcp");
}

/* ---- event dispatcher ---- */

static void handle_conn_event(session_t *s, conn_t *c, uint32_t events, int epoll_fd)
{
    /* --- EPOLLOUT --- */
    if ((events & EPOLLOUT) && c->state != CONN_CONNECTING) {
        int r = conn_flush_write(c);
        if (r < 0) { session_close(s, epoll_fd); return; }
        if (r == 1) {
            fd_mod(epoll_fd, c->ws.fd, c->epoll_events & ~EPOLLOUT, c);
            if (c->state == CONN_WS_WRITE_RESP) {
                c->state = CONN_READY;
                fd_mod(epoll_fd, c->ws.fd, EPOLLIN, c);
            }
        }
    }

    if (s->closing) return;

    /* handle connect completion on EPOLLOUT */
    if (c->state == CONN_CONNECTING && (events & EPOLLOUT)) {
        handle_connect_done(s, c, epoll_fd);
        return;
    }

    if (!(events & EPOLLIN)) return;

    /* --- EPOLLIN --- */
    switch (c->state) {

    case CONN_SSL_ACCEPT: {
        int r = do_ssl_accept(c, epoll_fd);
        if (r < 0) { session_close(s, epoll_fd); return; }
        if (r == 1) {
            if (c->is_down) {
                if (s->down_is_ws) {
                    c->state = CONN_WS_READ_REQ;
                    fd_mod(epoll_fd, c->ws.fd, EPOLLIN, c);
                } else {
                    c->state = CONN_READY;
                    fd_mod(epoll_fd, c->ws.fd, EPOLLIN | (c->wlen > 0 ? EPOLLOUT : 0), c);
                }
            } else {
                if (s->up_is_ws) {
                    c->state = CONN_WS_WRITE_REQ;
                    do_ws_connect_req(c, epoll_fd, s->ctx->up.host, s->ctx->up.port);
                } else {;
                    c->state = CONN_READY;
                    fd_mod(epoll_fd, c->ws.fd, EPOLLIN | (c->wlen > 0 ? EPOLLOUT : 0), c);
                }
            }
        }
        break;
    }

    case CONN_SSL_CONNECT: {
        int r = do_ssl_connect(c, epoll_fd);
        if (r < 0) { session_close(s, epoll_fd); return; }
        if (r == 1) {
            if (!c->is_down && s->up_is_ws) {
                c->state = CONN_WS_WRITE_REQ;
                do_ws_connect_req(c, epoll_fd, s->ctx->up.host, s->ctx->up.port);
            } else {
                c->state = CONN_READY;
                fd_mod(epoll_fd, c->ws.fd, EPOLLIN | (c->wlen > 0 ? EPOLLOUT : 0), c);
            }
        }
        break;
    }

    case CONN_WS_READ_REQ: {
        int r = hread(c);
        if (r < 0 || (r > 0 && do_ws_accept(c, epoll_fd) < 0))
            session_close(s, epoll_fd);
        break;
    }

    case CONN_WS_WRITE_REQ:
        /* waiting for write flush, then WS_READ_RESP takes over */
        break;

    case CONN_WS_READ_RESP: {
        if (c->wlen > 0) break; /* request not fully sent yet */
        int r = hread(c);
        if (r < 0) { session_close(s, epoll_fd); break; }
        r = do_ws_connect_resp(c);
        if (r < 0) { session_close(s, epoll_fd); break; }
        if (r == 1) {
            c->state = CONN_READY;
            fd_mod(epoll_fd, c->ws.fd, EPOLLIN, c);
        }
        break;
    }

    case CONN_WS_WRITE_RESP:
        /* waiting for write flush, then will change to READY in EPOLLOUT handler */
        break;

    case CONN_READY: {
        int nr = conn_read_raw(c);
        if (nr < 0) { session_close(s, epoll_fd); return; }
        if (nr == 0) break;

        bool src_is_ws = c->is_down ? s->down_is_ws : s->up_is_ws;
        conn_t *dst = c->is_down ? &s->up : &s->down;
        int r1 = relay_data(s, c, dst, epoll_fd);
        if (src_is_ws && r1 > 0) {
            while (relay_data(s, c, dst, epoll_fd) > 0);
        }
        break;
    }

    default:
        break;
    }
}

static void check_timeouts(session_t **slist, int epoll_fd)
{
    time_t now = time(NULL);
    for (session_t *s = *slist; s; s = s->next) {
        if (s->closing) continue;
        if (s->timeout <= 0) continue;
        if (now - s->last_active > s->timeout) {
            printf("[session:%d] idle timeout (%ds)\n", s->id, s->timeout);
            session_close(s, epoll_fd);
        }
    }
}

/* ---- public API ---- */

int endpoint_parse(const char *url, endpoint_t *ep)
{
    memset(ep, 0, sizeof(*ep));
    const char *p = url;

    if (strncmp(p, "stratum+ssl://", 14) == 0) { ep->proto = PROTO_TLS; p += 14; ep->port = 443; }
    else if (strncmp(p, "stratum+tcp://", 14) == 0) { ep->proto = PROTO_TCP; p += 14; ep->port = 3333; }
    else if (strncmp(p, "wss://", 6) == 0) { ep->proto = PROTO_WSS; p += 6; ep->port = 443; }
    else if (strncmp(p, "ws://", 5) == 0) { ep->proto = PROTO_WS; p += 5; ep->port = 80; }
    else { fprintf(stderr, "[proxy] unknown URL scheme: %s\n", url); return -1; }

    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    size_t host_len;
    if (colon && (!slash || colon < slash)) { host_len = colon - p; ep->port = atoi(colon + 1); }
    else if (slash) { host_len = slash - p; }
    else { host_len = strlen(p); }
    if (host_len >= sizeof(ep->host)) host_len = sizeof(ep->host) - 1;
    memcpy(ep->host, p, host_len); ep->host[host_len] = '\0';
    if (slash) { size_t plen = strlen(slash); if (plen >= sizeof(ep->path)) plen = sizeof(ep->path) - 1; memcpy(ep->path, slash, plen); ep->path[plen] = '\0'; }
    else strcpy(ep->path, "/");
    return 0;
}

int endpoint_listen(const endpoint_t *ep)
{
    struct sockaddr_in addr4 = { .sin_family = AF_INET, .sin_port = htons(ep->port), .sin_addr = { htonl(INADDR_ANY) } };
    int fd, opt = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(fd, (struct sockaddr *)&addr4, sizeof(addr4)) == 0) {
        listen(fd, 128);
        printf("[proxy] listening on port %d (%s)\n", ep->port,
               ep->proto == PROTO_WS ? "ws" : ep->proto == PROTO_WSS ? "wss" : "stratum");
        return fd;
    }
    close(fd);

    fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    opt = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
    struct sockaddr_in6 addr6 = { .sin6_family = AF_INET6, .sin6_port = htons(ep->port) };
    if (bind(fd, (struct sockaddr *)&addr6, sizeof(addr6)) == 0) {
        listen(fd, 128);
        printf("[proxy] listening on port %d (%s) [IPv6]\n", ep->port,
               ep->proto == PROTO_WS ? "ws" : ep->proto == PROTO_WSS ? "wss" : "stratum");
        return fd;
    }
    close(fd);
    return -1;
}

int proxy_init_tls(proxy_ctx_t *ctx)
{
    if (ctx->down.proto != PROTO_WSS && ctx->down.proto != PROTO_TLS) return 0;
    ctx->server_ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx->server_ctx) { fprintf(stderr, "[tls] SSL_CTX_new failed\n"); return -1; }

    if (ctx->cert_path[0]) {
        if (SSL_CTX_use_certificate_file(ctx->server_ctx, ctx->cert_path, SSL_FILETYPE_PEM) <= 0) {
            fprintf(stderr, "[tls] failed to load cert: %s\n", ctx->cert_path);
            goto fail;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx->server_ctx, ctx->key_path, SSL_FILETYPE_PEM) <= 0) {
            fprintf(stderr, "[tls] failed to load key: %s\n", ctx->key_path);
            goto fail;
        }
        printf("[tls] loaded cert=%s key=%s\n", ctx->cert_path, ctx->key_path);
    } else {
        EVP_PKEY *pkey = NULL;
        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!kctx) goto fail;
        if (EVP_PKEY_keygen_init(kctx) <= 0) { EVP_PKEY_CTX_free(kctx); goto fail; }
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0) { EVP_PKEY_CTX_free(kctx); goto fail; }
        if (EVP_PKEY_keygen(kctx, &pkey) <= 0) { EVP_PKEY_CTX_free(kctx); goto fail; }
        EVP_PKEY_CTX_free(kctx);
        if (!pkey) goto fail;

        X509 *x509 = X509_new();
        if (!x509) { EVP_PKEY_free(pkey); goto fail; }
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 365 * 86400);
        X509_set_pubkey(x509, pkey);
        X509_NAME *name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"xmr-proxy", -1, -1, 0);
        X509_set_issuer_name(x509, name);
        X509_sign(x509, pkey, EVP_sha256());

        if (SSL_CTX_use_certificate(ctx->server_ctx, x509) <= 0) { X509_free(x509); EVP_PKEY_free(pkey); goto fail; }
        if (SSL_CTX_use_PrivateKey(ctx->server_ctx, pkey) <= 0) { X509_free(x509); EVP_PKEY_free(pkey); goto fail; }
        X509_free(x509);
        EVP_PKEY_free(pkey);
        printf("[tls] using auto-generated self-signed cert (CN=xmr-proxy)\n");
    }

    ctx->client_ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx->client_ctx) { fprintf(stderr, "[tls] client SSL_CTX_new failed\n"); goto fail; }

    return 0;

fail:
    ERR_print_errors_fp(stderr);
    if (ctx->server_ctx) { SSL_CTX_free(ctx->server_ctx); ctx->server_ctx = NULL; }
    if (ctx->client_ctx) { SSL_CTX_free(ctx->client_ctx); ctx->client_ctx = NULL; }
    return -1;
}

void proxy_cleanup(proxy_ctx_t *ctx)
{
    if (ctx->server_ctx) { SSL_CTX_free(ctx->server_ctx); ctx->server_ctx = NULL; }
    if (ctx->client_ctx) { SSL_CTX_free(ctx->client_ctx); ctx->client_ctx = NULL; }
}

void proxy_run(proxy_ctx_t *ctx, volatile int *running)
{
    int epoll_fd = epoll_create(1);
    if (epoll_fd < 0) { perror("epoll_create"); return; }

    set_nonblock(ctx->listen_fd);
    conn_t listen_conn;
    memset(&listen_conn, 0, sizeof(listen_conn));
    fd_add(epoll_fd, ctx->listen_fd, EPOLLIN, &listen_conn);

    session_t *slist = NULL;
    struct epoll_event events[MAX_EVENTS];

    while (*running && ctx->running) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < n; i++) {
            conn_t *c = (conn_t *)events[i].data.ptr;
            if (c == &listen_conn) {
                if (events[i].events & EPOLLIN)
                    handle_accept(ctx, epoll_fd, &slist);
                continue;
            }

            /* O(1) session lookup via back-pointer instead of O(N) list scan */
            session_t *s = c->session;
            if (!s || s->closing) continue;

            handle_conn_event(s, c, events[i].events, epoll_fd);
        }

        check_timeouts(&slist, epoll_fd);
        session_cleanup_list(&slist);
    }

    for (session_t *s = slist; s; s = s->next)
        session_close(s, epoll_fd);
    session_cleanup_list(&slist);
    fd_del(epoll_fd, ctx->listen_fd);
    close(epoll_fd);
    close(ctx->listen_fd);
}
