/* proxy.h -- Epoll-based proxy types: endpoint, connection state machine, session.
 *
 * This is the core header for the epoll rewrite.  Defines:
 *   - endpoint_t / proxy_ctx_t : parsed CLI args + global config
 *   - conn_state_t             : state machine enum (INIT -> ... -> READY -> CLOSED)
 *   - conn_t                   : per-direction state (fd, buffer, SSL, write queue)
 *   - session_t                : down + up paired as a proxied connection
 */

#ifndef PROXY_H
#define PROXY_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <openssl/ssl.h>
#include "websocket.h"

/* Transport protocol for one side of the proxy. */
typedef enum { PROTO_TCP, PROTO_TLS, PROTO_WS, PROTO_WSS } proto_t;

/* Parsed endpoint: scheme, host, port, optional WS path. */
typedef struct {
    proto_t proto;
    char host[256];
    int port;
    char path[512];
} endpoint_t;

/* Top-level proxy config, populated from CLI flags. */
typedef struct {
    endpoint_t down;          /* listen side */
    endpoint_t up;            /* upstream side */
    int listen_fd;
    bool running;
    int verbosity;
    int timeout;              /* idle timeout in seconds, 0 = no timeout */
    char cert_path[512];
    char key_path[512];
    SSL_CTX *server_ctx;      /* TLS server context for WSS/TLS listen */
} proxy_ctx_t;

/* Connection state machine phases. */
typedef enum {
    CONN_INIT,            /* just allocated */
    CONN_CONNECTING,      /* non-blocking connect in progress */
    CONN_SSL_ACCEPT,      /* server-side TLS handshake */
    CONN_SSL_CONNECT,     /* client-side TLS handshake */
    CONN_WS_READ_REQ,     /* server: reading HTTP Upgrade request */
    CONN_WS_WRITE_REQ,    /* client: writing HTTP Upgrade request */
    CONN_WS_READ_RESP,    /* client: reading HTTP 101 response */
    CONN_WS_WRITE_RESP,   /* server: writing HTTP 101 response (flush pending) */
    CONN_READY,           /* data relay active */
    CONN_CLOSED           /* resources freed */
} conn_state_t;

#define CONN_BUF 16384
#define HANDSHAKE_BUF 4096

/* One direction of a proxied connection (downstream or upstream).
 *   ws       : ws_conn_t from websocket.h (fd, ssl, read_buf)
 *   state    : current state machine phase
 *   wbuf     : write queue for buffered EPOLLOUT writes
 *   wlen     : bytes pending in wbuf
 *   hbuf     : handshake HTTP header buffer
 *   hlen     : bytes in hbuf
 *   addr     : resolved remote address (upstream connect)
 *   epoll_events : currently-registered epoll flags (to avoid redundant MOD)
 *   is_down  : true if this is the downstream side
 *   session  : back-pointer to parent session for O(1) lookup (performance fix)
 */
typedef struct conn {
    ws_conn_t ws;
    conn_state_t state;

    uint8_t wbuf[CONN_BUF];
    size_t wlen;

    char hbuf[HANDSHAKE_BUF];
    size_t hlen;
    char expected_accept[64];

    struct sockaddr_storage addr;
    socklen_t addrlen;

    uint32_t epoll_events;
    bool is_down;

    struct session *session;
    struct conn *next;
} conn_t;

/* A proxied session pairing one downstream + one upstream connection.
 *   id        : monotonically increasing session number
 *   down      : downstream connection (incoming from miner)
 *   up        : upstream connection (outgoing to pool/proxy)
 *   down_is_ws: cached whether downstream speaks WS at CONN_READY
 *   up_is_ws  : cached whether upstream speaks WS
 *   timeout   : idle timeout copied from ctx
 *   last_active: timestamp of last relayed data
 *   closing   : tear-down in progress (prevents double-close)
 *   ctx       : back-pointer to global config
 */
typedef struct session {
    int id;
    conn_t down;
    conn_t up;
    bool down_is_ws;
    bool up_is_ws;
    int timeout;
    time_t last_active;
    bool closing;
    proxy_ctx_t *ctx;
    struct session *next;
} session_t;

/* Parse a URL string into an endpoint_t (proto, host, port, path). */
int  endpoint_parse(const char *url, endpoint_t *ep);

/* Create a listening socket bound to the endpoint's port (IPv4+IPv6 dual-stack). */
int  endpoint_listen(const endpoint_t *ep);

/* Initialise TLS: load cert/key or auto-generate self-signed cert. */
int  proxy_init_tls(proxy_ctx_t *ctx);

/* Main epoll event loop (blocks until *running == 0). */
void proxy_run(proxy_ctx_t *ctx, volatile int *running);

/* Free TLS server context. */
void proxy_cleanup(proxy_ctx_t *ctx);

#endif
