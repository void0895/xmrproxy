/* websocket.h -- Shared WS connection struct, legacy blocking API declarations.
 *
 * This header defines ws_conn_t (the per-connection I/O state struct shared
 * by both websocket.c and proxy.c) and the blocking ws_connect/ws_accept
 * helpers. The epoll-based proxy.c uses ws_conn_t but implements its own
 * async handshake and framing in proxy.c (ws_frame_parse, build_and_send_ws).
 */

#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/ssl.h>

/* Per-connection state: fd, optional TLS, read buffer.
 * Used by both the blocking API (websocket.c) and the epoll loop (proxy.c).
 *   fd       : socket fd, -1 when closed
 *   ssl      : non-NULL when TLS is active
 *   ctx      : SSL_CTX for client-mode TLS (freed on close)
 *   use_tls  : cached flag, 1 when ssl is valid
 *   host     : SNI hostname for client TLS
 *   read_buf : 64 KB ring/accumulation buffer
 *   read_len : bytes currently valid in read_buf
 */
typedef struct {
    int fd;
    SSL *ssl;
    SSL_CTX *ctx;
    int use_tls;
    char host[256];
    uint8_t read_buf[65536];
    size_t read_len;
} ws_conn_t;

/* Blocking outbound WS handshake (TCP+upgrade). Returns 0 on success. */
int  ws_connect(ws_conn_t *ws, const char *url);

/* Blocking inbound WS handshake (read HTTP Upgrade, send 101). Returns 0 on success. */
int  ws_accept(ws_conn_t *ws, int fd, SSL_CTX *server_ctx);

/* Send a text frame (blocking). Returns 0 on success. */
int  ws_send(ws_conn_t *ws, const char *data, size_t len);

/* Receive a text frame payload (blocking with timeout). Returns payload length. */
int  ws_recv(ws_conn_t *ws, char *buf, size_t buf_size, int timeout_ms);

/* Shut down WS connection, free SSL/ctx, close fd. */
void ws_close(ws_conn_t *ws);

#endif
