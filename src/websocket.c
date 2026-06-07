/* websocket.c -- Blocking WS client/server handshake + framing helpers.
 *
 * Implements the RFC 6455 handshake (client & server), text-frame send,
 * and framed receive with timeout.  Uses blocking I/O -- suitable for
 * one-shot use but NOT called by the epoll-based proxy.c at runtime.
 * The epoll loop has its own async equivalents (ws_frame_parse,
 * build_and_send_ws, do_ws_accept, do_ws_connect_req).
 */

#include "websocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/* create_socket — Resolve a hostname:port and connect a blocking TCP socket.
 *   host : remote hostname or IP
 *   port : remote TCP port
 *   Returns connected socket fd on success, -1 on failure.
 */
static int create_socket(const char *host, int port)
{
    struct addrinfo hints, *res;
    char port_str[16];
    int fd = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* base64_encode — Standard Base64 encoding (RFC 4648).  No line breaks.
 *   out : destination null-terminated string (must be large enough)
 *   in  : source binary data
 *   len : number of input bytes
 */
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

/* parse_url — Decompose a ws:// or wss:// URL into its components.
 *   url     : input URL string
 *   host    : output buffer for the hostname
 *   port    : output port number
 *   path    : output buffer for the request path
 *   use_tls : output flag set to 1 for wss://, 0 otherwise
 *   Returns 0 on success.
 */
static int parse_url(const char *url, char *host, int *port, char *path, int *use_tls)
{
    const char *p = url;
    *use_tls = 0;
    if (strncmp(p, "wss://", 6) == 0) { *use_tls = 1; *port = 443; p += 6; }
    else if (strncmp(p, "ws://", 5) == 0) { *port = 80; p += 5; }
    else { *port = 80; }
    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    size_t host_len;
    if (colon && (!slash || colon < slash)) { host_len = colon - p; *port = atoi(colon + 1); }
    else if (slash) { host_len = slash - p; }
    else { host_len = strlen(p); }
    memcpy(host, p, host_len); host[host_len] = '\0';
    if (slash) strcpy(path, slash); else strcpy(path, "/");
    return 0;
}

/* ws_connect — Establish a WebSocket client connection to the given URL.
 *   Performs TCP connect, optional TLS handshake, then the WebSocket
 *   HTTP Upgrade handshake with a randomly generated Sec-WebSocket-Key.
 *   ws  : uninitialised ws_conn_t; populated on success
 *   url : "ws://..." or "wss://..."
 *   Returns 0 on success, -1 on failure.
 */
int ws_connect(ws_conn_t *ws, const char *url)
{
    char host[256], path[512];
    int port, use_tls;
    memset(ws, 0, sizeof(*ws));
    parse_url(url, host, &port, path, &use_tls);
    snprintf(ws->host, sizeof(ws->host), "%s", host);
    ws->use_tls = use_tls;
    ws->fd = create_socket(host, port);
    if (ws->fd < 0) { fprintf(stderr, "[ws] connect failed %s:%d\n", host, port); return -1; }
    if (use_tls) {
        ws->ctx = SSL_CTX_new(TLS_client_method());
        if (!ws->ctx) { close(ws->fd); return -1; }
        ws->ssl = SSL_new(ws->ctx);
        SSL_set_fd(ws->ssl, ws->fd);
        SSL_set_tlsext_host_name(ws->ssl, host);
        if (SSL_connect(ws->ssl) <= 0) { fprintf(stderr, "[ws] TLS failed\n"); ws_close(ws); return -1; }
    }
    /* Generate random 16-byte key and Base64-encode it per RFC 6455. */
    uint8_t key[16];
    RAND_bytes(key, sizeof(key));
    char key_b64[256];
    base64_encode(key_b64, key, sizeof(key));
    char req[2048];
    snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
        path, host, key_b64);
    if (use_tls) SSL_write(ws->ssl, req, strlen(req));
    else (void)write(ws->fd, req, strlen(req));
    /* Read the HTTP response header (must contain "101 Switching Protocols"). */
    char resp[4096] = {0};
    size_t total = 0;
    int n;
    do {
        if (use_tls) n = SSL_read(ws->ssl, resp + total, sizeof(resp) - total - 1);
        else n = read(ws->fd, resp + total, sizeof(resp) - total - 1);
        if (n > 0) total += n;
    } while (total < 4 && n > 0);
    if (strstr(resp, "101") == NULL) { fprintf(stderr, "[ws] handshake failed\n"); ws_close(ws); return -1; }
    return 0;
}

/* ws_accept — Perform the server side of the WebSocket opening handshake.
 *   Reads the HTTP Upgrade request, extracts Sec-WebSocket-Key, computes
 *   the expected accept value per RFC 6455, and sends the 101 response.
 *   ws          : uninitialised ws_conn_t; populated on success
 *   fd          : accepted TCP socket (already connected)
 *   server_ctx  : SSL_CTX for TLS, or NULL for plain WS
 *   Returns 0 on success, -1 on failure.
 */
int ws_accept(ws_conn_t *ws, int fd, SSL_CTX *server_ctx)
{
    memset(ws, 0, sizeof(*ws));
    ws->fd = fd;
    if (server_ctx) {
        ws->use_tls = 1;
        ws->ssl = SSL_new(server_ctx);
        SSL_set_fd(ws->ssl, fd);
        if (SSL_accept(ws->ssl) <= 0) {
            SSL_free(ws->ssl); ws->ssl = NULL;
            close(fd); ws->fd = -1;
            return -1;
        }
    }
    /* Read the HTTP request byte-by-byte until we find \r\n\r\n. */
    char buf[4096] = {0};
    size_t total = 0;
    while (total < sizeof(buf) - 1) {
        int n;
        if (ws->use_tls) n = SSL_read(ws->ssl, buf + total, 1);
        else n = read(fd, buf + total, 1);
        if (n <= 0) { ws_close(ws); return -1; }
        total += n;
        if (total >= 4 && memcmp(buf + total - 4, "\r\n\r\n", 4) == 0) break;
    }
    /* Extract the Sec-WebSocket-Key header value. */
    char key[256] = {0};
    const char *k = strstr(buf, "Sec-WebSocket-Key: ");
    if (!k) { ws_close(ws); return -1; }
    k += 19;
    const char *kn = strstr(k, "\r\n");
    if (!kn) { ws_close(ws); return -1; }
    size_t klen = kn - k;
    if (klen > 255) klen = 255;
    memcpy(key, k, klen); key[klen] = '\0';
    /* Concatenate with the magic GUID and SHA-1 hash it per RFC 6455. */
    char concat[512];
    snprintf(concat, sizeof(concat), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    unsigned char sha[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)concat, strlen(concat), sha);
    char accept_key[64];
    base64_encode(accept_key, sha, SHA_DIGEST_LENGTH);
    char resp[1024];
    int rlen = snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
        accept_key);
    if (ws->use_tls) SSL_write(ws->ssl, resp, rlen);
    else write(fd, resp, rlen);
    return 0;
}

/* send_frame — Write a single WebSocket frame to the connection.
 *   This is a helper used by ws_send() and any future binary-frame sending.
 *   ws      : the connection
 *   opcode  : frame opcode (e.g. 0x01 for text)
 *   payload : frame payload bytes
 *   len     : payload length
 *   Returns 0 on success.
 */
static int send_frame(ws_conn_t *ws, uint8_t opcode, const uint8_t *payload, size_t len)
{
    uint8_t header[14];
    int hlen = 0;
    /* FIN bit set + opcode.  For small frames use 7-bit length, else 16-bit or 64-bit. */
    header[0] = 0x80 | opcode;
    if (len < 126) { header[1] = (uint8_t)len; hlen = 2; }
    else if (len < 65536) { header[1] = 126; header[2] = (len >> 8) & 0xFF; header[3] = len & 0xFF; hlen = 4; }
    else { header[1] = 127; for (int i = 0; i < 8; i++) header[2 + i] = (len >> (56 - i * 8)) & 0xFF; hlen = 10; }
    if (ws->use_tls) { SSL_write(ws->ssl, header, hlen); if (len > 0) SSL_write(ws->ssl, payload, len); }
    else { write(ws->fd, header, hlen); if (len > 0) write(ws->fd, payload, len); }
    return 0;
}

/* ws_send — Send a text frame (opcode 0x01) over the WebSocket connection. */
int ws_send(ws_conn_t *ws, const char *data, size_t len)
{
    return send_frame(ws, 0x01, (const uint8_t *)data, len);
}

/* ws_read_raw — Read raw bytes from the underlying transport (TLS or plain TCP).
 *   Applies a socket receive timeout via SO_RCVTIMEO.
 *   ws         : the connection
 *   buf        : destination buffer
 *   size       : number of bytes to read
 *   timeout_ms : receive timeout in milliseconds
 *   Returns the number of bytes read, 0 on shutdown, -1 on error.
 */
static int ws_read_raw(ws_conn_t *ws, uint8_t *buf, size_t size, int timeout_ms)
{
    struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
    setsockopt(ws->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (ws->use_tls) return SSL_read(ws->ssl, buf, size);
    else return read(ws->fd, buf, size);
}

/* ws_recv — Receive the next WebSocket frame and extract its payload.
 *   Reads the 2-byte frame header (handling extended length for 126/127),
 *   then reads the payload body.  No masking is applied (server side).
 *   ws         : the connection
 *   buf        : destination buffer for the payload
 *   buf_size   : capacity of buf
 *   timeout_ms : receive timeout passed to ws_read_raw for the header
 *   Returns payload length on success, 0 on shutdown, -1 on error/overflow.
 */
int ws_recv(ws_conn_t *ws, char *buf, size_t buf_size, int timeout_ms)
{
    uint8_t header[14];
    int n = ws_read_raw(ws, header, 2, timeout_ms);
    if (n <= 0) return n;
    size_t payload_len = header[1] & 0x7F;
    if (payload_len == 126) {
        n = ws_read_raw(ws, header + 2, 2, 1000);
        if (n <= 0) return -1;
        payload_len = ((size_t)header[2] << 8) | header[3];
    } else if (payload_len == 127) {
        n = ws_read_raw(ws, header + 2, 8, 1000);
        if (n <= 0) return -1;
        payload_len = 0;
        for (int i = 0; i < 8; i++) payload_len = (payload_len << 8) | header[2 + i];
    }
    if (payload_len >= buf_size) return -1;
    size_t total = 0;
    while (total < payload_len) {
        n = ws_read_raw(ws, (uint8_t *)buf + total, payload_len - total, 1000);
        if (n <= 0) break;
        total += n;
    }
    buf[total] = '\0';
    return (int)total;
}

/* ws_close — Gracefully shut down a WebSocket connection and free resources.
 *   Performs TLS shutdown if applicable, frees SSL and SSL_CTX objects,
 *   and closes the underlying socket.  The ws_conn_t is left in a safe state.
 */
void ws_close(ws_conn_t *ws)
{
    if (ws->ssl) { SSL_shutdown(ws->ssl); SSL_free(ws->ssl); }
    if (ws->ctx) SSL_CTX_free(ws->ctx);
    if (ws->fd >= 0) close(ws->fd);
    ws->fd = -1; ws->ssl = NULL; ws->ctx = NULL;
}
