# xmr-proxy — Stratum Protocol Bridge

Converts between stratum TCP/TLS and WebSocket WS/WSS. Sits between miner and xmrig-proxy (or pool).

## Quick Start

```bash
make
# WSS → TCP (hide mining on network)
./xmr-proxy -l wss://0.0.0.0:3335 -o stratum+tcp://127.0.0.1:3333

# Then connect miner to wss://127.0.0.1:3335
```

## Options

| Flag | Description |
|------|-------------|
| `-l` | Listen URL (stratum+tcp://, stratum+ssl://, ws://, wss://) |
| `-o` | Upstream URL (same formats) |
| `--cert` | TLS cert file (for WSS, optional) |
| `--key` | TLS key file (for WSS, optional) |
| `--timeout` | Connect + idle timeout in seconds |
| `-v` | Verbose output |

## What It Does

Each side is independent. Pick any listen protocol and any upstream protocol:

| Listen | Upstream | Use case |
|--------|----------|----------|
| WSS | TCP | Encrypt miner→proxy, plaintext to xmrig |
| WS | TCP | No encryption, plaintext WS→TCP |
| TCP | WSS | Plain → encrypted (reverse proxy) |
| TLS | TCP | Encrypted → plain |

The proxy **terminates** the protocol on each side — not end-to-end encryption. Data is decrypted at the proxy.

## Architecture

```
Miner ←→ WSS/TLS ←→ xmr-proxy ←→ TCP ←→ xmrig-proxy ←→ TLS ←→ Pool
        encrypted          plaintext          encrypted
```

With chaining (multiple proxies):

```
Miner ←→ WSS ←→ proxy1 ←→ TCP ←→ proxy2 ←→ TCP ←→ xmrig-proxy
```

The JSON stratum data passes through each proxy unchanged — only the transport layer changes.

## Architecture History

### Original (void0895/xmrproxy initial commit)

Thread-per-connection model:
- `select()` in the accept loop with 1s tick
- `pthread_create()` per accepted session
- Each session thread runs a `select()` loop with blocking I/O
- Synchronous `ws_connect()` / `ws_accept()` for WS handshakes
- Synchronous TLS via `SSL_connect()` / `SSL_accept()` with `SO_RCVTIMEO`
- Direct `write()` / `SSL_write()` for data relay
- Log output truncated to 64 bytes via `printf("%.*s")`
- `pthread_join()` in accept-loop tick to reap finished threads

### Current (epoll rewrite)

Single-threaded epoll event loop with non-blocking state machines:
- `epoll_create()` + single `epoll_wait()` loop driving everything
- Per-connection `conn_state_t` state machine (INIT → CONNECTING → SSL/WS handshake phases → READY → CLOSED)
- Non-blocking `connect()` with completion detected via `EPOLLOUT`
- Async TLS: `SSL_connect()` / `SSL_accept()` returning `SSL_ERROR_WANT_READ/WRITE`, retried on epoll events
- Async WS handshake: `do_ws_accept()` / `do_ws_connect_req()` / `do_ws_connect_resp()` using non-blocking HTTP reads
- Write buffering: `conn_write()` queues in `wbuf` and arms `EPOLLOUT`; `conn_flush_write()` drains on `EPOLLOUT`
- Inline WS frame parser `ws_frame_parse()` in proxy.c (not relying on blocking `ws_recv()` in websocket.c)
- `build_and_send_ws()` with proper RFC 6455 client masking (MASK bit + XOR payload)
- `json_print()` pretty-prints relay data as indented JSON (no truncation)
- Deferred cleanup with `closing` guard prevents double-free

### Why the rewrite

The old thread-per-connection design crashes at ~400 connections on proot Termux due to `ptrace` serialization bottleneck in `pthread_create()`. The epoll event loop eliminates threads entirely.

## Bugs fixed in the rewrite

1. **WS client masking**: Old `send_frame()` never sets MASK bit. RFC 6455 §5.1 requires client frames to be masked. Upstream WS servers that enforce this reject unmasked frames with `1002 protocol error`.
2. **Newline in WS→TCP relay**: Restored `\n` appending when forwarding WS payload to raw TCP (stratum line protocol convention).
3. **Buffer compaction**: After `relay_data()` forwards a WS payload, remaining bytes are moved to front and `read_len` adjusted so subsequent frame parses see valid data.
4. **Single ws_frame_parse call**: Parse is called only from `relay_data()` — not from `conn_read_raw()` — preventing double-parse data loss.
5. **TLS listen**: `proxy_init_tls()` now also handles `PROTO_TLS` (stratum+ssl://) listen, not just `PROTO_WSS`.
6. **Idle timeout**: Old idle timeout was dysfunctional (thread kept running without checking). Now enforced in `check_timeouts()`.
7. **Deferred cleanup**: Sessions closed during event dispatch are freed on next cleanup pass, avoiding use-after-free.

## Source files

| File | Purpose |
|------|---------|
| `src/config.h` | Version string (`VERSION "0.1.0"`) |
| `src/main.c` | CLI arg parsing (unchanged from original), signal handlers, calls `proxy_run()` |
| `src/proxy.h` | Types: `conn_state_t`, `conn_t`, `session_t`, `proxy_ctx_t`; public API declarations |
| `src/proxy.c` | Epoll event loop, WS frame parser, relay logic, async connect, TLS/WS handshake state machines, JSON pretty-printer |
| `src/websocket.h` | `ws_conn_t` struct definition (shared by both old and new code) + blocking API declarations |
| `src/websocket.c` | Blocking RFC 6455 handshake + framing (kept from original, unused by proxy.c at runtime) |

## Auto-Generated Cert

If no `--cert`/`--key` given for WSS, the proxy generates a self-signed 2048-bit RSA cert at startup. Miner accepts it fine (xmrminer doesn't verify certs).
