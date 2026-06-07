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

## Auto-Generated Cert

If no `--cert`/`--key` given for WSS, the proxy generates a self-signed 2048-bit RSA cert at startup. Miner accepts it fine (xmrminer doesn't verify certs).
