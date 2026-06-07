/* main.c -- Entry point: CLI parsing, init, signal handling, run loop. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "config.h"
#include "proxy.h"

/* Flag set to 0 by signal handler for graceful shutdown. */
static volatile int g_running = 1;

/* Catches SIGINT/SIGTERM, sets g_running = 0 so proxy_run() exits cleanly. */
static void signal_handler(int sig)
{
    (void)sig;
    printf("\n[main] shutting down...\n");
    g_running = 0;
}

/* Prints help text describing all CLI flags and endpoint URL formats. */
static void print_usage(const char *prog)
{
    printf("Usage: %s -l <listen URL> -o <upstream URL> [options]\n", prog);
    printf("\nOptions:\n");
    printf("  -l, --listen URL    Listen endpoint (stratum+tcp://, stratum+ssl://, ws://, wss://)\n");
    printf("  -o, --upstream URL  Upstream endpoint\n");
    printf("  --cert FILE         TLS certificate (optional, auto-generates self-signed for wss://)\n");
    printf("  --key FILE          TLS private key (optional, auto-generates self-signed for wss://)\n");
    printf("  --timeout SEC       Upstream connect timeout & session idle timeout (default: no timeout)\n");
    printf("  -v, --verbose       Verbose output\n");
    printf("  -h, --help          Show this help\n");
    printf("\nEndpoint URL formats:\n");
    printf("  stratum+tcp://host:port   Raw TCP stratum\n");
    printf("  stratum+ssl://host:port   TLS-secured stratum\n");
    printf("  ws://host:port/path       WebSocket (plain)\n");
    printf("  wss://host:port/path       Secure WebSocket\n");
    printf("\nExamples:\n");
    printf("  %s -l stratum+tcp://0.0.0.0:3333 -o ws://127.0.0.1:3333\n", prog);
    printf("  %s -l ws://0.0.0.0:3334 -o stratum+tcp://pool:5555\n", prog);
    printf("  %s -l wss://0.0.0.0:3335 --cert cert.pem --key key.pem -o stratum+tcp://127.0.0.1:3333\n", prog);
    printf("\n");
}

int main(int argc, char *argv[])
{
    char listen_url[512] = {0};
    char upstream_url[512] = {0};
    int verbose = 0;

    proxy_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--listen") == 0) {
            if (i + 1 < argc) strncpy(listen_url, argv[++i], sizeof(listen_url) - 1);
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--upstream") == 0) {
            if (i + 1 < argc) strncpy(upstream_url, argv[++i], sizeof(upstream_url) - 1);
        } else if (strcmp(argv[i], "--cert") == 0) {
            if (i + 1 < argc) strncpy(ctx.cert_path, argv[++i], sizeof(ctx.cert_path) - 1);
        } else if (strcmp(argv[i], "--key") == 0) {
            if (i + 1 < argc) strncpy(ctx.key_path, argv[++i], sizeof(ctx.key_path) - 1);
        } else if (strcmp(argv[i], "--timeout") == 0) {
            if (i + 1 < argc) { ctx.timeout = atoi(argv[++i]); if (ctx.timeout < 0) ctx.timeout = 0; }
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (!listen_url[0] || !upstream_url[0]) {
        fprintf(stderr, "Error: both --listen and --upstream are required.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    if (endpoint_parse(listen_url, &ctx.down) != 0) {
        fprintf(stderr, "[main] invalid listen URL\n");
        return 1;
    }
    if (endpoint_parse(upstream_url, &ctx.up) != 0) {
        fprintf(stderr, "[main] invalid upstream URL\n");
        return 1;
    }

    if (proxy_init_tls(&ctx) != 0) {
        fprintf(stderr, "[main] TLS init failed\n");
        return 1;
    }

    ctx.listen_fd = endpoint_listen(&ctx.down);
    if (ctx.listen_fd < 0) {
        fprintf(stderr, "[main] failed to listen on %s\n", listen_url);
        proxy_cleanup(&ctx);
        return 1;
    }

    ctx.verbosity = verbose;
    ctx.running = true;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("=== xmr-proxy v%s ===\n", VERSION);
    printf("listen:   %s\n", listen_url);
    printf("upstream: %s\n", upstream_url);
    if (ctx.timeout > 0) printf("timeout:  %ds\n", ctx.timeout);
    printf("[main] ready. forwarding connections...\n");

    proxy_run(&ctx, &g_running);
    ctx.running = false;
    proxy_cleanup(&ctx);
    printf("[main] exited.\n");
    return 0;
}
