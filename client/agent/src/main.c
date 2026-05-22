#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "config.h"
#include "sender.h"
#include "enroll.h"
#include "process_collector.h"

#define COLLECTION_TIMEOUT_MS 90000

/* Run one collection cycle in a thread so we can enforce a timeout */
static ProcessSnap *g_snaps = NULL;
static int          g_snap_count = 0;

static DWORD WINAPI collect_thread(LPVOID arg) {
    (void)arg;
    g_snap_count = proc_collect_all(&g_snaps);
    return 0;
}

static void run_collection(void) {
    g_snaps      = NULL;
    g_snap_count = 0;

    HANDLE t = CreateThread(NULL, 0, collect_thread, NULL, 0, NULL);
    if (!t) {
        log_warn("Failed to create collection thread");
        return;
    }

    DWORD waited = WaitForSingleObject(t, COLLECTION_TIMEOUT_MS);
    if (waited == WAIT_TIMEOUT) {
        log_warn("Collection timed out after %ds", COLLECTION_TIMEOUT_MS / 1000);
        TerminateThread(t, 1);
        if (g_snaps) { proc_free(g_snaps); g_snaps = NULL; }
        g_snap_count = 0;
    }
    CloseHandle(t);
}

static void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s                          — run agent (normal mode)\n", prog);
    printf("  %s --enroll <url> <token>   — enroll with server\n",      prog);
}

int main(int argc, char *argv[]) {
    /* Initialise Winsock (required for all socket operations) */
    WSADATA wsd;
    WSAStartup(MAKEWORD(2, 2), &wsd);

    log_init();

    /* --enroll mode */
    if (argc == 4 && strcmp(argv[1], "--enroll") == 0) {
        config_load();
        if (!enroll_agent(argv[2], argv[3])) {
            fprintf(stderr, "Enrollment failed.\n");
            WSACleanup();
            return 1;
        }
        printf("Enrollment successful.\n");
        WSACleanup();
        return 0;
    }

    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    config_load();
    log_info("Voidwatch agent starting  agent_id=%s  server=%s  mode=%s",
             g_cfg.agent_id, g_cfg.server_url, g_cfg.mode);

    /* Best-effort initial registration */
    if (!sender_register())
        log_warn("Initial registration failed — will retry via telemetry");

    int interval_ms = g_cfg.collection_interval * 1000;
    if (interval_ms < 1000) interval_ms = 5000;

    while (1) {
        /* Heartbeat first — updates last_seen before (possibly slow) collection */
        if (!sender_send(NULL, 0))
            log_warn("Heartbeat failed — backend may be unreachable");

        run_collection();

        if (g_snap_count > 0) {
            if (!sender_send(g_snaps, g_snap_count))
                log_warn("Telemetry send failed (%d processes)", g_snap_count);
            else
                log_info("Sent %d process records", g_snap_count);
            proc_free(g_snaps);
            g_snaps = NULL;
        }

        Sleep(interval_ms);
    }

    WSACleanup();
    return 0;
}
