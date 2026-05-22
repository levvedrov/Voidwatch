#pragma once
#include "process_collector.h"

/* Register this agent with the server (best-effort, non-fatal) */
int sender_register(void);

/* Send a heartbeat (empty process list) + optional telemetry.
   Returns 1 on HTTP 201, 0 otherwise. */
int sender_send(ProcessSnap *snaps, int count);

/* Low-level: POST json_body to url, store HTTP status in *status_out.
   Returns allocated response body (caller must free), or NULL on error. */
char *http_post(const char *url,
                const char *extra_header,   /* e.g. "X-Agent-ID: foo\r\n..." */
                const char *json_body,
                int        *status_out);
