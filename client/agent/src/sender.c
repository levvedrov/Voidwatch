#include "sender.h"
#include "config.h"
#include "metadata.h"
#include "json.h"
#include "log.h"
#include <windows.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* HTTP POST via WinHTTP                                                */
/* ------------------------------------------------------------------ */

char *http_post(const char *url, const char *extra_header,
                const char *body, int *status_out) {
    if (status_out) *status_out = 0;

    /* Convert URL to wide */
    wchar_t wurl[512] = {0};
    MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl, 512);

    /* Crack URL */
    URL_COMPONENTS uc = {0};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {0}, path[512] = {0};
    uc.lpszHostName     = host; uc.dwHostNameLength     = 256;
    uc.lpszUrlPath      = path; uc.dwUrlPathLength      = 512;
    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) return NULL;

    BOOL is_https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    INTERNET_PORT port = uc.nPort ? uc.nPort : (is_https ? 443 : 80);

    HINTERNET session = WinHttpOpen(
        L"VoidwatchAgent/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return NULL;

    /* Short timeouts: connect 5s, send/recv 10s */
    WinHttpSetTimeouts(session, 5000, 5000, 10000, 10000);

    HINTERNET conn = WinHttpConnect(session, host, port, 0);
    if (!conn) { WinHttpCloseHandle(session); return NULL; }

    DWORD flags = is_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET req = WinHttpOpenRequest(
        conn, L"POST", path, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return NULL;
    }

    /* Build headers */
    wchar_t wheaders[1024] = L"Content-Type: application/json\r\n";
    if (extra_header && *extra_header) {
        wchar_t wextra[768] = {0};
        MultiByteToWideChar(CP_UTF8, 0, extra_header, -1, wextra, 768);
        size_t used = wcslen(wheaders);
        wcsncat(wheaders, wextra, (sizeof(wheaders) / sizeof(wchar_t)) - used - 1);
    }

    DWORD body_len = (DWORD)(body ? strlen(body) : 0);
    BOOL sent = WinHttpSendRequest(
        req, wheaders, (DWORD)-1,
        (LPVOID)body, body_len, body_len, 0);

    char *response = NULL;
    if (sent && WinHttpReceiveResponse(req, NULL)) {
        /* Read status */
        DWORD status = 0, sz = sizeof(status);
        WinHttpQueryHeaders(req,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
        if (status_out) *status_out = (int)status;

        /* Read body */
        char   *buf  = NULL;
        size_t  total = 0;
        DWORD   avail = 0;
        while (WinHttpQueryDataAvailable(req, &avail) && avail > 0) {
            buf = (char *)realloc(buf, total + avail + 1);
            DWORD read = 0;
            WinHttpReadData(req, buf + total, avail, &read);
            total += read;
        }
        if (buf) { buf[total] = '\0'; response = buf; }
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return response;
}

/* ------------------------------------------------------------------ */
/* Auth headers                                                         */
/* ------------------------------------------------------------------ */

static void build_auth_header(char *out, int outlen) {
    out[0] = '\0';
    if (g_cfg.api_key[0]) {
        snprintf(out, outlen, "X-API-Key: %s\r\n", g_cfg.api_key);
    } else if (g_cfg.agent_secret[0]) {
        snprintf(out, outlen,
                 "X-Agent-ID: %s\r\nX-Agent-Secret: %s\r\n",
                 g_cfg.agent_id, g_cfg.agent_secret);
    }
}

/* ------------------------------------------------------------------ */
/* Payload serialisation                                                */
/* ------------------------------------------------------------------ */

static void utc_timestamp(char *out, int outlen) {
    time_t t = time(NULL);
    struct tm *tm = gmtime(&t);
    strftime(out, outlen, "%Y-%m-%dT%H:%M:%S.000000", tm);
}

static void build_payload(ProcessSnap *snaps, int count, JsonBuf *jb) {
    Metadata meta;
    metadata_collect(&meta);

    char ts[64];
    utc_timestamp(ts, sizeof(ts));

    jb_append(jb, "{");
    jb_append(jb, "\"agent_id\":"); jb_str(jb, g_cfg.agent_id); jb_append(jb, ",");
    jb_append(jb, "\"timestamp\":"); jb_str(jb, ts); jb_append(jb, ",");

    jb_append(jb, "\"metadata\":{");
    jb_append(jb, "\"hostname\":"); jb_str(jb, meta.hostname); jb_append(jb, ",");
    jb_append(jb, "\"os\":");       jb_str(jb, meta.os);       jb_append(jb, ",");
    jb_append(jb, "\"ip\":");       jb_str(jb, meta.ip);       jb_append(jb, ",");
    jb_append(jb, "\"username\":"); jb_str(jb, meta.username);
    jb_append(jb, "},");

    jb_append(jb, "\"processes\":[");
    for (int i = 0; i < count; i++) {
        ProcessSnap *s = &snaps[i];
        if (i) jb_append(jb, ",");
        jb_append(jb, "{");
        jb_append(jb, "\"name\":");             jb_str(jb, s->name);         jb_append(jb, ",");
        jb_append(jb, "\"parent_name\":");      jb_str(jb, s->parent_name);  jb_append(jb, ",");
        jb_append(jb, "\"command_line\":");     jb_str(jb, s->command_line); jb_append(jb, ",");
        jb_append(jb, "\"path\":");             jb_str(jb, s->path);         jb_append(jb, ",");
        jb_append(jb, "\"pid\":");              jb_int(jb, s->pid);          jb_append(jb, ",");
        jb_append(jb, "\"parent_pid\":");       jb_int(jb, s->parent_pid);   jb_append(jb, ",");
        jb_append(jb, "\"cpu_usage\":");        jb_double(jb, s->cpu_usage);    jb_append(jb, ",");
        jb_append(jb, "\"mem_usage\":");        jb_double(jb, s->mem_usage_mb); jb_append(jb, ",");
        jb_append(jb, "\"is_signed\":");        jb_bool(jb, s->is_signed);   jb_append(jb, ",");
        jb_append(jb, "\"sha256\":");           jb_str(jb, s->sha256);       jb_append(jb, ",");
        jb_append(jb, "\"connection_count\":"); jb_int(jb, s->net.count);    jb_append(jb, ",");

        /* destination_ips */
        jb_append(jb, "\"destination_ips\":[");
        for (int k = 0; k < s->net.count; k++) {
            if (k) jb_append(jb, ",");
            jb_str(jb, s->net.ips[k]);
        }
        jb_append(jb, "],");

        /* destination_ports */
        jb_append(jb, "\"destination_ports\":[");
        for (int k = 0; k < s->net.count; k++) {
            if (k) jb_append(jb, ",");
            jb_int(jb, s->net.ports[k]);
        }
        jb_append(jb, "],");

        /* protocols */
        jb_append(jb, "\"protocols\":[");
        for (int k = 0; k < s->net.count; k++) {
            if (k) jb_append(jb, ",");
            jb_str(jb, s->net.is_tcp[k] ? "TCP" : "UDP");
        }
        jb_append(jb, "]");

        jb_append(jb, "}");
    }
    jb_append(jb, "]}");
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

int sender_register(void) {
    Metadata meta;
    metadata_collect(&meta);

    JsonBuf jb; jb_init(&jb);
    jb_append(&jb, "{\"agent_id\":");
    jb_str(&jb, g_cfg.agent_id);
    jb_append(&jb, ",\"metadata\":{\"hostname\":");
    jb_str(&jb, meta.hostname);
    jb_append(&jb, ",\"os\":"); jb_str(&jb, meta.os);
    jb_append(&jb, ",\"ip\":"); jb_str(&jb, meta.ip);
    jb_append(&jb, ",\"username\":"); jb_str(&jb, meta.username);
    jb_append(&jb, "}}");

    char url[512], auth[512];
    snprintf(url, sizeof(url), "%s/register", g_cfg.server_url);
    build_auth_header(auth, sizeof(auth));

    int status = 0;
    char *resp = http_post(url, auth, jb_get(&jb), &status);
    free(resp);
    jb_free(&jb);
    return (status >= 200 && status < 300);
}

int sender_send(ProcessSnap *snaps, int count) {
    JsonBuf jb; jb_init(&jb);
    build_payload(snaps, count, &jb);

    char url[512], auth[512];
    snprintf(url, sizeof(url), "%s/telemetry", g_cfg.server_url);
    build_auth_header(auth, sizeof(auth));

    int status = 0;
    char *resp = http_post(url, auth, jb_get(&jb), &status);
    free(resp);
    jb_free(&jb);
    return (status == 201);
}
