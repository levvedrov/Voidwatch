#include "enroll.h"
#include "sender.h"
#include "config.h"
#include "metadata.h"
#include "json.h"
#include "log.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Simple JSON string value extractor (reused from config.c pattern) */
static int jget(const char *json, const char *key, char *out, int outlen) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return 0;
    p += strlen(search);
    while (*p == ' ' || *p == '\t') p++;
    if (*p++ != ':') return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (*p++ != '"') return 0;
    int i = 0;
    while (*p && *p != '"' && i < outlen - 1) {
        if (*p == '\\' && *(p + 1)) { p++; }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 1;
}

int enroll_agent(const char *server_url, const char *token) {
    Metadata meta;
    metadata_collect(&meta);

    JsonBuf jb; jb_init(&jb);
    jb_append(&jb, "{");
    jb_append(&jb, "\"token\":");    jb_str(&jb, token);
    jb_append(&jb, ",\"hostname\":"); jb_str(&jb, meta.hostname);
    jb_append(&jb, ",\"os\":");       jb_str(&jb, meta.os);
    jb_append(&jb, ",\"ip\":");       jb_str(&jb, meta.ip);
    jb_append(&jb, ",\"username\":"); jb_str(&jb, meta.username);
    jb_append(&jb, "}");

    char url[512];
    snprintf(url, sizeof(url), "%s/agents/enroll", server_url);

    int status = 0;
    char *resp = http_post(url, "", jb_get(&jb), &status);
    jb_free(&jb);

    if (!resp) {
        log_error("Enrollment: connection to %s failed", url);
        return 0;
    }
    if (status != 200 && status != 201) {
        log_error("Enrollment: server returned HTTP %d — %s", status, resp);
        free(resp);
        return 0;
    }

    char agent_id[128] = {0}, agent_secret[256] = {0}, mode[32] = "collect_only";
    if (!jget(resp, "agent_id",     agent_id,     sizeof(agent_id))     ||
        !jget(resp, "agent_secret", agent_secret, sizeof(agent_secret))) {
        log_error("Enrollment: missing agent_id/agent_secret in response");
        free(resp);
        return 0;
    }
    jget(resp, "mode", mode, sizeof(mode));
    free(resp);

    config_save_id(agent_id);
    config_save_secret(agent_secret);
    config_write_json(server_url, "", mode);

    log_info("Enrolled as: %s  mode: %s", agent_id, mode);
    return 1;
}
