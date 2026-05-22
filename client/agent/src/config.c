#include "config.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

AgentConfig g_cfg = {
    .server_url         = "http://localhost:8000",
    .api_key            = "",
    .agent_id           = "",
    .agent_secret       = "",
    .mode               = "detect",
    .collection_interval = 5,
    .collect_command_line = 1,
    .collect_network    = 1,
    .anonymize_paths    = 0,
};

void config_exe_dir(char *out, int outlen) {
    GetModuleFileNameA(NULL, out, outlen);
    char *last = strrchr(out, '\\');
    if (last) *last = '\0';
}

static void home_dir(char *out, int outlen) {
    if (!GetEnvironmentVariableA("USERPROFILE", out, outlen))
        GetTempPathA(outlen, out);
}

/* ---------- minimal JSON value extractors ---------- */

static int jget_str(const char *json, const char *key, char *out, int outlen) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return 0;
    p += strlen(search);
    while (*p == ' ' || *p == '\t') p++;
    if (*p != ':') return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return 0;
    p++;
    int i = 0;
    while (*p && *p != '"' && i < outlen - 1) {
        if (*p == '\\' && *(p + 1)) {
            p++;
            switch (*p) {
                case 'n': out[i++] = '\n'; break;
                case 'r': out[i++] = '\r'; break;
                case 't': out[i++] = '\t'; break;
                default:  out[i++] = *p;   break;
            }
        } else {
            out[i++] = *p;
        }
        p++;
    }
    out[i] = '\0';
    return 1;
}

static int jget_int(const char *json, const char *key, int *out) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return 0;
    p += strlen(search);
    while (*p == ' ' || *p == '\t') p++;
    if (*p != ':') return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    *out = atoi(p);
    return 1;
}

static int jget_bool(const char *json, const char *key, int *out) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return 0;
    p += strlen(search);
    while (*p == ' ' || *p == '\t') p++;
    if (*p != ':') return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "true",  4) == 0) { *out = 1; return 1; }
    if (strncmp(p, "false", 5) == 0) { *out = 0; return 1; }
    return 0;
}

/* ---------- read a small text file ---------- */

static int read_file_str(const char *path, char *out, int outlen) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    int n = (int)fread(out, 1, outlen - 1, f);
    fclose(f);
    if (n <= 0) { out[0] = '\0'; return 0; }
    out[n] = '\0';
    /* trim whitespace */
    while (n > 0 && (out[n-1] == '\r' || out[n-1] == '\n' ||
                     out[n-1] == ' '  || out[n-1] == '\t'))
        out[--n] = '\0';
    return n > 0;
}

static void write_file_str(const char *path, const char *value) {
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fwrite(value, 1, strlen(value), f);
    fclose(f);
}

/* ---------- public API ---------- */

void config_load(void) {
    char exe_dir[MAX_PATH], home[MAX_PATH];
    config_exe_dir(exe_dir, MAX_PATH);
    home_dir(home, MAX_PATH);

    /* 1. Read config.json */
    char cfg_path[MAX_PATH];
    snprintf(cfg_path, MAX_PATH, "%s\\config.json", exe_dir);
    char json[2048] = {0};
    if (!read_file_str(cfg_path, json, sizeof(json))) {
        /* try ~/.voidwatch/config.json */
        snprintf(cfg_path, MAX_PATH, "%s\\.voidwatch\\config.json", home);
        read_file_str(cfg_path, json, sizeof(json));
    }
    if (*json) {
        jget_str( json, "server_url",          g_cfg.server_url,  sizeof(g_cfg.server_url));
        jget_str( json, "api_key",             g_cfg.api_key,     sizeof(g_cfg.api_key));
        jget_str( json, "mode",                g_cfg.mode,        sizeof(g_cfg.mode));
        jget_int( json, "collection_interval", &g_cfg.collection_interval);
        jget_bool(json, "collect_command_line",&g_cfg.collect_command_line);
        jget_bool(json, "collect_network",     &g_cfg.collect_network);
        jget_bool(json, "anonymize_paths",     &g_cfg.anonymize_paths);
    }

    /* Environment overrides */
    char env[256];
    if (GetEnvironmentVariableA("VOIDWATCH_SERVER_URL", env, sizeof(env)) && *env)
        strncpy(g_cfg.server_url, env, sizeof(g_cfg.server_url) - 1);
    if (GetEnvironmentVariableA("VOIDWATCH_API_KEY", env, sizeof(env)) && *env)
        strncpy(g_cfg.api_key, env, sizeof(g_cfg.api_key) - 1);

    /* 2. Read .agent_id */
    char id_path[MAX_PATH], id_fb[MAX_PATH];
    snprintf(id_path, MAX_PATH, "%s\\.agent_id",              exe_dir);
    snprintf(id_fb,   MAX_PATH, "%s\\.voidwatch\\.agent_id",  home);
    if (!read_file_str(id_path, g_cfg.agent_id, sizeof(g_cfg.agent_id)))
        read_file_str(id_fb, g_cfg.agent_id, sizeof(g_cfg.agent_id));

    /* Auto-generate agent_id if missing */
    if (!*g_cfg.agent_id) {
        char hostname[256] = "unknown";
        DWORD sz = sizeof(hostname);
        GetComputerNameA(hostname, &sz);
        GUID guid;
        CoCreateGuid(&guid);
        snprintf(g_cfg.agent_id, sizeof(g_cfg.agent_id),
                 "%s-%08lx", hostname, guid.Data1);
        config_save_id(g_cfg.agent_id);
    }

    /* 3. Read .agent_secret */
    char sec_path[MAX_PATH], sec_fb[MAX_PATH];
    snprintf(sec_path, MAX_PATH, "%s\\.agent_secret",             exe_dir);
    snprintf(sec_fb,   MAX_PATH, "%s\\.voidwatch\\.agent_secret", home);
    if (!read_file_str(sec_path, g_cfg.agent_secret, sizeof(g_cfg.agent_secret)))
        read_file_str(sec_fb, g_cfg.agent_secret, sizeof(g_cfg.agent_secret));
}

void config_save_id(const char *id) {
    char exe_dir[MAX_PATH], home[MAX_PATH];
    config_exe_dir(exe_dir, MAX_PATH);
    home_dir(home, MAX_PATH);
    char path[MAX_PATH];
    snprintf(path, MAX_PATH, "%s\\.agent_id", exe_dir);
    write_file_str(path, id);
    /* fallback copy */
    char dir[MAX_PATH];
    snprintf(dir, MAX_PATH, "%s\\.voidwatch", home);
    CreateDirectoryA(dir, NULL);
    snprintf(path, MAX_PATH, "%s\\.voidwatch\\.agent_id", home);
    write_file_str(path, id);
    strncpy(g_cfg.agent_id, id, sizeof(g_cfg.agent_id) - 1);
}

void config_save_secret(const char *secret) {
    char exe_dir[MAX_PATH], home[MAX_PATH];
    config_exe_dir(exe_dir, MAX_PATH);
    home_dir(home, MAX_PATH);
    char path[MAX_PATH];
    snprintf(path, MAX_PATH, "%s\\.agent_secret", exe_dir);
    write_file_str(path, secret);
    char dir[MAX_PATH];
    snprintf(dir, MAX_PATH, "%s\\.voidwatch", home);
    CreateDirectoryA(dir, NULL);
    snprintf(path, MAX_PATH, "%s\\.voidwatch\\.agent_secret", home);
    write_file_str(path, secret);
    strncpy(g_cfg.agent_secret, secret, sizeof(g_cfg.agent_secret) - 1);
}

void config_write_json(const char *server_url, const char *api_key, const char *mode) {
    char exe_dir[MAX_PATH];
    config_exe_dir(exe_dir, MAX_PATH);
    char path[MAX_PATH];
    snprintf(path, MAX_PATH, "%s\\config.json", exe_dir);
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fprintf(f,
        "{\n"
        "  \"server_url\": \"%s\",\n"
        "  \"api_key\": \"%s\",\n"
        "  \"mode\": \"%s\",\n"
        "  \"collection_interval\": 5,\n"
        "  \"collect_command_line\": true,\n"
        "  \"collect_network\": true,\n"
        "  \"anonymize_paths\": false\n"
        "}\n",
        server_url, api_key, mode);
    fclose(f);
    strncpy(g_cfg.server_url, server_url, sizeof(g_cfg.server_url) - 1);
    strncpy(g_cfg.api_key,    api_key,    sizeof(g_cfg.api_key)    - 1);
    strncpy(g_cfg.mode,       mode,       sizeof(g_cfg.mode)       - 1);
}
