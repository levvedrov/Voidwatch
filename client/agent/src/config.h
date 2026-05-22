#pragma once

typedef struct {
    char server_url[256];
    char api_key[256];
    char agent_id[128];
    char agent_secret[256];
    char mode[32];           /* collect_only | detect | debug */
    int  collection_interval;
    int  collect_command_line;
    int  collect_network;
    int  anonymize_paths;
} AgentConfig;

extern AgentConfig g_cfg;

/* Load config.json, .agent_id, .agent_secret from exe directory (or ~/.voidwatch fallback) */
void config_load(void);

/* Persist agent_id / agent_secret to disk */
void config_save_id(const char *id);
void config_save_secret(const char *secret);

/* Write config.json (called after enrollment) */
void config_write_json(const char *server_url, const char *api_key, const char *mode);

/* Directory containing the running exe */
void config_exe_dir(char *out, int outlen);
