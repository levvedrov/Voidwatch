#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "network_collector.h"

typedef struct {
    char         name[256];
    char         parent_name[256];
    char         command_line[2048];
    char         path[1024];
    DWORD        pid;
    DWORD        parent_pid;
    double       cpu_usage;
    double       mem_usage_mb;
    int          is_signed;
    char         sha256[65];     /* always empty — reserved for future use */
    NetTelemetry net;
} ProcessSnap;

/*
 * Enumerate all running processes and fill out an allocated array.
 * Caller must free(*out) when done.
 * Returns number of entries, or -1 on fatal error.
 */
int proc_collect_all(ProcessSnap **out);

void proc_free(ProcessSnap *snaps);
