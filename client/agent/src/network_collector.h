#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#define NET_MAX_CONNECTIONS 128

typedef struct {
    int  count;
    char ips[NET_MAX_CONNECTIONS][48];
    int  ports[NET_MAX_CONNECTIONS];
    int  is_tcp[NET_MAX_CONNECTIONS];   /* 1 = TCP, 0 = UDP */
} NetTelemetry;

void net_collect(DWORD pid, NetTelemetry *out);
