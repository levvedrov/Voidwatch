#include "network_collector.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Fetch all TCP connections for a specific PID */
static void collect_tcp(DWORD pid, NetTelemetry *out) {
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return;

    MIB_TCPTABLE_OWNER_PID *table = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (!table) return;

    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID *row = &table->table[i];
            if (row->dwOwningPid != pid) continue;
            if (row->dwRemoteAddr == 0)  continue;
            if (out->count >= NET_MAX_CONNECTIONS) break;

            struct in_addr addr;
            addr.s_addr = row->dwRemoteAddr;
            InetNtopA(AF_INET, &addr,
                      out->ips[out->count], sizeof(out->ips[0]));
            out->ports[out->count]  = ntohs((u_short)row->dwRemotePort);
            out->is_tcp[out->count] = 1;
            out->count++;
        }
    }
    free(table);
}

/* Fetch all UDP connections for a specific PID */
static void collect_udp(DWORD pid, NetTelemetry *out) {
    DWORD size = 0;
    GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (size == 0) return;

    MIB_UDPTABLE_OWNER_PID *table = (MIB_UDPTABLE_OWNER_PID *)malloc(size);
    if (!table) return;

    if (GetExtendedUdpTable(table, &size, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            MIB_UDPROW_OWNER_PID *row = &table->table[i];
            if (row->dwOwningPid != pid) continue;
            if (out->count >= NET_MAX_CONNECTIONS) break;

            /* UDP has no remote addr; record local port as a listener indicator */
            snprintf(out->ips[out->count], sizeof(out->ips[0]), "0.0.0.0");
            out->ports[out->count]  = ntohs((u_short)row->dwLocalPort);
            out->is_tcp[out->count] = 0;
            out->count++;
        }
    }
    free(table);
}

void net_collect(DWORD pid, NetTelemetry *out) {
    memset(out, 0, sizeof(*out));
    collect_tcp(pid, out);
    collect_udp(pid, out);
}
