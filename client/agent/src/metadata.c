#include "metadata.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

/* Use RtlGetVersion (always works, unlike GetVersionEx which lies on Win8+) */
typedef NTSTATUS (WINAPI *RtlGetVersion_t)(OSVERSIONINFOEXW *);

static void get_os(char *out, int outlen) {
    OSVERSIONINFOEXW vi = {0};
    vi.dwOSVersionInfoSize = sizeof(vi);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    RtlGetVersion_t fn = (RtlGetVersion_t)(void *)GetProcAddress(ntdll, "RtlGetVersion");
    if (fn) fn(&vi);
    snprintf(out, outlen, "Windows %lu.%lu Build %lu",
             vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
}

static void get_outbound_ip(char *out, int outlen) {
    /* Connect a UDP socket to a routable address — no data is sent,
       this just tells us which local interface would be used. */
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) { strncpy(out, "127.0.0.1", outlen); return; }
    struct sockaddr_in dst = {0};
    dst.sin_family      = AF_INET;
    dst.sin_port        = htons(80);
    dst.sin_addr.s_addr = inet_addr("8.8.8.8");
    if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) == 0) {
        struct sockaddr_in local = {0};
        int len = sizeof(local);
        if (getsockname(s, (struct sockaddr *)&local, &len) == 0)
            InetNtopA(AF_INET, &local.sin_addr, out, outlen);
        else
            strncpy(out, "127.0.0.1", outlen);
    } else {
        strncpy(out, "127.0.0.1", outlen);
    }
    closesocket(s);
}

void metadata_collect(Metadata *m) {
    DWORD sz;

    sz = (DWORD)sizeof(m->hostname);
    GetComputerNameA(m->hostname, &sz);

    get_os(m->os, sizeof(m->os));
    get_outbound_ip(m->ip, sizeof(m->ip));

    sz = (DWORD)sizeof(m->username);
    if (!GetUserNameA(m->username, &sz)) {
        char *env = getenv("USERNAME");
        strncpy(m->username, env ? env : "unknown", sizeof(m->username) - 1);
    }
}
