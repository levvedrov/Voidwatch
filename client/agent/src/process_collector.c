#include "process_collector.h"
#include "network_collector.h"
#include "config.h"
#include "log.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* Known system process names — always treated as signed               */
/* ------------------------------------------------------------------ */
static const char *KNOWN_SYSTEM[] = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "lsass.exe", "lsaiso.exe", "services.exe",
    "svchost.exe", "spoolsv.exe", "explorer.exe", "taskhostw.exe",
    "taskhost.exe", "dwm.exe", "conhost.exe", "fontdrvhost.exe",
    "sihost.exe", "ctfmon.exe", "runtimebroker.exe",
    "searchindexer.exe", "searchhost.exe", "msdtc.exe",
    "securityhealthservice.exe", "audiodg.exe", "wuauclt.exe",
    NULL
};

static const char *SYS_PATHS[] = {
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    NULL
};

static void str_lower(char *s) {
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

static int is_known_system(const char *name) {
    char lo[256];
    strncpy(lo, name, sizeof(lo) - 1); lo[sizeof(lo)-1] = '\0';
    str_lower(lo);
    for (int i = 0; KNOWN_SYSTEM[i]; i++)
        if (strcmp(lo, KNOWN_SYSTEM[i]) == 0) return 1;
    return 0;
}

static int path_under_system(const char *path) {
    char lo[1024];
    strncpy(lo, path, sizeof(lo) - 1); lo[sizeof(lo)-1] = '\0';
    str_lower(lo);
    for (int i = 0; SYS_PATHS[i]; i++)
        if (strstr(lo, SYS_PATHS[i])) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Authenticode signature check via WinVerifyTrust                     */
/* ------------------------------------------------------------------ */
static int check_signature(const char *path_utf8) {
    if (!path_utf8 || !*path_utf8) return 0;

    wchar_t wpath[1024] = {0};
    MultiByteToWideChar(CP_UTF8, 0, path_utf8, -1, wpath, 1024);

    WINTRUST_FILE_INFO fi = {0};
    fi.cbStruct       = sizeof(fi);
    fi.pcwszFilePath  = wpath;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd = {0};
    wd.cbStruct          = sizeof(wd);
    wd.dwUIChoice        = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice     = WTD_CHOICE_FILE;
    wd.pFile             = &fi;
    wd.dwStateAction     = WTD_STATEACTION_VERIFY;

    LONG result = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);

    return result == ERROR_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Signature cache — batch-verify unique paths once per collection run */
/* ------------------------------------------------------------------ */
#define SIG_CACHE_MAX 1024
typedef struct { char path[1024]; int signed_ok; } SigEntry;
static SigEntry s_sig_cache[SIG_CACHE_MAX];
static int      s_sig_count = 0;

static void sig_cache_reset(void) { s_sig_count = 0; }

static int sig_cache_lookup(const char *path) {
    for (int i = 0; i < s_sig_count; i++)
        if (strcmp(s_sig_cache[i].path, path) == 0)
            return s_sig_cache[i].signed_ok;
    return -1; /* not found */
}

static void sig_cache_store(const char *path, int ok) {
    if (s_sig_count >= SIG_CACHE_MAX) return;
    strncpy(s_sig_cache[s_sig_count].path, path, sizeof(s_sig_cache[0].path) - 1);
    s_sig_cache[s_sig_count].signed_ok = ok;
    s_sig_count++;
}

static int resolve_signed(const char *name, const char *path) {
    if (is_known_system(name)) return 1;
    if (!path || !*path) return 0;
    int cached = sig_cache_lookup(path);
    if (cached >= 0) return cached;
    int ok = check_signature(path);
    if (!ok && path_under_system(path)) ok = 1;
    sig_cache_store(path, ok);
    return ok;
}

/* ------------------------------------------------------------------ */
/* CPU tracking                                                         */
/* ------------------------------------------------------------------ */
#define CPU_TRACK_MAX 2048
typedef struct {
    DWORD     pid;
    ULONGLONG prev_kernel;
    ULONGLONG prev_user;
    ULONGLONG prev_wall_ms;
} CpuEntry;

static CpuEntry s_cpu[CPU_TRACK_MAX];
static int      s_cpu_count = 0;

static CpuEntry *cpu_find(DWORD pid) {
    for (int i = 0; i < s_cpu_count; i++)
        if (s_cpu[i].pid == pid) return &s_cpu[i];
    return NULL;
}

static double cpu_get_and_update(DWORD pid, ULONGLONG kernel, ULONGLONG user) {
    ULONGLONG now_ms = GetTickCount64();
    CpuEntry *e = cpu_find(pid);
    if (!e) {
        if (s_cpu_count < CPU_TRACK_MAX) {
            e = &s_cpu[s_cpu_count++];
            e->pid          = pid;
            e->prev_kernel  = kernel;
            e->prev_user    = user;
            e->prev_wall_ms = now_ms;
        }
        return 0.0;
    }
    ULONGLONG elapsed_100ns = (now_ms - e->prev_wall_ms) * 10000ULL;
    double pct = 0.0;
    if (elapsed_100ns > 0) {
        ULONGLONG delta = (kernel - e->prev_kernel) + (user - e->prev_user);
        pct = 100.0 * (double)delta / (double)elapsed_100ns;
        if (pct < 0.0) pct = 0.0;
        if (pct > 100.0) pct = 100.0;
    }
    e->prev_kernel  = kernel;
    e->prev_user    = user;
    e->prev_wall_ms = now_ms;
    return pct;
}

/* ------------------------------------------------------------------ */
/* Get command line via NtQueryInformationProcess (class 60)           */
/* ------------------------------------------------------------------ */
typedef LONG (WINAPI *NtQIP_t)(HANDLE, DWORD, PVOID, ULONG, PULONG);
static NtQIP_t s_NtQIP = NULL;

static void init_ntqip(void) {
    if (!s_NtQIP) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        s_NtQIP = (NtQIP_t)(void *)GetProcAddress(ntdll, "NtQueryInformationProcess");
    }
}

typedef struct { USHORT Length, MaxLen; PWSTR Buffer; } UnicodeString;

static void get_cmdline(HANDLE hProc, char *out, int outlen) {
    out[0] = '\0';
    if (!s_NtQIP) return;
    ULONG retLen = 0;
    /* first call to get required size */
    s_NtQIP(hProc, 60, NULL, 0, &retLen);
    if (retLen == 0 || retLen > 65536) return;
    unsigned char *buf = (unsigned char *)malloc(retLen);
    if (!buf) return;
    if (s_NtQIP(hProc, 60, buf, retLen, &retLen) == 0) {
        UnicodeString *us = (UnicodeString *)buf;
        if (us->Buffer && us->Length > 0 && us->Length < 32000) {
            WideCharToMultiByte(CP_UTF8, 0, us->Buffer, us->Length / 2,
                                out, outlen - 1, NULL, NULL);
            out[outlen - 1] = '\0';
        }
    }
    free(buf);
}

/* ------------------------------------------------------------------ */
/* Main collection function                                             */
/* ------------------------------------------------------------------ */

/* Intermediate snapshot before parent-name resolution */
typedef struct {
    DWORD pid;
    DWORD parent_pid;
    char  name[256];
    char  path[1024];
    char  command_line[2048];
    double cpu_usage;
    double mem_usage_mb;
    int    is_signed;
} RawSnap;

int proc_collect_all(ProcessSnap **out) {
    *out = NULL;
    init_ntqip();
    sig_cache_reset();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return -1;

    /* Pass 1 — enumerate processes */
    int cap = 512, count = 0;
    RawSnap *raw = (RawSnap *)malloc(cap * sizeof(RawSnap));
    if (!raw) { CloseHandle(snap); return -1; }

    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);
    for (BOOL ok = Process32First(snap, &pe); ok; ok = Process32Next(snap, &pe)) {
        if (count >= cap) {
            cap *= 2;
            RawSnap *tmp = (RawSnap *)realloc(raw, cap * sizeof(RawSnap));
            if (!tmp) { free(raw); CloseHandle(snap); return -1; }
            raw = tmp;
        }
        RawSnap *r = &raw[count];
        memset(r, 0, sizeof(*r));
        r->pid        = pe.th32ProcessID;
        r->parent_pid = pe.th32ParentProcessID;
        strncpy(r->name, pe.szExeFile, sizeof(r->name) - 1);
        r->name[sizeof(r->name) - 1] = '\0';

        HANDLE hProc = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE, r->pid);

        if (hProc) {
            /* Exe path */
            wchar_t wpath[1024] = {0};
            DWORD plen = 1024;
            if (QueryFullProcessImageNameW(hProc, 0, wpath, &plen))
                WideCharToMultiByte(CP_UTF8, 0, wpath, -1,
                                    r->path, sizeof(r->path) - 1, NULL, NULL);

            /* Command line */
            if (g_cfg.collect_command_line)
                get_cmdline(hProc, r->command_line, sizeof(r->command_line));

            /* Memory (RSS in MB) */
            PROCESS_MEMORY_COUNTERS pmc = {0};
            pmc.cb = sizeof(pmc);
            if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc)))
                r->mem_usage_mb = (double)pmc.WorkingSetSize / (1024.0 * 1024.0);

            /* CPU times */
            FILETIME ct, et, kt, ut;
            if (GetProcessTimes(hProc, &ct, &et, &kt, &ut)) {
                ULONGLONG kernel = ((ULONGLONG)kt.dwHighDateTime << 32) | kt.dwLowDateTime;
                ULONGLONG user   = ((ULONGLONG)ut.dwHighDateTime << 32) | ut.dwLowDateTime;
                r->cpu_usage = cpu_get_and_update(r->pid, kernel, user);
            }

            /* Signature (resolved later from cache) */
            r->is_signed = resolve_signed(r->name, r->path);

            CloseHandle(hProc);
        } else {
            /* No handle — still treat known system processes as signed */
            r->is_signed = is_known_system(r->name);
        }
        count++;
    }
    CloseHandle(snap);

    /* Pass 2 — build pid→name map for parent resolution */
    ProcessSnap *result = (ProcessSnap *)calloc(count, sizeof(ProcessSnap));
    if (!result) { free(raw); return -1; }

    for (int i = 0; i < count; i++) {
        ProcessSnap *s = &result[i];
        RawSnap     *r = &raw[i];

        strncpy(s->name,         r->name,         sizeof(s->name)         - 1);
        strncpy(s->path,         r->path,         sizeof(s->path)         - 1);
        strncpy(s->command_line, r->command_line, sizeof(s->command_line) - 1);
        s->pid          = r->pid;
        s->parent_pid   = r->parent_pid;
        s->cpu_usage    = r->cpu_usage;
        s->mem_usage_mb = r->mem_usage_mb;
        s->is_signed    = r->is_signed;
        s->sha256[0]    = '\0';

        /* Resolve parent name */
        for (int j = 0; j < count; j++) {
            if (raw[j].pid == r->parent_pid) {
                strncpy(s->parent_name, raw[j].name, sizeof(s->parent_name) - 1);
                break;
            }
        }

        /* Network connections */
        if (g_cfg.collect_network)
            net_collect(r->pid, &s->net);
    }

    free(raw);
    *out = result;
    return count;
}

void proc_free(ProcessSnap *snaps) {
    free(snaps);
}
