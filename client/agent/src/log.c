#include "log.h"
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

#define MAX_LOG_BYTES (5 * 1024 * 1024)
#define LOG_BACKUPS   3

static char   s_path[MAX_PATH];
static HANDLE s_file = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION s_cs;

static void rotate(void) {
    if (s_file != INVALID_HANDLE_VALUE) {
        CloseHandle(s_file);
        s_file = INVALID_HANDLE_VALUE;
    }
    char old_name[MAX_PATH], new_name[MAX_PATH];
    for (int i = LOG_BACKUPS; i >= 1; i--) {
        snprintf(old_name, MAX_PATH, "%s.%d", s_path, i);
        snprintf(new_name, MAX_PATH, "%s.%d", s_path, i + 1);
        MoveFileExA(old_name, new_name, MOVEFILE_REPLACE_EXISTING);
    }
    snprintf(new_name, MAX_PATH, "%s.1", s_path);
    MoveFileExA(s_path, new_name, MOVEFILE_REPLACE_EXISTING);
    s_file = CreateFileA(s_path, GENERIC_WRITE, FILE_SHARE_READ,
                         NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

void log_init(void) {
    InitializeCriticalSection(&s_cs);
    char home[MAX_PATH];
    if (!GetEnvironmentVariableA("USERPROFILE", home, MAX_PATH))
        GetTempPathA(MAX_PATH, home);
    char dir[MAX_PATH];
    snprintf(dir,    MAX_PATH, "%s\\.voidwatch",           home);
    snprintf(s_path, MAX_PATH, "%s\\.voidwatch\\agent.log", home);
    CreateDirectoryA(dir, NULL);
    s_file = CreateFileA(s_path, GENERIC_WRITE | FILE_APPEND_DATA,
                         FILE_SHARE_READ, NULL, OPEN_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, NULL);
    if (s_file != INVALID_HANDLE_VALUE)
        SetFilePointer(s_file, 0, NULL, FILE_END);
}

void log_msg(int level, const char *fmt, ...) {
    static const char *lvl[] = {"INFO", "WARN", "ERROR"};
    SYSTEMTIME st;
    GetLocalTime(&st);
    char line[4096];
    int n = snprintf(line, sizeof(line),
        "%04d-%02d-%02d %02d:%02d:%02d [%s] ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond,
        lvl[level < 3 ? level : 2]);
    va_list ap;
    va_start(ap, fmt);
    n += vsnprintf(line + n, (int)sizeof(line) - n - 2, fmt, ap);
    va_end(ap);
    if (n < (int)sizeof(line) - 2) { line[n++] = '\n'; line[n] = '\0'; }

    printf("%s", line);
    fflush(stdout);

    EnterCriticalSection(&s_cs);
    if (s_file != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz = {0};
        if (GetFileSizeEx(s_file, &sz) && sz.QuadPart >= MAX_LOG_BYTES)
            rotate();
        if (s_file != INVALID_HANDLE_VALUE) {
            DWORD w;
            WriteFile(s_file, line, (DWORD)n, &w, NULL);
        }
    }
    LeaveCriticalSection(&s_cs);
}
