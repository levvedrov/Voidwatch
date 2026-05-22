#include "json.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void jb_init(JsonBuf *j) {
    j->cap = 8192;
    j->len = 0;
    j->buf = (char *)malloc(j->cap);
    if (j->buf) j->buf[0] = '\0';
}

void jb_free(JsonBuf *j) {
    free(j->buf);
    j->buf = NULL;
    j->len = j->cap = 0;
}

static void ensure(JsonBuf *j, size_t n) {
    if (j->len + n + 1 > j->cap) {
        while (j->len + n + 1 > j->cap) j->cap *= 2;
        char *tmp = (char *)realloc(j->buf, j->cap);
        if (!tmp) return;
        j->buf = tmp;
    }
}

void jb_append(JsonBuf *j, const char *s) {
    size_t n = strlen(s);
    ensure(j, n);
    memcpy(j->buf + j->len, s, n + 1);
    j->len += n;
}

void jb_str(JsonBuf *j, const char *s) {
    if (!s || !*s) { jb_append(j, "\"\""); return; }
    ensure(j, strlen(s) * 6 + 2);
    j->buf[j->len++] = '"';
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if      (c == '"')  { j->buf[j->len++] = '\\'; j->buf[j->len++] = '"';  }
        else if (c == '\\') { j->buf[j->len++] = '\\'; j->buf[j->len++] = '\\'; }
        else if (c == '\n') { j->buf[j->len++] = '\\'; j->buf[j->len++] = 'n';  }
        else if (c == '\r') { j->buf[j->len++] = '\\'; j->buf[j->len++] = 'r';  }
        else if (c == '\t') { j->buf[j->len++] = '\\'; j->buf[j->len++] = 't';  }
        else if (c < 0x20)  { j->len += sprintf(j->buf + j->len, "\\u%04x", c); }
        else                 { j->buf[j->len++] = (char)c; }
    }
    j->buf[j->len++] = '"';
    j->buf[j->len]   = '\0';
}

void jb_int(JsonBuf *j, int64_t v) {
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%lld", (long long)v);
    jb_append(j, tmp);
}

void jb_double(JsonBuf *j, double v) {
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%.2f", v);
    jb_append(j, tmp);
}

void jb_bool(JsonBuf *j, int v) {
    jb_append(j, v ? "true" : "false");
}

const char *jb_get(const JsonBuf *j) {
    return (j && j->buf) ? j->buf : "";
}
