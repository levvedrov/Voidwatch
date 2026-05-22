#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} JsonBuf;

void        jb_init(JsonBuf *j);
void        jb_free(JsonBuf *j);
void        jb_append(JsonBuf *j, const char *s);
void        jb_str(JsonBuf *j, const char *s);
void        jb_int(JsonBuf *j, int64_t v);
void        jb_double(JsonBuf *j, double v);
void        jb_bool(JsonBuf *j, int v);
const char *jb_get(const JsonBuf *j);
