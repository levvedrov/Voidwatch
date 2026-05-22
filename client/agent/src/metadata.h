#pragma once

typedef struct {
    char hostname[256];
    char os[128];
    char ip[64];
    char username[128];
} Metadata;

void metadata_collect(Metadata *m);
