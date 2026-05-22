#pragma once

void log_init(void);
void log_msg(int level, const char *fmt, ...);

#define log_info(...)  log_msg(0, __VA_ARGS__)
#define log_warn(...)  log_msg(1, __VA_ARGS__)
#define log_error(...) log_msg(2, __VA_ARGS__)
