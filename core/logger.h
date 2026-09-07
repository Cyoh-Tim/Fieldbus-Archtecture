#ifndef LOGGER_H
#define LOGGER_H

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <time.h>

/* 포맷: [timestamp][LEVEL][component] message */
#define LOG_IMPL(level, component, fmt, ...)                                  \
    do {                                                                      \
        time_t t_ = time(NULL);                                               \
        struct tm tm_;                                                        \
        localtime_r(&t_, &tm_);                                               \
        char ts_[32];                                                         \
        strftime(ts_, sizeof(ts_), "%Y-%m-%d %H:%M:%S", &tm_);                \
        fprintf(stderr, "[%s][%s][%s] " fmt "\n", ts_, level, component,      \
                ##__VA_ARGS__);                                               \
    } while (0)

#define LOG_INFO(component, fmt, ...) LOG_IMPL("INFO", component, fmt, ##__VA_ARGS__)
#define LOG_WARN(component, fmt, ...) LOG_IMPL("WARN", component, fmt, ##__VA_ARGS__)
#define LOG_ERROR(component, fmt, ...) LOG_IMPL("ERROR", component, fmt, ##__VA_ARGS__)

#endif /* LOGGER_H */
