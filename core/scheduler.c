#define _POSIX_C_SOURCE 200809L

#include "scheduler.h"

#include <errno.h>
#include <string.h>
#include <time.h>

#include "logger.h"

static long timespec_diff_ms(const struct timespec *a, const struct timespec *b)
{
    long sec_diff = a->tv_sec - b->tv_sec;
    long nsec_diff = a->tv_nsec - b->tv_nsec;
    return sec_diff * 1000 + nsec_diff / 1000000;
}

static void timespec_add_ms(struct timespec *t, long ms)
{
    t->tv_sec += ms / 1000;
    t->tv_nsec += (ms % 1000) * 1000000L;
    if (t->tv_nsec >= 1000000000L) {
        t->tv_nsec -= 1000000000L;
        t->tv_sec += 1;
    }
}

int scheduler_run(protocol_adapter_t *adapter, int cycle_ms,
                   volatile int *stop_flag)
{
    if (!adapter || !adapter->poll_cycle || cycle_ms <= 0) {
        return -1;
    }

    struct timespec next;
    clock_gettime(CLOCK_MONOTONIC, &next);

    while (!*stop_flag) {
        struct timespec before;
        clock_gettime(CLOCK_MONOTONIC, &before);

        adapter->poll_cycle(adapter);

        struct timespec after;
        clock_gettime(CLOCK_MONOTONIC, &after);
        long elapsed_ms = timespec_diff_ms(&after, &before);
        if (elapsed_ms > cycle_ms) {
            LOG_WARN("scheduler",
                     "cycle 초과: elapsed=%ldms > cycle_ms=%d", elapsed_ms,
                     cycle_ms);
        }

        timespec_add_ms(&next, cycle_ms);

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (timespec_diff_ms(&next, &now) > 0) {
            struct timespec rem;
            int rc;
            do {
                rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next,
                                      &rem);
            } while (rc == EINTR);
        } else {
            /* 이미 다음 주기를 넘겼으면 기준점을 현재로 재설정해 밀림 누적 방지 */
            next = now;
        }
    }
    return 0;
}
