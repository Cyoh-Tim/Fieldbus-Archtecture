#define _POSIX_C_SOURCE 200809L

#include "cycle_clock.h"

#include <errno.h>
#include <stdint.h>

void ctt_cycle_clock_init(ctt_cycle_clock_t *c, uint64_t period_ns)
{
    if (!c) {
        return;
    }
    c->period_ns = period_ns;
    c->armed = 0;
    c->next.tv_sec = 0;
    c->next.tv_nsec = 0;
}

static void timespec_add_ns(struct timespec *t, uint64_t ns)
{
    t->tv_sec += (time_t)(ns / 1000000000ull);
    t->tv_nsec += (long)(ns % 1000000000ull);
    while (t->tv_nsec >= 1000000000L) {
        t->tv_nsec -= 1000000000L;
        t->tv_sec += 1;
    }
}

static int timespec_lt(const struct timespec *a, const struct timespec *b)
{
    if (a->tv_sec != b->tv_sec) {
        return a->tv_sec < b->tv_sec;
    }
    return a->tv_nsec < b->tv_nsec;
}

/* a - b in ns; 0 if a < b. */
static uint64_t timespec_sub_ns(const struct timespec *a,
                                const struct timespec *b)
{
    if (timespec_lt(a, b)) {
        return 0;
    }
    int64_t ds = (int64_t)a->tv_sec - (int64_t)b->tv_sec;
    int64_t dn = (int64_t)a->tv_nsec - (int64_t)b->tv_nsec;
    int64_t ns = ds * 1000000000LL + dn;
    return ns > 0 ? (uint64_t)ns : 0;
}

void ctt_cycle_clock_wait(ctt_cycle_clock_t *c)
{
    if (!c || c->period_ns == 0) {
        return;
    }
    if (!c->armed) {
        if (clock_gettime(CLOCK_MONOTONIC, &c->next) != 0) {
            return;
        }
        c->armed = 1;
    }

    struct timespec prev = c->next;
    timespec_add_ns(&c->next, c->period_ns);

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return;
    }

    /*
     * If this iteration started well after the previous deadline, resync
     * (sleep a full period from now) instead of a short catch-up to the
     * old grid. That short slot inflated jitter_max without recovering
     * the missed time. Soft; not PREEMPT_RT.
     */
    uint64_t late_ns = timespec_sub_ns(&now, &prev);
    if (late_ns > c->period_ns / 4ull) {
        c->next = now;
        timespec_add_ns(&c->next, c->period_ns);
    } else {
        while (timespec_lt(&c->next, &now)) {
            timespec_add_ns(&c->next, c->period_ns);
        }
    }

    int rc;
    do {
        rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &c->next, NULL);
    } while (rc == EINTR);
}
