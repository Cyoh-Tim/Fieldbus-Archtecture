#ifndef CTT_CYCLE_CLOCK_H
#define CTT_CYCLE_CLOCK_H

#include <stdint.h>
#include <time.h>

/*
 * Absolute-time cycle wait for CTT soak / cyclic loops.
 * CLOCK_MONOTONIC + clock_nanosleep(TIMER_ABSTIME) — same idea as
 * core/scheduler.c. Soft budget on a normal kernel; not PREEMPT_RT / IRT.
 */
typedef struct ctt_cycle_clock {
    struct timespec next;
    uint64_t period_ns;
    int armed;
} ctt_cycle_clock_t;

void ctt_cycle_clock_init(ctt_cycle_clock_t *c, uint64_t period_ns);

/* Advance one period and sleep until that absolute deadline.
 * If this iteration started well after the previous deadline, resync
 * (full period from now) instead of a short catch-up slot.
 * period_ns == 0 is a no-op. */
void ctt_cycle_clock_wait(ctt_cycle_clock_t *c);

#endif /* CTT_CYCLE_CLOCK_H */
