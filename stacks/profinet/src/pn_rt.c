#include "pn_internal.h"

#include <errno.h>
#include <sched.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

#include "logger.h"
#include "pn_endian.h"

static void copy_from_csdu(pn_stack_t *s, const uint8_t *csdu, size_t clen)
{
    const pn_iocr_t *cr = &s->ar.iocr_out;
    pthread_mutex_lock(&s->io_lock);
    if (cr->n_data == 0) {
        size_t n = s->ar.out_data_len;
        if (n > PN_IO_MAX) {
            n = PN_IO_MAX;
        }
        if (n > clen) {
            n = clen;
        }
        memcpy(s->output_image, csdu, n);
    } else {
        for (int i = 0; i < cr->n_data; i++) {
            const pn_submod_t *sm =
                pn_find_sub(&s->ar, cr->data[i].slot, cr->data[i].subslot);
            uint16_t len = sm ? sm->out_len : s->ar.out_data_len;
            uint16_t pi = sm ? sm->out_pi : 0;
            uint16_t off = cr->data[i].frame_off;
            if ((size_t)off + len > clen) {
                continue;
            }
            if ((size_t)pi + len > PN_IO_MAX) {
                if (pi >= PN_IO_MAX) {
                    continue;
                }
                len = (uint16_t)(PN_IO_MAX - pi);
            }
            memcpy(s->output_image + pi, csdu + off, len);
        }
    }
    pthread_mutex_unlock(&s->io_lock);
}

static size_t build_input_csdu(pn_stack_t *s, uint8_t *csdu, size_t cap)
{
    const pn_iocr_t *cr = &s->ar.iocr_in;
    size_t clen = cr->data_len;
    if (clen < (size_t)s->ar.in_data_len + 1u) {
        clen = (size_t)s->ar.in_data_len + 1u;
    }
    if (clen > cap) {
        clen = cap;
    }
    memset(csdu, 0, clen);
    pthread_mutex_lock(&s->io_lock);
    if (cr->n_data == 0) {
        size_t n = s->ar.in_data_len;
        if (n > PN_IO_MAX) {
            n = PN_IO_MAX;
        }
        if (n > clen) {
            n = clen;
        }
        memcpy(csdu, s->input_image, n);
        if (n < clen) {
            csdu[n] = PN_IOPS_GOOD;
        }
    } else {
        for (int i = 0; i < cr->n_data; i++) {
            const pn_submod_t *sm =
                pn_find_sub(&s->ar, cr->data[i].slot, cr->data[i].subslot);
            uint16_t len = sm ? sm->in_len : s->ar.in_data_len;
            uint16_t pi = sm ? sm->in_pi : 0;
            uint16_t iops_len = sm && sm->iops_len ? sm->iops_len : 1;
            uint16_t off = cr->data[i].frame_off;
            if ((size_t)off + len > clen) {
                continue;
            }
            if ((size_t)pi + len > PN_IO_MAX) {
                continue;
            }
            memcpy(csdu + off, s->input_image + pi, len);
            if ((size_t)off + len + iops_len <= clen) {
                memset(csdu + off + len, PN_IOPS_GOOD, iops_len);
            }
        }
        for (int i = 0; i < cr->n_iocs; i++) {
            uint16_t off = cr->iocs[i].frame_off;
            if (off < clen) {
                csdu[off] = PN_IOPS_GOOD;
            }
        }
    }
    pthread_mutex_unlock(&s->io_lock);
    return clen;
}

static void pn_rt_advance_next(pn_stack_t *s, uint64_t now, uint64_t period)
{
    if (period == 0) {
        period = pn_ar_cycle_ns(&s->ar, s->cfg.cycle_us);
    }
    if (s->next_rt_ns == 0) {
        s->next_rt_ns = now + period;
        return;
    }
    s->next_rt_ns += period;
    /* Missed cycles are skipped, not burst, so the absolute grid is kept. */
    while (s->next_rt_ns <= now) {
        s->next_rt_ns += period;
    }
}

static uint64_t pn_rt_spin_ns(uint64_t period)
{
    uint64_t spin = period / 8ull;
    if (spin > 1000000ull) {
        spin = 1000000ull;
    }
    if (spin < 200000ull) {
        spin = 200000ull;
    }
    if (period != 0 && spin * 2ull >= period) {
        spin = period / 4ull;
    }
    return spin ? spin : 200000ull;
}

static void pn_rt_cpu_relax(void)
{
#if defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#elif defined(__aarch64__)
    __asm__ __volatile__("yield" ::: "memory");
#endif
}

static void pn_rt_sleep_until(pn_stack_t *s, uint64_t ns)
{
    /* Slice sleeps so pn_stack_stop() is not stuck for a 16–512 ms cycle. */
    while (s->running) {
        uint64_t now = pn_now_ns();
        if (now >= ns) {
            return;
        }
        uint64_t wake = ns;
        if (wake - now > 1000000ull) {
            wake = now + 1000000ull;
        }
        struct timespec abs;
        abs.tv_sec = (time_t)(wake / 1000000000ull);
        abs.tv_nsec = (long)(wake % 1000000000ull);
        int rc;
        do {
            rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &abs, NULL);
        } while (rc == EINTR && s->running);
    }
}

static void pn_rt_spin_until(pn_stack_t *s, uint64_t ns)
{
    while (s->running && pn_now_ns() < ns) {
        pn_rt_cpu_relax();
    }
}

static void pn_rt_note_interval(pn_stack_t *s, uint64_t t)
{
    if (s->rt_tx_last_ns != 0) {
        uint64_t dt = t - s->rt_tx_last_ns;
        uint64_t period = pn_ar_cycle_ns(&s->ar, s->cfg.cycle_us);
        s->rt_tx_sum += dt;
        s->rt_tx_n++;
        if (dt < s->rt_tx_min) {
            s->rt_tx_min = dt;
        }
        if (dt > s->rt_tx_max) {
            s->rt_tx_max = dt;
        }
        if (dt > period && dt - period > s->rt_tx_late_max) {
            s->rt_tx_late_max = dt - period;
        }
        if (!s->rt_tx_logged && s->rt_tx_n == 125) {
            uint64_t mean = s->rt_tx_sum / s->rt_tx_n;
            LOG_INFO(
                "pn_rt",
                "TX grid mean=%lluus min=%lluus max=%lluus late_max=%lluus n=%u",
                (unsigned long long)(mean / 1000ull),
                (unsigned long long)(s->rt_tx_min / 1000ull),
                (unsigned long long)(s->rt_tx_max / 1000ull),
                (unsigned long long)(s->rt_tx_late_max / 1000ull), s->rt_tx_n);
            s->rt_tx_logged = 1;
        }
    }
    s->rt_tx_last_ns = t;
}

static int pn_rt_build_frame(pn_stack_t *s, uint8_t *frame, size_t cap,
                             size_t *out_len)
{
    uint8_t pay[PN_FRAME_MAX];
    size_t n = 0;
    pn_wr_be16(pay, s->ar.in_frame_id);
    n += 2;
    n += build_input_csdu(s, pay + n, sizeof(pay) - n - 4);
    pn_wr_be16(pay + n, s->cycle_counter);
    n += 2;
    pay[n++] = (uint8_t)(PN_DATASTATUS_PRIMARY | PN_DATASTATUS_VALID |
                         PN_DATASTATUS_RUN);
    pay[n++] = 0;

    uint8_t dst[6];
    memcpy(dst, s->ar.initiator_mac, 6);
    uint16_t vid = s->ar.iocr_in.vlan_id;
    size_t flen;
    if (vid != 0) {
        uint8_t pcp = s->ar.iocr_in.pcp ? s->ar.iocr_in.pcp : 6;
        uint16_t tci = (uint16_t)(((uint16_t)pcp << 13) | vid);
        flen = pn_eth_build_vlan(frame, cap, dst, s->cfg.mac, tci, PN_ETHTYPE_PN,
                                 pay, n);
    } else {
        flen = pn_eth_build(frame, cap, dst, s->cfg.mac, PN_ETHTYPE_PN, pay, n);
    }
    if (!flen) {
        return -ENOBUFS;
    }
    *out_len = flen;
    return 0;
}

static void pn_rt_emit(pn_stack_t *s, const uint8_t *frame, size_t flen)
{
    uint64_t t = pn_now_ns();
    uint64_t period = pn_ar_cycle_ns(&s->ar, s->cfg.cycle_us);
    s->last_rt_ns = t;
    pn_rt_note_interval(s, t);
    pn_rt_advance_next(s, t, period);
    if (flen) {
        pn_eth_send(s, frame, flen);
    }
    s->cycle_counter++;
}

static void pn_rt_send_locked(pn_stack_t *s)
{
    uint8_t frame[PN_FRAME_MAX];
    size_t flen = 0;
    if (pn_rt_build_frame(s, frame, sizeof(frame), &flen) != 0) {
        return;
    }
    pn_rt_emit(s, frame, flen);
}

void pn_rt_on_frame(pn_stack_t *s, const uint8_t *payload, size_t plen)
{
    if (s->ar.cm_state < PN_CM_CONNECTED || plen < 6) {
        return;
    }
    uint16_t fid = pn_rd_be16(payload);
    if (fid != s->ar.out_frame_id) {
        return;
    }
    size_t csdu_len = s->ar.iocr_out.data_len;
    if (csdu_len == 0) {
        csdu_len = (size_t)s->ar.out_data_len + 1u;
    }
    if (2 + csdu_len > plen) {
        /* APDU status may still fit with a shorter C_SDU; take what we have. */
        if (plen < 7) {
            return;
        }
        csdu_len = plen - 6; /* leave room for APDU status if present */
        if (2 + csdu_len > plen) {
            csdu_len = plen - 2;
        }
    }
    copy_from_csdu(s, payload + 2, csdu_len);
    s->last_cpm_ns = pn_now_ns();
}

void pn_rt_send_if_due(pn_stack_t *s)
{
    pthread_mutex_lock(&s->rt_lock);
    if (!s->ar.established || s->ar.cm_state != PN_CM_DATAEX) {
        pthread_mutex_unlock(&s->rt_lock);
        return;
    }
    uint64_t now = pn_now_ns();
    if (s->next_rt_ns != 0 && now < s->next_rt_ns) {
        pthread_mutex_unlock(&s->rt_lock);
        return;
    }
    pn_rt_send_locked(s);
    pthread_mutex_unlock(&s->rt_lock);
}

void pn_rt_watchdog(pn_stack_t *s)
{
    pthread_mutex_lock(&s->rt_lock);
    int established = s->ar.established && s->ar.cm_state == PN_CM_DATAEX;
    int has_out = s->ar.out_data_len != 0 || s->ar.iocr_out.n_data != 0;
    uint64_t last_cpm = s->last_cpm_ns;
    uint64_t wd = pn_ar_watchdog_ns(&s->ar, s->cfg.cycle_us);
    pthread_mutex_unlock(&s->rt_lock);
    if (!established || !has_out) {
        return;
    }
    if (last_cpm == 0) {
        return;
    }
    if (pn_now_ns() - last_cpm <= wd) {
        return;
    }
    LOG_WARN("pn_rt", "output CR watchdog expired — AR down");
    pn_ar_reset(s);
}

static void *pn_rt_thread_main(void *arg)
{
    pn_stack_t *s = arg;
#ifdef __linux__
    prctl(PR_SET_NAME, "pn-rtc1");
    /* Default slack is 50 us; tighten so cycle wakeups stay near the grid. */
    prctl(PR_SET_TIMERSLACK, 1UL);
#endif
    {
        struct rlimit rl;
        rl.rlim_cur = 50;
        rl.rlim_max = 50;
        (void)setrlimit(RLIMIT_RTPRIO, &rl);
        struct sched_param sp;
        memset(&sp, 0, sizeof(sp));
        sp.sched_priority = 50;
        if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp) == 0) {
            LOG_INFO("pn_rt", "RTC1 thread SCHED_FIFO prio=50");
        }
    }

    /* Sleep until spin_ns before due, build the frame, then sendto on the
     * configured SendClock×ReductionRatio grid (8 ms min, 16/32/... ms). */

    while (s->running) {
        uint64_t next = 0;
        uint64_t period = 0;
        int active = 0;
        pthread_mutex_lock(&s->rt_lock);
        active = s->ar.established && s->ar.cm_state == PN_CM_DATAEX;
        next = s->next_rt_ns;
        period = pn_ar_cycle_ns(&s->ar, s->cfg.cycle_us);
        pthread_mutex_unlock(&s->rt_lock);

        if (!active) {
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 50000};
            nanosleep(&ts, NULL);
            continue;
        }

        uint64_t now = pn_now_ns();
        if (next == 0 || now >= next) {
            pn_rt_send_if_due(s);
            continue;
        }

        uint64_t spin_ns = pn_rt_spin_ns(period);
        if (next > now + spin_ns) {
            pn_rt_sleep_until(s, next - spin_ns);
            if (!s->running) {
                break;
            }
        }

        uint8_t frame[PN_FRAME_MAX];
        size_t flen = 0;
        int have = 0;
        pthread_mutex_lock(&s->rt_lock);
        if (s->ar.established && s->ar.cm_state == PN_CM_DATAEX) {
            have = pn_rt_build_frame(s, frame, sizeof(frame), &flen) == 0;
        }
        pthread_mutex_unlock(&s->rt_lock);
        if (!have) {
            continue;
        }

        pn_rt_spin_until(s, next);
        if (!s->running) {
            break;
        }

        pthread_mutex_lock(&s->rt_lock);
        if (s->ar.established && s->ar.cm_state == PN_CM_DATAEX) {
            pn_rt_emit(s, frame, flen);
        }
        pthread_mutex_unlock(&s->rt_lock);
    }
    return NULL;
}

void pn_rt_thread_start(pn_stack_t *s)
{
    if (!s || s->rt_thread_started || s->use_eth_ops) {
        return;
    }
    int rc = pthread_create(&s->rt_thread, NULL, pn_rt_thread_main, s);
    if (rc != 0) {
        LOG_WARN("pn_rt",
                 "RTC1 thread create failed (%d) — cyclic stays poll-driven",
                 rc);
        return;
    }
    s->rt_thread_started = 1;
}

void pn_rt_thread_stop(pn_stack_t *s)
{
    if (!s || !s->rt_thread_started) {
        return;
    }
    pthread_join(s->rt_thread, NULL);
    s->rt_thread_started = 0;
}
