#include "mock_eth.h"

#include <errno.h>
#include <string.h>
#include <time.h>

uint64_t ctt_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

void ctt_mock_init(ctt_mock_eth_t *m)
{
    memset(m, 0, sizeof(*m));
}

int ctt_ring_push(ctt_ring_t *r, const uint8_t *frame, size_t len, uint64_t ts)
{
    if (len > CTT_FRAME_MAX || r->count >= CTT_RING_SLOTS) {
        r->overflow = 1;
        return -ENOSPC;
    }
    ctt_frame_t *s = &r->slots[r->head];
    memcpy(s->data, frame, len);
    s->len = len;
    s->ts_ns = ts;
    r->head = (r->head + 1) % CTT_RING_SLOTS;
    r->count++;
    return 0;
}

int ctt_ring_pop(ctt_ring_t *r, uint8_t *frame, size_t cap, uint64_t *ts)
{
    if (r->count <= 0) {
        return -EAGAIN;
    }
    const ctt_frame_t *s = &r->slots[r->tail];
    size_t n = s->len < cap ? s->len : cap;
    memcpy(frame, s->data, n);
    if (ts) {
        *ts = s->ts_ns;
    }
    r->tail = (r->tail + 1) % CTT_RING_SLOTS;
    r->count--;
    return (int)n;
}

void ctt_ring_clear(ctt_ring_t *r)
{
    r->head = 0;
    r->tail = 0;
    r->count = 0;
}

int ctt_mock_dut_send(void *ctx, const uint8_t *frame, size_t len)
{
    ctt_mock_eth_t *m = ctx;
    (void)ctt_ring_push(&m->to_ctl, frame, len, ctt_now_ns());
    return 0;
}

int ctt_mock_dut_recv(void *ctx, uint8_t *frame, size_t cap, int timeout_ms)
{
    ctt_mock_eth_t *m = ctx;
    (void)timeout_ms;
    return ctt_ring_pop(&m->to_dut, frame, cap, NULL);
}
