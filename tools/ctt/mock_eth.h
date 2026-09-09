#ifndef CTT_MOCK_ETH_H
#define CTT_MOCK_ETH_H

#include <stddef.h>
#include <stdint.h>

#define CTT_FRAME_MAX  1518
#define CTT_RING_SLOTS 32

typedef struct {
    uint8_t data[CTT_FRAME_MAX];
    size_t len;
    uint64_t ts_ns;
} ctt_frame_t;

typedef struct {
    ctt_frame_t slots[CTT_RING_SLOTS];
    int head;
    int tail;
    int count;
    int overflow;
} ctt_ring_t;

typedef struct {
    ctt_ring_t to_dut;
    ctt_ring_t to_ctl;
} ctt_mock_eth_t;

void ctt_mock_init(ctt_mock_eth_t *m);
uint64_t ctt_now_ns(void);

int ctt_ring_push(ctt_ring_t *r, const uint8_t *frame, size_t len, uint64_t ts);
int ctt_ring_pop(ctt_ring_t *r, uint8_t *frame, size_t cap, uint64_t *ts);
void ctt_ring_clear(ctt_ring_t *r);

/* pn_eth_ops_t callbacks. ctx is ctt_mock_eth_t *. */
int ctt_mock_dut_send(void *ctx, const uint8_t *frame, size_t len);
int ctt_mock_dut_recv(void *ctx, uint8_t *frame, size_t cap, int timeout_ms);

#endif /* CTT_MOCK_ETH_H */
