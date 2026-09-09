#ifndef CTT_TRANSPORT_H
#define CTT_TRANSPORT_H

#include "ctt.h"

void ctt_opts_init(ctt_opts_t *opts);
int ctt_opts_parse_transport(const char *s, ctt_transport_kind_t *out);
void ctt_opts_apply_env(ctt_opts_t *opts);

int ctt_transport_open(ctt_run_t *run);
void ctt_transport_close(ctt_run_t *run);

int ctt_ctl_send(ctt_run_t *run, const uint8_t *frame, size_t len);
void ctt_ctl_harvest(ctt_run_t *run);
void ctt_ctl_clear_rx(ctt_run_t *run);

/* pn_eth_ops_t callbacks. ctx is ctt_run_t *. */
int ctt_mock_run_send(void *ctx, const uint8_t *frame, size_t len);
int ctt_mock_run_recv(void *ctx, uint8_t *frame, size_t cap, int timeout_ms);

#endif /* CTT_TRANSPORT_H */
