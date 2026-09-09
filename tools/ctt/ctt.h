#ifndef CTT_H
#define CTT_H

#include "mock_eth.h"
#include "yaml_mini.h"

#include <stddef.h>
#include <stdint.h>

#define CTT_JITTER_BUCKETS 6

typedef enum {
    CTT_TRANSPORT_MOCK = 0,
    CTT_TRANSPORT_AF_PACKET = 1
} ctt_transport_kind_t;

typedef struct ctt_opts {
    ctt_transport_kind_t transport;
    char iface[32];     /* controller AF_PACKET iface */
    char dut_iface[32]; /* DUT AF_PACKET iface */
    char capture[512];  /* directory or .pcap/.bin */
} ctt_opts_t;

typedef struct ctt_metrics {
    unsigned unexpected_frames;
    unsigned ar_drops;
    unsigned rtc1_frames;
    uint64_t period_min_ns;
    uint64_t period_max_ns;
    uint64_t period_sum_ns;
    unsigned period_samples;
    /* period buckets: <4, <8, <12, <16, <20, >=20 ms (mock soft) */
    unsigned jitter_hist[CTT_JITTER_BUCKETS];
} ctt_metrics_t;

typedef struct ctt_run {
    const char *path;
    const char *name;
    const char *protocol;
    const yaml_node_t *root;
    ctt_opts_t opts;
    ctt_mock_eth_t mock;
    ctt_metrics_t metrics;
    int failures;
    void *priv;
    int af_fd;
    int af_ifindex;
    uint8_t ctl_mac[6];
} ctt_run_t;

typedef struct ctt_plugin {
    const char *name;
    int (*setup)(ctt_run_t *run);
    int (*step)(ctt_run_t *run, const yaml_node_t *step, int index);
    void (*teardown)(ctt_run_t *run);
} ctt_plugin_t;

int ctt_run_file(const char *path, const ctt_opts_t *opts);
const ctt_plugin_t *ctt_plugin_lookup(const char *protocol);

void ctt_failf(ctt_run_t *run, int step, const char *action, const char *fmt,
               ...);
int ctt_check(ctt_run_t *run, int step, const char *action, int cond,
              const char *fmt, ...);

void ctt_metrics_note_period(ctt_metrics_t *m, uint64_t dt_ns);
void ctt_metrics_log(const ctt_run_t *run);

int ctt_golden_check(ctt_run_t *run, int step, const char *action,
                      const uint8_t *frame, size_t len, const char *rel);
int ctt_capture_step_frame(ctt_run_t *run, int step, const char *action,
                           const uint8_t *frame, size_t len);

extern const ctt_plugin_t ctt_plugin_profinet;
extern const ctt_plugin_t ctt_plugin_ethernetip;

#endif /* CTT_H */
