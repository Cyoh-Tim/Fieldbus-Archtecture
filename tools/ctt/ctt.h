#ifndef CTT_H
#define CTT_H

#include "mock_eth.h"
#include "yaml_mini.h"

#define CTT_JITTER_BUCKETS 6

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
    ctt_mock_eth_t mock;
    ctt_metrics_t metrics;
    int failures;
    void *priv;
} ctt_run_t;

typedef struct ctt_plugin {
    const char *name;
    int (*setup)(ctt_run_t *run);
    int (*step)(ctt_run_t *run, const yaml_node_t *step, int index);
    void (*teardown)(ctt_run_t *run);
} ctt_plugin_t;

int ctt_run_file(const char *path);
const ctt_plugin_t *ctt_plugin_lookup(const char *protocol);

void ctt_failf(ctt_run_t *run, int step, const char *action, const char *fmt,
               ...);
int ctt_check(ctt_run_t *run, int step, const char *action, int cond,
              const char *fmt, ...);

void ctt_metrics_note_period(ctt_metrics_t *m, uint64_t dt_ns);
void ctt_metrics_log(const ctt_run_t *run);

extern const ctt_plugin_t ctt_plugin_profinet;

#endif /* CTT_H */
