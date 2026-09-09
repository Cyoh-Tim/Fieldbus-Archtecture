#ifndef CTT_H
#define CTT_H

#include "mock_eth.h"
#include "yaml_mini.h"

typedef struct ctt_run {
    const char *path;
    const char *name;
    const char *protocol;
    const yaml_node_t *root;
    ctt_mock_eth_t mock;
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

extern const ctt_plugin_t ctt_plugin_profinet;

#endif /* CTT_H */
