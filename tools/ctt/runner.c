#include "ctt.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "logger.h"

void ctt_failf(ctt_run_t *run, int step, const char *action, const char *fmt,
               ...)
{
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    LOG_ERROR("ctt", "FAIL protocol=%s scenario=%s step=%d action=%s %s",
              run->protocol ? run->protocol : "?",
              run->name ? run->name : run->path, step,
              action ? action : "?", msg);
    run->failures++;
}

int ctt_check(ctt_run_t *run, int step, const char *action, int cond,
              const char *fmt, ...)
{
    if (cond) {
        return 0;
    }
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    LOG_ERROR("ctt", "FAIL protocol=%s scenario=%s step=%d action=%s %s",
              run->protocol ? run->protocol : "?",
              run->name ? run->name : run->path, step,
              action ? action : "?", msg);
    run->failures++;
    return -1;
}

int ctt_run_file(const char *path)
{
    char err[256];
    yaml_node_t *root = yaml_parse_file(path, err, sizeof(err));
    if (!root) {
        LOG_ERROR("ctt", "FAIL yaml load %s: %s", path, err);
        return 1;
    }

    ctt_run_t run;
    memset(&run, 0, sizeof(run));
    run.path = path;
    run.root = root;
    run.name = yaml_cstr(root, "name", path);
    run.protocol = yaml_cstr(root, "protocol", "");
    ctt_mock_init(&run.mock);

    if (!run.protocol[0]) {
        LOG_ERROR("ctt", "FAIL %s: missing protocol:", path);
        yaml_free(root);
        return 1;
    }

    const ctt_plugin_t *plugin = ctt_plugin_lookup(run.protocol);
    if (!plugin) {
        LOG_ERROR("ctt",
                  "FAIL protocol=%s scenario=%s: plugin not implemented "
                  "(Phase 1 is profinet only; ethernetip/ is a reserved slot)",
                  run.protocol, run.name);
        yaml_free(root);
        return 1;
    }

    LOG_INFO("ctt", "run protocol=%s scenario=%s file=%s", run.protocol,
             run.name, path);

    if (plugin->setup(&run) != 0) {
        LOG_ERROR("ctt", "FAIL protocol=%s scenario=%s: plugin setup",
                  run.protocol, run.name);
        if (plugin->teardown) {
            plugin->teardown(&run);
        }
        yaml_free(root);
        return 1;
    }

    const yaml_node_t *steps = yaml_map_get(root, "steps");
    if (!steps || steps->kind != YAML_KIND_SEQ || !steps->child) {
        ctt_failf(&run, 0, "-", "missing steps: sequence");
    } else {
        int idx = 0;
        for (const yaml_node_t *st = steps->child; st; st = st->next) {
            idx++;
            const char *action = yaml_cstr(st, "action", "");
            if (!action[0]) {
                ctt_failf(&run, idx, "-", "step missing action");
                continue;
            }
            LOG_INFO("ctt", "step %d action=%s", idx, action);
            if (plugin->step(&run, st, idx) != 0) {
                /* plugin already logged specifics */
            }
        }
    }

    if (run.mock.to_dut.overflow || run.mock.to_ctl.overflow) {
        ctt_failf(&run, 0, "mock_eth",
                  "ring overflow (unexpected drop) to_dut=%d to_ctl=%d",
                  run.mock.to_dut.overflow, run.mock.to_ctl.overflow);
    }

    if (plugin->teardown) {
        plugin->teardown(&run);
    }

    int rc = run.failures ? 1 : 0;
    if (rc == 0) {
        LOG_INFO("ctt", "OK protocol=%s scenario=%s", run.protocol, run.name);
    } else {
        LOG_ERROR("ctt", "FAIL protocol=%s scenario=%s failures=%d",
                  run.protocol, run.name, run.failures);
    }
    yaml_free(root);
    return rc;
}
