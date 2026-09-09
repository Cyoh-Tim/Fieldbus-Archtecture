#include "ctt.h"
#include "transport.h"

#include <stdio.h>
#include <string.h>

#include "logger.h"

static int starts_with(const char *s, const char *pfx)
{
    return strncmp(s, pfx, strlen(pfx)) == 0;
}

int main(int argc, char **argv)
{
    ctt_opts_t opts;
    ctt_opts_init(&opts);
    ctt_opts_apply_env(&opts);

    const char *scenario = NULL;
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--scenario") == 0 ||
             strcmp(argv[i], "-s") == 0) &&
            i + 1 < argc) {
            scenario = argv[++i];
        } else if (starts_with(argv[i], "--transport=")) {
            if (ctt_opts_parse_transport(argv[i] + 12, &opts.transport) != 0) {
                LOG_ERROR("ctt", "unknown --transport (mock|af_packet)");
                return 2;
            }
        } else if (strcmp(argv[i], "--transport") == 0 && i + 1 < argc) {
            if (ctt_opts_parse_transport(argv[++i], &opts.transport) != 0) {
                LOG_ERROR("ctt", "unknown --transport (mock|af_packet)");
                return 2;
            }
        } else if (starts_with(argv[i], "--iface=")) {
            snprintf(opts.iface, sizeof(opts.iface), "%s", argv[i] + 8);
        } else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            snprintf(opts.iface, sizeof(opts.iface), "%s", argv[++i]);
        } else if (starts_with(argv[i], "--dut-iface=")) {
            snprintf(opts.dut_iface, sizeof(opts.dut_iface), "%s",
                     argv[i] + 12);
        } else if (strcmp(argv[i], "--dut-iface") == 0 && i + 1 < argc) {
            snprintf(opts.dut_iface, sizeof(opts.dut_iface), "%s", argv[++i]);
        } else if (starts_with(argv[i], "--capture=")) {
            snprintf(opts.capture, sizeof(opts.capture), "%s", argv[i] + 10);
        } else if (strcmp(argv[i], "--capture") == 0 && i + 1 < argc) {
            snprintf(opts.capture, sizeof(opts.capture), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "-h") == 0) {
            LOG_INFO("ctt",
                     "usage: ctt --scenario <file.yaml> "
                     "[--transport=mock|af_packet] [--iface <ctl>] "
                     "[--dut-iface <dut>] [--capture <dir|file.pcap>]");
            LOG_INFO("ctt",
                     "default transport=mock (no AF_PACKET/sudo). "
                     "lab: --transport=af_packet --iface=ctt-ctl "
                     "--dut-iface=ctt-dut (CAP_NET_RAW). env: CTT_TRANSPORT, "
                     "CTT_IFACE, CTT_DUT_IFACE, CTT_CAPTURE");
            return 0;
        } else if (!scenario && argv[i][0] != '-') {
            scenario = argv[i];
        } else {
            LOG_ERROR("ctt",
                      "unknown argument %s (usage: ctt --scenario <yaml> "
                      "[--transport=mock|af_packet])",
                      argv[i]);
            return 2;
        }
    }
    if (!scenario) {
        LOG_ERROR("ctt", "usage: ctt --scenario <file.yaml>");
        return 2;
    }
    return ctt_run_file(scenario, &opts);
}
