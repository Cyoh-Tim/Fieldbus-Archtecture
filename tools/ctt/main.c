#include "ctt.h"

#include <string.h>

#include "logger.h"

int main(int argc, char **argv)
{
    const char *scenario = NULL;
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--scenario") == 0 ||
             strcmp(argv[i], "-s") == 0) &&
            i + 1 < argc) {
            scenario = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "-h") == 0) {
            LOG_INFO("ctt", "usage: ctt --scenario <file.yaml>");
            return 0;
        } else if (!scenario && argv[i][0] != '-') {
            scenario = argv[i];
        } else {
            LOG_ERROR("ctt", "unknown argument %s (usage: ctt --scenario <yaml>)",
                      argv[i]);
            return 2;
        }
    }
    if (!scenario) {
        LOG_ERROR("ctt", "usage: ctt --scenario <file.yaml>");
        return 2;
    }
    return ctt_run_file(scenario);
}
