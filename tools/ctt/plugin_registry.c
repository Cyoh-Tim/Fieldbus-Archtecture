#include "ctt.h"

#include <string.h>

const ctt_plugin_t *ctt_plugin_lookup(const char *protocol)
{
    static const ctt_plugin_t *plugins[] = {
        &ctt_plugin_profinet,
        &ctt_plugin_ethernetip,
        NULL,
    };
    if (!protocol) {
        return NULL;
    }
    for (int i = 0; plugins[i]; i++) {
        if (strcmp(plugins[i]->name, protocol) == 0) {
            return plugins[i];
        }
    }
    return NULL;
}
