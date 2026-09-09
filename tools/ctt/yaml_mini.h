#ifndef YAML_MINI_H
#define YAML_MINI_H

#include <stddef.h>

/*
 * Constrained YAML subset for CTT scenarios (see tools/ctt/README.md):
 *   - block mappings and sequences (2-space indent typical)
 *   - scalars: unquoted, "double" / 'single' quoted
 *   - integers (decimal or 0x hex), booleans true/false
 *   - `#` comments
 *   - flow sequences like [a, b] are kept as a single scalar
 * Not supported: anchors, tags, multiline `|`/`>`, merge keys.
 */

typedef enum {
    YAML_KIND_SCALAR = 0,
    YAML_KIND_MAP,
    YAML_KIND_SEQ
} yaml_kind_t;

typedef struct yaml_node {
    yaml_kind_t kind;
    char *key;
    char *scalar;
    struct yaml_node *child;
    struct yaml_node *next;
} yaml_node_t;

yaml_node_t *yaml_parse_file(const char *path, char *err, size_t errcap);
void yaml_free(yaml_node_t *n);

const yaml_node_t *yaml_map_get(const yaml_node_t *map, const char *key);
int yaml_has(const yaml_node_t *map, const char *key);
const char *yaml_cstr(const yaml_node_t *map, const char *key, const char *def);
int yaml_bool(const yaml_node_t *map, const char *key, int def);
long yaml_long(const yaml_node_t *map, const char *key, long def);
unsigned long yaml_ulong(const yaml_node_t *map, const char *key, unsigned long def);

#endif /* YAML_MINI_H */
