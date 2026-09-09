#include "eip_endian.h"
#include "eip_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

uint64_t eip_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int ensure_room(size_t used, size_t need, size_t cap)
{
    return used + need <= cap ? 0 : -ENOSPC;
}

int eip_path_append_class(uint8_t *path, size_t cap, size_t *used,
                          uint16_t class_id)
{
    if (class_id <= 0xff) {
        if (ensure_room(*used, 2, cap) != 0) {
            return -ENOSPC;
        }
        path[(*used)++] = 0x20;
        path[(*used)++] = (uint8_t)class_id;
        return 0;
    }
    if (ensure_room(*used, 4, cap) != 0) {
        return -ENOSPC;
    }
    path[(*used)++] = 0x21;
    path[(*used)++] = 0x00;
    eip_wr_le16(path + *used, class_id);
    *used += 2;
    return 0;
}

int eip_path_append_instance(uint8_t *path, size_t cap, size_t *used,
                             uint16_t instance)
{
    if (instance <= 0xff) {
        if (ensure_room(*used, 2, cap) != 0) {
            return -ENOSPC;
        }
        path[(*used)++] = 0x24;
        path[(*used)++] = (uint8_t)instance;
        return 0;
    }
    if (ensure_room(*used, 4, cap) != 0) {
        return -ENOSPC;
    }
    path[(*used)++] = 0x25;
    path[(*used)++] = 0x00;
    eip_wr_le16(path + *used, instance);
    *used += 2;
    return 0;
}

int eip_path_append_attribute(uint8_t *path, size_t cap, size_t *used,
                              uint16_t attribute)
{
    if (attribute <= 0xff) {
        if (ensure_room(*used, 2, cap) != 0) {
            return -ENOSPC;
        }
        path[(*used)++] = 0x30;
        path[(*used)++] = (uint8_t)attribute;
        return 0;
    }
    if (ensure_room(*used, 4, cap) != 0) {
        return -ENOSPC;
    }
    path[(*used)++] = 0x31;
    path[(*used)++] = 0x00;
    eip_wr_le16(path + *used, attribute);
    *used += 2;
    return 0;
}

int eip_path_append_ansi_tag(uint8_t *path, size_t cap, size_t *used,
                             const char *tag)
{
    size_t n = tag ? strlen(tag) : 0;
    if (n == 0 || n > 255) {
        return -EINVAL;
    }
    size_t need = 2 + n + (n & 1);
    if (ensure_room(*used, need, cap) != 0) {
        return -ENOSPC;
    }
    path[(*used)++] = 0x91; /* ANSI extended symbol */
    path[(*used)++] = (uint8_t)n;
    memcpy(path + *used, tag, n);
    *used += n;
    if (n & 1) {
        path[(*used)++] = 0x00;
    }
    return 0;
}

int eip_path_parse(const uint8_t *path, size_t path_bytes, uint16_t *class_id,
                   uint16_t *instance, uint16_t *attribute, char *tag,
                   size_t tag_cap)
{
    size_t i = 0;
    if (class_id) {
        *class_id = 0;
    }
    if (instance) {
        *instance = 0;
    }
    if (attribute) {
        *attribute = 0;
    }
    if (tag && tag_cap) {
        tag[0] = '\0';
    }

    while (i < path_bytes) {
        uint8_t seg = path[i++];
        if (seg == 0x20 && i < path_bytes) {
            if (class_id) {
                *class_id = path[i];
            }
            i += 1;
        } else if (seg == 0x21 && i + 2 < path_bytes) {
            i += 1; /* pad */
            if (class_id) {
                *class_id = eip_rd_le16(path + i);
            }
            i += 2;
        } else if (seg == 0x24 && i < path_bytes) {
            if (instance) {
                *instance = path[i];
            }
            i += 1;
        } else if (seg == 0x25 && i + 2 < path_bytes) {
            i += 1;
            if (instance) {
                *instance = eip_rd_le16(path + i);
            }
            i += 2;
        } else if (seg == 0x30 && i < path_bytes) {
            if (attribute) {
                *attribute = path[i];
            }
            i += 1;
        } else if (seg == 0x31 && i + 2 < path_bytes) {
            i += 1;
            if (attribute) {
                *attribute = eip_rd_le16(path + i);
            }
            i += 2;
        } else if (seg == 0x91 && i < path_bytes) {
            uint8_t n = path[i++];
            if (i + n > path_bytes) {
                return -EINVAL;
            }
            if (tag && tag_cap) {
                size_t c = n;
                if (c >= tag_cap) {
                    c = tag_cap - 1;
                }
                memcpy(tag, path + i, c);
                tag[c] = '\0';
            }
            i += n;
            if (n & 1) {
                i += 1;
            }
        } else {
            /* Skip unknown logical segments conservatively */
            return -EINVAL;
        }
    }
    return 0;
}

static int add_asm(eip_stack_t *s, uint16_t instance, uint16_t size,
                   int is_input, uint8_t **out_ptr)
{
    if (s->assembly_count >= EIP_ASSEMBLY_INSTANCES_MAX) {
        return -ENOMEM;
    }
    if (size > EIP_ASSEMBLY_SIZE_MAX) {
        return -EINVAL;
    }
    eip_assembly_t *a = &s->assemblies[s->assembly_count++];
    memset(a, 0, sizeof(*a));
    a->instance = instance;
    a->size = size;
    a->is_input = is_input;
    a->data = calloc(1, size ? size : 1);
    if (!a->data) {
        s->assembly_count--;
        return -ENOMEM;
    }
    if (out_ptr) {
        *out_ptr = a->data;
    }
    return 0;
}

int eip_assembly_init(eip_stack_t *s)
{
    int rc;
    s->assembly_count = 0;
    rc = add_asm(s, s->cfg.config_assembly, s->cfg.config_size, 0,
                 &s->config_data);
    if (rc != 0) {
        return rc;
    }
    s->config_size = s->cfg.config_size;

    rc = add_asm(s, s->cfg.output_assembly, s->cfg.output_size, 0,
                 &s->output_data);
    if (rc != 0) {
        return rc;
    }
    s->output_size = s->cfg.output_size;

    rc = add_asm(s, s->cfg.input_assembly, s->cfg.input_size, 1,
                 &s->input_data);
    if (rc != 0) {
        return rc;
    }
    s->input_size = s->cfg.input_size;
    return 0;
}

void eip_assembly_fini(eip_stack_t *s)
{
    for (int i = 0; i < s->assembly_count; i++) {
        free(s->assemblies[i].data);
        s->assemblies[i].data = NULL;
    }
    s->assembly_count = 0;
    s->input_data = s->output_data = s->config_data = NULL;
}

eip_assembly_t *eip_assembly_find(eip_stack_t *s, uint16_t instance)
{
    for (int i = 0; i < s->assembly_count; i++) {
        if (s->assemblies[i].instance == instance) {
            return &s->assemblies[i];
        }
    }
    return NULL;
}

int eip_assembly_read(eip_stack_t *s, uint16_t instance, uint8_t *dst,
                      size_t *inout_len)
{
    eip_assembly_t *a = eip_assembly_find(s, instance);
    if (!a || !dst || !inout_len) {
        return -ENOENT;
    }
    size_t n = a->size;
    if (n > *inout_len) {
        n = *inout_len;
    }
    memcpy(dst, a->data, n);
    *inout_len = n;
    return 0;
}

int eip_assembly_write(eip_stack_t *s, uint16_t instance, const uint8_t *src,
                       size_t len)
{
    eip_assembly_t *a = eip_assembly_find(s, instance);
    if (!a || !src) {
        return -ENOENT;
    }
    if (len > a->size) {
        len = a->size;
    }
    memcpy(a->data, src, len);
    return 0;
}
