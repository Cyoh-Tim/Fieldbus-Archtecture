#include "yaml_mini.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define YAML_MAX_LINES 512
#define YAML_MAX_LINE  4096

typedef struct {
    char *text;
    int indent;
    int lineno;
} yline_t;

static char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    if (d) {
        memcpy(d, s, n);
    }
    return d;
}

static yaml_node_t *node_new(yaml_kind_t kind)
{
    yaml_node_t *n = calloc(1, sizeof(*n));
    if (n) {
        n->kind = kind;
    }
    return n;
}

static void node_add_child(yaml_node_t *parent, yaml_node_t *child)
{
    if (!parent->child) {
        parent->child = child;
        return;
    }
    yaml_node_t *p = parent->child;
    while (p->next) {
        p = p->next;
    }
    p->next = child;
}

void yaml_free(yaml_node_t *n)
{
    while (n) {
        yaml_node_t *next = n->next;
        yaml_free(n->child);
        free(n->key);
        free(n->scalar);
        free(n);
        n = next;
    }
}

static void strip_comment(char *s)
{
    int in_s = 0, in_d = 0;
    for (char *p = s; *p; p++) {
        if (*p == '\'' && !in_d) {
            in_s = !in_s;
        } else if (*p == '"' && !in_s) {
            in_d = !in_d;
        } else if (*p == '#' && !in_s && !in_d) {
            if (p == s || isspace((unsigned char)p[-1])) {
                *p = '\0';
                break;
            }
        }
    }
}

static void rtrim(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) {
        s[--n] = '\0';
    }
}

static char *unquote(const char *s)
{
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }
    char *tmp = xstrdup(s);
    if (!tmp) {
        return NULL;
    }
    rtrim(tmp);
    size_t n = strlen(tmp);
    if (n >= 2 &&
        ((tmp[0] == '"' && tmp[n - 1] == '"') ||
         (tmp[0] == '\'' && tmp[n - 1] == '\''))) {
        tmp[n - 1] = '\0';
        memmove(tmp, tmp + 1, n - 1);
    }
    return tmp;
}

static int split_key(const char *text, char **key, char **val)
{
    const char *colon = NULL;
    int in_s = 0, in_d = 0;
    for (const char *p = text; *p; p++) {
        if (*p == '\'' && !in_d) {
            in_s = !in_s;
        } else if (*p == '"' && !in_s) {
            in_d = !in_d;
        } else if (*p == ':' && !in_s && !in_d) {
            colon = p;
            break;
        }
    }
    if (!colon) {
        return -1;
    }
    size_t klen = (size_t)(colon - text);
    char *k = malloc(klen + 1);
    if (!k) {
        return -1;
    }
    memcpy(k, text, klen);
    k[klen] = '\0';
    rtrim(k);
    *key = k;
    const char *v = colon + 1;
    while (*v && isspace((unsigned char)*v)) {
        v++;
    }
    *val = unquote(v);
    return 0;
}

static yaml_node_t *parse_map(yline_t *L, int n, int *i, int key_indent,
                              char *err, size_t errcap);
static yaml_node_t *parse_seq(yline_t *L, int n, int *i, int dash_indent,
                              char *err, size_t errcap);

static yaml_node_t *parse_nested(yline_t *L, int n, int *i, int parent_indent,
                                 char *err, size_t errcap)
{
    if (*i >= n || L[*i].indent <= parent_indent) {
        yaml_node_t *empty = node_new(YAML_KIND_MAP);
        return empty;
    }
    if (L[*i].text[0] == '-') {
        return parse_seq(L, n, i, L[*i].indent, err, errcap);
    }
    return parse_map(L, n, i, L[*i].indent, err, errcap);
}

static yaml_node_t *parse_map(yline_t *L, int n, int *i, int key_indent,
                              char *err, size_t errcap)
{
    yaml_node_t *map = node_new(YAML_KIND_MAP);
    if (!map) {
        return NULL;
    }
    while (*i < n) {
        if (L[*i].indent < key_indent) {
            break;
        }
        if (L[*i].indent > key_indent) {
            snprintf(err, errcap, "line %d: unexpected indent", L[*i].lineno);
            yaml_free(map);
            return NULL;
        }
        if (L[*i].text[0] == '-') {
            break;
        }
        char *key = NULL, *val = NULL;
        if (split_key(L[*i].text, &key, &val) != 0) {
            snprintf(err, errcap, "line %d: expected key:", L[*i].lineno);
            yaml_free(map);
            return NULL;
        }
        (*i)++;
        yaml_node_t *child;
        if (val && val[0]) {
            child = node_new(YAML_KIND_SCALAR);
            child->scalar = val;
            val = NULL;
        } else {
            free(val);
            child = parse_nested(L, n, i, key_indent, err, errcap);
            if (!child) {
                free(key);
                yaml_free(map);
                return NULL;
            }
        }
        child->key = key;
        node_add_child(map, child);
    }
    return map;
}

static yaml_node_t *parse_seq(yline_t *L, int n, int *i, int dash_indent,
                              char *err, size_t errcap)
{
    yaml_node_t *seq = node_new(YAML_KIND_SEQ);
    if (!seq) {
        return NULL;
    }
    while (*i < n && L[*i].indent == dash_indent && L[*i].text[0] == '-') {
        const char *p = L[*i].text + 1;
        while (*p && isspace((unsigned char)*p)) {
            p++;
        }
        int item_line = L[*i].lineno;
        (*i)++;

        yaml_node_t *item;
        if (*p == '\0') {
            item = parse_nested(L, n, i, dash_indent, err, errcap);
        } else {
            char *key = NULL, *val = NULL;
            if (split_key(p, &key, &val) == 0) {
                item = node_new(YAML_KIND_MAP);
                yaml_node_t *first;
                if (val && val[0]) {
                    first = node_new(YAML_KIND_SCALAR);
                    first->scalar = val;
                    val = NULL;
                } else {
                    free(val);
                    first = parse_nested(L, n, i, dash_indent, err, errcap);
                    if (!first) {
                        free(key);
                        yaml_free(item);
                        yaml_free(seq);
                        return NULL;
                    }
                }
                first->key = key;
                node_add_child(item, first);
                if (*i < n && L[*i].indent > dash_indent &&
                    L[*i].text[0] != '-') {
                    yaml_node_t *rest =
                        parse_map(L, n, i, L[*i].indent, err, errcap);
                    if (!rest) {
                        yaml_free(item);
                        yaml_free(seq);
                        return NULL;
                    }
                    yaml_node_t *ch = rest->child;
                    rest->child = NULL;
                    yaml_free(rest);
                    while (ch) {
                        yaml_node_t *nx = ch->next;
                        ch->next = NULL;
                        node_add_child(item, ch);
                        ch = nx;
                    }
                }
            } else {
                item = node_new(YAML_KIND_SCALAR);
                item->scalar = unquote(p);
            }
        }
        if (!item) {
            snprintf(err, errcap, "line %d: bad sequence item", item_line);
            yaml_free(seq);
            return NULL;
        }
        node_add_child(seq, item);
    }
    return seq;
}

yaml_node_t *yaml_parse_file(const char *path, char *err, size_t errcap)
{
    if (err && errcap) {
        err[0] = '\0';
    }
    FILE *fp = fopen(path, "r");
    if (!fp) {
        snprintf(err, errcap, "cannot open %s", path);
        return NULL;
    }

    yline_t lines[YAML_MAX_LINES];
    int n = 0;
    char buf[YAML_MAX_LINE];
    int lineno = 0;
    while (fgets(buf, sizeof(buf), fp)) {
        lineno++;
        strip_comment(buf);
        rtrim(buf);
        char *p = buf;
        int indent = 0;
        while (*p == ' ') {
            indent++;
            p++;
        }
        if (*p == '\t') {
            snprintf(err, errcap, "line %d: tabs not allowed", lineno);
            fclose(fp);
            for (int i = 0; i < n; i++) {
                free(lines[i].text);
            }
            return NULL;
        }
        if (*p == '\0') {
            continue;
        }
        if (n >= YAML_MAX_LINES) {
            snprintf(err, errcap, "too many lines (max %d)", YAML_MAX_LINES);
            fclose(fp);
            for (int i = 0; i < n; i++) {
                free(lines[i].text);
            }
            return NULL;
        }
        lines[n].text = xstrdup(p);
        lines[n].indent = indent;
        lines[n].lineno = lineno;
        n++;
    }
    fclose(fp);

    if (n == 0) {
        snprintf(err, errcap, "empty YAML file");
        return NULL;
    }

    int i = 0;
    int leftover_line = 0;
    yaml_node_t *root = parse_map(lines, n, &i, lines[0].indent, err, errcap);
    if (i != n) {
        leftover_line = lines[i].lineno;
    }
    for (int k = 0; k < n; k++) {
        free(lines[k].text);
    }
    if (!root) {
        return NULL;
    }
    if (i != n) {
        snprintf(err, errcap, "line %d: unparsed content", leftover_line);
        yaml_free(root);
        return NULL;
    }
    return root;
}

const yaml_node_t *yaml_map_get(const yaml_node_t *map, const char *key)
{
    if (!map || map->kind != YAML_KIND_MAP || !key) {
        return NULL;
    }
    for (const yaml_node_t *c = map->child; c; c = c->next) {
        if (c->key && strcmp(c->key, key) == 0) {
            return c;
        }
    }
    return NULL;
}

int yaml_has(const yaml_node_t *map, const char *key)
{
    return yaml_map_get(map, key) != NULL;
}

const char *yaml_cstr(const yaml_node_t *map, const char *key, const char *def)
{
    const yaml_node_t *n = yaml_map_get(map, key);
    if (!n) {
        return def;
    }
    if (n->kind == YAML_KIND_SCALAR && n->scalar) {
        return n->scalar;
    }
    return def;
}

int yaml_bool(const yaml_node_t *map, const char *key, int def)
{
    const char *s = yaml_cstr(map, key, NULL);
    if (!s) {
        return def;
    }
    if (strcmp(s, "true") == 0 || strcmp(s, "True") == 0 ||
        strcmp(s, "yes") == 0 || strcmp(s, "1") == 0) {
        return 1;
    }
    if (strcmp(s, "false") == 0 || strcmp(s, "False") == 0 ||
        strcmp(s, "no") == 0 || strcmp(s, "0") == 0) {
        return 0;
    }
    return def;
}

static unsigned long parse_num(const char *s, int *ok)
{
    if (!s || !*s) {
        *ok = 0;
        return 0;
    }
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 0);
    *ok = (end && *end == '\0');
    return v;
}

long yaml_long(const yaml_node_t *map, const char *key, long def)
{
    const char *s = yaml_cstr(map, key, NULL);
    int ok = 0;
    unsigned long v = parse_num(s, &ok);
    return ok ? (long)v : def;
}

unsigned long yaml_ulong(const yaml_node_t *map, const char *key,
                         unsigned long def)
{
    const char *s = yaml_cstr(map, key, NULL);
    int ok = 0;
    unsigned long v = parse_num(s, &ok);
    return ok ? v : def;
}
