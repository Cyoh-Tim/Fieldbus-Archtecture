/*
 * T11-2: FieldbusSensor.eds layout and adapter minor_rev.
 *
 * Connection1 is 15 comma fields (CIP Vol 1 EDS Connection entry): the RPI
 * slots are single Param references, O→T/T→O formats name Assem101/Assem150,
 * and the last field is the connection path. Param data type and size agree.
 * Port1 is type, name, TCP/IP Interface EPATH, port number.
 * RPI Params are UDINT with min = example cycle_ms × 1000 µs.
 * The adapter copies protocol_params.minor_rev into Identity (default 0,
 * which is EDS MinRev for the example config).
 */
#include "eip_endian.h"
#include "eip_stack.h"
#include "eip_types.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef T11_2_HAVE_ADAPTER
#include "ethernetip_adapter.h"
#include "protocol_adapter.h"
#endif

#ifndef T11_2_EDS_PATH
#define T11_2_EDS_PATH "stacks/ethernetip/eds/FieldbusSensor.eds"
#endif
#ifndef T11_2_EXAMPLE_CFG
#define T11_2_EXAMPLE_CFG "config/example.ethernetip.json"
#endif

#define EDS_MAX_SECTIONS 12
#define EDS_MAX_KEYS 16
#define EDS_MAX_FIELDS 32
#define EDS_NAME_LEN 64
#define EDS_FIELD_LEN 160

static int g_fail;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

typedef struct {
    char key[EDS_NAME_LEN];
    int nfields;
    char fields[EDS_MAX_FIELDS][EDS_FIELD_LEN];
} eds_entry_t;

typedef struct {
    char name[EDS_NAME_LEN];
    int nentries;
    eds_entry_t entries[EDS_MAX_KEYS];
} eds_section_t;

typedef struct {
    int nsections;
    eds_section_t sections[EDS_MAX_SECTIONS];
} eds_doc_t;

static int stmt_blank(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (s[i] != ' ' && s[i] != '\t' && s[i] != '\r' && s[i] != '\n') {
            return 0;
        }
    }
    return 1;
}

static int copy_trim(char *dst, size_t cap, const char *src, size_t n)
{
    while (n > 0 &&
           (*src == ' ' || *src == '\t' || *src == '\r' || *src == '\n')) {
        src++;
        n--;
    }
    while (n > 0 && (src[n - 1] == ' ' || src[n - 1] == '\t' ||
                     src[n - 1] == '\r' || src[n - 1] == '\n')) {
        n--;
    }
    if (n + 1 > cap) {
        return -1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
    return 0;
}

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0 || sz > 1024 * 1024) {
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

static int add_field(eds_entry_t *ent, const char *src, size_t n)
{
    if (ent->nfields >= EDS_MAX_FIELDS) {
        return -1;
    }
    return copy_trim(ent->fields[ent->nfields++], EDS_FIELD_LEN, src, n);
}

/* CIP Vol 1 EDS: '$' comments, quoted commas kept, ';' ends a statement. */
static int parse_eds(const char *text, eds_doc_t *doc)
{
    memset(doc, 0, sizeof(*doc));
    size_t n = strlen(text);
    char *stmt = malloc(n + 1);
    if (!stmt) {
        return -1;
    }
    size_t slen = 0;
    int inq = 0;
    eds_section_t *cur = NULL;
    size_t i = 0;
    int rc = 0;

    while (i < n) {
        char ch = text[i];
        if (ch == '"') {
            inq = !inq;
        }
        if (!inq && ch == '$') {
            while (i < n && text[i] != '\n') {
                i++;
            }
            continue;
        }
        if (!inq && ch == '[' && stmt_blank(stmt, slen)) {
            size_t end = i + 1;
            while (end < n && text[end] != ']') {
                end++;
            }
            if (end >= n || doc->nsections >= EDS_MAX_SECTIONS) {
                rc = -1;
                break;
            }
            cur = &doc->sections[doc->nsections++];
            memset(cur, 0, sizeof(*cur));
            if (copy_trim(cur->name, sizeof(cur->name), text + i + 1,
                          end - (i + 1)) != 0) {
                rc = -1;
                break;
            }
            slen = 0;
            i = end + 1;
            continue;
        }
        if (!inq && ch == ';') {
            size_t eq = 0;
            while (eq < slen && stmt[eq] != '=') {
                eq++;
            }
            if (!cur || eq >= slen || cur->nentries >= EDS_MAX_KEYS) {
                rc = -1;
                break;
            }
            eds_entry_t *ent = &cur->entries[cur->nentries++];
            memset(ent, 0, sizeof(*ent));
            if (copy_trim(ent->key, sizeof(ent->key), stmt, eq) != 0) {
                rc = -1;
                break;
            }
            const char *rest = stmt + eq + 1;
            size_t rest_n = slen - (eq + 1);
            size_t start = 0;
            int q = 0;
            for (size_t k = 0; k < rest_n; k++) {
                if (rest[k] == '"') {
                    q = !q;
                }
                if (rest[k] == ',' && !q) {
                    if (add_field(ent, rest + start, k - start) != 0) {
                        rc = -1;
                        break;
                    }
                    start = k + 1;
                }
            }
            if (rc != 0) {
                break;
            }
            if (add_field(ent, rest + start, rest_n - start) != 0) {
                rc = -1;
                break;
            }
            slen = 0;
        } else {
            stmt[slen++] = ch;
        }
        i++;
    }
    free(stmt);
    return rc;
}

static const eds_entry_t *eds_get(const eds_doc_t *doc, const char *section,
                                  const char *key)
{
    for (int s = 0; s < doc->nsections; s++) {
        if (strcmp(doc->sections[s].name, section) != 0) {
            continue;
        }
        for (int e = 0; e < doc->sections[s].nentries; e++) {
            if (strcmp(doc->sections[s].entries[e].key, key) == 0) {
                return &doc->sections[s].entries[e];
            }
        }
    }
    return NULL;
}

static void dump_fields(const char *what, const eds_entry_t *ent)
{
    fprintf(stderr, "FAIL: %s (%d fields)\n", what, ent ? ent->nfields : -1);
    if (!ent) {
        return;
    }
    for (int i = 0; i < ent->nfields; i++) {
        fprintf(stderr, "  [%d] %s\n", i, ent->fields[i]);
    }
    g_fail = 1;
}

static int parse_int(const char *s, long *out)
{
    if (!s || !s[0]) {
        return -1;
    }
    errno = 0;
    char *end = NULL;
    long v = strtol(s, &end, 0);
    if (end == s || *end != '\0' || errno != 0) {
        return -1;
    }
    *out = v;
    return 0;
}

static int unquote(const char *s, char *dst, size_t cap)
{
    size_t n = strlen(s);
    if (n < 2 || s[0] != '"' || s[n - 1] != '"') {
        return -1;
    }
    if (n - 1 > cap) {
        return -1;
    }
    memcpy(dst, s + 1, n - 2);
    dst[n - 2] = '\0';
    return 0;
}

/* CIP Vol 1 Appendix C elementary types used by the oracle. */
static int cip_type_size(unsigned code, unsigned *sz)
{
    switch (code) {
    case 0xC1:
    case 0xC2:
    case 0xC6:
    case 0xD1:
        *sz = 1;
        return 0;
    case 0xC3:
    case 0xC7:
    case 0xD2:
        *sz = 2;
        return 0;
    case 0xC4:
    case 0xC8:
    case 0xCA:
    case 0xD3:
        *sz = 4;
        return 0;
    case 0xC5:
    case 0xC9:
    case 0xCB:
    case 0xD4:
        *sz = 8;
        return 0;
    default:
        return -1;
    }
}

static int is_param_ref(const char *s)
{
    if (strncmp(s, "Param", 5) != 0) {
        return 0;
    }
    if (s[5] == '\0') {
        return 0;
    }
    for (const char *p = s + 5; *p; p++) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
    }
    return 1;
}

static int example_cycle_ms(int *out)
{
    char *text = read_file(T11_2_EXAMPLE_CFG);
    if (!text) {
        return -1;
    }
    const char *p = strstr(text, "\"cycle_ms\"");
    if (!p) {
        free(text);
        return -1;
    }
    p += strlen("\"cycle_ms\"");
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ':') {
        p++;
    }
    char *end = NULL;
    long v = strtol(p, &end, 10);
    free(text);
    if (end == p || v <= 0 || v > 1000000) {
        return -1;
    }
    *out = (int)v;
    return 0;
}

static void test_connection(const eds_doc_t *doc)
{
    const eds_entry_t *conn = eds_get(doc, "Connection Manager", "Connection1");
    if (!conn || conn->nfields != 15) {
        dump_fields("Connection1 field count (want 15)", conn);
        return;
    }
    if (strcmp(conn->fields[4], "Assem101") != 0 ||
        strcmp(conn->fields[7], "Assem150") != 0) {
        dump_fields("Connection1 O->T/T->O format (want Assem101, Assem150)",
                    conn);
        return;
    }
    char path[EDS_FIELD_LEN];
    char compact[EDS_FIELD_LEN];
    if (unquote(conn->fields[14], path, sizeof(path)) != 0) {
        dump_fields("Connection1 path is not a quoted string", conn);
        return;
    }
    size_t j = 0;
    for (size_t i = 0; path[i] != '\0' && j + 1 < sizeof(compact); i++) {
        unsigned char c = (unsigned char)path[i];
        if (c == ' ' || c == '\t') {
            continue;
        }
        if (c >= 'a' && c <= 'z') {
            c = (unsigned char)(c - 'a' + 'A');
        }
        compact[j++] = (char)c;
    }
    compact[j] = '\0';
    expect(strstr(compact, "20042464") != NULL, "path has config 100");
    expect(strstr(compact, "2C652C96") != NULL, "path has O->T 101 then T->O 150");
    if (!strstr(compact, "20042464") || !strstr(compact, "2C652C96")) {
        fprintf(stderr, "  path %s\n", path);
    }
}

static void test_params(const eds_doc_t *doc)
{
    const eds_section_t *params = NULL;
    for (int s = 0; s < doc->nsections; s++) {
        if (strcmp(doc->sections[s].name, "Params") == 0) {
            params = &doc->sections[s];
            break;
        }
    }
    expect(params != NULL && params->nentries > 0, "Params section");
    if (!params) {
        return;
    }
    for (int e = 0; e < params->nentries; e++) {
        const eds_entry_t *ent = &params->entries[e];
        if (strncmp(ent->key, "Param", 5) != 0) {
            continue;
        }
        if (ent->nfields < 6) {
            dump_fields("Param shorter than type/size", ent);
            continue;
        }
        long code = 0;
        long size = 0;
        unsigned want = 0;
        if (parse_int(ent->fields[4], &code) != 0 ||
            parse_int(ent->fields[5], &size) != 0 ||
            cip_type_size((unsigned)code, &want) != 0 ||
            (long)want != size) {
            fprintf(stderr,
                    "FAIL: %s type/size mismatch type=%s size=%s\n",
                    ent->key, ent->fields[4], ent->fields[5]);
            g_fail = 1;
        }
    }
}

static void test_port(const eds_doc_t *doc)
{
    const eds_entry_t *port = eds_get(doc, "Port", "Port1");
    if (!port || port->nfields != 4) {
        dump_fields("Port1 field count (want 4: type, name, EPATH, number)",
                    port);
        return;
    }
    expect(strcmp(port->fields[0], "TCP") == 0, "Port1 type TCP");
    char name[EDS_FIELD_LEN];
    char ep[EDS_FIELD_LEN];
    if (unquote(port->fields[1], name, sizeof(name)) != 0) {
        fprintf(stderr, "FAIL: Port1 name not quoted: %s\n", port->fields[1]);
        g_fail = 1;
    }
    if (unquote(port->fields[2], ep, sizeof(ep)) != 0) {
        fprintf(stderr, "FAIL: Port1 path not quoted: %s\n", port->fields[2]);
        g_fail = 1;
        return;
    }
    char tmp[EDS_FIELD_LEN];
    snprintf(tmp, sizeof(tmp), "%s", ep);
    char *tok1 = strtok(tmp, " \t");
    char *tok2 = strtok(NULL, " \t");
    if (!tok1 || !tok2 || strcmp(tok1, "20") != 0 || strcmp(tok2, "F5") != 0) {
        fprintf(stderr, "FAIL: Port1 EPATH want 20 F5 ... got %s\n", ep);
        g_fail = 1;
    }
    long portno = 0;
    if (parse_int(port->fields[3], &portno) != 0) {
        fprintf(stderr, "FAIL: Port1 number not an integer: %s\n",
                port->fields[3]);
        g_fail = 1;
    }
}

static void test_rpi_param(const eds_doc_t *doc)
{
    int cycle_ms = 0;
    expect(example_cycle_ms(&cycle_ms) == 0, "example cycle_ms");
    if (g_fail && cycle_ms == 0) {
        return;
    }
    const eds_entry_t *conn = eds_get(doc, "Connection Manager", "Connection1");
    if (!conn || conn->nfields < 6) {
        return;
    }
    const int idx[2] = {2, 5};
    for (int i = 0; i < 2; i++) {
        const char *ref = conn->fields[idx[i]];
        if (!is_param_ref(ref)) {
            fprintf(stderr, "FAIL: Connection1 RPI field %d is not ParamN: %s\n",
                    idx[i], ref);
            g_fail = 1;
            continue;
        }
        const eds_entry_t *p = eds_get(doc, "Params", ref);
        if (!p || p->nfields < 10) {
            fprintf(stderr, "FAIL: RPI %s missing or short\n", ref);
            g_fail = 1;
            continue;
        }
        long code = 0;
        long size = 0;
        long min_us = 0;
        long want = (long)cycle_ms * 1000L;
        if (parse_int(p->fields[4], &code) != 0 || code != 0xC8 ||
            parse_int(p->fields[5], &size) != 0 || size != 4 ||
            parse_int(p->fields[9], &min_us) != 0 || min_us != want) {
            fprintf(stderr,
                    "FAIL: %s want UDINT size 4 min %ld, got type=%s size=%s min=%s\n",
                    ref, want, p->nfields > 4 ? p->fields[4] : "?",
                    p->nfields > 5 ? p->fields[5] : "?",
                    p->nfields > 9 ? p->fields[9] : "?");
            g_fail = 1;
        }
    }
}

#ifdef T11_2_HAVE_ADAPTER
typedef struct {
    eip_stack_t *stack;
} eip_ctx_peek_t;

static int identity_revision(protocol_adapter_t *a, uint8_t *major, uint8_t *minor)
{
    if (!a || !a->ctx) {
        return -1;
    }
    eip_stack_t *s = ((eip_ctx_peek_t *)a->ctx)->stack;
    if (!s) {
        return -1;
    }
    uint8_t req[EIP_ENCAP_HDR_SIZE];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_LISTIDENTITY);
    uint8_t resp[256];
    size_t resp_len = 0;
    if (eip_stack_handle_encap(s, req, sizeof(req), resp, sizeof(resp),
                               &resp_len) != 0) {
        return -1;
    }
    /* Encap header + CPF: version(2) after item hdr(6), sockaddr(16),
     * vendor/type/code (6) → revision at payload offset 30. */
    const size_t rev_at = EIP_ENCAP_HDR_SIZE + 30;
    if (resp_len < rev_at + 2) {
        return -1;
    }
    const eip_cfg_t *cfg = eip_stack_cfg(s);
    if (!cfg || resp[rev_at] != cfg->major_rev ||
        resp[rev_at + 1] != cfg->minor_rev) {
        return -1;
    }
    *major = resp[rev_at];
    *minor = resp[rev_at + 1];
    return 0;
}

static void check_revision(const char *params, uint8_t want_maj, uint8_t want_min,
                           const char *msg)
{
    protocol_adapter_t *a = ethernetip_adapter_create();
    expect(a != NULL, "adapter create");
    if (!a) {
        return;
    }
    int rc = a->init(a, params, "[]");
    if (rc != 0) {
        fprintf(stderr, "FAIL: %s init rc=%d\n", msg, rc);
        g_fail = 1;
        a->destroy(a);
        return;
    }
    uint8_t maj = 0xFF;
    uint8_t min = 0xFF;
    if (identity_revision(a, &maj, &min) != 0) {
        fprintf(stderr, "FAIL: %s ListIdentity\n", msg);
        g_fail = 1;
    } else if (maj != want_maj || min != want_min) {
        fprintf(stderr, "FAIL: %s Identity %u.%u want %u.%u\n", msg,
                (unsigned)maj, (unsigned)min, (unsigned)want_maj,
                (unsigned)want_min);
        g_fail = 1;
    }
    a->destroy(a);
}

static void test_minor_rev(const eds_doc_t *doc)
{
    const eds_entry_t *maj = eds_get(doc, "Device", "MajRev");
    const eds_entry_t *min = eds_get(doc, "Device", "MinRev");
    long maj_v = 0;
    long min_v = 0;
    if (!maj || !min || maj->nfields < 1 || min->nfields < 1 ||
        parse_int(maj->fields[0], &maj_v) != 0 ||
        parse_int(min->fields[0], &min_v) != 0 || maj_v < 0 || maj_v > 255 ||
        min_v < 0 || min_v > 255) {
        expect(0, "EDS MajRev/MinRev");
        return;
    }
    check_revision("{\"mock\":true,\"security_class\":0}", (uint8_t)maj_v,
                   (uint8_t)min_v, "default minor_rev matches EDS");
    check_revision(
        "{\"mock\":true,\"security_class\":0,\"major_rev\":1,\"minor_rev\":7}",
        1, 7, "minor_rev from config");
}
#endif

int main(void)
{
    char *text = read_file(T11_2_EDS_PATH);
    if (!text) {
        fprintf(stderr, "FAIL: cannot read %s\n", T11_2_EDS_PATH);
        return 1;
    }
    eds_doc_t *doc = calloc(1, sizeof(*doc));
    if (!doc || parse_eds(text, doc) != 0) {
        fprintf(stderr, "FAIL: EDS parse\n");
        free(text);
        free(doc);
        return 1;
    }
    free(text);

    test_connection(doc);
    test_params(doc);
    test_port(doc);
    test_rpi_param(doc);
#ifdef T11_2_HAVE_ADAPTER
    test_minor_rev(doc);
#endif
    free(doc);
    if (g_fail) {
        fprintf(stderr, "test_eip_t11_2: FAILED\n");
        return 1;
    }
    printf("test_eip_t11_2: ok\n");
    return 0;
}
