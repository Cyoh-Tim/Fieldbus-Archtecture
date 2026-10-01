/*
 * EtherNet/IP oracle DUT (tests/oracle): Originator (client) path.
 *
 *   eip_oracle_originator --port N get <class> <instance> <attribute>
 *   eip_oracle_originator --port N tag-read <tag>
 *   eip_oracle_originator --port N tag-write <tag> <hex bytes>
 *
 * Connects to 127.0.0.1:N (RegisterSession), runs one explicit request and
 * prints one line: "RC <rc> <hex data>". The fake target server in
 * test_eip_oracle.py (spec-based, Logix-like) decides whether the request
 * on the wire and the returned data are right. Not a product binary.
 */
#define _POSIX_C_SOURCE 200809L

#include "eip_stack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_rc(int rc, const uint8_t *data, size_t n)
{
    printf("RC %d ", rc);
    for (size_t i = 0; i < n; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    int port = 44818;
    int i = 1;
    if (i + 1 < argc && strcmp(argv[i], "--port") == 0) {
        port = atoi(argv[i + 1]);
        i += 2;
    }
    if (i >= argc) {
        fprintf(stderr, "usage: see header\n");
        return 2;
    }
    const char *op = argv[i++];

    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ORIGINATOR;
    snprintf(cfg.remote_ip, sizeof(cfg.remote_ip), "127.0.0.1");
    cfg.remote_port = port;
    cfg.tcp_port = port;
    cfg.vendor_id = 0xABCD;
    cfg.device_type = 12;
    cfg.product_code = 1;
    cfg.major_rev = 1;
    cfg.minor_rev = 1;
    cfg.serial_number = 0x12345678u;
    snprintf(cfg.product_name, sizeof(cfg.product_name), "FieldbusOracle");
    cfg.security_class = 0;
    cfg.lldp_enable = 0;
    cfg.acd_enable = 0;

    eip_stack_t *s = eip_stack_create(&cfg);
    if (!s) {
        fprintf(stderr, "eip_stack_create failed\n");
        return 1;
    }
    int rc = eip_stack_start(s);
    if (rc != 0) {
        print_rc(rc, NULL, 0);
        eip_stack_destroy(s);
        return 0;
    }

    uint8_t out[1024];
    size_t n = sizeof(out);
    if (strcmp(op, "get") == 0 && i + 2 < argc) {
        rc = eip_stack_explicit_get(s, (uint16_t)strtoul(argv[i], NULL, 0),
                                    (uint16_t)strtoul(argv[i + 1], NULL, 0),
                                    (uint16_t)strtoul(argv[i + 2], NULL, 0),
                                    out, &n);
        print_rc(rc, out, rc == 0 ? n : 0);
    } else if (strcmp(op, "tag-read") == 0 && i < argc) {
        rc = eip_stack_tag_read(s, argv[i], out, &n);
        print_rc(rc, out, rc == 0 ? n : 0);
    } else if (strcmp(op, "tag-write") == 0 && i + 1 < argc) {
        const char *hex = argv[i + 1];
        size_t len = strlen(hex) / 2;
        uint8_t data[256];
        if (len > sizeof(data)) {
            len = sizeof(data);
        }
        for (size_t k = 0; k < len; k++) {
            unsigned b = 0;
            sscanf(hex + 2 * k, "%2x", &b);
            data[k] = (uint8_t)b;
        }
        rc = eip_stack_tag_write(s, argv[i], data, len);
        print_rc(rc, NULL, 0);
    } else {
        fprintf(stderr, "unknown op %s\n", op);
        eip_stack_destroy(s);
        return 2;
    }
    eip_stack_destroy(s);
    return 0;
}
