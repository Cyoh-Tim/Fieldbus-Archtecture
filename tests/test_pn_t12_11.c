/*
 * T12-11: PROFINET LLDP must advertise a topology a controller can read.
 *
 *   PNO OUI is 00-0E-CF (not 00-0C-CF).
 *   Port ID is subtype 7, locally assigned "port-001" (not the MAC).
 *   Port Status (PNO subtype 2), IEEE 802.3 MAC/PHY (OUI 00-12-0F
 *   subtype 1) and Management Address (TLV type 8, IPv4) are present.
 *   Chassis MAC stays, with the corrected PNO OUI.
 *
 * RT Class 1 only: RTClass2 and RTClass3 Port Status are OFF (0).
 * Operational MAU type 16 is this device's GSDML MAUTypes value
 * (dot3MauType100BaseTXFD). The advertised-capability bit is the
 * RFC 3636 b100baseTXFD bit in IEEE bit order (0x0400).
 */
#include "pn_endian.h"
#include "pn_stack.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

static uint8_t g_tx[PN_FRAME_MAX];
static size_t g_txlen;
static int g_ntx;

static int capture_send(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    if (len <= PN_FRAME_MAX) {
        memcpy(g_tx, frame, len);
        g_txlen = len;
        g_ntx++;
    }
    return 0;
}

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static void dump_bytes(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        fprintf(stderr, "%02x%s", p[i], (i + 1 == n) ? "" : " ");
    }
    fprintf(stderr, "\n");
}

typedef struct {
    uint8_t type;
    uint16_t len;
    const uint8_t *val;
} tlv_view_t;

static int next_tlv(const uint8_t *pdu, size_t n, size_t *off, tlv_view_t *t)
{
    if (*off + 2 > n) {
        return -1;
    }
    uint16_t hdr = pn_rd_be16(pdu + *off);
    t->type = (uint8_t)(hdr >> 9);
    t->len = (uint16_t)(hdr & 0x1FFu);
    *off += 2;
    if (*off + t->len > n) {
        return -1;
    }
    t->val = pdu + *off;
    *off += t->len;
    return 0;
}

static const uint8_t *lldp_pdu(size_t *pdu_len)
{
    static const uint8_t mc[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};
    if (g_txlen < 14 || memcmp(g_tx, mc, 6) != 0 ||
        pn_rd_be16(g_tx + 12) != PN_ETHTYPE_LLDP) {
        return NULL;
    }
    *pdu_len = g_txlen - 14;
    return g_tx + 14;
}

/* Walk every TLV. Returns 0 when the PDU ends on an End TLV. */
static int find_tlv(const uint8_t *pdu, size_t n, uint8_t type, tlv_view_t *out,
                     int *count)
{
    size_t off = 0;
    int nfound = 0;
    int ended = 0;
    tlv_view_t t;
    while (!ended && next_tlv(pdu, n, &off, &t) == 0) {
        if (t.type == type) {
            if (nfound == 0 && out) {
                *out = t;
            }
            nfound++;
        }
        if (t.type == 0) {
            ended = 1;
            if (off != n) {
                return -2; /* trailing bytes after End */
            }
        }
    }
    if (!ended) {
        return -1;
    }
    if (count) {
        *count = nfound;
    }
    return nfound > 0 ? 0 : 1;
}

static int find_org(const uint8_t *pdu, size_t n, const uint8_t oui[3],
                    uint8_t subtype, tlv_view_t *out)
{
    size_t off = 0;
    tlv_view_t t;
    while (next_tlv(pdu, n, &off, &t) == 0) {
        if (t.type == 127 && t.len >= 4 && memcmp(t.val, oui, 3) == 0 &&
            t.val[3] == subtype) {
            if (out) {
                *out = t;
            }
            return 0;
        }
        if (t.type == 0) {
            break;
        }
    }
    return -1;
}

static int oui_present(const uint8_t *pdu, size_t n, const uint8_t oui[3])
{
    size_t off = 0;
    tlv_view_t t;
    while (next_tlv(pdu, n, &off, &t) == 0) {
        if (t.type == 127 && t.len >= 3 && memcmp(t.val, oui, 3) == 0) {
            return 1;
        }
        if (t.type == 0) {
            break;
        }
    }
    return 0;
}

static pn_stack_t *make_stack(void)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "sensor-line1");
    cfg.mac[0] = 0x02;
    cfg.mac[1] = 0xFB;
    cfg.mac[2] = 0x00;
    cfg.mac[3] = 0x00;
    cfg.mac[4] = 0x00;
    cfg.mac[5] = 0x01;
    cfg.mac_set = 1;
    cfg.ip = 0xC0A8C802u; /* 192.168.200.2, host order */
    cfg.security_class = 0;
    cfg.input_len = 32;
    cfg.output_len = 8;
    pn_stack_t *s = pn_stack_create(&cfg);
    if (!s) {
        return NULL;
    }
    pn_eth_ops_t ops = {.send = capture_send, .recv = NULL, .ctx = NULL};
    pn_stack_set_eth_ops(s, ops);
    if (pn_stack_start(s) != 0) {
        pn_stack_destroy(s);
        return NULL;
    }
    return s;
}

static void test_lldp_required_tlvs(void)
{
    static const uint8_t pno_oui[3] = {0x00, 0x0E, 0xCF};
    static const uint8_t wrong_oui[3] = {0x00, 0x0C, 0xCF};
    static const uint8_t ieee_oui[3] = {0x00, 0x12, 0x0F};
    static const uint8_t mac[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
    static const char port_id[] = "port-001";
    static const char name[] = "sensor-line1";

    pn_stack_t *s = make_stack();
    expect(s != NULL, "stack create/start");
    if (!s) {
        return;
    }
    /* Startup already sent one LLDPDU. Check the CTT helper too. */
    int startup_ntx = g_ntx;
    expect(startup_ntx == 1, "start sends one LLDP frame");
    g_ntx = 0;
    g_txlen = 0;
    pn_stack_send_lldp(s);
    expect(g_ntx == 1, "pn_stack_send_lldp sends one frame");

    size_t pdulen = 0;
    const uint8_t *pdu = lldp_pdu(&pdulen);
    if (!pdu) {
        fprintf(stderr, "FAIL: no LLDP frame (len=%zu et=%04x)\n", g_txlen,
                g_txlen >= 14 ? pn_rd_be16(g_tx + 12) : 0);
        if (g_txlen) {
            fprintf(stderr, "  frame:");
            dump_bytes(g_tx, g_txlen > 64 ? 64 : g_txlen);
        }
        g_fail = 1;
        pn_stack_destroy(s);
        return;
    }
    expect(memcmp(g_tx + 6, mac, 6) == 0, "LLDP source MAC");

    tlv_view_t chassis;
    int nchassis = 0;
    int rc = find_tlv(pdu, pdulen, 1, &chassis, &nchassis);
    expect(rc == 0 && nchassis == 1, "one Chassis ID TLV");
    if (rc == 0) {
        int ok = chassis.len == 1 + sizeof(name) - 1 && chassis.val[0] == 7 &&
                 memcmp(chassis.val + 1, name, sizeof(name) - 1) == 0;
        if (!ok) {
            fprintf(stderr, "FAIL: Chassis ID want subtype 7 \"%s\", got ",
                    name);
            dump_bytes(chassis.val, chassis.len);
            g_fail = 1;
        }
    } else if (rc == -1) {
        fprintf(stderr, "FAIL: LLDPDU has no End TLV\n");
        g_fail = 1;
    } else if (rc == -2) {
        fprintf(stderr, "FAIL: bytes after End of LLDPDU\n");
        g_fail = 1;
    }

    tlv_view_t port;
    int nport = 0;
    rc = find_tlv(pdu, pdulen, 2, &port, &nport);
    expect(rc == 0 && nport == 1, "one Port ID TLV");
    if (rc == 0) {
        int ok = port.len == 1 + sizeof(port_id) - 1 && port.val[0] == 7 &&
                 memcmp(port.val + 1, port_id, sizeof(port_id) - 1) == 0;
        if (!ok) {
            fprintf(stderr,
                    "FAIL: Port ID want subtype 7 \"%s\", got len=%u ",
                    port_id, port.len);
            dump_bytes(port.val, port.len);
            g_fail = 1;
        }
    }

    tlv_view_t ttl;
    expect(find_tlv(pdu, pdulen, 3, &ttl, NULL) == 0 && ttl.len == 2 &&
               pn_rd_be16(ttl.val) == 20,
           "TTL TLV is 20 seconds");

    tlv_view_t sysname;
    expect(find_tlv(pdu, pdulen, 5, &sysname, NULL) == 0 &&
               sysname.len == sizeof(name) - 1 &&
               memcmp(sysname.val, name, sizeof(name) - 1) == 0,
           "System Name TLV is the station name");

    tlv_view_t mgmt;
    rc = find_tlv(pdu, pdulen, 8, &mgmt, NULL);
    if (rc != 0) {
        fprintf(stderr, "FAIL: Management Address TLV (type 8) missing\n");
        g_fail = 1;
    } else {
        /* addrlen 5, IPv4 subtype 1, 192.168.200.2, ifIndex, number 1
         * (mock has no OS ifindex), OID length 0. */
        uint8_t want[12] = {5, 1, 0xC0, 0xA8, 0xC8, 0x02, 2, 0, 0, 0, 1, 0};
        int ok = mgmt.len == sizeof(want) &&
                 memcmp(mgmt.val, want, sizeof(want)) == 0;
        if (!ok) {
            fprintf(stderr, "FAIL: Management Address want ");
            dump_bytes(want, sizeof(want));
            fprintf(stderr, "  got ");
            dump_bytes(mgmt.val, mgmt.len);
            g_fail = 1;
        }
    }

    if (oui_present(pdu, pdulen, wrong_oui)) {
        fprintf(stderr, "FAIL: org TLV still uses OUI 00-0C-CF\n");
        g_fail = 1;
    }
    expect(oui_present(pdu, pdulen, pno_oui), "PNO OUI 00-0E-CF present");

    tlv_view_t portst;
    if (find_org(pdu, pdulen, pno_oui, 2, &portst) != 0) {
        fprintf(stderr, "FAIL: Port Status TLV (PNO subtype 2) missing\n");
        g_fail = 1;
    } else {
        /* OUI(3) + subtype(1) + RTClass2(2) + RTClass3(2), both OFF. */
        int ok = portst.len == 8 && pn_rd_be16(portst.val + 4) == 0 &&
                 pn_rd_be16(portst.val + 6) == 0;
        if (!ok) {
            fprintf(stderr, "FAIL: Port Status want RTClass2/3 OFF, got ");
            dump_bytes(portst.val, portst.len);
            g_fail = 1;
        }
    }

    tlv_view_t chassis_mac;
    if (find_org(pdu, pdulen, pno_oui, 5, &chassis_mac) != 0) {
        fprintf(stderr, "FAIL: Chassis MAC TLV (PNO subtype 5) missing\n");
        g_fail = 1;
    } else {
        int ok = chassis_mac.len == 10 &&
                 memcmp(chassis_mac.val + 4, mac, 6) == 0;
        if (!ok) {
            fprintf(stderr, "FAIL: Chassis MAC got ");
            dump_bytes(chassis_mac.val, chassis_mac.len);
            g_fail = 1;
        }
    }

    tlv_view_t macphy;
    if (find_org(pdu, pdulen, ieee_oui, 1, &macphy) != 0) {
        fprintf(stderr,
                "FAIL: MAC/PHY TLV (IEEE 802.3 00-12-0F subtype 1) missing\n");
        g_fail = 1;
    } else {
        /* autoneg supported+enabled, b100baseTXFD, MAU type 16. */
        int ok = macphy.len == 9 && macphy.val[4] == 0x03 &&
                 pn_rd_be16(macphy.val + 5) == 0x0400 &&
                 pn_rd_be16(macphy.val + 7) == 16;
        if (!ok) {
            fprintf(stderr, "FAIL: MAC/PHY got ");
            dump_bytes(macphy.val, macphy.len);
            g_fail = 1;
        }
    }

    pn_stack_destroy(s);
}

int main(int argc, char **argv)
{
    int dump = argc > 1 && strcmp(argv[1], "--dump") == 0;
    test_lldp_required_tlvs();
    if (dump && g_txlen > 0) {
        if (fwrite(g_tx, 1, g_txlen, stdout) != g_txlen) {
            fprintf(stderr, "FAIL: dump short write\n");
            return 1;
        }
    }
    if (g_fail) {
        fprintf(stderr, "test_pn_t12_11: FAILED\n");
        return 1;
    }
    if (!dump) {
        printf("test_pn_t12_11: OK\n");
    }
    return 0;
}
