#include "eip_endian.h"
#include "eip_internal.h"
#include "eip_sec.h"

#include <errno.h>
#include <string.h>

#include "logger.h"

static size_t cip_error(uint8_t *resp, size_t cap, uint8_t service,
                        uint8_t status, uint8_t ext)
{
    if (cap < 4) {
        return 0;
    }
    resp[0] = (uint8_t)(service | CIP_SVC_REPLY);
    resp[1] = 0; /* reserved */
    resp[2] = status;
    resp[3] = ext ? 1 : 0;
    if (ext && cap >= 6) {
        eip_wr_le16(resp + 4, ext);
        return 6;
    }
    return 4;
}

static size_t cip_ok_header(uint8_t *resp, size_t cap, uint8_t service)
{
    if (cap < 4) {
        return 0;
    }
    resp[0] = (uint8_t)(service | CIP_SVC_REPLY);
    resp[1] = 0;
    resp[2] = CIP_STATUS_SUCCESS;
    resp[3] = 0;
    return 4;
}

uint16_t eip_identity_status(const eip_stack_t *s)
{
    uint16_t st;

    if (!s) {
        return 0;
    }
    /* Owned (bit 0) when an Exclusive Owner Class 1 connection is up.
     * Configured (bit 2) is a separate "settings differ from out-of-box"
     * flag and is not used as a stand-in for ownership. ACD raises Minor
     * Recoverable Fault (bit 8). State value 2 is Standby, not that fault. */
    st = eip_stack_class1_up(s) ? 0x0001u : 0x0000u;
    if (s->acd_conflict) {
        st = (uint16_t)(st | 0x0100u);
    }
    return st;
}

uint8_t eip_identity_state(const eip_stack_t *s)
{
    if (!s) {
        return 0;
    }
    return s->device_state ? s->device_state : 3;
}

static int identity_get_attr(eip_stack_t *s, uint16_t attr, uint8_t *out,
                             size_t cap, size_t *out_len)
{
    const eip_cfg_t *c = &s->cfg;
    switch (attr) {
    case 1: /* Vendor ID */
        if (cap < 2) {
            return -ENOSPC;
        }
        eip_wr_le16(out, c->vendor_id);
        *out_len = 2;
        return 0;
    case 2: /* Device Type */
        if (cap < 2) {
            return -ENOSPC;
        }
        eip_wr_le16(out, c->device_type);
        *out_len = 2;
        return 0;
    case 3: /* Product Code */
        if (cap < 2) {
            return -ENOSPC;
        }
        eip_wr_le16(out, c->product_code);
        *out_len = 2;
        return 0;
    case 4: /* Revision */
        if (cap < 2) {
            return -ENOSPC;
        }
        out[0] = c->major_rev;
        out[1] = c->minor_rev;
        *out_len = 2;
        return 0;
    case 5: /* Status */
        if (cap < 2) {
            return -ENOSPC;
        }
        eip_wr_le16(out, eip_identity_status(s));
        *out_len = 2;
        return 0;
    case 6: /* Serial Number */
        if (cap < 4) {
            return -ENOSPC;
        }
        eip_wr_le32(out, c->serial_number);
        *out_len = 4;
        return 0;
    case 7: { /* Product Name SHORT_STRING */
        size_t n = strlen(c->product_name);
        if (n > 32) {
            n = 32;
        }
        if (cap < 1 + n) {
            return -ENOSPC;
        }
        out[0] = (uint8_t)n;
        memcpy(out + 1, c->product_name, n);
        *out_len = 1 + n;
        return 0;
    }
    case 8: /* State */
        if (cap < 1) {
            return -ENOSPC;
        }
        out[0] = eip_identity_state(s);
        *out_len = 1;
        return 0;
    case 9: /* Configuration Consistency Value */
        if (cap < 2) {
            return -ENOSPC;
        }
        eip_wr_le16(out, s->config_consistency);
        *out_len = 2;
        return 0;
    case 10: /* Heartbeat Interval */
        if (cap < 1) {
            return -ENOSPC;
        }
        out[0] = 0;
        *out_len = 1;
        return 0;
    default:
        /* Attr 17 is Geographic_Location, not Protection Mode. The
         * Protection Mode attribute number is unconfirmed, so it is not
         * exposed. protection_mode remains an internal Set/Reset gate. */
        return -ENOTSUP;
    }
}

static int identity_get_attr_all(eip_stack_t *s, uint8_t *out, size_t cap,
                                 size_t *out_len)
{
    size_t used = 0;
    size_t piece = 0;
    uint8_t tmp[64];
    for (uint16_t attr = 1; attr <= 10; attr++) {
        piece = 0;
        if (identity_get_attr(s, attr, tmp, sizeof(tmp), &piece) != 0) {
            continue;
        }
        if (used + piece > cap) {
            return -ENOSPC;
        }
        memcpy(out + used, tmp, piece);
        used += piece;
    }
    *out_len = used;
    return 0;
}

static int assembly_get_attr(eip_stack_t *s, uint16_t instance, uint16_t attr,
                             uint8_t *out, size_t cap, size_t *out_len)
{
    eip_assembly_t *a = eip_assembly_find(s, instance);
    if (!a) {
        return -ENOENT;
    }
    if (attr == 3) { /* data */
        if (cap < a->size) {
            return -ENOSPC;
        }
        memcpy(out, a->data, a->size);
        *out_len = a->size;
        return 0;
    }
    if (attr == 4) { /* size */
        if (cap < 2) {
            return -ENOSPC;
        }
        eip_wr_le16(out, a->size);
        *out_len = 2;
        return 0;
    }
    return -ENOTSUP;
}

static int assembly_set_attr(eip_stack_t *s, uint16_t instance, uint16_t attr,
                             const uint8_t *data, size_t len)
{
    if (attr != 3) {
        return -ENOTSUP;
    }
    return eip_assembly_write(s, instance, data, len);
}

static int cip_is_set_or_reset(uint8_t service)
{
    return service == CIP_SVC_SET_ATTR_SINGLE || service == CIP_SVC_RESET;
}

/* Identity Reset, QoS/LLDP writes, Assembly Set, … */
static int gate_set_reset(eip_stack_t *s, unsigned auth, uint8_t service,
                          uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    if (!cip_is_set_or_reset(service)) {
        return 0;
    }
    if (!(auth & EIP_CIP_AUTH_SESSION)) {
        LOG_WARN("ethernetip", "CIP Set/Reset without owned session — 거부");
        *resp_len = cip_error(resp, resp_cap, service, CIP_STATUS_PRIVILEGE, 0);
        return -1;
    }
    if (eip_sec_required(s) && !(auth & EIP_CIP_AUTH_SECURE)) {
        LOG_WARN("ethernetip",
                 "%s: CIP Set/Reset without authenticated channel (security_class=%d)",
                 EIP_OWN_SECURITY_PROFILE, s->cfg.security_class);
        *resp_len = cip_error(resp, resp_cap, service, CIP_STATUS_PRIVILEGE, 0);
        return -1;
    }
    if (s->cfg.protection_mode != 0) {
        LOG_WARN("ethernetip",
                 "CIP Set/Reset rejected: protection_mode=0x%x",
                 s->cfg.protection_mode);
        *resp_len = cip_error(resp, resp_cap, service, CIP_STATUS_PRIVILEGE, 0);
        return -1;
    }
    return 0;
}

/* Class object (instance 0) attribute 1 is Revision. Returns 1 if handled. */
static int class_revision(uint8_t service, uint16_t attribute, uint16_t revision,
                          uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    if (service == CIP_SVC_GET_ATTR_SINGLE) {
        if (attribute != 1) {
            *resp_len =
                cip_error(resp, resp_cap, service, CIP_STATUS_ATTR_NSUP, 0);
            return 1;
        }
        size_t hdr = cip_ok_header(resp, resp_cap, service);
        if (resp_cap < hdr + 2) {
            *resp_len =
                cip_error(resp, resp_cap, service, CIP_STATUS_RESOURCE, 0);
            return 1;
        }
        eip_wr_le16(resp + hdr, revision);
        *resp_len = hdr + 2;
        return 1;
    }
    if (service == CIP_SVC_SET_ATTR_SINGLE) {
        uint8_t st = (attribute == 1) ? CIP_STATUS_NOT_SETTABLE
                                      : CIP_STATUS_ATTR_NSUP;
        *resp_len = cip_error(resp, resp_cap, service, st, 0);
        return 1;
    }
    return 0;
}

static int handle_object(eip_stack_t *s, unsigned auth, uint8_t service,
                         uint16_t class_id, uint16_t instance,
                         uint16_t attribute, const uint8_t *data,
                         size_t data_len, uint8_t *resp, size_t resp_cap,
                         size_t *resp_len)
{
    if (gate_set_reset(s, auth, service, resp, resp_cap, resp_len) != 0) {
        return 0;
    }

    if (class_id == CIP_CLASS_CONN_MANAGER && instance == 1) {
        if (service == CIP_SVC_FORWARD_OPEN) {
            return eip_cm_forward_open(s, data, data_len, 0, resp, resp_cap,
                                       resp_len);
        }
        if (service == CIP_SVC_LARGE_FORWARD_OPEN) {
            return eip_cm_forward_open(s, data, data_len, 1, resp, resp_cap,
                                       resp_len);
        }
        if (service == CIP_SVC_FORWARD_CLOSE) {
            return eip_cm_forward_close(s, data, data_len, resp, resp_cap,
                                        resp_len);
        }
        *resp_len = cip_error(resp, resp_cap, service, CIP_STATUS_SERVICE_NSUP, 0);
        return 0;
    }

    if (class_id == CIP_CLASS_IDENTITY && instance == 0) {
        if (class_revision(service, attribute, 1, resp, resp_cap, resp_len)) {
            return 0;
        }
    }

    if (class_id == CIP_CLASS_IDENTITY && instance == 1) {
        if (service == CIP_SVC_GET_ATTR_SINGLE) {
            size_t hdr = cip_ok_header(resp, resp_cap, service);
            size_t n = 0;
            int rc = identity_get_attr(s, attribute, resp + hdr,
                                       resp_cap - hdr, &n);
            if (rc == -ENOTSUP) {
                *resp_len =
                    cip_error(resp, resp_cap, service, CIP_STATUS_ATTR_NSUP, 0);
                return 0;
            }
            if (rc != 0) {
                *resp_len =
                    cip_error(resp, resp_cap, service, CIP_STATUS_RESOURCE, 0);
                return 0;
            }
            *resp_len = hdr + n;
            return 0;
        }
        if (service == CIP_SVC_GET_ATTR_ALL) {
            size_t hdr = cip_ok_header(resp, resp_cap, service);
            size_t n = 0;
            if (identity_get_attr_all(s, resp + hdr, resp_cap - hdr, &n) != 0) {
                *resp_len =
                    cip_error(resp, resp_cap, service, CIP_STATUS_RESOURCE, 0);
                return 0;
            }
            *resp_len = hdr + n;
            return 0;
        }
        if (service == CIP_SVC_RESET) {
            /* Parameter is one USINT. Omitted means type 0 (power-cycle
             * emulation): clear the I/O image and Class 1 connections.
             * The success reply is filled before that runs. Types 1 and 2
             * need a factory-default store this stack does not have, so
             * they are rejected with 0x20 along with every other
             * unsupported type. */
            uint8_t rtype = 0;
            if (data_len > 0 && data) {
                rtype = data[0];
            }
            if (rtype != 0) {
                LOG_WARN("ethernetip",
                         "Identity Reset type %u is not supported", rtype);
                *resp_len = cip_error(resp, resp_cap, service,
                                      CIP_STATUS_INVALID_PARAM, 0);
                return 0;
            }
            *resp_len = cip_ok_header(resp, resp_cap, service);
            if (*resp_len == 0) {
                return 0;
            }
            if (s->input_data && s->input_size > 0) {
                memset(s->input_data, 0, s->input_size);
            }
            if (s->output_data && s->output_size > 0) {
                memset(s->output_data, 0, s->output_size);
            }
            for (int i = 0; i < EIP_CLASS1_CONN_MAX; i++) {
                s->class1[i].in_use = 0;
            }
            s->config_consistency++;
            return 0;
        }
        if (service == CIP_SVC_SET_ATTR_SINGLE) {
            /* Instance attributes 1..10 are defined and read-only.
             * Attr 17 is Geographic_Location and is not implemented. */
            uint8_t st = (attribute >= 1 && attribute <= 10)
                             ? CIP_STATUS_NOT_SETTABLE
                             : CIP_STATUS_ATTR_NSUP;
            *resp_len = cip_error(resp, resp_cap, service, st, 0);
            return 0;
        }
    }

    if (class_id == CIP_CLASS_MSG_ROUTER && instance == 1 &&
        service == CIP_SVC_GET_ATTR_SINGLE) {
        size_t hdr = cip_ok_header(resp, resp_cap, service);
        if (attribute == 1 && resp_cap >= hdr + 2) { /* object list count stub */
            eip_wr_le16(resp + hdr, 8);
            *resp_len = hdr + 2;
            return 0;
        }
        *resp_len = cip_error(resp, resp_cap, service, CIP_STATUS_ATTR_NSUP, 0);
        return 0;
    }

    if (class_id == CIP_CLASS_ASSEMBLY) {
        if (service == CIP_SVC_GET_ATTR_SINGLE) {
            size_t hdr = cip_ok_header(resp, resp_cap, service);
            size_t n = 0;
            int rc = assembly_get_attr(s, instance, attribute, resp + hdr,
                                       resp_cap - hdr, &n);
            if (rc == -ENOENT) {
                *resp_len =
                    cip_error(resp, resp_cap, service, CIP_STATUS_PATH_DEST, 0);
                return 0;
            }
            if (rc == -ENOTSUP) {
                *resp_len =
                    cip_error(resp, resp_cap, service, CIP_STATUS_ATTR_NSUP, 0);
                return 0;
            }
            if (rc != 0) {
                *resp_len =
                    cip_error(resp, resp_cap, service, CIP_STATUS_RESOURCE, 0);
                return 0;
            }
            *resp_len = hdr + n;
            return 0;
        }
        if (service == CIP_SVC_SET_ATTR_SINGLE) {
            int rc = assembly_set_attr(s, instance, attribute, data, data_len);
            if (rc == -ENOENT) {
                *resp_len =
                    cip_error(resp, resp_cap, service, CIP_STATUS_PATH_DEST, 0);
                return 0;
            }
            if (rc != 0) {
                *resp_len = cip_error(resp, resp_cap, service,
                                      CIP_STATUS_INVALID_PARAM, 0);
                return 0;
            }
            *resp_len = cip_ok_header(resp, resp_cap, service);
            return 0;
        }
    }

    /* TCP/IP Interface Object — CT-facing attributes + ACD */
    if (class_id == CIP_CLASS_TCPIP && instance == 1 &&
        service == CIP_SVC_GET_ATTR_SINGLE) {
        size_t hdr = cip_ok_header(resp, resp_cap, service);
        if (attribute == 1 && resp_cap >= hdr + 4) {
            uint32_t st = 0x00000001; /* config valid */
            if (s->acd_conflict) {
                st |= 0x00000040; /* ACD status bit — conflict detected */
            }
            eip_wr_le32(resp + hdr, st);
            *resp_len = hdr + 4;
            return 0;
        }
        if (attribute == 2 && resp_cap >= hdr + 4) {
            /* bit 4 configuration settable, bit 7 ACD capable.
             * bit 2 is DHCP client and is not how ACD is advertised. */
            uint32_t capb = 0x00000010u;
            if (s->cfg.acd_enable) {
                capb |= 0x00000080u;
            }
            eip_wr_le32(resp + hdr, capb);
            *resp_len = hdr + 4;
            return 0;
        }
        if (attribute == 3 && resp_cap >= hdr + 4) {
            eip_wr_le32(resp + hdr, 0);
            *resp_len = hdr + 4;
            return 0;
        }
        if (attribute == 4 && resp_cap >= hdr + 2) {
            eip_wr_le16(resp + hdr, 0);
            *resp_len = hdr + 2;
            return 0;
        }
        if (attribute == 5) {
            /* Interface Configuration: 5×UDINT + domain STRING.
             * IP is the bind address (or the interface that received the
             * encapsulation request). Mask, gateway, and DNS are not read
             * from the host; loopback uses 255.0.0.0. Domain is empty. */
            uint32_t ip = s->bind_ip_host;
            uint32_t mask = 0;
            if (ip == 0 || ip == 0xffffffffu) {
                ip = s->encap_local_ip;
            }
            if (ip == 0xffffffffu) {
                ip = 0;
            }
            if ((ip & 0xff000000u) == 0x7f000000u) {
                mask = 0xff000000u;
            }
            if (resp_cap < hdr + 22) {
                *resp_len =
                    cip_error(resp, resp_cap, service, CIP_STATUS_RESOURCE, 0);
                return 0;
            }
            eip_wr_le32(resp + hdr + 0, ip);
            eip_wr_le32(resp + hdr + 4, mask);
            eip_wr_le32(resp + hdr + 8, 0);
            eip_wr_le32(resp + hdr + 12, 0);
            eip_wr_le32(resp + hdr + 16, 0);
            eip_wr_le16(resp + hdr + 20, 0);
            *resp_len = hdr + 22;
            return 0;
        }
        if (attribute == 10 && resp_cap >= hdr + 1) { /* Select ACD, BOOL */
            resp[hdr] = s->cfg.acd_enable ? 1 : 0;
            *resp_len = hdr + 1;
            return 0;
        }
        if (attribute == 11 && resp_cap >= hdr + 35) {
            /* Last Conflict Detected: USINT activity + MAC[6] + ARP PDU[28].
             * No ARP watcher is wired, so the record stays zero. */
            memset(resp + hdr, 0, 35);
            *resp_len = hdr + 35;
            return 0;
        }
        if (attribute == 13 && resp_cap >= hdr + 2) {
            uint32_t sec = 0;
            if (s->cfg.idle_timeout_ms > 0) {
                sec = (uint32_t)s->cfg.idle_timeout_ms / 1000u;
            }
            if (sec > 65535u) {
                sec = 65535u;
            }
            eip_wr_le16(resp + hdr, (uint16_t)sec);
            *resp_len = hdr + 2;
            return 0;
        }
        *resp_len = cip_error(resp, resp_cap, service, CIP_STATUS_ATTR_NSUP, 0);
        return 0;
    }

    if (class_id == CIP_CLASS_ETHERNET_LINK && instance == 1 &&
        service == CIP_SVC_GET_ATTR_SINGLE) {
        size_t hdr = cip_ok_header(resp, resp_cap, service);
        if (attribute == 1 && resp_cap >= hdr + 4) {
            eip_wr_le32(resp + hdr, 100);
            *resp_len = hdr + 4;
            return 0;
        }
        if (attribute == 2 && resp_cap >= hdr + 4) {
            eip_wr_le32(resp + hdr, 0xF);
            *resp_len = hdr + 4;
            return 0;
        }
        if (attribute == 3 && resp_cap >= hdr + 6) {
            memset(resp + hdr, 0x02, 6);
            *resp_len = hdr + 6;
            return 0;
        }
        *resp_len = cip_error(resp, resp_cap, service, CIP_STATUS_ATTR_NSUP, 0);
        return 0;
    }

    /* QoS Object — Vol 2 attribute numbers, not the old 1..5 DSCP shift. */
    if (class_id == CIP_CLASS_QOS && instance == 1) {
        uint8_t *slot = NULL;
        switch (attribute) {
        case 1:
            slot = &s->qos_8021q_enable;
            break;
        case 2:
            slot = &s->dscp_ptp_event;
            break;
        case 3:
            slot = &s->dscp_ptp_general;
            break;
        case 4:
            slot = &s->dscp_urgent;
            break;
        case 5:
            slot = &s->dscp_scheduled;
            break;
        case 6:
            slot = &s->dscp_high;
            break;
        case 7:
            slot = &s->dscp_low;
            break;
        case 8:
            slot = &s->dscp_explicit;
            break;
        default:
            break;
        }
        if (service == CIP_SVC_GET_ATTR_SINGLE) {
            size_t hdr = cip_ok_header(resp, resp_cap, service);
            if (!slot) {
                *resp_len =
                    cip_error(resp, resp_cap, service, CIP_STATUS_ATTR_NSUP, 0);
                return 0;
            }
            if (resp_cap < hdr + 1) {
                *resp_len =
                    cip_error(resp, resp_cap, service, CIP_STATUS_RESOURCE, 0);
                return 0;
            }
            resp[hdr] = *slot;
            *resp_len = hdr + 1;
            return 0;
        }
        if (service == CIP_SVC_SET_ATTR_SINGLE && data_len >= 1) {
            if (!slot) {
                *resp_len =
                    cip_error(resp, resp_cap, service, CIP_STATUS_ATTR_NSUP, 0);
                return 0;
            }
            *slot = data[0];
            eip_stack_apply_qos(s);
            *resp_len = cip_ok_header(resp, resp_cap, service);
            return 0;
        }
    }

    /* Port Object */
    if (class_id == CIP_CLASS_PORT && instance == 1 &&
        service == CIP_SVC_GET_ATTR_SINGLE) {
        size_t hdr = cip_ok_header(resp, resp_cap, service);
        if (attribute == 1 && resp_cap >= hdr + 2) {
            eip_wr_le16(resp + hdr, 4); /* TCP/IP port */
            *resp_len = hdr + 2;
            return 0;
        }
        if (attribute == 2 && resp_cap >= hdr + 2) {
            eip_wr_le16(resp + hdr, 1);
            *resp_len = hdr + 2;
            return 0;
        }
        *resp_len = cip_error(resp, resp_cap, service, CIP_STATUS_ATTR_NSUP, 0);
        return 0;
    }

    /* Class 0x5E attributes are the repository profile, not ODVA CIP Security. */
    if (class_id == CIP_CLASS_EIP_SECURITY && instance == 1 &&
        service == CIP_SVC_GET_ATTR_SINGLE) {
        size_t hdr = cip_ok_header(resp, resp_cap, service);
        if (attribute == 1 && resp_cap >= hdr + 2) {
            eip_wr_le16(resp + hdr, (uint16_t)s->cfg.security_class);
            *resp_len = hdr + 2;
            return 0;
        }
        if (attribute == 2 && resp_cap >= hdr + 4) {
            uint32_t caps = 0;
            if (s->cfg.security_class >= EIP_SECURITY_CLASS_1) {
                caps |= 0x1;
            }
            if (s->cfg.security_class >= EIP_SECURITY_CLASS_2) {
                caps |= 0x2;
            }
            eip_wr_le32(resp + hdr, caps);
            *resp_len = hdr + 4;
            return 0;
        }
        if (attribute == 3 && resp_cap >= hdr + 2) {
            eip_wr_le16(resp + hdr, (uint16_t)s->cfg.secure_tcp_port);
            *resp_len = hdr + 2;
            return 0;
        }
        *resp_len = cip_error(resp, resp_cap, service, CIP_STATUS_ATTR_NSUP, 0);
        return 0;
    }

    /* LLDP Management Object (0x109) — TX required for first-time cert */
    if (class_id == CIP_CLASS_LLDP_MGMT && instance == 1) {
        if (service == CIP_SVC_GET_ATTR_SINGLE) {
            size_t hdr = cip_ok_header(resp, resp_cap, service);
            if (attribute == 1 && resp_cap >= hdr + 4) {
                eip_wr_le32(resp + hdr, s->lldp_enable_flags);
                *resp_len = hdr + 4;
                return 0;
            }
            if (attribute == 2 && resp_cap >= hdr + 2) {
                eip_wr_le16(resp + hdr, s->lldp_tx_interval_sec);
                *resp_len = hdr + 2;
                return 0;
            }
            if (attribute == 3 && resp_cap >= hdr + 2) {
                eip_wr_le16(resp + hdr, s->lldp_tx_hold);
                *resp_len = hdr + 2;
                return 0;
            }
            if (attribute == 5 && resp_cap >= hdr + 4) {
                /* Last Change = sysUpTime at last datastore/TX change.
                 * TX-only: we do not expose Data Store (attr 4). */
                eip_wr_le32(resp + hdr, s->lldp_last_change_sec);
                *resp_len = hdr + 4;
                return 0;
            }
            *resp_len =
                cip_error(resp, resp_cap, service, CIP_STATUS_ATTR_NSUP, 0);
            return 0;
        }
        if (service == CIP_SVC_SET_ATTR_SINGLE) {
            if (attribute == 1 && data_len >= 4) {
                uint32_t v = eip_rd_le32(data);
                /* Clearing global enable shall wipe TX cache (802.1AB align) */
                if ((s->lldp_enable_flags & 1) && !(v & 1)) {
                    s->lldp_last_frame_len = 0;
                    s->lldp_last_change_sec = s->lldp_sys_uptime_sec;
                }
                s->lldp_enable_flags = v;
                *resp_len = cip_ok_header(resp, resp_cap, service);
                return 0;
            }
            if (attribute == 2 && data_len >= 2) {
                uint16_t v = eip_rd_le16(data);
                if (v < 1) {
                    v = 1;
                }
                s->lldp_tx_interval_sec = v;
                *resp_len = cip_ok_header(resp, resp_cap, service);
                return 0;
            }
            if (attribute == 3 && data_len >= 2) {
                s->lldp_tx_hold = eip_rd_le16(data);
                *resp_len = cip_ok_header(resp, resp_cap, service);
                return 0;
            }
            *resp_len =
                cip_error(resp, resp_cap, service, CIP_STATUS_ATTR_NSUP, 0);
            return 0;
        }
    }

    /* LLDP Data Table — not implemented (TX-only / no reception) */
    if (class_id == CIP_CLASS_LLDP_DATA_TABLE) {
        *resp_len = cip_error(resp, resp_cap, service, CIP_STATUS_PATH_DEST, 0);
        return 0;
    }

    *resp_len = cip_error(resp, resp_cap, service, CIP_STATUS_PATH_DEST, 0);
    return 0;
}

int eip_cip_route_auth(eip_stack_t *s, unsigned auth, const uint8_t *req,
                       size_t req_len, uint8_t *resp, size_t resp_cap,
                       size_t *resp_len)
{
    if (!req || req_len < 2 || !resp || !resp_len) {
        return -EINVAL;
    }
    uint8_t service = req[0];
    uint8_t path_words = req[1];
    size_t path_bytes = (size_t)path_words * 2u;
    if (req_len < 2 + path_bytes) {
        *resp_len =
            cip_error(resp, resp_cap, service, CIP_STATUS_PATH_SEGMENT, 0);
        return 0;
    }

    uint16_t class_id = 0, instance = 0, attribute = 0;
    char tag[EIP_TAG_NAME_MAX];
    if (eip_path_parse(req + 2, path_bytes, &class_id, &instance, &attribute,
                       tag, sizeof(tag)) != 0) {
        *resp_len =
            cip_error(resp, resp_cap, service, CIP_STATUS_PATH_SEGMENT, 0);
        return 0;
    }

    const uint8_t *data = req + 2 + path_bytes;
    size_t data_len = req_len - (2 + path_bytes);

    /* Symbolic tag path without class: map onto input assembly attr 3 for
     * adapter diagnostics / simple UCMM writes from scanners that use tags.
     * Full Logix symbolic object model is out of scope; assembly mapping is
     * the scalable sensor path. */
    if (tag[0] && class_id == 0) {
        class_id = CIP_CLASS_ASSEMBLY;
        instance = s->cfg.input_assembly;
        if (attribute == 0) {
            attribute = 3;
        }
    }

    return handle_object(s, auth, service, class_id, instance, attribute, data,
                         data_len, resp, resp_cap, resp_len);
}

int eip_cip_route(eip_stack_t *s, const uint8_t *req, size_t req_len,
                  uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    return eip_cip_route_auth(s, 0, req, req_len, resp, resp_cap, resp_len);
}
