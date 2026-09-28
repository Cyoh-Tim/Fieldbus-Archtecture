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
        {
            uint16_t st = eip_stack_class1_up(s) ? 0x0004 : 0x0000;
            if (s->acd_conflict) {
                st |= 0x0100; /* minor recoverable fault (ACD) */
            }
            eip_wr_le16(out, st);
        }
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
        if (s->acd_conflict) {
            out[0] = 2; /* Minor Recoverable Fault — CT23 ACD guidance */
        } else {
            out[0] = s->device_state ? s->device_state : 3; /* operational */
        }
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
    case 17: /* Protection Mode */
        if (cap < 4) {
            return -ENOSPC;
        }
        eip_wr_le32(out, c->protection_mode);
        *out_len = 4;
        return 0;
    default:
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
    /* Attr 17 Protection Mode */
    piece = 0;
    if (identity_get_attr(s, 17, tmp, sizeof(tmp), &piece) == 0) {
        if (used + piece <= cap) {
            memcpy(out + used, tmp, piece);
            used += piece;
        }
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

/* Identity Reset, Identity attr 17, QoS/LLDP writes, Assembly Set, … */
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
                 "CIP Set/Reset without authenticated channel (sec class %d)",
                 s->cfg.security_class);
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
            /* Type 0 = power-cycle equivalent soft reset of IO image */
            memset(s->input_data, 0, s->input_size);
            memset(s->output_data, 0, s->output_size);
            for (int i = 0; i < EIP_CLASS1_CONN_MAX; i++) {
                s->class1[i].in_use = 0;
            }
            s->config_consistency++;
            *resp_len = cip_ok_header(resp, resp_cap, service);
            return 0;
        }
        if (service == CIP_SVC_SET_ATTR_SINGLE && attribute == 17) {
            if (data_len < 4) {
                *resp_len = cip_error(resp, resp_cap, service,
                                      CIP_STATUS_INVALID_PARAM, 0);
                return 0;
            }
            s->cfg.protection_mode = eip_rd_le32(data);
            *resp_len = cip_ok_header(resp, resp_cap, service);
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
            eip_wr_le32(resp + hdr, 0x00000010 | (s->cfg.acd_enable ? 0x4 : 0));
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
        if (attribute == 10 && resp_cap >= hdr + 4) { /* ACD Status */
            eip_wr_le32(resp + hdr, s->acd_conflict ? 1u : 0u);
            *resp_len = hdr + 4;
            return 0;
        }
        if (attribute == 11 && resp_cap >= hdr + 4) { /* ACD Activity */
            eip_wr_le32(resp + hdr, s->acd_activity);
            *resp_len = hdr + 4;
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

    /* QoS Object — DSCP defaults used by CT manuals */
    if (class_id == CIP_CLASS_QOS && instance == 1) {
        if (service == CIP_SVC_GET_ATTR_SINGLE) {
            size_t hdr = cip_ok_header(resp, resp_cap, service);
            if (resp_cap < hdr + 1) {
                *resp_len =
                    cip_error(resp, resp_cap, service, CIP_STATUS_RESOURCE, 0);
                return 0;
            }
            uint8_t v = 0;
            switch (attribute) {
            case 1: /* DSCP Urgent */
                v = s->dscp_urgent;
                break;
            case 2: /* DSCP Scheduled */
                v = s->dscp_scheduled;
                break;
            case 3: /* DSCP High */
                v = s->dscp_high;
                break;
            case 4: /* DSCP Low */
                v = s->dscp_low;
                break;
            case 5: /* DSCP Explicit */
                v = s->dscp_explicit;
                break;
            default:
                *resp_len =
                    cip_error(resp, resp_cap, service, CIP_STATUS_ATTR_NSUP, 0);
                return 0;
            }
            resp[hdr] = v;
            *resp_len = hdr + 1;
            return 0;
        }
        if (service == CIP_SVC_SET_ATTR_SINGLE && data_len >= 1) {
            switch (attribute) {
            case 1:
                s->dscp_urgent = data[0];
                break;
            case 2:
                s->dscp_scheduled = data[0];
                break;
            case 3:
                s->dscp_high = data[0];
                break;
            case 4:
                s->dscp_low = data[0];
                break;
            case 5:
                s->dscp_explicit = data[0];
                break;
            default:
                *resp_len =
                    cip_error(resp, resp_cap, service, CIP_STATUS_ATTR_NSUP, 0);
                return 0;
            }
            *resp_len = cip_ok_header(resp, resp_cap, service);
            return 0;
        }
    }

    /* Port Object */
    if (class_id == CIP_CLASS_PORT && instance == 1 &&
        service == CIP_SVC_GET_ATTR_SINGLE) {
        size_t hdr = cip_ok_header(resp, resp_cap, service);
        if (attribute == 1 && resp_cap >= hdr + 2) {
            eip_wr_le16(resp + hdr, 0);
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

    /* EtherNet/IP Security Object — advertise profile capabilities */
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
