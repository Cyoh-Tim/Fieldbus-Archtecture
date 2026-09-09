#include "eip_endian.h"
#include "eip_internal.h"

#include <errno.h>
#include <string.h>

#include "logger.h"

int eip_io_handle_udp(eip_stack_t *s, const uint8_t *frame, size_t len,
                      uint32_t src_ip, uint16_t src_port)
{
    if (len < 2) {
        return -EINVAL;
    }
    uint16_t items = eip_rd_le16(frame);
    size_t off = 2;
    uint32_t conn_id = 0;
    uint32_t seq = 0;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;

    for (uint16_t i = 0; i < items; i++) {
        if (off + 4 > len) {
            return -EINVAL;
        }
        uint16_t type = eip_rd_le16(frame + off);
        uint16_t length = eip_rd_le16(frame + off + 2);
        off += 4;
        if (off + length > len) {
            return -EINVAL;
        }
        if (type == EIP_ITEM_SEQ_ADDR && length >= 8) {
            conn_id = eip_rd_le32(frame + off);
            seq = eip_rd_le32(frame + off + 4);
        } else if (type == EIP_ITEM_CONNECTED_DATA) {
            payload = frame + off;
            payload_len = length;
        }
        off += length;
    }

    if (!payload) {
        return -EINVAL;
    }

    eip_class1_conn_t *c = NULL;
    for (int i = 0; i < EIP_CLASS1_CONN_MAX; i++) {
        if (s->class1[i].in_use && s->class1[i].o2t_conn_id == conn_id) {
            c = &s->class1[i];
            break;
        }
    }
    if (!c) {
        return -ENOENT;
    }

    c->peer_ip = src_ip;
    c->peer_udp_port = src_port;
    c->o2t_seq = seq;
    c->last_rx_ns = eip_now_ns();

    const uint8_t *data = payload;
    size_t dlen = payload_len;
    if (dlen >= 2) {
        data += 2;
        dlen -= 2;
    }
    if (s->output_data && dlen > 0) {
        size_t n = dlen;
        if (n > s->output_size) {
            n = s->output_size;
        }
        memcpy(s->output_data, data, n);
    }
    return 0;
}

void eip_io_watchdog(eip_stack_t *s)
{
    uint64_t now = eip_now_ns();
    for (int i = 0; i < EIP_CLASS1_CONN_MAX; i++) {
        eip_class1_conn_t *c = &s->class1[i];
        if (!c->in_use) {
            continue;
        }
        uint32_t wd = c->watchdog_us;
        if (wd == 0) {
            uint32_t rpi = c->o2t_rpi_us ? c->o2t_rpi_us : s->cfg.rpi_us;
            wd = eip_class1_watchdog_us(rpi, c->timeout_multiplier);
            c->watchdog_us = wd;
        }
        /* Only arm after first O->T so FO without IO yet is not killed */
        if (c->last_rx_ns == 0 || c->peer_udp_port == 0) {
            continue;
        }
        if (now - c->last_rx_ns > (uint64_t)wd * 1000ull) {
            LOG_WARN("ethernetip",
                     "Class1 watchdog: conn_id O->T=%u timed out after %uus",
                     c->o2t_conn_id, wd);
            c->in_use = 0;
            s->class1_timeouts++;
        }
    }
}

void eip_io_produce(eip_stack_t *s)
{
    uint64_t now = eip_now_ns();
    for (int i = 0; i < EIP_CLASS1_CONN_MAX; i++) {
        eip_class1_conn_t *c = &s->class1[i];
        if (!c->in_use || c->peer_udp_port == 0) {
            continue;
        }
        uint32_t rpi = c->t2o_rpi_us ? c->t2o_rpi_us : s->cfg.rpi_us;
        if (rpi == 0) {
            rpi = 8000;
        }
        uint64_t period_ns = (uint64_t)rpi * 1000ull;
        /* last_tx_ns = next due (0 = due immediately). Keep RPI phase. */
        if (c->last_tx_ns != 0 && now < c->last_tx_ns) {
            continue;
        }

        uint8_t *frame = c->last_produce;
        size_t cap = sizeof(c->last_produce);
        size_t need = 20u + (size_t)s->input_size;
        if (need > cap) {
            LOG_ERROR("ethernetip",
                      "Class1 produce overflow need=%zu cap=%zu input=%u",
                      need, cap, s->input_size);
            continue;
        }
        size_t off = 0;
        eip_wr_le16(frame + off, 2);
        off += 2;
        eip_wr_le16(frame + off, EIP_ITEM_SEQ_ADDR);
        off += 2;
        eip_wr_le16(frame + off, 8);
        off += 2;
        eip_wr_le32(frame + off, c->t2o_conn_id);
        off += 4;
        eip_wr_le32(frame + off, ++c->t2o_seq);
        off += 4;

        uint16_t data_len = (uint16_t)(2 + s->input_size);
        eip_wr_le16(frame + off, EIP_ITEM_CONNECTED_DATA);
        off += 2;
        eip_wr_le16(frame + off, data_len);
        off += 2;
        eip_wr_le16(frame + off, (uint16_t)(c->t2o_seq & 0xffff));
        off += 2;
        if (s->input_data && s->input_size) {
            if (off + s->input_size > cap) {
                LOG_ERROR("ethernetip", "Class1 produce truncated");
                continue;
            }
            memcpy(frame + off, s->input_data, s->input_size);
            off += s->input_size;
        }

        c->last_produce_len = off;
        c->produce_ready = 1;
        if (c->last_tx_ns == 0) {
            c->last_tx_ns = now + period_ns;
        } else {
            c->last_tx_ns += period_ns;
            if (c->last_tx_ns <= now) {
                c->last_tx_ns = now + period_ns;
            }
        }

        if (s->tops_set && s->tops.udp_send) {
            uint32_t be = ((c->peer_ip >> 24) & 0xff) |
                          ((c->peer_ip >> 8) & 0xff00) |
                          ((c->peer_ip << 8) & 0xff0000) |
                          ((c->peer_ip << 24) & 0xff000000);
            s->tops.udp_send(s->tops.ctx, frame, off, be, c->peer_udp_port);
            c->produce_ready = 0;
        }
    }
}
