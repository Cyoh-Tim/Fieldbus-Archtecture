#ifndef EIP_SEC_H
#define EIP_SEC_H

#include <stddef.h>
#include <stdint.h>

#include "eip_types.h"

struct eip_stack;

/*
 * Fieldbus EIP Security profiles (repository profiles — not a claim of
 * completed ODVA Declaration of Conformity by themselves).
 *
 * 0 = open / lab
 * 1 = Integrity (HMAC-SHA256 PSK on mutating UCMM / Forward Open)
 * 2 = Confidentiality path: Integrity + TLS listener on secure port 2221
 *     (CIP Security–oriented transport; full CT still needs ODVA lab)
 */

#define EIP_SEC_ITEM_INTEGRITY  0x00C1 /* CPF vendor-profile integrity item */

int eip_sec_required(const struct eip_stack *s);
int eip_sec_confidentiality(const struct eip_stack *s);

/* Verify optional trailing integrity CPF item / HMAC over CIP bytes. */
int eip_sec_check_ucmm(struct eip_stack *s, uint32_t session,
                       const uint8_t *cip, size_t cip_len,
                       const uint8_t *mac_item, size_t mac_len);

/* Append integrity CPF item (type + len + mac) into buffer; returns bytes. */
size_t eip_sec_append_mac_item(struct eip_stack *s, uint32_t session,
                               const uint8_t *cip, size_t cip_len, uint8_t *out,
                               size_t cap);

int eip_sec_service_needs_mac(uint8_t service);

/* TLS (security_class >= 2) */
int eip_sec_tls_start(struct eip_stack *s);
void eip_sec_tls_stop(struct eip_stack *s);
void eip_sec_tls_poll(struct eip_stack *s);

#endif /* EIP_SEC_H */
