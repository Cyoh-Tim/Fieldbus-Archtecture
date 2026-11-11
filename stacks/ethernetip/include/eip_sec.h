#ifndef EIP_SEC_H
#define EIP_SEC_H

#include <stddef.h>
#include <stdint.h>

#include "eip_types.h"

struct eip_stack;

/*
 * 자체 보안 프로파일 (HMAC 무결성 / TLS-PSK, ODVA CIP Security 아님, 인증 주장 아님).
 *
 * security_class (config key, unchanged):
 * 0 = off / lab
 * 1 = HMAC-SHA256 PSK on mutating UCMM / Forward Open
 * 2 = 1 + TLS-PSK listener on TCP 2221 (plaintext 44818 stays up; no DTLS)
 *
 * EIP_SECURITY_CLASS_* and the security_class config key keep their names.
 */

/* Log and comment name. Not a certification claim. */
#define EIP_OWN_SECURITY_PROFILE \
    "자체 보안 프로파일 (HMAC 무결성 / TLS-PSK, ODVA CIP Security 아님, 인증 주장 아님)"

#define EIP_SEC_ITEM_INTEGRITY  0x00C1 /* repository CPF item, not an ODVA-assigned CIP Security item */

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
