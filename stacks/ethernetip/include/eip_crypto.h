#ifndef EIP_CRYPTO_H
#define EIP_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "eip_types.h"

void eip_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                     size_t data_len, uint8_t out[EIP_HMAC_LEN]);

/* Constant-time compare; returns 0 if equal. */
int eip_hmac_verify(const uint8_t *key, size_t key_len, const uint8_t *data,
                    size_t data_len, const uint8_t mac[EIP_HMAC_LEN]);

#endif /* EIP_CRYPTO_H */
