#ifndef PN_CRYPTO_H
#define PN_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

void pn_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void pn_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                    size_t data_len, uint8_t out[32]);

#endif /* PN_CRYPTO_H */
