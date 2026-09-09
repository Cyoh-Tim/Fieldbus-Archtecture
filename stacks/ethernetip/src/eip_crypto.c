#include "eip_crypto.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

void eip_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                     size_t data_len, uint8_t out[EIP_HMAC_LEN])
{
    unsigned int out_len = EIP_HMAC_LEN;
    HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len);
}

int eip_hmac_verify(const uint8_t *key, size_t key_len, const uint8_t *data,
                    size_t data_len, const uint8_t mac[EIP_HMAC_LEN])
{
    uint8_t calc[EIP_HMAC_LEN];
    eip_hmac_sha256(key, key_len, data, data_len, calc);
    uint8_t diff = 0;
    for (int i = 0; i < EIP_HMAC_LEN; i++) {
        diff |= (uint8_t)(calc[i] ^ mac[i]);
    }
    return diff == 0 ? 0 : -1;
}
