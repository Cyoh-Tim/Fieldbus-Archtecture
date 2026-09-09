#include "logger.h"
#include "pn_crypto.h"

#include <string.h>

/* RFC 4231 HMAC-SHA256 test case 1 */
int main(void)
{
    uint8_t key[20];
    memset(key, 0x0b, sizeof(key));
    const uint8_t *data = (const uint8_t *)"Hi There";
    uint8_t mac[32];
    pn_hmac_sha256(key, sizeof(key), data, 8, mac);
    static const uint8_t exp[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf,
        0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83,
        0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};
    if (memcmp(mac, exp, 32) != 0) {
        LOG_ERROR("test_pn_crypto", "FAIL HMAC-SHA256 RFC4231 case 1");
        return 1;
    }
    LOG_INFO("test_pn_crypto", "OK HMAC-SHA256 RFC4231 case 1");
    return 0;
}
