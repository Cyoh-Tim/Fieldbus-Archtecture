#include "pn_crypto.h"

#include <string.h>

static const uint32_t k_sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

typedef struct {
    uint32_t st[8];
    uint64_t bits;
    uint8_t buf[64];
    size_t buf_len;
} sha256_ctx;

static uint32_t rotr32(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32u - n));
}

static void sha256_transform(uint32_t st[8], const uint8_t block[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
    uint32_t e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + k_sha256_k[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    st[0] += a;
    st[1] += b;
    st[2] += c;
    st[3] += d;
    st[4] += e;
    st[5] += f;
    st[6] += g;
    st[7] += h;
}

static void sha256_init(sha256_ctx *c)
{
    c->st[0] = 0x6a09e667u;
    c->st[1] = 0xbb67ae85u;
    c->st[2] = 0x3c6ef372u;
    c->st[3] = 0xa54ff53au;
    c->st[4] = 0x510e527fu;
    c->st[5] = 0x9b05688cu;
    c->st[6] = 0x1f83d9abu;
    c->st[7] = 0x5be0cd19u;
    c->bits = 0;
    c->buf_len = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len)
{
    c->bits += (uint64_t)len * 8u;
    while (len) {
        size_t take = 64 - c->buf_len;
        if (take > len) {
            take = len;
        }
        memcpy(c->buf + c->buf_len, data, take);
        c->buf_len += take;
        data += take;
        len -= take;
        if (c->buf_len == 64) {
            sha256_transform(c->st, c->buf);
            c->buf_len = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    c->buf[c->buf_len++] = 0x80;
    if (c->buf_len > 56) {
        while (c->buf_len < 64) {
            c->buf[c->buf_len++] = 0;
        }
        sha256_transform(c->st, c->buf);
        c->buf_len = 0;
    }
    while (c->buf_len < 56) {
        c->buf[c->buf_len++] = 0;
    }
    for (int b = 0; b < 8; b++) {
        c->buf[63 - b] = (uint8_t)(c->bits >> (b * 8));
    }
    sha256_transform(c->st, c->buf);
    for (int j = 0; j < 8; j++) {
        out[j * 4] = (uint8_t)(c->st[j] >> 24);
        out[j * 4 + 1] = (uint8_t)(c->st[j] >> 16);
        out[j * 4 + 2] = (uint8_t)(c->st[j] >> 8);
        out[j * 4 + 3] = (uint8_t)c->st[j];
    }
}

void pn_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

void pn_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                    size_t data_len, uint8_t out[32])
{
    uint8_t k[64];
    memset(k, 0, sizeof(k));
    if (key_len > 64) {
        pn_sha256(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, data, data_len);
    uint8_t inner[32];
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
}
