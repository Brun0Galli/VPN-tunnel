// hmac.c
#include "hmac.h"
#include <string.h>

void hmac_sha256(const uint8_t *key, size_t keylen,
                 const uint8_t *data, size_t datalen,
                 uint8_t out[HMAC_SHA256_TAG_SIZE])
{
    uint8_t k_ipad[HMAC_BLOCK_SIZE];
    uint8_t k_opad[HMAC_BLOCK_SIZE];
    uint8_t tk[SHA256_DIGEST_LENGTH];
    size_t i;

    // Si la clave es más larga que el bloque, la reducimos con SHA-256
    if (keylen > HMAC_BLOCK_SIZE) {
        sha256_ctx tctx;
        sha256_init(&tctx);
        sha256_update(&tctx, key, keylen);
        sha256_final(&tctx, tk);
        key = tk;
        keylen = SHA256_DIGEST_LENGTH;
    }

    // rellenar con ceros
    memset(k_ipad, 0, HMAC_BLOCK_SIZE);
    memset(k_opad, 0, HMAC_BLOCK_SIZE);
    memcpy(k_ipad, key, keylen);
    memcpy(k_opad, key, keylen);

    // XOR con ipad y opad
    for (i = 0; i < HMAC_BLOCK_SIZE; ++i) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    // inner hash = H( (K xor ipad) || data )
    sha256_ctx ctx;
    uint8_t inner_hash[SHA256_DIGEST_LENGTH];

    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, HMAC_BLOCK_SIZE);
    sha256_update(&ctx, data, datalen);
    sha256_final(&ctx, inner_hash);

    // outer hash = H( (K xor opad) || inner_hash )
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, HMAC_BLOCK_SIZE);
    sha256_update(&ctx, inner_hash, SHA256_DIGEST_LENGTH);
    sha256_final(&ctx, out);
}