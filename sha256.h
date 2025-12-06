// sha256.h
#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_DIGEST_LENGTH 32

typedef struct {
    uint32_t state[8];   // H0..H7
    uint64_t bitlen;     // número de bits procesados
    uint8_t  data[64];   // bloque actual (512 bits)
    uint32_t datalen;    // bytes usados en data[]
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t hash[SHA256_DIGEST_LENGTH]);

#endif // SHA256_H