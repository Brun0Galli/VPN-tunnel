// aes.h
#ifndef AES_H
#define AES_H

#include <stdint.h>

#define AES_BLOCK_SIZE 16    // 128 bits
#define AES_256_KEY_SIZE 32  // 256 bits
#define AES_256_ROUNDS 14
#define AES_256_EXP_KEY_SIZE 240 // 4*(Nr+1)*4 = 4*15*4 = 240 bytes

typedef struct {
    uint8_t round_keys[AES_256_EXP_KEY_SIZE];
} aes256_ctx;

// Inicializa el contexto expandiendo la clave de 256 bits
void aes256_init(aes256_ctx *ctx, const uint8_t key[AES_256_KEY_SIZE]);

// Cifra un bloque de 16 bytes (ECB de un solo bloque)
void aes256_encrypt_block(const aes256_ctx *ctx,
                          const uint8_t in[AES_BLOCK_SIZE],
                          uint8_t out[AES_BLOCK_SIZE]);

// (Opcional) función helper para modo CTR después
void aes256_ctr_xor(const aes256_ctx *ctx,
                    uint8_t counter[AES_BLOCK_SIZE],
                    const uint8_t *in, uint8_t *out, uint32_t len);

#endif // AES_H