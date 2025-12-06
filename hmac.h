// hmac.h
#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>
#include <stddef.h>
#include "sha256.h"

#define HMAC_SHA256_TAG_SIZE 32
#define HMAC_BLOCK_SIZE      64   // bloque interno de SHA-256

void hmac_sha256(const uint8_t *key, size_t keylen,
                 const uint8_t *data, size_t datalen,
                 uint8_t out[HMAC_SHA256_TAG_SIZE]);

#endif // HMAC_H