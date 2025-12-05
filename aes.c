// aes.c
#include "aes.h"
#include <string.h>

// S-box AES
static const uint8_t sbox[256] = {
    // 16 x 16 = 256 valores
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// Rcon para la expansión de clave
static const uint8_t Rcon[15] = {
    0x00, // no se usa
    0x01,0x02,0x04,0x08,0x10,0x20,
    0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D
};

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}

static void sub_word(uint8_t *w) {
    w[0] = sbox[w[0]];
    w[1] = sbox[w[1]];
    w[2] = sbox[w[2]];
    w[3] = sbox[w[3]];
}

static void rot_word(uint8_t *w) {
    uint8_t tmp = w[0];
    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = tmp;
}

// Expansión de clave AES-256
void aes256_init(aes256_ctx *ctx, const uint8_t key[AES_256_KEY_SIZE]) {
    // Nk = 8, Nb = 4, Nr = 14
    const int Nk = 8;
    const int Nb = 4;
    const int Nr = AES_256_ROUNDS;
    int i = 0;

    // Copiar clave original a las primeras 8 palabras (8*4 bytes = 32)
    while (i < Nk) {
        ctx->round_keys[4*i + 0] = key[4*i + 0];
        ctx->round_keys[4*i + 1] = key[4*i + 1];
        ctx->round_keys[4*i + 2] = key[4*i + 2];
        ctx->round_keys[4*i + 3] = key[4*i + 3];
        i++;
    }

    uint8_t temp[4];
    int total_words = Nb * (Nr + 1); // 4*(14+1)=60

    while (i < total_words) {
        temp[0] = ctx->round_keys[4*(i-1) + 0];
        temp[1] = ctx->round_keys[4*(i-1) + 1];
        temp[2] = ctx->round_keys[4*(i-1) + 2];
        temp[3] = ctx->round_keys[4*(i-1) + 3];

        if (i % Nk == 0) {
            rot_word(temp);
            sub_word(temp);
            temp[0] ^= Rcon[i / Nk];
        } else if (i % Nk == 4) {
            sub_word(temp);
        }

        ctx->round_keys[4*i + 0] = ctx->round_keys[4*(i-Nk) + 0] ^ temp[0];
        ctx->round_keys[4*i + 1] = ctx->round_keys[4*(i-Nk) + 1] ^ temp[1];
        ctx->round_keys[4*i + 2] = ctx->round_keys[4*(i-Nk) + 2] ^ temp[2];
        ctx->round_keys[4*i + 3] = ctx->round_keys[4*(i-Nk) + 3] ^ temp[3];

        i++;
    }
}

static void add_round_key(uint8_t state[4][4], const uint8_t *round_key) {
    for (int c = 0; c < 4; c++) {
        state[0][c] ^= round_key[4*c + 0];
        state[1][c] ^= round_key[4*c + 1];
        state[2][c] ^= round_key[4*c + 2];
        state[3][c] ^= round_key[4*c + 3];
    }
}

static void sub_bytes(uint8_t state[4][4]) {
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            state[r][c] = sbox[state[r][c]];
        }
    }
}

static void shift_rows(uint8_t state[4][4]) {
    uint8_t tmp;

    // Fila 1: rot izq 1
    tmp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = tmp;

    // Fila 2: rot izq 2
    tmp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tmp;
    tmp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tmp;

    // Fila 3: rot izq 3 (o der 1)
    tmp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = tmp;
}

static void mix_columns(uint8_t state[4][4]) {
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = state[0][c];
        uint8_t a1 = state[1][c];
        uint8_t a2 = state[2][c];
        uint8_t a3 = state[3][c];

        uint8_t r0 = (uint8_t)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
        uint8_t r1 = (uint8_t)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
        uint8_t r2 = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
        uint8_t r3 = (uint8_t)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));

        state[0][c] = r0;
        state[1][c] = r1;
        state[2][c] = r2;
        state[3][c] = r3;
    }
}

void aes256_encrypt_block(const aes256_ctx *ctx,
                          const uint8_t in[AES_BLOCK_SIZE],
                          uint8_t out[AES_BLOCK_SIZE]) {
    uint8_t state[4][4];

    // Cargar estado por columnas
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] = in[c*4 + r];
        }
    }

    const uint8_t *round_key = ctx->round_keys;
    add_round_key(state, round_key); // ronda 0

    int Nr = AES_256_ROUNDS;
    for (int round = 1; round < Nr; round++) {
        round_key += 16;
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_key);
    }

    // Última ronda sin mix_columns
    round_key += 16;
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_key);

    // Guardar resultado
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            out[c*4 + r] = state[r][c];
        }
    }
}

// Modo CTR: counter se cifra, se XORea con los datos, y se incrementa como entero de 128 bits.
void aes256_ctr_xor(const aes256_ctx *ctx,
                    uint8_t counter[AES_BLOCK_SIZE],
                    const uint8_t *in, uint8_t *out, uint32_t len) {
    uint8_t keystream[AES_BLOCK_SIZE];
    uint32_t i = 0;

    while (i < len) {
        aes256_encrypt_block(ctx, counter, keystream);

        // XOR con este bloque
        uint32_t block_size = (len - i > AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (len - i);
        for (uint32_t j = 0; j < block_size; j++) {
            out[i + j] = in[i + j] ^ keystream[j];
        }

        // Incrementar counter (último byte ++, con carry)
        for (int k = AES_BLOCK_SIZE - 1; k >= 0; k--) {
            counter[k]++;
            if (counter[k] != 0) break; // no carry → paramos
        }

        i += block_size;
    }
}