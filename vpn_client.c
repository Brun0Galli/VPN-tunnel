// vpn_client.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "tun.h"
#include "aes.h"
#include "common.h"

#define MAX_PACKET_SIZE 2000

// Mismas funciones de envío/recepción cifrada que en el server
int send_encrypted(int sock, aes256_ctx *ctx, const uint8_t *plain, uint32_t len) {
    uint8_t nonce[AES_BLOCK_SIZE];
    uint8_t ctr[AES_BLOCK_SIZE];
    uint8_t *cipher;
    uint32_t net_len;
    int n;

    cipher = malloc(len);
    if (!cipher) return -1;

    // ⚠️ Proyecto real: aquí deberías usar un nonce aleatorio + contador.
    // Por ahora, todos ceros solo para probar funcionamiento.
    memset(nonce, 0, AES_BLOCK_SIZE);

    // Usamos una copia del nonce como contador interno
    memcpy(ctr, nonce, AES_BLOCK_SIZE);

    // Ciframos: AES-CTR(ctr, plaintext) → ciphertext
    aes256_ctr_xor(ctx, ctr, plain, cipher, len);

    // Enviamos: [len][nonce][ciphertext]
    net_len = htonl(len);

    // longitud
    n = send(sock, &net_len, sizeof(net_len), 0);
    if (n != sizeof(net_len)) {
        free(cipher);
        return -1;
    }

    // nonce ORIGINAL (no el ctr modificado)
    n = send(sock, nonce, AES_BLOCK_SIZE, 0);
    if (n != AES_BLOCK_SIZE) {
        free(cipher);
        return -1;
    }

    // ciphertext
    n = send(sock, cipher, len, 0);
    if (n != (int)len) {
        free(cipher);
        return -1;
    }

    free(cipher);
    return 0;
}

int recv_decrypted(int sock, aes256_ctx *ctx, uint8_t *plain, uint32_t *out_len) {
    uint32_t net_len;
    uint8_t counter[AES_BLOCK_SIZE];
    uint8_t *cipher;
    int n;

    n = recv(sock, &net_len, sizeof(net_len), MSG_WAITALL);
    if (n == 0) return 1; // cerrado
    if (n != sizeof(net_len)) return -1;

    uint32_t len = ntohl(net_len);
    if (len > MAX_PACKET_SIZE) return -1;

    n = recv(sock, counter, AES_BLOCK_SIZE, MSG_WAITALL);
    if (n != AES_BLOCK_SIZE) return -1;

    cipher = malloc(len);
    if (!cipher) return -1;

    n = recv(sock, cipher, len, MSG_WAITALL);
    if (n != (int)len) {
        free(cipher);
        return -1;
    }

    aes256_ctr_xor(ctx, counter, cipher, plain, len);
    *out_len = len;

    free(cipher);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <IP_del_gateway>\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];

    int tun_fd = tun_create("tun0");
    if (tun_fd < 0) {
        fprintf(stderr, "Error creando tun0\n");
        return 1;
    }

    aes256_ctx aes_ctx;
    aes256_init(&aes_ctx, VPN_PSK);

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(VPN_PORT);
    if (inet_pton(AF_INET, server_ip, &srv.sin_addr) <= 0) {
        perror("inet_pton");
        return 1;
    }

    if (connect(sock_fd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        perror("connect");
        return 1;
    }

    printf("[CLIENT] Conectado a servidor %s:%d\n", server_ip, VPN_PORT);

    uint8_t buf[MAX_PACKET_SIZE];
    fd_set readfds;
    int maxfd = (tun_fd > sock_fd) ? tun_fd : sock_fd;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(tun_fd, &readfds);
        FD_SET(sock_fd, &readfds);

        int ret = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (ret < 0) {
            perror("select");
            break;
        }

        // tun0 → socket (cifrado)
        if (FD_ISSET(tun_fd, &readfds)) {
            int n = read(tun_fd, buf, sizeof(buf));
            if (n < 0) {
                perror("read tun");
                break;
            }
            // printf("[CLIENT] Leído %d bytes de tun0\n", n);
            if (send_encrypted(sock_fd, &aes_ctx, buf, (uint32_t)n) < 0) {
                fprintf(stderr, "[CLIENT] Error enviando al servidor\n");
                break;
            }
        }

        // socket → tun0 (descifrado)
        if (FD_ISSET(sock_fd, &readfds)) {
            uint32_t plain_len;
            int r = recv_decrypted(sock_fd, &aes_ctx, buf, &plain_len);
            if (r == 1) {
                printf("[CLIENT] Servidor cerró conexión\n");
                break;
            }
            if (r < 0) {
                fprintf(stderr, "[CLIENT] Error recibiendo del servidor\n");
                break;
            }
            // printf("[CLIENT] Escribiendo %u bytes a tun0\n", plain_len);
            int n = write(tun_fd, buf, plain_len);
            if (n < 0) {
                perror("write tun");
                break;
            }
        }
    }

    close(sock_fd);
    close(tun_fd);
    return 0;
}