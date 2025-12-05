// vpn_server.c
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

// Envía un buffer cifrado: [4 bytes len][16 bytes nonce][ciphertext]
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
// Recibe [len][nonce][ciphertext] y devuelve plaintext
int recv_decrypted(int sock, aes256_ctx *ctx, uint8_t *plain, uint32_t *out_len) {
    uint32_t net_len;
    uint8_t counter[AES_BLOCK_SIZE];
    uint8_t *cipher;
    int n;

    // recibir longitud
    n = recv(sock, &net_len, sizeof(net_len), MSG_WAITALL);
    if (n == 0) return 1; // conexión cerrada
    if (n != sizeof(net_len)) return -1;

    uint32_t len = ntohl(net_len);
    if (len > MAX_PACKET_SIZE) return -1;

    // recibir nonce
    n = recv(sock, counter, AES_BLOCK_SIZE, MSG_WAITALL);
    if (n != AES_BLOCK_SIZE) return -1;

    cipher = malloc(len);
    if (!cipher) return -1;

    // recibir ciphertext
    n = recv(sock, cipher, len, MSG_WAITALL);
    if (n != (int)len) {
        free(cipher);
        return -1;
    }

    // descifrar
    aes256_ctr_xor(ctx, counter, cipher, plain, len);
    *out_len = len;

    free(cipher);
    return 0;
}

int main(void) {
    int tun_fd = tun_create("tun0");
    if (tun_fd < 0) {
        fprintf(stderr, "Error creando tun0\n");
        return 1;
    }

    // AES con PSK
    aes256_ctx aes_ctx;
    aes256_init(&aes_ctx, VPN_PSK);

    // Servidor TCP
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(VPN_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(listen_fd, 1) < 0) {
        perror("listen");
        return 1;
    }

    printf("[SERVER] Esperando cliente en puerto %d...\n", VPN_PORT);

    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    int client_fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
    if (client_fd < 0) {
        perror("accept");
        return 1;
    }

    char ipstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &cli_addr.sin_addr, ipstr, sizeof(ipstr));
    printf("[SERVER] Cliente conectado desde %s\n", ipstr);

    uint8_t buf[MAX_PACKET_SIZE];
    fd_set readfds;
    int maxfd = (tun_fd > client_fd) ? tun_fd : client_fd;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(tun_fd, &readfds);
        FD_SET(client_fd, &readfds);

        int ret = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (ret < 0) {
            perror("select");
            break;
        }

        // Datos desde tun0 → al cliente (cifrado)
        if (FD_ISSET(tun_fd, &readfds)) {
            int n = read(tun_fd, buf, sizeof(buf));
            if (n < 0) {
                perror("read tun");
                break;
            }
            // printf("[SERVER] Leído %d bytes de tun0\n", n);
            if (send_encrypted(client_fd, &aes_ctx, buf, (uint32_t)n) < 0) {
                fprintf(stderr, "[SERVER] Error enviando al cliente\n");
                break;
            }
        }

        // Datos desde el cliente → tun0 (descifrado)
        if (FD_ISSET(client_fd, &readfds)) {
            uint32_t plain_len;
            int r = recv_decrypted(client_fd, &aes_ctx, buf, &plain_len);
            if (r == 1) {
                printf("[SERVER] Cliente cerró la conexión\n");
                break;
            }
            if (r < 0) {
                fprintf(stderr, "[SERVER] Error recibiendo del cliente\n");
                break;
            }
            // printf("[SERVER] Escribiendo %u bytes a tun0\n", plain_len);
            int n = write(tun_fd, buf, plain_len);
            if (n < 0) {
                perror("write tun");
                break;
            }
        }
    }

    close(client_fd);
    close(listen_fd);
    close(tun_fd);
    return 0;
}