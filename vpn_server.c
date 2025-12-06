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
#include "hmac.h"

#define MAX_PACKET_SIZE 2000
#define MAX_CLIENTS 4

// Enviar [len][nonce][ciphertext] a un cliente
int send_encrypted(int sock, aes256_ctx *ctx, const uint8_t *plain, uint32_t len) {
    uint8_t nonce[AES_BLOCK_SIZE];
    uint8_t ctr[AES_BLOCK_SIZE];
    uint8_t *cipher;
    uint8_t mac[HMAC_TAG_SIZE];
    uint8_t *mac_input;
    uint32_t net_len;
    int n;

    cipher = malloc(len);
    if (!cipher) return -1;

    memset(nonce, 0, AES_BLOCK_SIZE);
    memcpy(ctr, nonce, AES_BLOCK_SIZE);

    aes256_ctr_xor(ctx, ctr, plain, cipher, len);

    mac_input = malloc(AES_BLOCK_SIZE + len);
    if (!mac_input) {
        free(cipher);
        return -1;
    }
    memcpy(mac_input, nonce, AES_BLOCK_SIZE);
    memcpy(mac_input + AES_BLOCK_SIZE, cipher, len);

    hmac_sha256(VPN_PSK, AES_256_KEY_SIZE,
                mac_input, AES_BLOCK_SIZE + len,
                mac);

    free(mac_input);

    net_len = htonl(len);

    // length
    n = send(sock, &net_len, sizeof(net_len), 0);
    if (n != sizeof(net_len)) {
        free(cipher);
        return -1;
    }

    // nonce
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

    // mac
    n = send(sock, mac, HMAC_TAG_SIZE, 0);
    if (n != HMAC_TAG_SIZE) {
        free(cipher);
        return -1;
    }

    free(cipher);
    return 0;
}

// Recibir [len][nonce][ciphertext] y devolver plaintext
int recv_decrypted(int sock, aes256_ctx *ctx, uint8_t *plain, uint32_t *out_len) {
    uint32_t net_len;
    uint8_t nonce[AES_BLOCK_SIZE];
    uint8_t mac_recv[HMAC_TAG_SIZE];
    uint8_t mac_calc[HMAC_TAG_SIZE];
    uint8_t *cipher;
    uint8_t *mac_input;
    int n;

    // leer longitud
    n = recv(sock, &net_len, sizeof(net_len), MSG_WAITALL);
    if (n == 0) return 1; // conexión cerrada
    if (n != sizeof(net_len)) return -1;

    uint32_t len = ntohl(net_len);
    if (len > MAX_PACKET_SIZE) return -1;

    // leer nonce
    n = recv(sock, nonce, AES_BLOCK_SIZE, MSG_WAITALL);
    if (n != AES_BLOCK_SIZE) return -1;

    // leer ciphertext
    cipher = malloc(len);
    if (!cipher) return -1;
    n = recv(sock, cipher, len, MSG_WAITALL);
    if (n != (int)len) {
        free(cipher);
        return -1;
    }

    // leer MAC
    n = recv(sock, mac_recv, HMAC_TAG_SIZE, MSG_WAITALL);
    if (n != HMAC_TAG_SIZE) {
        free(cipher);
        return -1;
    }

    // recalcular HMAC
    mac_input = malloc(AES_BLOCK_SIZE + len);
    if (!mac_input) {
        free(cipher);
        return -1;
    }
    memcpy(mac_input, nonce, AES_BLOCK_SIZE);
    memcpy(mac_input + AES_BLOCK_SIZE, cipher, len);

    hmac_sha256(VPN_PSK, AES_256_KEY_SIZE,
                mac_input, AES_BLOCK_SIZE + len,
                mac_calc);

    free(mac_input);

    if (memcmp(mac_recv, mac_calc, HMAC_TAG_SIZE) != 0) {
        fprintf(stderr, "[SERVER] MAC inválido: paquete corrupto o atacado\n");
        free(cipher);
        return -1;    // DESCARTAMOS EL PAQUETE
    }

    // MAC ok → descifrar
    uint8_t ctr[AES_BLOCK_SIZE];
    memcpy(ctr, nonce, AES_BLOCK_SIZE);
    aes256_ctr_xor(ctx, ctr, cipher, plain, len);
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

    aes256_ctx aes_ctx;
    aes256_init(&aes_ctx, VPN_PSK);

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

    if (listen(listen_fd, MAX_CLIENTS) < 0) {
        perror("listen");
        return 1;
    }

    printf("[SERVER] Escuchando en puerto %d...\n", VPN_PORT);

    int clients[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; i++) clients[i] = -1;

    uint8_t buf[MAX_PACKET_SIZE];

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);

        FD_SET(tun_fd, &readfds);
        FD_SET(listen_fd, &readfds);

        int maxfd = (tun_fd > listen_fd) ? tun_fd : listen_fd;

        // añadir clientes al set
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i] >= 0) {
                FD_SET(clients[i], &readfds);
                if (clients[i] > maxfd) maxfd = clients[i];
            }
        }

        int ret = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (ret < 0) {
            perror("select");
            break;
        }

        // 1) Nuevo cliente
        if (FD_ISSET(listen_fd, &readfds)) {
            struct sockaddr_in cli_addr;
            socklen_t cli_len = sizeof(cli_addr);
            int new_fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
            if (new_fd < 0) {
                perror("accept");
            } else {
                char ipstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &cli_addr.sin_addr, ipstr, sizeof(ipstr));
                printf("[SERVER] Nuevo cliente desde %s\n", ipstr);

                int placed = 0;
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (clients[i] < 0) {
                        clients[i] = new_fd;
                        placed = 1;
                        break;
                    }
                }
                if (!placed) {
                    printf("[SERVER] Máximo de clientes alcanzado, cerrando nueva conexión\n");
                    close(new_fd);
                }
            }
        }

        // 2) Paquetes desde tun0 → reenviar a TODOS los clientes
        if (FD_ISSET(tun_fd, &readfds)) {
            int n = read(tun_fd, buf, sizeof(buf));
            if (n < 0) {
                perror("read tun");
                break;
            }
            // printf("[SERVER] Paquete %d bytes desde tun0\n", n);

            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i] >= 0) {
                    if (send_encrypted(clients[i], &aes_ctx, buf, (uint32_t)n) < 0) {
                        printf("[SERVER] Error enviando a cliente %d, cerrando\n", i);
                        close(clients[i]);
                        clients[i] = -1;
                    }
                }
            }
        }

        // 3) Paquetes desde clientes → escribir en tun0
        for (int i = 0; i < MAX_CLIENTS; i++) {
            int cfd = clients[i];
            if (cfd >= 0 && FD_ISSET(cfd, &readfds)) {
                uint32_t plain_len;
                int r = recv_decrypted(cfd, &aes_ctx, buf, &plain_len);
                if (r == 1) {
                    printf("[SERVER] Cliente %d cerró conexión\n", i);
                    close(cfd);
                    clients[i] = -1;
                    continue;
                }
                if (r < 0) {
                    printf("[SERVER] Error recibiendo de cliente %d, cerrando\n", i);
                    close(cfd);
                    clients[i] = -1;
                    continue;
                }

                int n = write(tun_fd, buf, plain_len);
                if (n < 0) {
                    perror("write tun");
                    // aquí podrías decidir abortar todo
                }
            }
        }
    }

    // limpieza (por si acaso)
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] >= 0) close(clients[i]);
    }
    close(listen_fd);
    close(tun_fd);
    return 0;
}