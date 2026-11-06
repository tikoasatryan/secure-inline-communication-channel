#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_SIZE 16384

static int send_all(int fd, const unsigned char *buf, size_t len) {
    while (len > 0) {
        ssize_t n = send(fd, buf, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        buf += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

int main(int argc, char **argv) {
    int sock = -1;
    FILE *input = NULL;
    struct sockaddr_in addr;
    unsigned char buffer[BUFFER_SIZE];
    unsigned short port;
    size_t n;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s <server-ip> <port> <input-file>\n", argv[0]);
        return 2;
    }

    char *end = NULL;
    unsigned long parsed_port = strtoul(argv[2], &end, 10);
    if (!end || *end || parsed_port == 0 || parsed_port > 65535) {
        fprintf(stderr, "Invalid port\n");
        return 2;
    }
    port = (unsigned short)parsed_port;

    input = fopen(argv[3], "rb");
    if (!input) {
        perror("fopen");
        return 1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        fclose(input);
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, argv[1], &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address\n");
        fclose(input);
        close(sock);
        return 2;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        fclose(input);
        close(sock);
        return 1;
    }

    while ((n = fread(buffer, 1, sizeof(buffer), input)) > 0) {
        if (send_all(sock, buffer, n) < 0) {
            perror("send");
            fclose(input);
            close(sock);
            return 1;
        }
    }

    if (ferror(input)) {
        perror("fread");
        fclose(input);
        close(sock);
        return 1;
    }

    shutdown(sock, SHUT_WR);
    fclose(input);
    close(sock);
    printf("File sent successfully.\n");
    return 0;
}
