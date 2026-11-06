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

int main(int argc, char **argv) {
    int server_fd = -1, client_fd = -1;
    struct sockaddr_in addr;
    unsigned char buffer[BUFFER_SIZE];
    unsigned short port;
    FILE *output = NULL;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <port> <output-file>\n", argv[0]);
        return 2;
    }

    char *end = NULL;
    unsigned long parsed_port = strtoul(argv[1], &end, 10);
    if (!end || *end || parsed_port == 0 || parsed_port > 65535) {
        fprintf(stderr, "Invalid port\n");
        return 2;
    }
    port = (unsigned short)parsed_port;

    output = fopen(argv[2], "wb");
    if (!output) {
        perror("fopen");
        return 1;
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        fclose(output);
        return 1;
    }

    int reuse = 1;
    (void)setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(server_fd, 1) < 0) {
        perror("bind/listen");
        fclose(output);
        close(server_fd);
        return 1;
    }

    printf("Listening on TCP port %u...\n", (unsigned)port);
    client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        fclose(output);
        close(server_fd);
        return 1;
    }

    for (;;) {
        ssize_t n = recv(client_fd, buffer, sizeof(buffer), 0);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recv");
            fclose(output);
            close(client_fd);
            close(server_fd);
            return 1;
        }
        if (fwrite(buffer, 1, (size_t)n, output) != (size_t)n) {
            perror("fwrite");
            fclose(output);
            close(client_fd);
            close(server_fd);
            return 1;
        }
    }

    fclose(output);
    close(client_fd);
    close(server_fd);
    printf("File received successfully: %s\n", argv[2]);
    return 0;
}
