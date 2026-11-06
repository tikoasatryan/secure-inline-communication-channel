/* sender <receiver-ip> <port> <file> : plain TCP client that sends a file. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <receiver-ip> <port> <file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[3], "rb");
    if (!f) { perror("fopen"); return 1; }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &a.sin_addr) != 1) {
        fprintf(stderr, "bad IP address\n"); return 1;
    }
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { perror("connect"); return 1; }

    char buf[16384];
    size_t n;
    unsigned long long total = 0;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        size_t off = 0;
        while (off < n) {
            ssize_t w = send(fd, buf + off, n - off, 0);
            if (w < 0) { if (errno == EINTR) continue; perror("send"); return 1; }
            off += (size_t)w;
        }
        total += n;
    }
    fclose(f);
    shutdown(fd, SHUT_WR);                       /* tell the receiver: end of file   */
    char c;
    while (recv(fd, &c, 1, 0) > 0) { }           /* wait until receiver closes       */
    close(fd);
    printf("sender: sent %llu bytes\n", total);
    return 0;
}
