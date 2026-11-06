/* receiver <port> <output-file> : plain TCP server that stores what it receives. */
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
    if (argc != 3) {
        fprintf(stderr, "usage: %s <port> <output-file>\n", argv[0]);
        return 1;
    }
    int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    if (ls < 0) { perror("socket"); return 1; }
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons((uint16_t)atoi(argv[1]));
    if (bind(ls, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return 1; }
    if (listen(ls, 1) < 0) { perror("listen"); return 1; }

    FILE *f = fopen(argv[2], "wb");
    if (!f) { perror("fopen"); return 1; }

    printf("receiver: listening on port %s\n", argv[1]);
    fflush(stdout);
    int c = accept(ls, NULL, NULL);
    if (c < 0) { perror("accept"); return 1; }

    char buf[16384];
    ssize_t n;
    unsigned long long total = 0;
    while ((n = recv(c, buf, sizeof buf, 0)) != 0) {
        if (n < 0) { if (errno == EINTR) continue; perror("recv"); return 1; }
        if (fwrite(buf, 1, (size_t)n, f) != (size_t)n) { perror("fwrite"); return 1; }
        total += (unsigned long long)n;
    }
    fclose(f);
    close(c);
    close(ls);
    printf("receiver: stored %llu bytes in %s\n", total, argv[2]);
    return 0;
}
