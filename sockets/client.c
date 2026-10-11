#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

static int connect_to(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, ip, &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }
    return fd;
}

static void send_line(int fd, const char *s) { if (write(fd, s, strlen(s)) < 0) perror("write"); }

static void read_reply(int fd) {
    char buf[256];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    if (n > 0) { buf[n] = 0; printf("<- %s", buf); }
}

int main(int argc, char **argv) {
    if (argc < 5) {
        printf("usage: %s <ip> <port> <normal|badlogin|burst> <count> [delay_ms]\n", argv[0]);
        return 1;
    }
    const char *ip = argv[1];
    int port = atoi(argv[2]);
    const char *mode = argv[3];
    int count = atoi(argv[4]);
    /* optional pause between actions, in milliseconds.
       defaults: normal 1000, badlogin 200, burst 50 */
    int delay_ms = argc > 5 ? atoi(argv[5]) : -1;

    if (strcmp(mode, "normal") == 0) {
        for (int i = 0; i < count; i++) {
            int fd = connect_to(ip, port);
            if (fd < 0) { perror("connect"); return 1; }
            send_line(fd, "LOGIN admin secret123\n"); read_reply(fd);
            send_line(fd, "ECHO hello\n");            read_reply(fd);
            send_line(fd, "QUIT\n");                  read_reply(fd);
            close(fd);
            usleep((delay_ms >= 0 ? delay_ms : 1000) * 1000);
        }
    } else if (strcmp(mode, "badlogin") == 0) {
        int fd = connect_to(ip, port);
        if (fd < 0) { perror("connect"); return 1; }
        for (int i = 0; i < count; i++) {
            send_line(fd, "LOGIN admin wrongpass\n");
            read_reply(fd);
            usleep((delay_ms >= 0 ? delay_ms : 200) * 1000);
        }
        send_line(fd, "QUIT\n");
        close(fd);
    } else if (strcmp(mode, "burst") == 0) {
        for (int i = 0; i < count; i++) {
            int fd = connect_to(ip, port);
            if (fd >= 0) close(fd);
            usleep((delay_ms >= 0 ? delay_ms : 50) * 1000);
        }
        printf("opened %d connections\n", count);
    } else {
        printf("unknown mode\n");
        return 1;
    }
    return 0;
}
