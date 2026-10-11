#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "hostblock.h"

int send_block(const char *ctrl_ip, int ctrl_port, const char *ip,
               int secs, char *reply, int reply_len) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = { 2, 0 };                    /* 2 s timeouts */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(ctrl_port);
    if (inet_pton(AF_INET, ctrl_ip, &a.sin_addr) != 1) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }

    char msg[64];
    int len = snprintf(msg, sizeof msg, "BLOCK %s %d\n", ip, secs);
    if (write(fd, msg, len) < 0) { close(fd); return -1; }

    int n = (int)read(fd, reply, reply_len - 1);
    close(fd);
    if (n <= 0) return -1;
    reply[n] = 0;
    reply[strcspn(reply, "\r\n")] = 0;
    return 0;
}
