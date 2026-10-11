/* Stand-in for the Ryu controller. Listens on port 9100, prints every line it
   receives and replies OK (or ERR whitelisted for the protected hosts). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

static int whitelisted(const char *ip) {
    return !strcmp(ip, "10.0.0.1") || !strcmp(ip, "10.0.0.4") || !strcmp(ip, "10.0.0.254");
}

int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 9100;
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(port);
    if (bind(srv, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return 1; }
    listen(srv, 8);
    printf("mock controller listening on %d\n", port);
    fflush(stdout);

    for (;;) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) continue;
        char buf[128];
        ssize_t n = read(c, buf, sizeof buf - 1);
        if (n > 0) {
            buf[n] = 0;
            buf[strcspn(buf, "\r\n")] = 0;
            printf("received: %s\n", buf);
            char cmd[16] = "", ip[32] = "";
            sscanf(buf, "%15s %31s", cmd, ip);
            const char *r = (!strcmp(cmd, "BLOCK") && whitelisted(ip)) ? "ERR whitelisted\n" : "OK\n";
            if (write(c, r, strlen(r)) < 0) perror("write");
            fflush(stdout);
        }
        close(c);
    }
}
