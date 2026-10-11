#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "hostblock.h"

#define USER "admin"
#define PASS "secret123"
#define THRESHOLD 5     /* failed logins ...            */
#define WINDOW    10    /* ... within this many seconds */
#define BLOCK_SEC 30    /* block duration               */

static int  g_port = 9000;
static char g_ctrl_ip[32] = "127.0.0.1";
static int  g_ctrl_port = 9100;

struct client { int fd; struct sockaddr_in addr; };

static void report_block(const char *ip) {
    char reply[64];
    printf("THRESHOLD reached for %s: sending BLOCK to controller %s:%d\n",
           ip, g_ctrl_ip, g_ctrl_port);
    if (send_block(g_ctrl_ip, g_ctrl_port, ip, detect_block_seconds(),
                   reply, sizeof reply) == 0) {
        printf("controller replied: %s\n", reply);
    } else {
        printf("WARNING: controller unreachable, will retry on next failure\n");
        mark_unblocked(ip);
    }
}

static void *handle(void *arg) {
    struct client *c = (struct client *)arg;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &c->addr.sin_addr, ip, sizeof ip);
    printf("connect from %s:%d\n", ip, ntohs(c->addr.sin_port));

    FILE *in  = fdopen(c->fd, "r");
    FILE *out = fdopen(dup(c->fd), "w");
    free(c);
    if (!in || !out) return NULL;

    char line[256];
    while (fgets(line, sizeof line, in)) {
        line[strcspn(line, "\r\n")] = 0;
        char cmd[16] = "", a[64] = "", b[64] = "";
        sscanf(line, "%15s %63s %63s", cmd, a, b);

        if (strcmp(cmd, "LOGIN") == 0) {
            int ok = (strcmp(a, USER) == 0 && strcmp(b, PASS) == 0);
            fprintf(out, "%s\n", ok ? "OK" : "FAIL");
            fflush(out);
            printf("LOGIN from %s user=%s result=%s\n", ip, a, ok ? "OK" : "FAIL");
            if (!ok && detect_failure(ip, time(NULL)))
                report_block(ip);
        } else if (strcmp(cmd, "ECHO") == 0) {
            fprintf(out, "ECHO %s\n", line[4] == ' ' ? line + 5 : "");
        } else if (strcmp(cmd, "QUIT") == 0) {
            fprintf(out, "BYE\n");
            fflush(out);
            break;
        } else {
            fprintf(out, "ERR unknown command\n");
        }
        fflush(out);
    }
    fclose(in);
    fclose(out);
    printf("disconnect %s\n", ip);
    return NULL;
}

int main(int argc, char **argv) {
    /* usage: ./server [port] [controller_ip] [controller_port] */
    if (argc > 1) g_port = atoi(argv[1]);
    if (argc > 2) snprintf(g_ctrl_ip, sizeof g_ctrl_ip, "%s", argv[2]);
    if (argc > 3) g_ctrl_port = atoi(argv[3]);

    setvbuf(stdout, NULL, _IOLBF, 0);   /* flush each line even when redirected to a file */
    signal(SIGPIPE, SIG_IGN);
    detect_init(THRESHOLD, WINDOW, BLOCK_SEC);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(g_port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); return 1; }
    if (listen(srv, 16) < 0) { perror("listen"); return 1; }
    printf("listening on port %d (controller %s:%d, block after %d fails in %ds)\n",
           g_port, g_ctrl_ip, g_ctrl_port, THRESHOLD, WINDOW);

    for (;;) {
        struct client *c = malloc(sizeof *c);
        socklen_t len = sizeof c->addr;
        c->fd = accept(srv, (struct sockaddr *)&c->addr, &len);
        if (c->fd < 0) { perror("accept"); free(c); continue; }
        pthread_t t;
        pthread_create(&t, NULL, handle, c);
        pthread_detach(t);
    }
}
