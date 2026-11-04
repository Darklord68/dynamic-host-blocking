/* TCP server with failed-login detection.
 *
 *   ./server [port] [controller_ip] [controller_port] [idle_sec]
 *   defaults: 9000  127.0.0.1  9100  30
 *
 * Commands (one line each, max 255 characters):
 *   LOGIN <user> <pass>   -> OK | FAIL
 *   ECHO <text>           -> ECHO <text>
 *   STATS                 -> STATS connections=<n> logins_ok=<n> logins_failed=<n>
 *   STATS <ip>            -> STATS ip=<ip> connections=<n>
 *   QUIT                  -> BYE
 *   anything else         -> ERR unknown command
 * A longer line gets "ERR line too long". A client silent for idle_sec seconds is disconnected.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "hostblock.h"

#define USER "admin"
#define PASS "secret123"
#define THRESHOLD 5       /* failed logins ...            */
#define WINDOW    10      /* ... within this many seconds */
#define BLOCK_SEC 30      /* block duration               */
#define MAX_LINE  255     /* longest accepted line, without the newline */
#define MAX_STAT_IPS 64   /* hosts tracked in the per-IP connection table */

static int  g_port = 9000;
static char g_ctrl_ip[32] = "127.0.0.1";
static int  g_ctrl_port = 9100;
static int  g_idle_sec = 30;

/* ------------------------------------------------------------- statistics */
static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;
static long g_conns = 0, g_login_ok = 0, g_login_fail = 0;
static struct { char ip[16]; long conns; } ipstat[MAX_STAT_IPS];
static int n_ipstat = 0;

static void stat_connect(const char *ip) {
    pthread_mutex_lock(&stats_lock);
    g_conns++;
    int i;
    for (i = 0; i < n_ipstat; i++)
        if (strcmp(ipstat[i].ip, ip) == 0) break;
    if (i == n_ipstat && n_ipstat < MAX_STAT_IPS) {
        snprintf(ipstat[i].ip, sizeof ipstat[i].ip, "%s", ip);
        ipstat[i].conns = 0;
        n_ipstat++;
    }
    if (i < n_ipstat) ipstat[i].conns++;
    pthread_mutex_unlock(&stats_lock);
}

static void stat_login(int ok) {
    pthread_mutex_lock(&stats_lock);
    if (ok) g_login_ok++; else g_login_fail++;
    pthread_mutex_unlock(&stats_lock);
}

static long stat_for_ip(const char *ip) {
    long n = 0;
    pthread_mutex_lock(&stats_lock);
    for (int i = 0; i < n_ipstat; i++)
        if (strcmp(ipstat[i].ip, ip) == 0) n = ipstat[i].conns;
    pthread_mutex_unlock(&stats_lock);
    return n;
}

/* --------------------------------------------------------------- logging */
/* One log line with a millisecond timestamp: [2026-11-02 14:03:11.482] text */
static void log_line(const char *fmt, ...) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    char stamp[32];
    strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M:%S", &tm);

    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    printf("[%s.%03ld] %s\n", stamp, ts.tv_nsec / 1000000, msg);
}

struct client { int fd; struct sockaddr_in addr; };

static void report_block(const char *ip) {
    char reply[64];
    log_line("THRESHOLD reached for %s: sending BLOCK to controller %s:%d", ip, g_ctrl_ip, g_ctrl_port);
    if (send_block(g_ctrl_ip, g_ctrl_port, ip, detect_block_seconds(), reply, sizeof reply) == 0) {
        log_line("controller replied: %s", reply);
    } else {
        log_line("WARNING: controller unreachable, will retry on next failure");
        mark_unblocked(ip);
    }
}

static void *handle(void *arg) {
    struct client *c = (struct client *)arg;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &c->addr.sin_addr, ip, sizeof ip);
    log_line("connect from %s:%d", ip, ntohs(c->addr.sin_port));
    stat_connect(ip);

    struct timeval tv = { g_idle_sec, 0 };            /* idle timeout: a read gives up after this long */
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    FILE *in  = fdopen(c->fd, "r");
    FILE *out = fdopen(dup(c->fd), "w");
    free(c);
    if (!in || !out) return NULL;

    char line[MAX_LINE + 2];                          /* text + newline + end marker */
    while (fgets(line, sizeof line, in)) {
        size_t len = strlen(line);
        if (len == sizeof line - 1 && line[len - 1] != '\n') {      /* line too long */
            int ch;
            while ((ch = fgetc(in)) != EOF && ch != '\n') { /* discard the rest of the line */ }
            fprintf(out, "ERR line too long\n");
            fflush(out);
            log_line("line too long from %s, discarded", ip);
            continue;
        }
        line[strcspn(line, "\r\n")] = 0;
        char cmd[16] = "", a[64] = "", b[64] = "";
        sscanf(line, "%15s %63s %63s", cmd, a, b);

        if (strcmp(cmd, "LOGIN") == 0) {
            int ok = (strcmp(a, USER) == 0 && strcmp(b, PASS) == 0);
            fprintf(out, "%s\n", ok ? "OK" : "FAIL");
            fflush(out);
            stat_login(ok);
            log_line("LOGIN from %s user=%s result=%s", ip, a, ok ? "OK" : "FAIL");
            if (!ok && detect_failure(ip, time(NULL)))
                report_block(ip);
        } else if (strcmp(cmd, "ECHO") == 0) {
            fprintf(out, "ECHO %s\n", line[4] == ' ' ? line + 5 : "");
        } else if (strcmp(cmd, "STATS") == 0) {
            if (a[0]) {
                fprintf(out, "STATS ip=%s connections=%ld\n", a, stat_for_ip(a));
            } else {
                pthread_mutex_lock(&stats_lock);
                fprintf(out, "STATS connections=%ld logins_ok=%ld logins_failed=%ld\n",
                        g_conns, g_login_ok, g_login_fail);
                pthread_mutex_unlock(&stats_lock);
            }
        } else if (strcmp(cmd, "QUIT") == 0) {
            fprintf(out, "BYE\n");
            fflush(out);
            break;
        } else {
            fprintf(out, "ERR unknown command\n");
        }
        fflush(out);
    }
    if (ferror(in)) log_line("idle timeout, closing connection from %s", ip);
    fclose(in);
    fclose(out);
    log_line("disconnect %s", ip);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc > 1) g_port = atoi(argv[1]);
    if (argc > 2) snprintf(g_ctrl_ip, sizeof g_ctrl_ip, "%s", argv[2]);
    if (argc > 3) g_ctrl_port = atoi(argv[3]);
    if (argc > 4) g_idle_sec = atoi(argv[4]);
    if (g_idle_sec < 1) g_idle_sec = 1;

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
    if (listen(srv, 128) < 0) { perror("listen"); return 1; }
    log_line("listening on port %d (controller %s:%d, block after %d fails in %ds, idle timeout %ds)",
             g_port, g_ctrl_ip, g_ctrl_port, THRESHOLD, WINDOW, g_idle_sec);

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
