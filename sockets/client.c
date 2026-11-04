/* Test client / traffic generator.
 *
 *   ./client <ip> <port> normal   <count> [delay_ms]    valid logins, like a real user
 *   ./client <ip> <port> badlogin <count> [delay_ms]    wrong passwords on one connection
 *   ./client <ip> <port> burst    <count> [delay_ms]    many quick connections
 *   ./client <ip> <port> latency  <count> [delay_ms]    D2: timed logins, prints a summary line
 *   ./client <ip> <port> flood    <rate>  <seconds>     D2: steady connection flood, never hangs
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

#define TIMEOUT_MS  1000   /* connect and reply timeout for latency and flood modes */
#define MAX_PENDING 900    /* open, unfinished connections allowed in flood mode */

/* ---------------------------------------------------------------- time helpers */
static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static long long epoch_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ------------------------------------------------------------ original helpers */
static int make_addr(struct sockaddr_in *a, const char *ip, int port) {
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_port = htons(port);
    return inet_pton(AF_INET, ip, &a->sin_addr) == 1 ? 0 : -1;
}

static int connect_to(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    if (make_addr(&a, ip, port) < 0) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }
    return fd;
}

static void send_line(int fd, const char *s) { if (write(fd, s, strlen(s)) < 0) perror("write"); }

static void read_reply(int fd) {
    char buf[256];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    if (n > 0) { buf[n] = 0; printf("<- %s", buf); }
}

/* ------------------------------------------------- D2: connect with a timeout */
/* Returns a connected socket, -1 on error (refused, unreachable), -2 on timeout. */
static int connect_timeout(const char *ip, int port, int ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    if (make_addr(&a, ip, port) < 0) { close(fd); return -1; }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int rc = connect(fd, (struct sockaddr *)&a, sizeof a);
    if (rc < 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (rc < 0) {
        struct pollfd p = { fd, POLLOUT, 0 };
        int n = poll(&p, 1, ms);
        if (n == 0) { close(fd); return -2; }
        if (n < 0)  { close(fd); return -1; }
        int err = 0;
        socklen_t l = sizeof err;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l);
        if (err) { close(fd); return -1; }
    }
    fcntl(fd, F_SETFL, flags);                        /* back to blocking */
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    return fd;
}

/* ------------------------------------------------------- D2: latency mode */
static int cmp_dbl(const void *x, const void *y) {
    double a = *(const double *)x, b = *(const double *)y;
    return (a > b) - (a < b);
}

static void run_latency(const char *ip, int port, int count, int delay_ms) {
    double *lat = malloc((count > 0 ? count : 1) * sizeof *lat);
    int ok = 0, fail = 0, err = 0, tmo = 0;

    for (int i = 1; i <= count; i++) {
        double t0 = now_ms();
        const char *res = "error";
        int fd = connect_timeout(ip, port, TIMEOUT_MS);
        if (fd == -2) {
            res = "timeout";
        } else if (fd >= 0) {
            char buf[64];
            if (write(fd, "LOGIN admin secret123\n", 22) < 0) {
                res = "error";
            } else {
                ssize_t n = read(fd, buf, sizeof buf - 1);
                if (n > 0) {
                    buf[n] = 0;
                    res = strncmp(buf, "OK", 2) == 0 ? "ok" : "fail";
                } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    res = "timeout";
                }
            }
        }
        double ms = now_ms() - t0;                    /* connect + login round trip */
        if (fd >= 0) {
            if (write(fd, "QUIT\n", 5) < 0) { /* ignore */ }
            close(fd);
        }

        if (strcmp(res, "ok") == 0)           lat[ok++] = ms;
        else if (strcmp(res, "timeout") == 0) tmo++;
        else if (strcmp(res, "fail") == 0)    fail++;
        else                                  err++;
        printf("attempt=%d result=%s ms=%.2f\n", i, res, ms);
        fflush(stdout);
        if (i < count) usleep(delay_ms * 1000);
    }

    double avg = 0, p95 = 0, max = 0;
    if (ok > 0) {
        qsort(lat, ok, sizeof *lat, cmp_dbl);
        for (int i = 0; i < ok; i++) avg += lat[i];
        avg /= ok;
        int idx = (int)(0.95 * ok + 0.999999) - 1;    /* ceil(0.95 * n) - 1 */
        if (idx < 0) idx = 0;
        p95 = lat[idx];
        max = lat[ok - 1];
    }
    printf("summary attempts=%d ok=%d failed=%d timeout=%d success_pct=%.1f avg_ms=%.2f p95_ms=%.2f max_ms=%.2f\n",
           count, ok, fail + err, tmo, count > 0 ? 100.0 * ok / count : 0.0, avg, p95, max);
    free(lat);
}

/* -------------------------------------------------------- D2: flood mode */
struct pend { int fd; double t0; };

static void run_flood(const char *ip, int port, int rate, int seconds) {
    struct sockaddr_in a;
    if (make_addr(&a, ip, port) < 0) { printf("bad ip\n"); return; }

    struct pend pend[MAX_PENDING];
    int np = 0;
    long attempted = 0, connected = 0, failed = 0, timed_out = 0, skipped = 0;

    printf("flood start_epoch_ms=%lld rate=%d seconds=%d\n", epoch_ms(), rate, seconds);
    fflush(stdout);

    double start = now_ms();
    double end = start + seconds * 1000.0;
    double interval = 1000.0 / rate;
    double next = start;

    for (;;) {
        double t = now_ms();
        if (t >= end && np == 0) break;

        /* start every connection that is due (catch up if we fell behind) */
        while (t < end && t >= next) {
            attempted++;
            next += interval;
            if (np >= MAX_PENDING) { skipped++; continue; }
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) { failed++; continue; }
            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
            int rc = connect(fd, (struct sockaddr *)&a, sizeof a);
            if (rc == 0) { connected++; close(fd); }
            else if (errno != EINPROGRESS) { failed++; close(fd); }
            else { pend[np].fd = fd; pend[np].t0 = t; np++; }
        }

        /* collect finished and timed-out connections */
        if (np > 0) {
            struct pollfd pf[MAX_PENDING];
            for (int i = 0; i < np; i++) { pf[i].fd = pend[i].fd; pf[i].events = POLLOUT; pf[i].revents = 0; }
            poll(pf, np, 0);
            t = now_ms();
            for (int i = np - 1; i >= 0; i--) {
                int done = 0;
                if (pf[i].revents) {
                    int e = 0;
                    socklen_t l = sizeof e;
                    getsockopt(pend[i].fd, SOL_SOCKET, SO_ERROR, &e, &l);
                    if (e == 0) connected++; else failed++;
                    done = 1;
                } else if (t - pend[i].t0 >= TIMEOUT_MS) {
                    timed_out++;
                    done = 1;
                }
                if (done) {
                    close(pend[i].fd);
                    pend[i] = pend[--np];
                }
            }
        }
        usleep(1000);
    }

    double secs = (now_ms() - start) / 1000.0;
    printf("flood attempted=%ld connected=%ld failed=%ld timeout=%ld skipped=%ld seconds=%.1f achieved_rate=%.1f\n",
           attempted, connected, failed, timed_out, skipped, secs, secs > 0 ? attempted / (double)seconds : 0.0);
}

/* ------------------------------------------------------------------------ main */
int main(int argc, char **argv) {
    if (argc < 5) {
        printf("usage: %s <ip> <port> <normal|badlogin|burst|latency> <count> [delay_ms]\n"
               "       %s <ip> <port> flood <rate_per_s> <seconds>\n", argv[0], argv[0]);
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);

    const char *ip = argv[1];
    int port = atoi(argv[2]);
    const char *mode = argv[3];
    int count = atoi(argv[4]);
    /* optional pause between actions, in milliseconds.
       defaults: normal 1000, badlogin 200, burst 50, latency 250 */
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
    } else if (strcmp(mode, "latency") == 0) {
        if (count < 1) { printf("count must be at least 1\n"); return 1; }
        run_latency(ip, port, count, delay_ms >= 0 ? delay_ms : 250);
    } else if (strcmp(mode, "flood") == 0) {
        if (count < 1 || delay_ms < 1) { printf("usage: %s <ip> <port> flood <rate_per_s> <seconds>\n", argv[0]); return 1; }
        run_flood(ip, port, count, delay_ms);
    } else {
        printf("unknown mode\n");
        return 1;
    }
    return 0;
}
