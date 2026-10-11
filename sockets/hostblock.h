#ifndef HOSTBLOCK_H
#define HOSTBLOCK_H

#include <time.h>

#define MAX_HOSTS 256

typedef struct {
    int    used;
    char   ip[16];
    int    fail_count;      /* failed logins in the current window */
    time_t window_start;    /* when the current window began */
    int    blocked;         /* 1 while we believe the host is blocked */
    time_t blocked_until;   /* when the block expires */
} HostEntry;

/* ---- detect.c (all functions are thread-safe) ---- */
void detect_init(int threshold, int window_sec, int block_sec);
int  record_failure(const char *ip, time_t now);   /* returns failure count in window */
int  should_block(const char *ip, time_t now);     /* 1 if threshold reached */
void mark_blocked(const char *ip, time_t until);
void mark_unblocked(const char *ip);
int  is_blocked(const char *ip);
int  unblock_expired(time_t now);                  /* returns how many were cleared */
int  detect_failure(const char *ip, time_t now);   /* record + check + mark, atomic.
                                                      returns 1 = send BLOCK now */
int  detect_block_seconds(void);

/* ---- reporter.c ---- */
/* Sends "BLOCK <ip> <secs>\n" to the controller. Returns 0 and fills reply
   if the controller answered, -1 if it could not be reached. */
int send_block(const char *ctrl_ip, int ctrl_port, const char *ip,
               int secs, char *reply, int reply_len);

#endif
