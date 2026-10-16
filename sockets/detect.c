#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "hostblock.h"

static HostEntry table[MAX_HOSTS];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int g_threshold = 5, g_window = 10, g_block = 30;

/* ---- helpers: caller must hold the lock ---- */
static HostEntry *find(const char *ip, int create) {
    for (int i = 0; i < MAX_HOSTS; i++)
        if (table[i].used && strcmp(table[i].ip, ip) == 0) return &table[i];
    if (!create) return NULL;

    HostEntry *slot = NULL;
    for (int i = 0; i < MAX_HOSTS && !slot; i++)
        if (!table[i].used) slot = &table[i];
    for (int i = 0; i < MAX_HOSTS && !slot; i++)      /* table full: evict an unblocked host */
        if (!table[i].blocked) slot = &table[i];
    if (!slot) return NULL;

    memset(slot, 0, sizeof *slot);
    slot->used = 1;
    snprintf(slot->ip, sizeof slot->ip, "%s", ip);
    return slot;
}

static int record_locked(HostEntry *e, time_t now) {                /*Records a failure attempt for a host entry within a sliding time window.*/
    if (e->fail_count == 0 || now - e->window_start >= g_window) {
        e->fail_count = 1;
        e->window_start = now;
    } else {
        e->fail_count++;
    }
    return e->fail_count;
}

static int over_threshold(HostEntry *e, time_t now) {  /*Evaluates whether a host has breached the failure limit*/
    return !e->blocked && e->fail_count >= g_threshold &&
           now - e->window_start < g_window;
}

static int expire_locked(time_t now) { /*Scans the table and lifts blocks for hosts whose penalty duration has elapsed*/
    int n = 0;
    for (int i = 0; i < MAX_HOSTS; i++) {
        if (table[i].used && table[i].blocked && now >= table[i].blocked_until) {
            table[i].blocked = 0;
            table[i].fail_count = 0;
            printf("block expired for %s\n", table[i].ip);
            n++;
        }
    }
    return n;
}

/* ---- public API ---- */
void detect_init(int threshold, int window_sec, int block_sec) {
    pthread_mutex_lock(&lock);
    g_threshold = threshold; g_window = window_sec; g_block = block_sec;
    memset(table, 0, sizeof table);
    pthread_mutex_unlock(&lock);
}

int detect_block_seconds(void) { return g_block; }

int record_failure(const char *ip, time_t now) {
    pthread_mutex_lock(&lock);
    HostEntry *e = find(ip, 1);
    int n = e ? record_locked(e, now) : 0;
    pthread_mutex_unlock(&lock);
    return n;
}

int should_block(const char *ip, time_t now) {
    pthread_mutex_lock(&lock);
    HostEntry *e = find(ip, 0);
    int r = e ? over_threshold(e, now) : 0;
    pthread_mutex_unlock(&lock);
    return r;
}

void mark_blocked(const char *ip, time_t until) {
    pthread_mutex_lock(&lock);
    HostEntry *e = find(ip, 1);
    if (e) { e->blocked = 1; e->blocked_until = until; e->fail_count = 0; }
    pthread_mutex_unlock(&lock);
}

void mark_unblocked(const char *ip) {
    pthread_mutex_lock(&lock);
    HostEntry *e = find(ip, 0);
    if (e) { e->blocked = 0; e->fail_count = 0; }
    pthread_mutex_unlock(&lock);
}

int is_blocked(const char *ip) {
    pthread_mutex_lock(&lock);
    HostEntry *e = find(ip, 0);
    int r = e ? e->blocked : 0;
    pthread_mutex_unlock(&lock);
    return r;
}

int unblock_expired(time_t now) {
    pthread_mutex_lock(&lock);
    int n = expire_locked(now);
    pthread_mutex_unlock(&lock);
    return n;
}

int detect_failure(const char *ip, time_t now) {
    pthread_mutex_lock(&lock);
    expire_locked(now);
    HostEntry *e = find(ip, 1);
    int fire = 0;
    if (e) {
        record_locked(e, now);
        if (over_threshold(e, now)) {
            e->blocked = 1;
            e->blocked_until = now + g_block;
            e->fail_count = 0;
            fire = 1;
        }
    }
    pthread_mutex_unlock(&lock);
    return fire;
}
