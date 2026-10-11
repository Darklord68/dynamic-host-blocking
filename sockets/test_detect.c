#include <stdio.h>
#include <assert.h>
#include "hostblock.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); failed++; } } while (0)
static int failed = 0;

int main(void) {
    time_t t = 1000;

    /* threshold 5, window 10 s, block 30 s */
    detect_init(5, 10, 30);

    /* 4 failures: no block */
    for (int i = 0; i < 4; i++) record_failure("10.0.0.2", t + i);
    CHECK(!should_block("10.0.0.2", t + 4));

    /* 5th failure: block */
    record_failure("10.0.0.2", t + 4);
    CHECK(should_block("10.0.0.2", t + 4));

    /* a different host is unaffected */
    CHECK(!should_block("10.0.0.3", t + 4));

    /* failures spread beyond the window do not add up */
    detect_init(5, 10, 30);
    for (int i = 0; i < 4; i++) record_failure("10.0.0.2", t + i * 4);   /* t, t+4, t+8, t+12 */
    CHECK(!should_block("10.0.0.2", t + 12));

    /* atomic detect_failure fires exactly once */
    detect_init(5, 10, 30);
    int fired = 0;
    for (int i = 0; i < 8; i++) fired += detect_failure("10.0.0.2", t + i);
    CHECK(fired == 1);
    CHECK(is_blocked("10.0.0.2"));

    /* block expires after 30 s */
    CHECK(unblock_expired(t + 20) == 0);
    CHECK(is_blocked("10.0.0.2"));
    CHECK(unblock_expired(t + 40) == 1);
    CHECK(!is_blocked("10.0.0.2"));

    /* can be blocked again after expiry */
    fired = 0;
    for (int i = 0; i < 5; i++) fired += detect_failure("10.0.0.2", t + 50 + i);
    CHECK(fired == 1);

    /* mark_unblocked allows a retry */
    mark_unblocked("10.0.0.2");
    CHECK(!is_blocked("10.0.0.2"));

    if (failed == 0) printf("all detect tests passed\n");
    return failed ? 1 : 0;
}
