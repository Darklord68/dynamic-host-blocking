# D2 Test Table

| # | Test | Action | Expected | Result |
|---|------|--------|----------|--------|
| 1 | Normal traffic | h3: 10 logins at 1/s | Served, no block | |
| 2 | Below threshold | h2: 10 conns in 5 s, 3 bad logins | No block | |
| 3 | Connection-rate block | h2 floods 25/s | DETECT, BLOCK, drop rule, h2 cut off | |
| 4 | Failed-login block | h5: 5 bad logins in 10 s | BLOCK for h5 | |
| 5 | Whitelist | h4: flood + 10 bad logins | Never blocked | |
| 6 | Expiry | Wait 30 s after a block | Rule gone, EXPIRE logged | |
| 7 | Isolation | While h2 blocked, h3 and h4 use server | Unaffected | |
| 8 | MODE none | MODE none, h2 floods | No DETECT, no rule | |
| 9 | MODE dynamic | MODE dynamic, h2 floods | Blocked as in test 3 | |
| 10 | RESET | RESET during a block | Drop rules removed, counters cleared | |
| 11 | Escalation | h2 attacks 3 times | Blocks of 30 s, 60 s, 120 s, ESCALATE logged | |
| 12 | Manual UNBLOCK | UNBLOCK h2 during a block | Rule removed, h2 works at once | |
| 13 | Stats rate flag (F1) | Flood, then check stats.csv | Rate column high for h2, low for h3 | |
| 14 | Recovery (stretch) | Restart Ryu during a block | Block reinstalled with time left | |