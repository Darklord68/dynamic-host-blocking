# D2 Scenario Scripts (scenarios/)

| ID | File | What it does | Priority |
|----|------|--------------|----------|
| S1 | s1_overload.sh | h3 latency client + h2 flood at 100/s for 20 s, run with MODE none then dynamic | Must |
| S2 | s2_two_attackers.sh | h2 floods connections, h5 guesses passwords; h3 and h4 keep working | Must |
| S3 | s3_repeat_offender.sh | Block h2, wait for expiry, flood again, expect a 60 s block | Must |
| S4 | s4_controller_failure.sh | Stop Ryu during a block, clients keep working, restart, blocks restored | Stretch |
| S5 | s5_false_positive.sh | Threshold 10, h3 opens 12 quick connections and gets blocked | Stretch |