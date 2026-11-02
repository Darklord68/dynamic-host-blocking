# D2 Experiment Matrix

## Factors
| Factor | Levels |
|--------|--------|
| Mode | none (baseline), dynamic |
| Attack rate (connections/s) | 10, 25, 50, 100 |
| Attackers | 1 (h2), 2 (h2 + h5) |
| Repetitions | 3 |

Main matrix: 2 x 4 x 2 x 3 = 48 runs (about 36 minutes automated).

## Threshold sweep (dynamic only)
Connection threshold 10, 15, 25 in 5 s, attack at 25/s, 1 attacker, 3 reps = 9 runs,
plus one legitimate burst from h3 to show false positives.

## One run
1. RESET the controller, set MODE, confirm no drop rules, restart the server on h1.
2. Start the h3 latency client (25 s, one login per 250 ms = 100 attempts).
3. After 3 s start the attacker(s): flood RATE 20.
4. Wait for everything to finish. Collect client outputs, server log counts,
   events.log lines for this run, dump-flows counters.
5. Append one row to results.csv. RESET before the next run.

## run_id format
<mode>_a<attackers>_r<rate>_rep<n>   e.g. dyn_a2_r50_rep3, none_a1_r10_rep1
Sweep runs: sweep_t<threshold>_rep<n>

## Missing values
mode none has no block: leave time_to_block_s and drop_packets EMPTY (not 0).