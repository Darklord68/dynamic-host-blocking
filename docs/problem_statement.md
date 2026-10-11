# Problem Statement: Dynamic Host Blocking System

## 1. Problem
Servers exposed to a network can be abused by a single misbehaving host. Two common
patterns are:

- **Connection floods:** a host opens a very large number of TCP connections in a short
  time, exhausting the server's resources and slowing it for everyone else.
- **Brute-force logins:** a host repeatedly tries wrong credentials to guess a password.

Both look like *abnormal TCP traffic patterns*: a rate far above what a normal client
produces.

## 2. Why a static blocklist is not enough
- It has to be written by hand before the attack, so it cannot react while the attack is
  happening.
- It never expires, so a legitimate host that was blocked once stays blocked.
- It has no view of traffic, so it cannot tell a heavy attacker from a normal user.

## 3. Our approach
A network that reacts on its own: **detect, decide, block, expire**.

1. **Detect:** two signals.
   - *Network signal:* the SDN controller counts new TCP connections per source host and
     polls flow statistics from the switch (threshold: 15 new connections in 5 s).
   - *Application signal:* the C server counts failed logins per source IP (threshold:
     5 failures in 10 s).
2. **Decide:** the controller checks the whitelist and the blocklist.
3. **Block:** the controller installs a high-priority OpenFlow **drop rule** on the switch
   for the offending source IP.
4. **Expire:** the drop rule has a 30 s timeout, so the host is allowed back
   automatically. Every step is written to a log file.

## 4. Objectives (from the project brief)
- Generate TCP traffic from multiple hosts (normal clients and an attacker).
- Monitor connection rates and collect flow statistics.
- Define thresholds for abnormal traffic and detect suspicious hosts.
- Maintain a dynamic blocklist and install SDN drop rules.
- Log detection and response events.

## 5. Scope of this deliverable (D1)
A working end-to-end path: a multi-client TCP server in C, clients that produce normal,
burst and bad-login traffic, a Mininet topology with an SDN controller, and a link between
the server and the controller that results in a block rule on the switch.

## 6. Limitations and pitfalls
- **Shared IPs (NAT, VPN, proxies):** many users share one address, so blocking it blocks
  innocent users too.
- **Spoofed source addresses:** an attacker could make someone else look guilty. Blocking
  on source IP alone can be fooled.
- **Whitelisting:** administrator and server addresses must never be blocked.
- **Distributed attacks:** many hosts each staying under the per-host threshold avoid
  detection.
- **Thresholds:** too low blocks legitimate bursts, too high lets attacks through.
- Test only on systems you own or have permission to test.
