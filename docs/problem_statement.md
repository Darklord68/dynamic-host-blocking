# Problem Statement: Dynamic Host Blocking System

## 1. The problem

A server on a network has to serve many clients at once, and it cannot tell in advance which of them will behave. A single misbehaving host can cause real damage in two common ways:

- **Connection flooding.** The host opens a very large number of TCP connections in a very short time. Each connection uses up server resources, so legitimate users see slow responses or cannot connect at all.
- **Password guessing.** The host sends login attempts over and over with wrong passwords, hoping to find a valid one. Even if it never succeeds, it wastes server time and is a security risk.

Both behaviours have the same shape: one source sends traffic at a rate far above what a normal user would. Our project builds a system that notices this abnormal pattern and stops the offending host automatically, without a person watching the network.

## 2. Why a static blocklist is not enough

The usual first answer is a fixed list of banned addresses. That approach has three weaknesses:

1. **It cannot react in time.** Someone must already know the attacker's address and write it into the list before the attack. It does nothing about a host that starts misbehaving right now.
2. **It never expires.** A legitimate host that was blocked once, for example during a misconfiguration, stays blocked until someone removes it by hand.
3. **It does not look at traffic.** The list has no idea how fast a host is sending, so it cannot tell a heavy attacker from a normal client.

A better system watches the traffic, decides by itself, blocks quickly, and lets the host back in after a short time. That is what "dynamic" means in our title.

## 3. Our approach

We use Software Defined Networking (SDN) so that the network itself can enforce the block. The system follows four steps: **detect, decide, block, expire**.

**Detect.** We use two signals:
- *Network signal.* The SDN controller sees every new TCP connection and counts them per source host. It also reads flow statistics from the switch. A host that makes 15 or more new connections within 5 seconds is flagged.
- *Application signal.* Our C server counts failed logins per source IP. A host with 5 failed logins within 10 seconds is flagged, and the server reports it to the controller by sending `BLOCK <ip> 30`.

**Decide.** The controller checks the host against a whitelist. The server, the administrator host and the controller itself are never blocked, so a mistake cannot cut off the system's own components.

**Block.** The controller installs a high-priority OpenFlow **drop rule** on the switch for the offending source address. Because the rule sits in the switch, the traffic is stopped in the network and never reaches the server. Other hosts are not affected.

**Expire.** The drop rule carries a 30 second timeout. When it runs out, the switch removes it, the controller updates its blocklist, and the host can connect again. Every detection and response event is written to a log file.

## 4. Objectives

Taken from the project brief, and what we do for each:

| Brief requirement | How we cover it |
|---|---|
| Generate TCP traffic from multiple hosts | A C client with three modes (normal, bad-login, burst) runs on several Mininet hosts |
| Monitor connection rates | The controller counts new connections per source host |
| Collect flow statistics | The controller polls the switch every 2 seconds |
| Define abnormal traffic thresholds | 15 connections in 5 s, and 5 failed logins in 10 s |
| Detect suspicious hosts | Controller (rate) and server (failed logins) |
| Maintain a dynamic blocklist | The controller adds hosts when flagged and removes them on expiry |
| Install SDN drop rules | OpenFlow drop rule with a 30 second timeout |
| Log detection and response events | Timestamped event log: detect, block, expire |

## 5. What we built for Deliverable 1

- A **multi-client TCP server in C**, using one thread per client, with the commands `LOGIN`, `ECHO` and `QUIT`.
- A **C client** that can behave as a normal user, a password guesser, or a connection flooder.
- A **failed-login detector** inside the server, with a mutex-protected table so counts add up correctly across threads.
- A **reporter** that sends `BLOCK <ip> 30` to the controller and reads back `OK` or `ERR <reason>`.
- A **Mininet topology** with one switch and four hosts, and an **SDN controller** that installs the drop rules.

## 6. Example from our testing

In a local test, a client sent five wrong passwords in about one second. The server logged five `LOGIN ... result=FAIL` lines, then printed `THRESHOLD reached for 127.0.0.1: sending BLOCK to controller`. The controller received `BLOCK 127.0.0.1 30` and the server logged `controller replied: OK`. This shows the full path from an application event to a network decision.

## 7. Limitations

- **Shared addresses.** If many users sit behind one address (NAT, VPN or a proxy), blocking that address blocks all of them, including innocent ones.
- **Spoofed addresses.** An attacker can forge a source address so that someone else gets blocked. Source-based blocking alone cannot prevent this.
- **Distributed attacks.** Many hosts that each stay under the threshold will not be detected, even though together they overload the server.
- **Choice of thresholds.** Too low and legitimate bursts are blocked. Too high and attacks get through. The values we use are suitable for a demonstration, not for a production network.

All testing was done in our own Mininet environment, on systems we control.
