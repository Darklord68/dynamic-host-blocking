# Application Protocol

Transport: TCP, server port 9000. Every message is one text line ending in "\n".

## Client to server
| Command | Server reply |
|---|---|
| `LOGIN <user> <pass>` | `OK` or `FAIL` |
| `ECHO <text>` | `ECHO <text>` |
| `QUIT` | `BYE`, then the connection closes |
| anything else | `ERR unknown command` |

Valid login for the demo: user `admin`, password `secret123`.

## Later (Day 3-5)
After 5 failed logins in 10 seconds from the same IP, the server will send
`BLOCK <ip> 30` to the controller on port 9100 and read back `OK` or `ERR <reason>`.
