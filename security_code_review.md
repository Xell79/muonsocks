# Security / Code / DevOps Review: muonsocks vs upstream microsocks

**Date:** 2026-08-28  
**Fork reviewed:** `/home/xell/git/muonsocks` (`origin` = `https://github.com/niklata/muonsocks.git`)  
**Upstream:** `https://github.com/rofl0r/microsocks`  
**Reviewer scope:** research + review only; **no source changes** in the fork.

---

## 1. Executive summary

muonsocks is a substantial, mostly-C rewrite of rofl0r/microsocks:
SOCKS4a, multi-bind, uid/chroot, IPv4/IPv6 egress switches, a streaming
SOCKS parser, lock-free thread GC, larger copy buffers, and a hardcoded
destination ban for `127.0.0.0/8` and `::1`. Those are real operational
improvements over the 2020-era codebase it started from.

The review found **one confirmed, remotely triggerable stack buffer
overflow in the fork’s own parser** (not present in current upstream).
AddressSanitizer reports a heap-adjacent **WRITE of 2003 bytes past a
1024-byte stack buffer**; the default Makefile binary dies with
`*** stack smashing detected ***`. Any unauthenticated TCP client that
can reach the listen port can crash the worker thread; without stack
canaries this is a classic stack smash.

A **second confirmed logic bug** is that the loopback destination ban
does **not** cover IPv4-mapped IPv6 (`::ffff:127.0.0.1`) or `0.0.0.0`.
Local tests showed SOCKS CONNECT to those addresses **succeeds** and
can reach the proxy’s own listen socket (nested SOCKS greeting
observed). Combined with default `0.0.0.0:1080` and optional no-auth,
this is an SSRF/hairpin class issue.

Protocol compatibility: successful RFC1929 username/password replies
send **status `0x02` (method code) instead of `0x00`**, so many clients
will treat a correct password as failure. That is a confirmed spec bug
with availability impact; it is not an auth bypass (failed auth still
drops the connection).

The fork is **not a git fork with a merge-base**. The initial commit
is a verbatim copy of microsocks at `31557857` (2020-10-24, between
tags `v1.0.1` and `v1.0.2`). All later work is independent. Several
upstream reliability fixes were reimplemented; **client IP whitelist
(`-w`) and idle-timeout (`-t`) were not**. Default idle timeout
diverged: fork still reaps at 15 minutes; upstream HEAD now defaults
to “wait forever.”

**Do not treat this as a pentest of a live deployment.** All dynamic tests targeted `127.0.0.1` on ephemeral ports.

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| MS-01 | **Critical** | `extend_cbuf()` reads `BUF_SIZE` into `char buf[1024]` | Confirmed (ASan + SSP abort) |
| MS-02 | **High** | Loopback dest-ban bypass (`::ffff:127.0.0.1`, `0.0.0.0`); hairpin to self | Confirmed locally |
| MS-03 | **High** | RFC1929 success status byte is `0x02` not `0x00` | Confirmed locally |
| MS-04 | **Medium** | `add_auth_ip()` NULL deref on `reallocarray` failure | Confirmed by code |
| MS-05 | **Medium** | `-p` via `atoi` wraps (e.g. `70000` → `4464`) | Confirmed locally |
| MS-06 | **Medium** | Default listen `0.0.0.0:1080`, no auth (open proxy) | Inherited + operational |
| MS-07 | **Medium** | Dest ban is a 2-entry hardcode; `is_banned()` uses first `addrinfo` only | Confirmed by code + tests |
| MS-08 | **Low** | Signed `char` used as SOCKS length (`nmethods`/`ulen`/`plen`) | Confirmed by type + experiment |
| MS-09 | **Low** | Unbounded `auth_ips` growth (`-1`) | Design / DoS |
| MS-10 | **Low** | `chroot` without `-u` remains root-in-jail | Operational |
| MS-11 | **Info** | Missing upstream `-w` / `-t`; OpenBSD 32K stack; no man page | Drift / hardening |

---

## 2. Scope and methodology

### In scope

- Fork tree: `main.c`, `sockunion.h`, `nk/privs.c`, `nk/privs.h`, `nk/log.h`, `Makefile`, `README.md`, `LICENSE`, `.gitignore`.
- Comparison to upstream microsocks **exact copy baseline** and **current HEAD**.
- Manual C/SOCKS review: memory safety, integer/length,
  sockets/address parsing, auth/ACL/default exposure, privilege drop,
  DNS, fd/resource lifecycle, signals, concurrency, logging, compiler
  hardening, portability, deployment.
- Local compilation, `gcc -fanalyzer`, ASan/UBSan, and **localhost-only** protocol probes.

### Out of scope

- Modifying fork sources.
- Adding git remotes or changing fork history.
- Active scans or tests against third-party systems.
- Installing packages.
- Claiming CVEs (public search tools were unavailable in this environment).

### Skills / checklists applied

- Code review: correctness, concurrency, resource lifetime, protocol state machines.
- C/POSIX SOCKS (security-best-practices skill has no C reference
  file; review used CWE/SOCKS RFCs 1928/1929/1924a and C memory-safety
  practice).
- DevOps: listen defaults, privilege drop order, Makefile hardening, supervisor integration (`-d`).
- Mapped web-vuln classes: SSRF (A10), broken access control,
  misconfiguration, auth failures, DoS/resource exhaustion,
  insufficient logging — adapted to a TCP proxy, not HTTP.

---

## 3. Exact comparison baseline and evidence

### 3.1 Fork identity

| Item | Value |
|------|--------|
| Fork HEAD | `f9921a7aa48a0b52fe043faac678d605343ce9a2` (2026-07-04) `nk/privs: Invoke the capget() and capset() syscalls directly` |
| Fork initial commit | `a5fb30c67191967d67064260da29bd0790745ead` (2020-11-23) `Initial commit.` |
| Commits on `HEAD` | 122 |
| Remote | `origin https://github.com/niklata/muonsocks.git` (no microsocks remote; none added) |

### 3.2 Upstream identity (cloned only under `/tmp/kilo`)

| Item | Value |
|------|--------|
| Clone | `git clone https://github.com/rofl0r/microsocks.git /tmp/kilo/microsocks` then `git fetch --unshallow --tags` |
| Upstream HEAD | `2ea69c409cf88f3a0dadcba5822c426b8f077e7c` (2026-08-25) `add timeout option, and change default timeout to forever` |
| Describe | `v1.0.5-5-g2ea69c4` |
| Latest tag | `v1.0.5` = `98421a21c4adc4c77c0cf3a5d650cc28ad3e0107` (2024-05-24) |

### 3.3 Why there is no merge-base

The two repositories do not share git objects. muonsocks’ first commit **imports** microsocks sources as new blobs.

**Byte-identical match** (verified with `diff -q` of `git show` blobs):

- Fork `a5fb30c:sockssrv.c` == upstream `31557857ccce5e4fdd2cfdae7ab640d589aa2b41:sockssrv.c`
- Fork `a5fb30c:server.c` == same upstream commit’s `server.c`
- Fork `a5fb30c:Makefile` == same upstream commit’s `Makefile`

That upstream commit is:

```text
31557857ccce5e4fdd2cfdae7ab640d589aa2b41  2020-10-24  use poll() instead of select()
```

It sits **after** tag `v1.0.1` (`c21540e9`, 2018-12-20) and **before** tag `v1.0.2` (`ef6f8e33`, 2021-02-03).

**Limitation:** comparison is “imported snapshot + independent
rewrite” vs “linear microsocks history,” not `git merge-base`.
Semantic diffs are by file role (`sockssrv.c`+`server.c` ≈
`main.c`+`sockunion.h`).

### 3.4 Commands used (all wrapped in `timeout 180s`)

```text
git -C /home/xell/git/muonsocks status / log / rev-parse
git clone --depth 50 https://github.com/rofl0r/microsocks.git /tmp/kilo/microsocks
git -C /tmp/kilo/microsocks fetch --unshallow --tags
git -C /tmp/kilo/microsocks log / describe / tag
diff -q <(git show a5fb30c:sockssrv.c) <(git -C /tmp/kilo/microsocks show 31557857:sockssrv.c)
make -C /tmp/kilo/muonsocks-build          # copy of sources; not the git worktree
make -C /tmp/kilo/microsocks-build
gcc -fanalyzer -c .../main.c
gcc -fsanitize=address,undefined ... -o /tmp/kilo/muonsocks-asan
python3 /tmp/kilo/muonsocks_local_tests.py   # 127.0.0.1 only
readelf -h/-l/-d/-s on produced binaries
```

Temporary artifacts lived only under `/tmp/kilo/`. The fork worktree was not used as a build directory.

---

## 4. Change inventory

### 4.1 Layout

| Fork (HEAD) | Upstream HEAD | Notes |
|-------------|---------------|--------|
| `main.c` (~1051 lines) | `sockssrv.c` (520) + `server.c` (64) | Merged + rewritten |
| `sockunion.h` | `server.h` (union + server API) | Union macros only |
| `nk/privs.c`, `nk/privs.h`, `nk/log.h` | — | Privilege drop / chroot |
| — | `sblist.c/.h`, `sblist_delete.c` | Replaced by lock-free freelist |
| `Makefile` | `Makefile` + `install.sh` | Fork: c17, LTO, strip, hard warnings |
| `LICENSE` (MIT, dual copyright) | `COPYING` (MIT, rofl0r) | Fork adds Nicholas J. Kain 2020–2022 |
| `README.md` | `README.md` + `microsocks.1` | Fork has no man page |
| — | `create-dist.sh` | Dist helper not carried |

### 4.2 Functional deltas (fork vs baseline 31557857 and vs HEAD)

**Added in muonsocks (not in 2020 baseline):**

- SOCKS4 / SOCKS4a CONNECT.
- Repeated `-i` listen addresses; one shared `-p`.
- `-4` / `-6` egress family locks.
- `-u` drop uid/gid; `-C` chroot (`nk_set_chroot` then `nk_set_uidgid`).
- `-v` opt-in logging (upstream later added `-q` with logging **on** by default).
- `-d` s6 readiness byte.
- Hardcoded dest bans: `127.0.0.0/8`, `::1`.
- Streaming parser (`extend_cbuf`) for split TCP reads.
- `accept4` + `SOCK_CLOEXEC` / `TCP_NODELAY`.
- Thread struct slab + lock-free GC list (`LIST_EXCHANGE_TOP`).
- Larger `copyloop` buffers (`BUF_SIZE` 8–31 KiB) and `MAX_BATCH`.
- 15-minute idle `poll` timeout (baseline used the same 15 min; **upstream HEAD default is infinite**).
- Linux `IP_BIND_ADDRESS_NO_PORT` when bind port is 0.
- `gethostbyname("fail.invalid")` NSS preload before chroot.
- `reallocarray` for growable arrays.

**Reimplemented independently (also in later upstream):**

- `addr_choose` / `family_choose` for `-b` (upstream `6ecc398` / `2702f85`, 2021-12).
- FD exhaustion delay (upstream `42143b1`, 2021-11; fork uses 10 ms + `abort()` on unexpected `nanosleep` errors).
- `pthread_create` failure closes fd and returns slot (upstream `7e83778`, 2026-08).
- Idle close without fake `EC_TTL_EXPIRED` (upstream `375e5a6`; fork `925899e`).
- Larger copy buffers (upstream `98421a2`).
- Bigger default thread stack on glibc/FreeBSD (upstream `c81760c`).

**Present in upstream HEAD, absent in muonsocks:**

- `-w` comma-separated client IP whitelist (`b3996c5`).
- `-t` idle timeout; default **0 = wait forever** (`2ea69c4`).
- `pthread_rwlock` for auth-once list (fork uses a mutex).
- OpenBSD/Clang 32K stack (`97fbf8d`); Solaris stack (`8f6cb09`).
- `install.sh` portable install; man page.
- Handshake still uses **one `recv` per state** (split-TCP intolerance) — fork intended to fix this, but see MS-01.

**Intentionally different CLI:**

- Upstream `-u` = SOCKS username; fork `-U`/`-P` = SOCKS user/pass, `-u` = Unix user.

### 4.3 Makefile / build

Fork `CFLAGS` (assignment, not `+=`):

```text
-MMD -O2 -flto -s -DNDEBUG -std=c17 -I. -Wall -pedantic -Wextra
-Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow
-Wpointer-arith -Wmissing-prototypes -Wcast-qual -Wsign-conversion
-Wstrict-overflow=5 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700
-D_GNU_SOURCE
```

Link: `$(CC) $(CFLAGS) $(LDFLAGS) -lpthread -o $@ $^`  
`config.mak` can replace `CFLAGS` entirely. UBSan is commented out. No tests, CI, or man page.

---

## 5. Positive changes (keep)

1. **Privilege drop and chroot** (`nk/privs.c`) with `setgroups` /
   `setresuid` / `setresgid`, restore-privs probe, optional Linux
   `capset` + `PR_SET_NO_NEW_PRIVS`. Direct syscalls avoid libcap.
   Order: bind → NSS preload → chroot → uid.
2. **CLOEXEC** on listen/accept/remote sockets reduces fd leaks into children (none spawned today, still good).
3. **Split-TCP handshake intent** is the right design vs upstream’s
   single-`recv` state machine (firefox/curl can still stall on
   upstream).
4. **OOM/FD exhaustion** path drops the connection instead of aborting the process (except `delay10ms` / mutex `abort()`).
5. **SOCKS4 rejected when `-P` is set** (`parse_socksreq` `if (g_auth_pass) return -2`) — avoids a silent SOCKS4 auth bypass.
6. **Compiler warning set** is much stricter than upstream `-Wall -std=c99`.
7. **Lock-free GC** avoids scanning a dynamic array of all threads on every accept (upstream `collect()` is O(n)).
8. **s6 notify** (`-d`) is appropriate for supervision.
9. **MIT license** retained with dual copyright; `fail.invalid` NSS trick is documented.

---

## 6. Findings

### MS-01 — Critical — Stack buffer overflow in SOCKS request parser

**Type:** Confirmed memory-safety defect (CWE-121 / CWE-120).  
**Fork:** `main.c:500-513` (`extend_cbuf`), `main.c:578-585` (`parse_socksreq`).  
**Upstream:** not applicable — `handshake()` uses `unsigned char buf[1024]` and `recv(..., sizeof buf, 0)` (`sockssrv.c:317-323`).

```500:513:main.c
static bool extend_cbuf(const struct thread *t, char *buf, size_t *buflen)
{
    for (;;) {
        ssize_t n = read(t->client.fd, buf + *buflen, BUF_SIZE - *buflen);
        ...
        *buflen += (size_t)n;
        return true;
    }
}
```

```578:585:main.c
static int parse_socksreq(struct thread *t, struct socksctx *ctx)
{
    char buf[1024];
    size_t buflen = 0;
    ...
    EXTEND_BUF();
```

`BUF_SIZE` is 8640 / 17280 / 31680 (`main.c:63-72`) depending on
`THREAD_STACK_SIZE`. The read length is **`BUF_SIZE - *buflen`**,
not `1024 - *buflen`. First packet of 2003 bytes writes past `buf`.

SOCKS4 userid skip uses `if (i > BUF_SIZE / 2) return -2`
(`main.c:707`) — a limit of thousands of bytes against a 1024-byte
array, so it **cannot** save this path.

**Preconditions:** TCP connect to any listen port; no authentication
required for the overflow (happens on first `EXTEND_BUF()`).  
**Impact:** worker-thread crash (DoS). Without canaries / with a
lucky layout, stack smash / potential RCE. Default Ubuntu gcc SSP
**does** abort (`*** stack smashing detected ***`).  
**Evidence:**

- ASan: `WRITE of size 2003` at `extend_cbuf` / `parse_socksreq:585`, object `[1472, 2496) 'buf' (line 580)`.
- Default `-flto -s` binary: same payload → process abort, listen socket dead.

**Remediation:** Change the read size to `sizeof` of the parser
buffer (introduce `SOCKS_BUF_SIZE 1024` and use it in both the
array and `extend_cbuf`). Cap `*buflen`. Treat `*buflen >= cap` as
protocol error. Add a regression test (the 2003-byte greeting).
Do not use `BUF_SIZE` from `copyloop` here.

---

### MS-02 — High — Destination ban bypass and hairpin/SSRF to loopback

**Type:** Confirmed access-control / SSRF-class defect (CWE-918 / CWE-284).  
**Fork:** `main.c:938-939` (ban seed), `main.c:540-569` (`is_banned`), `main.c:757-758` (call site).  
**Upstream:** no dest ban.

Bans only:

- `AF_INET` `127.0.0.0/8`
- `AF_INET6` `::1/128`

Local CONNECT results (reply field = SOCKS5 `REP`):

| Target | REP | Meaning |
|--------|-----|---------|
| `127.0.0.1:9` | 1 | general failure (banned) |
| `127.1.2.3:9` | 1 | banned |
| `::1:9` | 1 | banned |
| DNS `localhost:9` | 1 | banned (resolved to v4 loopback first) |
| **`0.0.0.0:<listen>`** | **0** | **success; nested `05 00` from the same process** |
| **`::ffff:127.0.0.1:<listen>`** | **0** | **success; nested `05 00`** |
| `0.0.0.0:9` | 5 | connection refused (not banned; connect attempted) |

**Preconditions:** Client allowed to use the proxy (default: anyone).  
**Impact:** Reach host-loopback services via mapped IPv6 or
`0.0.0.0`. On a dual-stack host this bypasses the documented
“don’t proxy to myself” control. Classic proxy SSRF to
`127.0.0.1:22`, admin HTTP, cloud metadata **is not fully covered**
(IPv4 `169.254.169.254` and ULA/link-local are not banned at all
— see MS-07).

**Remediation:** Ban after the **final** `connect` address is chosen
(`addr_choose` result), not `ctx.remote->ai_addr`. Treat as loopback:
`INADDR_LOOPBACK`/`INADDR_ANY`/`INADDR_BROADCAST`, `127.0.0.0/8`,
`::1`, `::`, IPv4-mapped v4, IPv4-compatible `::ffff:0:0/96`
extracts. Optionally reject link-local and RFC1918 when the proxy
is an egress appliance. Prefer `getsockname`/`getpeername` after
connect for a bind-to-self check.

---

### MS-03 — High — RFC1929 success status is wrong (`0x02` instead of `0x00`)

**Type:** Confirmed protocol / availability defect.  
**Fork:** `main.c:618-639`.  
**Upstream:** `sockssrv.c:333-334` `send_auth_response(fd, 1, ret)`
where `ret` is `EC_SUCCESS` (0) or `EC_NOT_ALLOWED` (2).

RFC1929: version `0x01`, status `0x00` success, non-zero failure.

Fork on success:

```c
if (send_auth_response(t->client.fd, 1, am) < 0) return -1;
```

`am` is `AM_USERNAME` (2). Measured: method select `0502`, auth reply `0102`.

Failed password: connection closed **without** a 2-byte status
(returns `-1` before send). Upstream sends `01 02` on failure
(also not ideal, but success path is `01 00`).

**Impact:** curl/Firefox and any RFC-compliant client may refuse to
proceed after a **correct** password. Not an auth bypass. Auth-once
(`-1`) is harder to use.

**Remediation:** Send `{0x01, 0x00}` on success and `{0x01, 0x01}` (or `0xFF`) on failure. Do not reuse `enum authmethod`.

---

### MS-04 — Medium — `add_auth_ip()` continues after `reallocarray` failure

**Type:** Confirmed null-deref (CWE-476); needs memory pressure.  
**Fork:** `main.c:357-361`.

```c
auth_ips = reallocarray(auth_ips, nauth_ips + 1, sizeof(union sockaddr_union));
if (!auth_ips) perror("reallocarray");
memcpy(auth_ips + (nauth_ips++), caddr, sizeof *caddr);
```

**Impact:** crash of the authing thread; `auth_ips` leaked/lost on
failure (pointer overwritten with NULL) so subsequent auth-once
checks also crash.  
**Remediation:** On NULL, keep the old pointer, do not increment,
return error to the client. Same pattern is OK in `ban_dest_add`
(it `exit`s) and listen-IP growth (it `return 1`s).

---

### MS-05 — Medium — Listen port from `atoi` wraps to `unsigned short`

**Type:** Confirmed misconfiguration / unexpected bind.  
**Fork:** `main.c:896-903`.  
**Upstream:** `unsigned port = atoi(optarg)` with no range check (`sockssrv.c:417,459`).

`muonsocks -p 70000` listened on **4464** (`70000 & 0xffff`). Negative ports are rejected; `0` is not.

**Impact:** Operator believes they bound 70000; process is on 4464 (or a privileged port if wrap hits 1–1023).  
**Remediation:** Parse with `strtoul`, require `1..65535`.

---

### MS-06 — Medium — Default bind `0.0.0.0:1080` without authentication

**Type:** Operational / inherited open-proxy default (CWE-1188, “open ports and services”).  
**Fork:** `main.c:916-922`. **Upstream:** same.

README example uses `-i 192.168.0.1` but the binary default is still
all-interfaces no-auth. SOCKS5 CONNECT then becomes an **open TCP
proxy** (SSRF, scan, spam).

**Remediation:** Document as unsafe; consider refusing to start
without `-i` or `-U/-P` unless `-i 127.0.0.1`; add `-w`. This is
**not** a new fork bug, but it is the dominant deployment risk.

---

### MS-07 — Medium — Incomplete dest policy and wrong address selection for bans

**Type:** Confirmed logic limitation.  
**Fork:** `is_banned()` uses `family` from `family_choose` but copies
from `remote->ai_addr` (first `getaddrinfo` node). `connect` uses
`addr_choose` (`main.c:755-776`).

If the first result’s family ≠ chosen family, the code casts
`sockaddr_in` as `sockaddr_in6` (or the reverse) and the ban match
is meaningless. Dual-stack hostnames can therefore **skip**
`::1`/`127.0.0.0/8` or false-positive.

Hardcoded policy also omits: `0.0.0.0/8`, `::`, IPv4-mapped,
link-local (`169.254.0.0/16`, `fe80::/10`), ULA, multicast, and
**no CLI** to extend bans (unlike a firewall).

**Remediation:** Ban the `addrinfo` node actually passed to
`connect`. Optionally walk all A/AAAA and refuse if any is
disallowed (fail-safe). Expose `--deny-dst`.

---

### MS-08 — Low — Signed `char buf[]` used as SOCKS length fields

**Type:** Confirmed robustness issue; overflow not demonstrated on this path.  
**Fork:** `main.c:580`, `590`, `622-624`, `654`.  
**Upstream:** `unsigned char buf[1024]` (`sockssrv.c:318`).

On this platform `char` is signed (`char 200` → `-56`). Then:

```c
size_t n_methods = buf[1] >= 0 ? (size_t)buf[1] : 0;
```

`nmethods=200` becomes `0`; handshake fails closed. `ulen`/`plen`
≥ 128 similarly collapse to 0. Not an overflow (those copies are
gated by the truncated length) but it **breaks legitimate 8-bit
lengths** and diverges from RFC1928.

**Remediation:** `unsigned char buf[1024]` (or `uint8_t`) everywhere in the parser.

---

### MS-09 — Low — Unbounded auth-once IP list

**Type:** Design DoS.  
**Fork:** `add_auth_ip` + `-1`. **Upstream:** same unbounded `sblist`.

Any client that completes user/pass appends a `sockaddr_union`.
No cap, expiry, or netmask. Memory grows for the process lifetime;
mutex held during realloc.

**Remediation:** Cap N, LRU, or CIDR; prefer explicit `-w`.

---

### MS-10 — Low — `chroot` without uid drop

**Type:** Operational.  
**Fork:** `main.c:965-968` — `-C` and `-u` are independent.

Root+chroot is not a security boundary (many known escapes).
README shows both flags together; the binary does not require it.

**Remediation:** If `-C` set and euid 0, require `-u` ≠ root.

---

### MS-11 — Informational — Upstream drift, portability, ops

| Topic | Detail |
|-------|--------|
| No `-w` | Operators cannot allow-list clients without auth-once. |
| Timeout | Fork: 15 min idle reap (`main.c:453`). Upstream HEAD: default infinite (`2ea69c4`). Fork is safer for FD leaks; document it. |
| OpenBSD/Clang stack | Upstream `97fbf8d` sets 32K; fork may use `PTHREAD_STACK_MIN` 16K (`main.c:43-47`) — segfault risk (upstream README). |
| Solaris | Upstream `8f6cb09` not present. |
| Man page | Missing; `usage()` omits nothing critical but does not document dest bans or RFC1929. |
| `gethostbyname` | Deprecated (`main.c:954`); fine as NSS pin, but `getaddrinfo` would match the rest of the file. |
| Logging | Off by default (`-v`). Good for secrets; bad for abuse forensics (A09). Logs dest host:port when enabled (`main.c:780-784`). |
| `delay10ms` | `abort()` on non-EINTR `nanosleep` (`main.c:304`). Harsh; `return` would match the “never abort on resource errors” README claim. |
| `pthread_mutex_lock` failure | `abort()` (`main.c:599`). |
| Listen `malloc(nsrvrs * pollfd)` | No NULL check (`main.c:970`). Startup-only, needs huge argv. |
| `config.mak` | `CFLAGS =` means a user file can drop `-Wall`/`-flto` silently. Prefer `CFLAGS +=`. |
| Strip (`-s`) | Breaks debug of MS-01 in production; keep unstripped package builds. |
| Hardening flags | Not explicit in Makefile. Ubuntu 24.04 gcc defaulted to PIE, `BIND_NOW`, `RELRO`, `-fstack-protector-strong`, `-fstack-clash-protection` — **distro-dependent**. Set `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now` in-tree. |
| FORTIFY | Default LTO/stripped build did not show `__stack_chk_fail` in `readelf -s`; SSP still fired. Non-LTO `-g` build had `__stack_chk_fail` and `__memcpy_chk`. |

---

## 7. Additional code notes (not scored as vulns)

- **`copyloop` fairness:** `MAX_BATCH` + `MSG_DONTWAIT` is a solid
  latency/throughput trade vs upstream’s one-read-per-poll.
  `write` retry on `EINTR` is better than upstream (`m < 0` returns).
- **`send_error` SOCKS4 IPv6 lie** (`main.c:397-403`): documented; clients may mis-cache BND.ADDR.
- **Wrong ATYP on SOCKS5 errors:** IPv6 dest errors still often emit
  ATYP=1 because `srcaddr` is zeroed `AF_INET` (`main.c:373`).
  Harmless for most clients.
- **`family_choose` vs `addr_choose` mismatch warning** observed
  with `-b 127.0.0.1` + CONNECT `::1` → REP 8. Correct failure,
  noisy log.
- **Capability path unused:** `nk_set_uidgid(..., NULL, 0)` — prologue/epilogue no-ops. Fine.
- **`nk_gidbyname`:** if `gid != NULL` returns `grp->gr_gid` as the
  **function** result (success should be 0). Not called from
  muonsocks.
- **`resolve()` + `AI_PASSIVE`:** appropriate for listen; slightly
  odd for SOCKS targets but `getaddrinfo` still resolves names.
  Empty host is `EAI_NONAME` (tested).
- **No UDP ASSOCIATE / BIND:** same as upstream; documented as TCP-only.
- **Signals:** `SIGPIPE` ignored. No `SIGTERM` graceful drain (same as upstream).
- **Concurrency:** GC list `atomic_compare_exchange_strong` is
  correct for push; main thread `atomic_exchange` steals the list.
  Freelist is main-thread only — good. `auth_ips` mutex covers
  realloc + scan.

---

## 8. Upstream drift — security/reliability commits after the import

From `31557857` to `2ea69c4` (20 commits). Security/reliability-relevant:

| Commit | Subject | In muonsocks? |
|--------|---------|----------------|
| `ef6f8e3` | curl auth-once example | Docs only — no |
| `42143b1` | FD exhaustion leak/CPU | Yes (different delay) |
| `9d463f4` | shared `FAILURE_TIMEOUT` | Partial (10 ms / `abort`) |
| `6ecc398` `2702f85` | bindaddr family pick | Yes |
| `375e5a6` | drop TTL on idle | Yes (`925899e`) |
| `8f6cb09` | Solaris stack | No |
| `655c53d` | `-q` logging | Inverse (`-v`) |
| `c81760c` | bigger stack | Partial (glibc/FreeBSD 32K) |
| `b3996c5` | `-w` whitelist | **No** |
| `98421a2` | bigger copyloop buf | Yes (even larger) |
| `97fbf8d` | OpenBSD 32K | **No** |
| `96bf8a8` | man page | **No** |
| `7e83778` `69f004a` | `pthread_create` cleanup | Yes |
| `2ea69c4` | `-t`, default infinite | **No** (fork 15 min) |

Nothing in that list is a named CVE fix. The important **missing
product features** are `-w` and a documented timeout. The important
**fork-introduced** issues (MS-01, MS-02, MS-03) are not upstream
bugs.

---

## 9. DevOps / build hardening

| Control | Fork today | Recommendation |
|---------|------------|----------------|
| Default listen | `0.0.0.0:1080` | Require explicit `-i` or localhost |
| Auth | Optional | Require for non-loopback |
| Privdrop | Optional `-u`/`-C` | README is good; enforce `-u` with `-C` |
| Supervisor | `-d` s6 | Keep; systemd `Type=notify` not implemented |
| Hardening CFLAGS | Distro-default + `-flto -s -DNDEBUG` | Explicit SSP, FORTIFY, relro, now; optional `-fPIE` |
| `NDEBUG` | On by default (`a30815d`) | OK; do not use `assert` for protocol (already mostly avoided; `assert(n>=0)` and `assert(m<8)` are compiled out) |
| Tests | None | Parser fuzzer / the ASan cases from this review |
| Reproducible install | GNU `install -D` | Fine on Linux; upstream `install.sh` is more portable |
| Secrets | `zero_arg` on `-U`/`-P` | Still in `/proc/pid/cmdline` until zeroed; `strdup` heap copies remain. Document. |

---

## 10. Validation performed

| Check | Result |
|-------|--------|
| `make` fork copy in `/tmp/kilo/muonsocks-build` | **exit 0**, binary 30864 bytes, PIE, `BIND_NOW`, `GNU_RELRO` |
| `make` upstream copy | **exit 0** with `#pragma RcB2` warnings |
| `gcc -fanalyzer` | 2 warnings: possible NULL `memcmp` in `is_authed` if AF is neither 4 nor 6 (CWE-476). Theoretical; `is_authed` already requires equal AF. |
| ASan/UBSan binary | Built with gcc 13.3 |
| Split SOCKS5 greeting `\x05` then `\x01\x00` | `0500` — parser works for small splits |
| CONNECT `127.0.0.1` / `::1` / `localhost` | REP 1 (ban) |
| CONNECT `0.0.0.0:<self>` / `::ffff:127.0.0.1:<self>` | REP 0 + nested greeting |
| 2003-byte first packet (ASan) | **stack-buffer-overflow WRITE 2003** |
| Same payload, default binary | **`stack smashing detected`, process dead** |
| SOCKS4 2000-byte userid, default binary | **same abort** |
| RFC1929 user `a` pass `b` | method `0502`, status **`0102`** |
| `-p 70000` | listens on **4464** |
| `-p -1` | rejected |
| `getaddrinfo("", AI_PASSIVE)` | `EAI_NONAME`; NULL host → wildcard (not used by muonsocks) |
| Public CVE search | **Unavailable** (search APIs unauthorized / rate-limited) |

No tests were run against non-local addresses.

---

## 11. Limitations

- No merge-base; semantic comparison only.
- No libFuzzer/AFL; overflow was a single crafted payload.
- No confirmation of RCE — SSP killed the process. Exploitability beyond DoS is **not claimed**.
- gcc analyzer NULL-memcmp is a false-positive-prone path.
- Capability-dropping code is untested (muonsocks never passes caps).
- BSD/macOS/musl not executed.
- `.codegraph` is not indexed for this repo; review used full file reads.

---

## 12. Prioritized remediation plan

1. **P0 / MS-01:** Bound `extend_cbuf` to the parser buffer size;
   add a unit/smoke test with >1024-byte first write. Rebuild with
   ASan and the default Makefile.
2. **P0 / MS-03:** RFC1929 status `0x00`/`0x01`; test with `curl --socks5`.
3. **P1 / MS-02 + MS-07:** Ban the connected address, including
   mapped-v4, `0.0.0.0`, `::`. Consider blocking link-local/metadata
   by default.
4. **P1 / MS-05:** Strict port parse.
5. **P1 / MS-04:** Fix `reallocarray` error path.
6. **P2 / MS-08:** `unsigned char` parser buffer.
7. **P2:** Add `-w` (or document why not) and document 15-minute idle timeout vs upstream.
8. **P2 / MS-06:** Safer listen defaults or a loud stderr warning on `0.0.0.0` without auth.
9. **P2:** Makefile: explicit SSP/FORTIFY/relro; don’t let
   `config.mak` clobber warnings; keep a non-stripped `CFLAGS` for
   distro debuginfo.
10. **P3:** OpenBSD stack size; man page; cap auth-once list; refuse chroot-as-root; replace `gethostbyname`.

---

## 13. Classification reminder

| Confirmed defects | Defense-in-depth / ops |
|-------------------|------------------------|
| MS-01 overflow | MS-06 default bind (inherited) |
| MS-02 ban bypass / hairpin | MS-10 chroot-as-root |
| MS-03 RFC1929 byte | MS-09 unbounded list |
| MS-04 realloc NULL | MS-11 missing `-w`, man page, explicit hardening flags |
| MS-05 port wrap | Distro-default PIE/SSP (works here, not portable) |
| MS-07 first-addrinfo ban | Logging off by default |

---

*End of report.*
