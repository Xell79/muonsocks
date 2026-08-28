# muonsocks

## Introduction

This is an enhancement of rofl0r's excellent
[microsocks](https://github.com/rofl0r/microsocks) program with the following
changes:

* Support SOCKS4a clients
* Support disabling outgoing ipv4 or ipv6
* Support changing uid and chroot
* Support binding to multiple ip/port tuples
* Rewritten SOCKS5 parser that tolerates inputs split across multiple recv()
* More performance from larger buffers and fewer poll invocations
* Use TCP_NODELAY to lower latency impact
* Use lock-free list rather than dynamic array for threads
* Minimal memory allocations after init, and low heap fragmentation
* Enhanced error handling
* Fixed security vulnerabilities (MS-01 through MS-11),
  buffer bounds, RFC 1929 compliance, and compiler hardening

muonsocks fully supports SOCKS5 and SOCKS4a TCP proxying as a server.

It inherits the good design from microsocks, so the only real limits
are set by the available RAM and file descriptor limits. OOM does not
cause termination, and explicit memory allocation and heap
fragmentation are minimized.

It is ~1100 LoC compared to microsocks's ~600 LoC, so it is not
as minimal, but it is still a very small program (~27KiB dynamically
linked to glibc on amd64).

## Requirements

* Linux or BSD system
* GCC or Clang
* GNU Make
* Python 3 (optional, for regression tests)

## Installation and Quick Start

### 1. Automated Installation & Updates (systemd)

To install or update muonsocks automatically as a systemd daemon:

```sh
sudo ./install.sh
```

To pull the latest git commits, rebuild, and restart the daemon:

```sh
sudo ./install.sh --update
```

The installer:

* Compiles `muonsocks` with all security hardening flags.
* Runs the test suite (`make test`).
* Creates the system user `muonsocks` if missing.
* Installs the binary to `/usr/local/bin/muonsocks`.
* Installs the configuration template `/etc/default/muonsocks`
  (preserving any existing config).
* Installs, enables, and starts `/etc/systemd/system/muonsocks.service`.

### 2. Manual Build

Compile and install muonsocks manually:

```sh
make
sudo make install
```

To run localhost regression tests:

```sh
make test
```

## Systemd Service and Configuration

The daemon configuration is stored in `/etc/default/muonsocks`.

### Example Configurations

Running without authentication on default port 1080:

```sh
MUONSOCKS_OPTS="-p 1080 -v"
```

Running with username/password authentication (RFC 1929):

```sh
MUONSOCKS_OPTS="-p 1080 -v -U myuser -P mysecretpassword"
```

Running with `auth_once` mode (whitelists client IP after first successful auth):

```sh
MUONSOCKS_OPTS="-p 1080 -v -U myuser -P mysecretpassword -1"
```

Listening only on specific interfaces (e.g. localhost or VPN):

```sh
MUONSOCKS_OPTS="-i 127.0.0.1 -p 1080 -v"
```

After modifying `/etc/default/muonsocks`, restart the service:

```sh
sudo systemctl restart muonsocks
```

Check status and logs:

```sh
sudo systemctl status muonsocks
sudo journalctl -u muonsocks -f
```

## Client Connection Examples

### 1. curl

Without authentication:

```sh
curl -s -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

With username and password (RFC 1929):

```sh
curl -s -x socks5h://myuser:mysecretpassword@127.0.0.1:1080 https://ifconfig.me
```

*(Note: `socks5h://` instructs curl to perform DNS resolution
remotely on the proxy server).*

### 2. Browsers and Proxy Clients

In browser SOCKS5 proxy settings (or FoxyProxy, SwitchyOmega, ProxyChains):

* **SOCKS Host**: `127.0.0.1` (or your proxy IP)
* **Port**: `1080`
* **SOCKS version**: SOCKS v5
* **Proxy DNS when using SOCKS v5**: Checked / Enabled
* **Username / Password**: Enter configured `-U` and `-P` credentials (if enabled)

## Command Line Options

```text
muonsocks -1 -i listenip -p port -U user -P password -b bindaddr
```

* `-i <ip>`: Listen IP (default: `0.0.0.0`, can be specified
  multiple times for multiple interfaces/IPs).
* `-p <port>`: Listen port (default: `1080`, range `1..65535`).
* `-U <user>`: Username for SOCKS5 RFC 1929 authentication.
* `-P <password>`: Password for SOCKS5 RFC 1929 authentication
  (must be used together with `-U`).
* `-1`: Activates `auth_once` mode: once a client IP
  authenticates successfully with user/password, it is added
  to an in-memory whitelist and can use the proxy without
  re-authenticating.
* `-v`: Enables verbose connection and disconnection logging to stderr/journal.
* `-4`: Disables outgoing IPv6 connections (IPv4 only).
* `-6`: Disables outgoing IPv4 connections (IPv6 only).
* `-b <ip>`: Binds outgoing connections to a specific source IP.
* `-u <user>`: Drops privileges and runs as specified system user.
* `-C <dir>`: Chroots to the specified directory before dropping privileges.
* `-d <fd>`: Specifies s6 notification file descriptor.

## Security Notes

* Destination CONNECT to loopback and unspecified addresses is refused:
  IPv4 `127.0.0.0/8` and `0.0.0.0/8`, IPv6 `::1` and `::`, plus IPv4-mapped
  and IPv4-compatible IPv6 forms (`::ffff:127.0.0.1`, `::ffff:0.0.0.0`).
* Default listen address is `0.0.0.0:1080` with no authentication.
  Running without `-U`/`-P` on a wildcard address prints a warning; do not
  expose an unauthenticated proxy to untrusted networks.
* `-p` must be an integer in `1..65535` (out-of-range values are rejected).
* `-C` (chroot) as root requires `-u` (drop uid).
* RFC 1929 username/password success replies with status `0x00`.
* Binary built with `-fstack-protector-strong`,
  `_FORTIFY_SOURCE=2`, RELRO, and `BIND_NOW`.

`make test` runs `test_security.py` against the built binary (localhost only).

## Rationale and History

muonsocks is a multithreaded, small, and efficient
SOCKS5/SOCKS4a server derived from rofl0r's microsocks.
It optimizes connection handling using threads and blocking
socket writes with `TCP_NODELAY`, lock-free list recycling
for thread metadata, minimal heap allocation after
initialization, and robust resource exhaustion handling.

## Upstream Links

* [GitLab](https://gitlab.com/niklata/muonsocks)
* [Codeberg](https://codeberg.org/niklata/muonsocks)
* [BitBucket](https://bitbucket.com/niklata/muonsocks)
* [GitHub](https://github.com/niklata/muonsocks)
