# muonsocks Security & Regression Test Suite

This directory contains the automated security and protocol regression test suite
for `muonsocks`.

## Overview

The test runner (`test_security.py`) spawns temporary `muonsocks` server
instances on dynamic localhost ports, executes raw SOCKS4/SOCKS5 handshakes and
malicious payloads, and validates proxy behavior, error codes, and vulnerability
mitigations.

All tests run strictly against `127.0.0.1` (localhost) without requiring
external network connectivity or root privileges.

## Requirements

* Python 3.8+ (standard library only, no third-party dependencies)
* Built `muonsocks` binary

## Running the Tests

### 1. Via Makefile (Standard)

From the project root:

```sh
make test
```

### 2. Direct Invocation with Python

From the project root:

```sh
python3 tests/test_security.py ./muonsocks
```

Or from within the `tests/` directory:

```sh
python3 test_security.py ../muonsocks
```

### 3. Running with Sanitizers (ASan / UBSan)

To run the test suite with AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
make clean
make SANITIZE=address,undefined
make test
```

This ensures that memory safety boundaries, buffer overflows, and undefined
behaviors are dynamically verified during test execution.

## Test Matrix

| Test Name | Target / CVE / Issue | Description |
|-----------|----------------------|-------------|
| `test_socks5_noauth_handshake_and_connect` | RFC 1928 | Verifies standard SOCKS5 handshake (no auth) and data proxying. |
| `test_rfc1929_success_status` | RFC 1929 / MS-03 | Verifies that successful username/password auth returns status `0x00`. |
| `test_rfc1929_failure_status` | RFC 1929 / MS-03 | Verifies that invalid credentials return non-zero error status `0x01`. |
| `test_ms01_no_stack_overflow` | MS-01 | Sends oversized method lists and malformed payloads to verify buffer bounds. |
| `test_ms01_socks4_long_userid` | MS-01 | Verifies SOCKS4/4a parser does not overflow when receiving oversized user IDs. |
| `test_ms02_loopback_and_mapped_bans` | MS-02, MS-07 | Verifies destination bans for `127.0.0.1`, `0.0.0.0`, `::1`, and IPv4-mapped IPv6 (`::ffff:127.0.0.1`). |
| `test_ms05_port_validation` | MS-05 | Verifies CLI rejects invalid port values (`0`, `70000`, `abc`, negative). |
| `test_ms08_unsigned_nmethods` | MS-08 | Verifies `nmethods > 127` is handled safely as unsigned length. |
| `test_open_proxy_warning` | MS-06 | Verifies warning output when starting unauthenticated on wildcard addresses. |

## Exit Codes

* `0`: All tests passed successfully.
* Non-zero: One or more tests failed, or proxy process crashed unexpectedly.
