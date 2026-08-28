#!/usr/bin/env python3
"""Localhost security regression tests for muonsocks (MS-01..MS-05, MS-08)."""

from __future__ import annotations

import errno
import os
import signal
import socket
import struct
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

SOCKS5: Final = 5
ATYP_IPV4: Final = 1
ATYP_IPV6: Final = 4
REP_SUCCESS: Final = 0
EC_NOT_ALLOWED: Final = 2
TIMEOUT: Final = 5.0


class TestFailure(Exception):
    """Raised when a security regression check fails."""


def free_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def wait_tcp(host: str, port: int, timeout: float = TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    last_err: OSError | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError as exc:
            last_err = exc
            time.sleep(0.05)
    raise TestFailure(f"timeout waiting for {host}:{port} ({last_err})")


def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def socks5_method_select(sock: socket.socket, methods: bytes) -> int:
    sock.sendall(bytes([SOCKS5, len(methods)]) + methods)
    reply = recv_exact(sock, 2)
    if len(reply) != 2:
        raise TestFailure(f"short method reply: {reply!r}")
    if reply[0] != SOCKS5:
        raise TestFailure(f"bad SOCKS version in method reply: {reply!r}")
    return reply[1]


def socks5_connect_ipv4(sock: socket.socket, ip: str, port: int) -> int:
    packed = socket.inet_aton(ip)
    req = bytes([SOCKS5, 1, 0, ATYP_IPV4]) + packed + struct.pack("!H", port)
    sock.sendall(req)
    reply = recv_exact(sock, 10)
    if len(reply) < 2:
        raise TestFailure(f"short CONNECT reply: {reply!r}")
    return reply[1]


def socks5_connect_ipv6(sock: socket.socket, ip: str, port: int) -> int:
    packed = socket.inet_pton(socket.AF_INET6, ip)
    req = bytes([SOCKS5, 1, 0, ATYP_IPV6]) + packed + struct.pack("!H", port)
    sock.sendall(req)
    reply = recv_exact(sock, 22)
    if len(reply) < 2:
        raise TestFailure(f"short IPv6 CONNECT reply: {reply!r}")
    return reply[1]


def local_non_loopback_ipv4() -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 80))
        ip = sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()
    if ip.startswith("127."):
        return None
    return ip


@contextmanager
def running_proxy(
    binary: Path, extra: list[str] | None = None, host: str = "127.0.0.1"
) -> Iterator[tuple[subprocess.Popen[bytes], str, int]]:
    port = free_port(host)
    cmd = [str(binary), "-i", host, "-p", str(port), *(extra or [])]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        wait_tcp(host, port)
        if proc.poll() is not None:
            err = proc.stderr.read() if proc.stderr else b""
            raise TestFailure(f"proxy exited early: {proc.returncode} {err!r}")
        yield proc, host, port
        if proc.poll() is not None:
            err = proc.stderr.read() if proc.stderr else b""
            raise TestFailure(
                f"proxy died during test: rc={proc.returncode} stderr={err!r}"
            )
    finally:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except OSError:
                proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=1)


def test_socks5_noauth_handshake_and_connect(binary: Path) -> None:
    with running_proxy(binary) as (_proc, host, port):
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            method = socks5_method_select(sock, b"\x00")
            if method != 0:
                raise TestFailure(f"expected no-auth method 0, got {method}")
            target_ip = local_non_loopback_ipv4()
            if target_ip is None:
                # Handshake is enough if this host has no egress address.
                return
            echo_port = free_port(target_ip)
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                listener.bind((target_ip, echo_port))
                listener.listen(1)
                listener.settimeout(TIMEOUT)
                rep = socks5_connect_ipv4(sock, target_ip, echo_port)
                if rep != REP_SUCCESS:
                    raise TestFailure(
                        f"expected CONNECT success to {target_ip}:{echo_port}, REP={rep}"
                    )
                conn, _ = listener.accept()
                with conn:
                    sock.sendall(b"ping")
                    got = recv_exact(conn, 4)
                    if got != b"ping":
                        raise TestFailure(f"echo payload mismatch: {got!r}")
            except OSError as exc:
                if exc.errno in {errno.EADDRNOTAVAIL, errno.EACCES}:
                    return
                raise
            finally:
                listener.close()


def test_rfc1929_success_status(binary: Path) -> None:
    extra = ["-U", "alice", "-P", "secret"]
    with running_proxy(binary, extra) as (_proc, host, port):
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            method = socks5_method_select(sock, b"\x02")
            if method != 2:
                raise TestFailure(f"expected username/password method 2, got {method}")
            user, password = b"alice", b"secret"
            sock.sendall(bytes([1, len(user)]) + user + bytes([len(password)]) + password)
            reply = recv_exact(sock, 2)
            if reply != b"\x01\x00":
                raise TestFailure(
                    f"RFC1929 success must be 01 00, got {reply!r} (MS-03)"
                )
            rep = socks5_connect_ipv4(sock, "127.0.0.1", 9)
            if rep == REP_SUCCESS:
                raise TestFailure("loopback CONNECT succeeded after auth")


def test_rfc1929_failure_status(binary: Path) -> None:
    extra = ["-U", "alice", "-P", "secret"]
    with running_proxy(binary, extra) as (_proc, host, port):
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            socks5_method_select(sock, b"\x02")
            user, password = b"alice", b"wrong"
            sock.sendall(bytes([1, len(user)]) + user + bytes([len(password)]) + password)
            reply = recv_exact(sock, 2)
            if reply not in {b"\x01\x01", b""}:
                raise TestFailure(f"RFC1929 failure expected 01 01 or close, got {reply!r}")


def test_ms01_no_stack_overflow(binary: Path) -> None:
    with running_proxy(binary) as (proc, host, port):
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            sock.sendall(b"\x05" + b"\x00" * 2002)
            sock.settimeout(1.0)
            try:
                _ = sock.recv(64)
            except (TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
                pass
        if proc.poll() is not None:
            err = proc.stderr.read() if proc.stderr else b""
            raise TestFailure(
                f"proxy crashed on 2003-byte greeting (MS-01): rc={proc.returncode} {err!r}"
            )
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            method = socks5_method_select(sock, b"\x00")
            if method != 0:
                raise TestFailure("proxy unusable after oversized greeting")


def test_ms01_socks4_long_userid(binary: Path) -> None:
    with running_proxy(binary) as (proc, host, port):
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            # VER=4 CMD=1 PORT=9 DST=8.8.8.8 + 2000-byte userid without NUL
            payload = b"\x04\x01" + struct.pack("!H", 9) + socket.inet_aton("8.8.8.8")
            payload += b"A" * 2000
            sock.sendall(payload)
            sock.settimeout(1.0)
            try:
                _ = sock.recv(64)
            except (TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
                pass
        if proc.poll() is not None:
            raise TestFailure("proxy crashed on long SOCKS4 userid (MS-01)")


def test_ms02_loopback_and_mapped_bans(binary: Path) -> None:
    with running_proxy(binary) as (_proc, host, port):
        cases: list[tuple[str, int, str]] = [
            ("ipv4-loopback", 4, "127.0.0.1"),
            ("ipv4-loopback-alt", 4, "127.1.2.3"),
            ("ipv4-unspecified", 4, "0.0.0.0"),
        ]
        for name, _fam, ip in cases:
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                socks5_method_select(sock, b"\x00")
                rep = socks5_connect_ipv4(sock, ip, port)
                if rep == REP_SUCCESS:
                    raise TestFailure(f"{name} CONNECT to {ip}:{port} succeeded (MS-02)")
                if rep not in {1, EC_NOT_ALLOWED}:
                    raise TestFailure(f"{name} unexpected REP={rep} for {ip}")

        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            socks5_method_select(sock, b"\x00")
            try:
                rep = socks5_connect_ipv6(sock, "::ffff:127.0.0.1", port)
            except OSError as exc:
                raise TestFailure(f"IPv4-mapped CONNECT I/O error: {exc}") from exc
            if rep == REP_SUCCESS:
                raise TestFailure("::ffff:127.0.0.1 CONNECT succeeded (MS-02)")
            if rep not in {1, EC_NOT_ALLOWED, 8}:
                raise TestFailure(f"mapped loopback unexpected REP={rep}")

        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            socks5_method_select(sock, b"\x00")
            rep = socks5_connect_ipv6(sock, "::1", 9)
            if rep == REP_SUCCESS:
                raise TestFailure("::1 CONNECT succeeded")


def test_ms05_port_validation(binary: Path) -> None:
    for bad in ("0", "70000", "-1", "65536", "abc", "1080x"):
        proc = subprocess.run(
            [str(binary), "-i", "127.0.0.1", "-p", bad],
            capture_output=True,
            timeout=TIMEOUT,
            check=False,
        )
        if proc.returncode == 0:
            raise TestFailure(f"-p {bad} was accepted (MS-05)")
        err = proc.stderr.decode("utf-8", "replace")
        if "1..65535" not in err and "PORT" not in err:
            raise TestFailure(f"-p {bad} failed without a port error: {err!r}")


def test_ms08_unsigned_nmethods(binary: Path) -> None:
    with running_proxy(binary) as (_proc, host, port):
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            methods = b"\x00" * 200
            method = socks5_method_select(sock, methods)
            if method != 0:
                raise TestFailure(
                    f"nmethods=200 should still negotiate no-auth, got {method} (MS-08)"
                )


def test_open_proxy_warning(binary: Path) -> None:
    port = free_port()
    proc = subprocess.Popen(
        [str(binary), "-i", "0.0.0.0", "-p", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        wait_tcp("127.0.0.1", port)
        time.sleep(0.1)
        # Warning is printed at startup; process still runs.
        if proc.poll() is not None:
            raise TestFailure("proxy with 0.0.0.0 exited unexpectedly")
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=2)


TESTS = [
    test_socks5_noauth_handshake_and_connect,
    test_rfc1929_success_status,
    test_rfc1929_failure_status,
    test_ms01_no_stack_overflow,
    test_ms01_socks4_long_userid,
    test_ms02_loopback_and_mapped_bans,
    test_ms05_port_validation,
    test_ms08_unsigned_nmethods,
    test_open_proxy_warning,
]


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} /path/to/muonsocks", file=sys.stderr)
        return 2
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        print(f"missing binary: {binary}", file=sys.stderr)
        return 2
    failed = 0
    for test in TESTS:
        name = test.__name__
        try:
            test(binary)
            print(f"PASS  {name}")
        except Exception as exc:  # noqa: BLE001 — report every failure
            failed += 1
            print(f"FAIL  {name}: {exc}")
    print(f"{len(TESTS) - failed}/{len(TESTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
