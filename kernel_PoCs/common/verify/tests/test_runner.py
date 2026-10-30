from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

from verify_kernel_poc.adb import Adb
from verify_kernel_poc.models import PayloadSpec, RunPlan
from verify_kernel_poc.runner import _exchange_listening, _socket_exchange, run_listening_payload


def test_listening_shell_retries_forward_before_guest_listener_is_ready() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(2)
    accepted = 0
    received = b""

    def serve() -> None:
        nonlocal accepted, received
        try:
            with server.accept()[0]:
                accepted += 1
            with server.accept()[0] as connection:
                accepted += 1
                while not received.endswith(b"exit\n"):
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    received += chunk
                connection.sendall(b"uid=0(root)\nroot-only-token\n")
        finally:
            server.close()

    thread = threading.Thread(target=serve)
    thread.start()
    process = Mock()
    process.poll.return_value = None

    output, error = _exchange_listening(
        server.getsockname()[1],
        deadline=time.monotonic() + 3,
        process=process,
        lines=["id", "cat /root/flag", "exit"],
    )
    thread.join(timeout=3)

    assert not thread.is_alive()
    assert accepted == 2
    assert received == b"id\ncat /root/flag\nexit\n"
    assert "root-only-token" in output
    assert error == ""


def test_socket_exchange_waits_for_reply_before_closing_write_side() -> None:
    client, server = socket.socketpair()
    received = b""
    half_closed_before_reply = False

    def serve() -> None:
        nonlocal received, half_closed_before_reply
        with server:
            while not received.endswith(b"exit\n"):
                chunk = server.recv(4096)
                if not chunk:
                    break
                received += chunk
            server.settimeout(0.1)
            try:
                half_closed_before_reply = server.recv(1, socket.MSG_PEEK) == b""
            except TimeoutError:
                pass
            server.sendall(b"uid=0(root)\nroot-only-token\n")

    thread = threading.Thread(target=serve)
    thread.start()
    with client:
        output = _socket_exchange(client, lines=["id", "exit"], timeout=3)
    thread.join(timeout=3)

    assert not thread.is_alive()
    assert received == b"id\nexit\n"
    assert not half_closed_before_reply
    assert "root-only-token" in output


def test_listening_payload_drains_output_before_shell_opens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "ready"
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.settimeout(3)
    thread: threading.Thread | None = None

    def serve() -> None:
        try:
            while True:
                with server.accept()[0] as connection:
                    if not marker.exists():
                        continue
                    request = b""
                    while not request.endswith(b"exit\n"):
                        request += connection.recv(4096)
                    connection.sendall(b"uid=0(root)\nroot-only-token\n")
                    return
        finally:
            server.close()

    def forward(local_port: int, remote_port: int) -> None:
        nonlocal thread
        assert remote_port == 1337
        server.bind(("127.0.0.1", local_port))
        server.listen()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

    def remove_forward(local_port: int) -> None:
        assert local_port > 0
        if thread is not None:
            thread.join(timeout=3)

    script = (
        "import pathlib, sys, time; "
        "sys.stdout.write('X' * 1048576); sys.stdout.flush(); "
        f"pathlib.Path({str(marker)!r}).touch(); time.sleep(0.2)"
    )
    adb = Adb("test")
    monkeypatch.setattr(adb, "adb_args", lambda *args: [sys.executable, "-c", script])
    monkeypatch.setattr(adb, "forward", forward)
    monkeypatch.setattr(adb, "remove_forward", remove_forward)
    plan = RunPlan(
        artifact="executable",
        run_mode="exec",
        payload=PayloadSpec(kind="listening_shell", port=1337),
        run_command=None,
        poc_args=(),
        root_check_mode="flag",
        root_check_command=None,
        root_check_regex=None,
        remote_path="/data/local/tmp/exploit",
        local_path="/tmp/exploit",
        metadata=None,
    )

    outcome = run_listening_payload(adb, plan, lines=["id", "exit"], timeout=3)

    assert not outcome.timed_out
    assert outcome.returncode == 0
    assert "root-only-token" in outcome.output
    assert outcome.output.count("X") == 1048576
