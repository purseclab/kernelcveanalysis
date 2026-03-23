"""
infra.verification — Deploy, run, and verify exploits/reproducers on target.

This module is the core of the test/verification feedback loop.  It:

1. Connects to the target via SSH (or ADB for Android/Cuttlefish).
2. Optionally starts/stops the VM instance.
3. Pushes the compiled binary to the device.
4. Captures dmesg before execution.
5. Runs the binary with a UID-checking wrapper.
6. Captures dmesg after execution.
7. Parses output for privilege escalation / crash indicators.
8. Returns a structured ``VerificationAttempt`` that feeds back to the agent.

The agent can then inspect the attempt's ``success``, ``failure_reason``,
and ``feedback`` fields to decide whether to iterate (fix code, adjust
offsets, try a different technique) or declare the exploit done.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core.log import console
from .ssh import SSHSession


# ── vmlinux extraction from kernel Image ──────────────────────────────

def _extract_vmlinux_from_image(
    kernel_image: str,
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    work_dir: Optional[str] = None,
) -> Optional[tuple]:
    """Extract vmlinux ELF + kallsyms from a raw kernel Image.

    Uses ``vmlinux-to-elf``'s :class:`KallsymsFinder` and
    :class:`ElfSymbolizer` to recover the full symbol table embedded
    in the ARM64/x86 kernel binary.  Works even when ``/proc/kallsyms``
    is restricted by ``kptr_restrict``.

    If *kernel_image* is a remote path, it is first fetched via SCP.

    Returns ``(vmlinux_path, kallsyms_path, symbol_count)`` on success,
    or ``None`` on failure.
    """
    try:
        from vmlinux_to_elf.core.kallsyms import KallsymsFinder
        from vmlinux_to_elf.core.elf_symbolizer import ElfSymbolizer
    except ImportError:
        console.print(
            "  [dim]vmlinux-to-elf not installed — skipping Image extraction[/]"
        )
        return None

    save_dir = work_dir or tempfile.mkdtemp(prefix="syzploit_vmlinux_")

    # If the Image is remote (doesn't exist locally), fetch it via SCP
    local_image = kernel_image
    if not Path(kernel_image).is_file() and ssh_host:
        console.print(
            f"  [dim]Fetching kernel Image from {ssh_host}:{kernel_image}…[/]"
        )
        local_image = os.path.join(save_dir, "kernel_Image")
        try:
            scp_cmd = ["scp", "-o", "StrictHostKeyChecking=no"]
            if ssh_port != 22:
                scp_cmd += ["-P", str(ssh_port)]
            scp_cmd += [f"{ssh_host}:{kernel_image}", local_image]
            r = subprocess.run(scp_cmd, capture_output=True, timeout=120)
            if r.returncode != 0 or not Path(local_image).is_file():
                console.print("  [dim]  SCP failed — cannot fetch Image[/]")
                return None
        except Exception as e:
            console.print(f"  [dim]  SCP error: {e}[/]")
            return None

    if not Path(local_image).is_file():
        return None

    console.print(
        "  [dim]Extracting symbols from kernel Image via vmlinux-to-elf…[/]"
    )

    try:
        with open(local_image, "rb") as f:
            data = f.read()

        # Monkey-patch version check for non-standard kernel Images
        import logging as _logging
        _logging.disable(_logging.WARNING)

        orig_find_ver = KallsymsFinder.find_linux_kernel_version

        def _patched_find_ver(self):
            import re as _re
            m = _re.search(
                rb'Linux version (\d+\.[\d.]*\d)[ -~]+', self.kernel_img
            )
            if m:
                self.version_string = m.group(0).decode("ascii")
                self.version_number = m.group(1).decode("ascii")
            else:
                # Fallback: allow extraction to proceed without version
                self.version_string = "Linux version (unknown)"
                self.version_number = "0.0.0"

        KallsymsFinder.find_linux_kernel_version = _patched_find_ver

        try:
            # Create vmlinux ELF with symbols
            vmlinux_path = os.path.join(save_dir, "vmlinux")
            ElfSymbolizer(data, vmlinux_path, bit_size=64)

            # Also extract kallsyms text file for our symbol resolver
            ks = KallsymsFinder(data, bit_size=64)
            type_map = {
                "TEXT": "T", "LOCAL_TEXT": "t",
                "DATA": "D", "LOCAL_DATA": "d",
                "BSS": "B", "LOCAL_BSS": "b",
                "RODATA": "R", "LOCAL_RODATA": "r",
                "WEAK": "W", "ABSOLUTE": "A", "UNKNOWN": "?",
            }
            kallsyms_path = os.path.join(save_dir, "kallsyms")
            with open(kallsyms_path, "w") as f:
                for s in ks.symbols:
                    stype = type_map.get(s.symbol_type.name, "?")
                    f.write(f"{s.virtual_address:016x} {stype} {s.name}\n")

            sym_count = len(ks.symbols)
            console.print(
                f"  [dim]  Extracted vmlinux ELF + {sym_count} symbols[/]"
            )
            return (vmlinux_path, kallsyms_path, sym_count)
        finally:
            KallsymsFinder.find_linux_kernel_version = orig_find_ver
            _logging.disable(_logging.NOTSET)

    except Exception as e:
        console.print(
            f"  [yellow]vmlinux extraction failed: {e}[/]"
        )
        return None


# ── ADB port calculation ─────────────────────────────────────────────

ADB_BASE_PORT = 6520


def _calc_adb_port(instance: Optional[int], explicit_port: int = 6520) -> int:
    """Return the ADB device port for a Cuttlefish instance.

    Formula matches ``launch_cvd``: ``6520 + (instance - 1)``.
    If no instance is given, return the explicitly provided port.
    """
    if instance is not None and instance >= 1:
        return ADB_BASE_PORT + (instance - 1)
    return explicit_port


# ── ADB helpers ───────────────────────────────────────────────────────

import shutil as _shutil

_ADB_EXE: Optional[str] = None


def _adb_exe() -> str:
    """Return the absolute path to the ``adb`` executable.

    Search order:
    1. ``$PATH`` (via ``shutil.which``)
    2. ``./adb`` next to the workspace (the user may have copied it in)
    3. ``../syzploit_old/adb`` (legacy location)
    4. Common Android SDK paths

    Raises ``FileNotFoundError`` if adb cannot be found anywhere.
    """
    global _ADB_EXE  # noqa: PLW0603
    if _ADB_EXE is not None:
        return _ADB_EXE

    candidates = [
        _shutil.which("adb"),
        # relative to this file → repo root
        str(Path(__file__).resolve().parents[3] / "adb"),
        str(Path.cwd() / "adb"),
    ]
    for c in candidates:
        if c and Path(c).is_file():
            _ADB_EXE = str(Path(c).resolve())
            console.print(f"  [dim]Using ADB: {_ADB_EXE}[/]")
            return _ADB_EXE

    raise FileNotFoundError(
        "Cannot find 'adb' executable. Either install the Android SDK "
        "platform-tools, put adb on $PATH, or place it in the repo root."
    )

def _adb_target(adb_port: int) -> str:
    """ADB device serial for ``-s`` flag.

    Uses ``localhost`` so connections go through the SSH port-forward
    tunnel (which binds to 127.0.0.1).  The old code used ``0.0.0.0``
    but that doesn't route through ``-L`` tunnels.
    """
    return f"localhost:{adb_port}"


def _adb_run(
    cmd: str,
    adb_port: int,
    *,
    timeout: int = 30,
) -> Tuple[int, str, str]:
    """Run a command on the device via ``adb shell``.

    Returns ``(returncode, stdout, stderr)``.
    """
    target = _adb_target(adb_port)
    adb = _adb_exe()
    argv = [adb, "-s", target, "shell", cmd]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as exc:
        # Capture any partial output produced before the timeout.
        partial_out = (exc.stdout or "") if isinstance(exc.stdout, str) else (exc.stdout.decode(errors="replace") if exc.stdout else "")
        partial_err = (exc.stderr or "") if isinstance(exc.stderr, str) else (exc.stderr.decode(errors="replace") if exc.stderr else "")
        return -1, partial_out, partial_err or "adb command timed out"
    except Exception as exc:
        return -1, "", str(exc)


def _adb_push(local: str, remote: str, adb_port: int, *, timeout: int = 30) -> bool:
    """Push a file to the device via ADB."""
    target = _adb_target(adb_port)
    adb = _adb_exe()
    try:
        r = subprocess.run(
            [adb, "-s", target, "push", local, remote],
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode != 0:
            console.print(f"  [red]adb push failed: {r.stderr[:200]}[/]")
        return r.returncode == 0
    except Exception as exc:
        console.print(f"  [red]adb push error: {exc}[/]")
        return False


def _tcp_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """Quick TCP-level check: can we even connect to *host:port*?

    Returns True if a TCP connection is established (something is
    listening), False otherwise.  This is faster and more diagnostic
    than ``adb connect`` because it distinguishes:
      - ``ConnectionRefused`` → port not listening (VM not ready / tunnel dead)
      - timeout → packets black-holed (firewall / tunnel forwarding to nothing)
      - success → something is listening (ADB should be reachable)
    """
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.close()
        return True
    except ConnectionRefusedError:
        return False
    except OSError:
        return False


def _check_remote_port(
    port: int,
    ssh_host: str,
    ssh_port: int = 22,
) -> Optional[str]:
    """SSH to the build host and check if *port* is listening there.

    Returns a short diagnostic string, or None on failure.
    """
    try:
        r = subprocess.run(
            [
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-p", str(ssh_port), ssh_host,
                f"ss -tlnp 2>/dev/null | grep :{port} || echo 'PORT_NOT_LISTENING'",
            ],
            capture_output=True, text=True, timeout=10,
        )
        out = r.stdout.strip()
        if not out or "PORT_NOT_LISTENING" in out:
            return "not_listening"
        return out[:200]
    except Exception:
        return None


# Track when we first saw an "offline" state to decide when to force
# a transport reset (disconnect + reconnect).
_offline_first_seen: float = 0.0


def _adb_is_alive(adb_port: int) -> bool:
    """Check if the device is reachable via ADB (connect + shell echo).

    IMPORTANT: when the device is "offline" (VM booting, adbd
    initialising), we do NOT disconnect the ADB transport.  ADB needs
    the transport to stay alive so the ``CNXN`` / ``AUTH`` handshake can
    complete in the background.  Disconnecting on every poll resets the
    state machine and prevents the "offline → device" transition.

    A forced transport reset is only done after the device has been
    "offline" for >90 s, to handle genuinely stuck transports.
    """
    global _offline_first_seen  # noqa: PLW0603
    target = _adb_target(adb_port)
    adb = _adb_exe()
    try:
        # Try to connect first (idempotent — returns "already connected"
        # if the transport exists)
        conn = subprocess.run(
            [adb, "connect", target],
            capture_output=True, text=True, timeout=10,
        )
        conn_out = (conn.stdout + conn.stderr).strip()
        # "already connected" or "connected to" are both good
        if "connected" not in conn_out.lower() and "ok" not in conn_out.lower():
            console.print(f"  [dim]  adb connect response: {conn_out[:120]}[/]")
            return False

        # Check device status via 'adb devices' (catches offline state)
        devs = subprocess.run(
            [adb, "devices"],
            capture_output=True, text=True, timeout=5,
        )
        found_device = False
        for line in devs.stdout.strip().splitlines():
            if target in line and "device" in line and "offline" not in line:
                found_device = True
                break
        if not found_device:
            dev_lines = [l for l in devs.stdout.strip().splitlines() if target in l]
            if dev_lines:
                console.print(f"  [dim]  adb device status: {dev_lines[0].strip()}[/]")

            # ── Offline handling: be patient during boot ──────────────
            now = time.time()
            if _offline_first_seen == 0.0:
                _offline_first_seen = now

            elapsed = now - _offline_first_seen
            if elapsed > 90:
                # Stuck offline for >90s — force a transport reset.
                console.print(
                    f"  [dim]  offline for {int(elapsed)}s — "
                    f"resetting ADB transport[/]"
                )
                subprocess.run(
                    [adb, "disconnect", target],
                    capture_output=True, text=True, timeout=5,
                )
                time.sleep(2)
                # Try 'adb reconnect offline' if supported
                subprocess.run(
                    [adb, "reconnect", "offline"],
                    capture_output=True, text=True, timeout=5,
                )
                _offline_first_seen = now  # reset timer
            # Else: leave transport in place — ADB will transition
            # from "offline" → "device" once boot completes.
            return False

        # Device is online — reset offline tracker
        _offline_first_seen = 0.0

        # Then verify with a simple command
        r = subprocess.run(
            [adb, "-s", target, "shell", "echo ok"],
            capture_output=True, text=True, timeout=10,
        )
        return r.returncode == 0 and "ok" in r.stdout
    except subprocess.TimeoutExpired:
        console.print(f"  [dim]  adb check timeout (port {adb_port})[/]")
        return False
    except Exception as exc:
        console.print(f"  [dim]  adb check error: {exc}[/]")
        return False


def _kill_stale_tunnels(port: int) -> None:
    """Kill any existing SSH tunnel processes forwarding *port*.

    Previous runs may leave behind ``ssh -N -L <port>:...`` processes
    that hold the local port.  If we don't clean them up, the new tunnel
    immediately exits with "Address already in use".

    Tries multiple strategies (lsof, fuser, ss+kill, pkill) because not
    all tools are available in every environment (e.g. Docker).
    Each strategy runs regardless of whether a previous one killed
    something — multiple processes may hold the port.
    """
    killed = False

    def _port_still_held() -> bool:
        """Check if port is still bound (quick socket probe)."""
        import socket as _s
        try:
            s = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
            s.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.close()
            return False  # port is free
        except OSError:
            return True  # port is still held

    # ── Strategy 1: lsof ──────────────────────────────────────────────
    try:
        result = subprocess.run(
            ["lsof", "-ti", f":{port}"],
            capture_output=True, text=True, timeout=5,
        )
        pids = [p.strip() for p in result.stdout.strip().splitlines() if p.strip()]
        if pids:
            console.print(
                f"  [dim]Killing {len(pids)} stale process(es) on port {port} (lsof)…[/]"
            )
            for pid in pids:
                try:
                    os.kill(int(pid), 9)
                    killed = True
                except (ValueError, ProcessLookupError, PermissionError):
                    pass
            if killed:
                time.sleep(0.5)
                if not _port_still_held():
                    return
    except FileNotFoundError:
        pass  # lsof not installed
    except Exception:
        pass

    # ── Strategy 2: fuser ─────────────────────────────────────────────
    try:
        r = subprocess.run(
            ["fuser", "-k", f"{port}/tcp"],
            capture_output=True, timeout=5,
        )
        if r.returncode == 0:
            killed = True
            time.sleep(0.5)
            if not _port_still_held():
                return
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # ── Strategy 3: ss + manual kill ──────────────────────────────────
    try:
        r = subprocess.run(
            ["ss", "-tlnp", f"sport = :{port}"],
            capture_output=True, text=True, timeout=5,
        )
        import re as _re
        for pid_match in _re.finditer(r"pid=(\d+)", r.stdout):
            try:
                os.kill(int(pid_match.group(1)), 9)
                killed = True
            except (ProcessLookupError, PermissionError):
                pass
        if killed and not _port_still_held():
            return
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # ── Strategy 4: pkill SSH tunnels matching the port ───────────────
    try:
        subprocess.run(
            ["pkill", "-9", "-f", f"ssh.*-L.*{port}"],
            capture_output=True, timeout=5,
        )
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # ── Strategy 5: brute-force grep /proc (works in any Linux) ──────
    try:
        r = subprocess.run(
            ["sh", "-c",
             f"grep -rl 'ssh.*-L.*{port}' /proc/*/cmdline 2>/dev/null "
             f"| head -20 | grep -oP '/proc/\\K\\d+'"],
            capture_output=True, text=True, timeout=5,
        )
        for pid_s in r.stdout.strip().splitlines():
            try:
                os.kill(int(pid_s.strip()), 9)
                killed = True
            except (ValueError, ProcessLookupError, PermissionError):
                pass
    except Exception:
        pass

    if killed:
        time.sleep(1)


def _strip_ssh_banner(stderr_text: str) -> str:
    """Strip common SSH MOTD / banner text to expose the real error.

    Many SSH servers print multi-line banners like::

        ==================== ATTENTION ====================
        This is a private computing system …

    which fills the truncation budget and hides the actual error.
    """
    import re
    # Remove lines that look like banner decoration or generic warnings
    lines = stderr_text.splitlines()
    filtered: List[str] = []
    for line in lines:
        stripped = line.strip()
        # Skip decorative separator lines (=== / --- / ***)
        if stripped and all(c in "=-*#~ " for c in stripped):
            continue
        # Skip common banner phrases
        lower = stripped.lower()
        _banner_phrases = (
            "private computing system",
            "authorized users only",
            "you are warned",
            "disconnect at once",
            "unauthorized access",
            "monitored and recorded",
            "subject to audit",
            "by continuing",
            "you consent",
        )
        if any(bp in lower for bp in _banner_phrases):
            continue
        if stripped:
            filtered.append(stripped)
    return "\n".join(filtered)


def _port_is_free(port: int) -> bool:
    """Return True if we can bind to *port* on localhost."""
    import socket as _socket
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        s.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.close()
        return True
    except OSError:
        return False


def _setup_adb_tunnel(
    adb_port: int,
    ssh_host: str,
    ssh_port: int = 22,
    _max_attempts: int = 3,
) -> Optional[subprocess.Popen]:
    """Set up an SSH port-forward tunnel for ADB access to a remote
    Cuttlefish instance.

    Creates:  ``ssh -N -L <adb_port>:localhost:<adb_port> <ssh_host>``

    Retries up to *_max_attempts* times on transient failures (port
    conflicts, SSH protocol issues).

    Returns the tunnel ``Popen`` handle (caller must kill it later).
    """
    adb = _adb_exe()

    for attempt in range(1, _max_attempts + 1):
        # Kill stale tunnels from previous runs that may hold the port
        _kill_stale_tunnels(adb_port)

        if attempt == 1:
            # Kill local ADB server for a clean state (avoids stale
            # device entries).  Only on first attempt to avoid
            # repeatedly cycling the server.
            console.print("  [dim]Restarting local ADB server…[/]")
            subprocess.run(
                [adb, "kill-server"],
                capture_output=True, text=True, timeout=10,
            )
            time.sleep(1)
            subprocess.run(
                [adb, "start-server"],
                capture_output=True, text=True, timeout=10,
            )
            time.sleep(1)

        # Quick-check whether the port is free.
        # If still held after kill, try one more aggressive pass.
        if not _port_is_free(adb_port):
            console.print(
                f"  [dim]Port {adb_port} still held after cleanup, "
                f"retrying kill…[/]"
            )
            _kill_stale_tunnels(adb_port)
            time.sleep(2)
            if not _port_is_free(adb_port):
                console.print(
                    f"  [dim]Port {adb_port} still in use "
                    f"(attempt {attempt}/{_max_attempts}), "
                    f"trying tunnel anyway…[/]"
                )

        argv = [
            "ssh", "-N",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            "-p", str(ssh_port),
            "-L", f"{adb_port}:localhost:{adb_port}",
            ssh_host,
        ]
        console.print(
            f"  [dim]Setting up ADB tunnel: "
            f"localhost:{adb_port} → {ssh_host}:{adb_port}"
            f" (attempt {attempt}/{_max_attempts})[/]"
        )
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # Give tunnel a moment to establish
            time.sleep(4)
            if proc.poll() is not None:
                rc = proc.returncode
                _, stderr_bytes = proc.communicate(timeout=5)
                raw_err = (
                    stderr_bytes.decode(errors="replace").strip()
                    if stderr_bytes else ""
                )
                # Strip SSH banner text so the real error is visible
                real_err = _strip_ssh_banner(raw_err) or raw_err
                console.print(
                    f"  [red]ADB tunnel exited (rc={rc}, "
                    f"attempt {attempt}/{_max_attempts}): "
                    f"{real_err[:500]}[/]"
                )
                if attempt < _max_attempts:
                    time.sleep(2)
                    continue
                return None
            # Tunnel is alive
            return proc
        except Exception as exc:
            console.print(
                f"  [red]Failed to set up ADB tunnel "
                f"(attempt {attempt}/{_max_attempts}): {exc}[/]"
            )
            if attempt < _max_attempts:
                time.sleep(2)
                continue
            return None

    return None  # all attempts exhausted


def _kill_proc(proc: Optional[subprocess.Popen]) -> None:
    """Kill a Popen process if still running."""
    if proc is None:
        return
    try:
        proc.kill()
        proc.wait(timeout=5)
    except Exception:
        pass


# ── Crash pattern detection ───────────────────────────────────────────

# Severity tiers: FATAL definitely means the kernel is dead/corrupt,
# SANITIZER means an instrumention check fired (KASAN etc.), WARNING
# is a non-fatal kernel diagnostic that does NOT indicate the exploit
# worked or caused instability.

FATAL_CRASH_PATTERNS: List[str] = [
    "kernel panic",
    "Oops:",
    "BUG:",
    "general protection fault",
    "unable to handle kernel",
    "Kernel panic - not syncing",
    "Internal error:",
    "Bad mode in",
]

SANITIZER_PATTERNS: List[str] = [
    "KASAN:",
    "UBSAN:",
    "KMSAN:",
    "KCSAN:",
    "KFENCE:",
]

# These appear frequently in normal kernel operation or non-fatal
# paths.  They are logged but do NOT count as "crash_occurred".
WARNING_PATTERNS: List[str] = [
    "WARNING: CPU:",
    "Call Trace:",
    "lockdep warning",
    "Segfault",  # userspace segfault, not kernel crash
]

# Legacy flat list kept for backward-compat with code that imports it.
CRASH_PATTERNS: List[str] = (
    FATAL_CRASH_PATTERNS + SANITIZER_PATTERNS + WARNING_PATTERNS
)

SUCCESS_INDICATORS: List[str] = [
    "got root",
    "privilege escalation successful",
    "exploit succeeded",
    "now running as root",
    "[+] SUCCESS",
    "we are root",
    "root shell",
    "SYZPLOIT_UID_AFTER=0",
    "setresuid(0,0,0) succeeded",
    "running root payload",
    "made process root",
    "root payload:",
    "listening shell on port",
]

# Strings that look like success but often appear inside error
# messages.  Only trusted when coming from the verification wrapper's
# own tags, never from raw exploit output substring matching.
_AMBIGUOUS_SUCCESS_STRINGS = [
    "uid=0",
    "euid=0",
]


def _detect_crash(logs: str) -> Tuple[bool, str]:
    """Check if dmesg / output contains kernel crash patterns.

    Returns ``(crash_detected, matched_pattern)``.

    Only FATAL and SANITIZER patterns count as crashes.  WARNING
    patterns are logged separately but do not set crash_detected.
    """
    lower = logs.lower()
    for pat in FATAL_CRASH_PATTERNS:
        if pat.lower() in lower:
            return True, pat
    for pat in SANITIZER_PATTERNS:
        if pat.lower() in lower:
            return True, pat
    return False, ""


def _detect_warnings(logs: str) -> List[str]:
    """Return non-fatal warning patterns found in *logs*."""
    lower = logs.lower()
    return [p for p in WARNING_PATTERNS if p.lower() in lower]


def _classify_crash_severity(logs: str) -> str:
    """Classify the severity of kernel log output.

    Returns one of: 'fatal', 'sanitizer', 'warning', 'none'.
    """
    lower = logs.lower()
    for pat in FATAL_CRASH_PATTERNS:
        if pat.lower() in lower:
            return "fatal"
    for pat in SANITIZER_PATTERNS:
        if pat.lower() in lower:
            return "sanitizer"
    for pat in WARNING_PATTERNS:
        if pat.lower() in lower:
            return "warning"
    return "none"


def _detect_success(output: str) -> bool:
    """Check if exploit output contains **reliable** privilege-escalation
    success markers.

    Only trusts structured tags (SYZPLOIT_UID_AFTER=0) and explicit
    success phrases.  Ambiguous strings like bare 'uid=0' are NOT
    checked here — they can appear in error messages, usage text, or
    other non-success contexts and cause false positives.
    """
    lower = output.lower()
    return any(ind.lower() in lower for ind in SUCCESS_INDICATORS)


def _parse_uid(output: str, marker: str) -> Optional[int]:
    """Extract UID from exploit output near *marker*.

    Looks for the ``SYZPLOIT_UID_BEFORE=<N>`` / ``SYZPLOIT_UID_AFTER=<N>``
    tags that the verification wrapper prints from within the exploit
    process, or falls back to ``uid=<N>`` from ``id`` output.
    """
    idx = output.find(marker)
    if idx < 0:
        # Try to find the UID tags anywhere in the output as fallback
        if "BEFORE" in marker:
            m = re.search(r"SYZPLOIT_UID_BEFORE=(\d+)", output)
        else:
            m = re.search(r"SYZPLOIT_UID_AFTER=(\d+)", output)
        if m:
            return int(m.group(1))
        return None
    section = output[idx:idx + 500]
    # Prefer our structured tags (printed from within the exploit process)
    m = re.search(r"SYZPLOIT_UID(?:_BEFORE|_AFTER)?=(\d+)", section)
    if m:
        return int(m.group(1))
    # Fall back to parsing `id` output (uid=N)
    m = re.search(r"uid=(\d+)", section)
    return int(m.group(1)) if m else None


def _capture_kernel_state(
    *,
    use_adb: bool = False,
    adb_port: int = 6520,
    ssh: Optional["SSHSession"] = None,
) -> Dict[str, Any]:
    """Capture kernel state that's useful for pre/post exploit comparison.

    Gathers:
    - Slab cache statistics (/proc/slabinfo or /sys/kernel/slab/)
    - Security context (SELinux enforcing state)
    - Process UID/GID namespace info
    - Kernel version
    - Key kernel memory stats (/proc/meminfo)

    Returns a dict of captured state, or empty dict on failure.
    """
    state: Dict[str, Any] = {}

    def _run(cmd: str, timeout: int = 10) -> str:
        """Run a command and return stdout."""
        try:
            if use_adb:
                _, out, _ = _adb_run(cmd, adb_port, timeout=timeout)
                return out or ""
            elif ssh:
                _, out, _ = ssh.run(cmd, timeout=timeout)
                return out or ""
        except Exception:
            pass
        return ""

    # Slab cache info — parse the caches most relevant to exploits
    slabinfo = _run("cat /proc/slabinfo 2>/dev/null || true")
    if slabinfo and "slabdata" in slabinfo.lower():
        slab_caches: Dict[str, Dict[str, int]] = {}
        for line in slabinfo.strip().splitlines()[2:]:  # skip 2 header lines
            parts = line.split()
            if len(parts) >= 6:
                name = parts[0]
                try:
                    slab_caches[name] = {
                        "active_objs": int(parts[1]),
                        "num_objs": int(parts[2]),
                        "objsize": int(parts[3]),
                        "objperslab": int(parts[4]),
                        "pagesperslab": int(parts[5]),
                    }
                except (ValueError, IndexError):
                    pass
        # Store the full dict but also extract key exploit caches
        _key_caches = [
            "kmalloc-64", "kmalloc-128", "kmalloc-192", "kmalloc-256",
            "kmalloc-512", "kmalloc-1k", "kmalloc-2k", "kmalloc-4k",
            "cred_jar", "files_cache", "task_struct", "signal_cache",
            "pid", "mm_struct", "inode_cache", "dentry",
            "ip6_dst_cache", "ip_dst_cache", "skbuff_head_cache",
        ]
        state["slab_key_caches"] = {
            k: v for k, v in slab_caches.items() if k in _key_caches
        }
        state["slab_total_caches"] = len(slab_caches)

    # SELinux state
    selinux = _run("cat /sys/fs/selinux/enforce 2>/dev/null || echo -1")
    if selinux.strip() in ("0", "1"):
        state["selinux_enforcing"] = int(selinux.strip())

    # Kernel version
    version = _run("uname -r 2>/dev/null || true")
    if version.strip():
        state["kernel_version"] = version.strip()

    # Memory overview (active slab, total slab, freeable pages)
    meminfo = _run(
        "grep -E '^(Slab|SReclaimable|SUnreclaim|MemFree|MemAvailable):' "
        "/proc/meminfo 2>/dev/null || true"
    )
    if meminfo.strip():
        mem: Dict[str, int] = {}
        for line in meminfo.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                try:
                    mem[parts[0].rstrip(":")] = int(parts[1])
                except ValueError:
                    pass
        state["meminfo"] = mem

    # Current process security context
    ctx_str = _run("id 2>/dev/null || true")
    if ctx_str.strip():
        state["security_context"] = ctx_str.strip()[:200]

    return state


def _diff_kernel_state(
    pre: Dict[str, Any],
    post: Dict[str, Any],
) -> str:
    """Generate a human-readable diff of kernel state before/after exploit.

    Focuses on changes meaningful for exploit verification:
    - Slab cache object count changes (indicates alloc/free activity)
    - SELinux enforcement changes
    - Memory pressure changes
    """
    parts: List[str] = ["=== Kernel State Diff (pre → post exploit) ==="]

    # Slab cache diff
    pre_slabs = pre.get("slab_key_caches", {})
    post_slabs = post.get("slab_key_caches", {})
    slab_changes: List[str] = []
    for cache in sorted(set(pre_slabs) | set(post_slabs)):
        pre_active = pre_slabs.get(cache, {}).get("active_objs", 0)
        post_active = post_slabs.get(cache, {}).get("active_objs", 0)
        delta = post_active - pre_active
        if delta != 0:
            slab_changes.append(
                f"  {cache}: {pre_active} → {post_active} ({delta:+d} objects)"
            )
    if slab_changes:
        parts.append(f"\n[SLAB CHANGES] ({len(slab_changes)} caches changed)")
        parts.extend(slab_changes)
    else:
        parts.append("\n[SLAB] No slab cache object count changes detected")

    # SELinux
    pre_sel = pre.get("selinux_enforcing")
    post_sel = post.get("selinux_enforcing")
    if pre_sel is not None and post_sel is not None and pre_sel != post_sel:
        parts.append(
            f"\n[SELINUX] Enforcement changed: {pre_sel} → {post_sel}"
        )
        if post_sel == 0:
            parts.append("  ** SELinux DISABLED — exploit may have toggled enforcement **")

    # Memory
    pre_mem = pre.get("meminfo", {})
    post_mem = post.get("meminfo", {})
    for key in ["Slab", "SReclaimable", "MemFree"]:
        pv = pre_mem.get(key, 0)
        av = post_mem.get(key, 0)
        if pv and av and abs(av - pv) > 100:  # >100 kB change
            parts.append(f"[MEM] {key}: {pv} → {av} kB ({av - pv:+d} kB)")

    return "\n".join(parts)


def _dmesg_diff(before: str, after: str) -> str:
    """Return only the new lines in *after* that don't appear in *before*.

    Uses the dmesg timestamp prefix to anchor the diff rather than a
    naive set-membership check (which silently drops repeated messages).
    Falls back to suffix matching when timestamps are absent.
    """
    before_lines = before.strip().splitlines()
    after_lines = after.strip().splitlines()

    if not after_lines:
        return ""
    if not before_lines:
        return "\n".join(after_lines)

    # Try to find the last *before* line in the *after* output.
    # dmesg is append-only so everything after that anchor is new.
    last_before = before_lines[-1].strip()
    anchor_idx = -1
    for i in range(len(after_lines) - 1, -1, -1):
        if after_lines[i].strip() == last_before:
            anchor_idx = i
            break

    if anchor_idx >= 0:
        new = after_lines[anchor_idx + 1:]
    else:
        # Fallback: simple set diff (preserves duplicates in `after`)
        before_set = set(before_lines)
        new = [l for l in after_lines if l not in before_set]

    return "\n".join(new)


# ── VM lifecycle helpers ──────────────────────────────────────────────


def _is_remote_host(host: Optional[str]) -> bool:
    """Return True if *host* refers to a remote machine (not localhost)."""
    if not host:
        return False
    return host not in ("localhost", "127.0.0.1", "::1")


def _run_lifecycle_cmd(
    cmd: str,
    *,
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    timeout: int = 120,
) -> Tuple[bool, str]:
    """Execute a **blocking** VM lifecycle command, locally or via SSH.

    If *ssh_host* is a remote host the command is executed on the remote
    machine via ``ssh``.  Used for commands that are expected to finish
    (e.g. ``stop.sh``).
    """
    try:
        if _is_remote_host(ssh_host):
            argv = [
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-p", str(ssh_port),
                ssh_host,
                cmd,
            ]
            console.print(f"  [dim]Running on {ssh_host}: {cmd[:80]}…[/]")
            result = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout,
            )
        else:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=timeout,
            )
        output = result.stdout + result.stderr
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, f"command timed out after {timeout}s"
    except Exception as exc:
        return False, str(exc)


def _run_start_cmd(
    start_cmd: str,
    *,
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
) -> Tuple[bool, Optional[subprocess.Popen]]:
    """Launch the VM start command via ``Popen`` (non‑blocking).

    Cuttlefish start scripts (``run.sh``, ``launch_cvd``) are
    long‑running processes that never exit while the VM is alive.
    We use ``Popen`` so Python does not block.  The caller stores the
    returned process handle and can ``kill()`` it during cleanup —
    exactly the same pattern the old syzploit code used.

    Returns ``(True, proc)`` on success, ``(False, None)`` on error.
    """
    try:
        if _is_remote_host(ssh_host):
            argv = [
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-p", str(ssh_port),
                ssh_host,
                start_cmd,
            ]
            console.print(
                f"  [dim]Starting on {ssh_host} (Popen): {start_cmd[:80]}…[/]"
            )
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            console.print(
                f"  [dim]Starting locally (Popen): {start_cmd[:80]}…[/]"
            )
            proc = subprocess.Popen(
                start_cmd, shell=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        return True, proc
    except Exception as exc:  # noqa: BLE001
        console.print(f"  [red]Start command failed: {exc}[/]")
        return False, None



def _run_stop_cmd(
    stop_cmd: str,
    *,
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    timeout: int = 60,
) -> Tuple[bool, str]:
    """Execute the user-supplied VM stop command (blocking)."""
    return _run_lifecycle_cmd(
        stop_cmd, ssh_host=ssh_host, ssh_port=ssh_port, timeout=timeout,
    )


def _is_gdb_start(start_cmd: Optional[str]) -> bool:
    """Return True if the start command implies a GDB-enabled launch."""
    return bool(start_cmd and "gdb" in start_cmd.lower())


def _qmp_check_running(
    ssh_host: Optional[str],
    ssh_port: int = 22,
    instance: int = 20,
) -> Optional[bool]:
    """Check if QEMU is running via QMP socket on the remote host.

    Returns ``True`` if running, ``False`` if paused, ``None`` if QMP
    is unavailable (socket not found, SSH error, etc.).
    """
    if not ssh_host or not _is_remote_host(ssh_host):
        return None
    # Cuttlefish convention: QMP socket path
    qmp_script = (
        "import socket, json, time, glob, sys\n"
        f"paths = glob.glob('/home/*/challenge-*/challenge-*/cuttlefish/instances/cvd-{instance}/internal/qemu_monitor.sock')\n"
        "if not paths:\n"
        "    print('NO_SOCKET')\n"
        "    sys.exit(0)\n"
        "try:\n"
        "    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
        "    s.connect(paths[0])\n"
        "    s.settimeout(3)\n"
        "    s.recv(4096)\n"
        '    s.send(json.dumps({"execute": "qmp_capabilities"}).encode() + b"\\n")\n'
        "    time.sleep(0.3)\n"
        "    s.recv(4096)\n"
        '    s.send(json.dumps({"execute": "query-status"}).encode() + b"\\n")\n'
        "    time.sleep(0.5)\n"
        "    data = s.recv(4096).decode()\n"
        "    s.close()\n"
        '    if "running" in data and "true" in data.lower():\n'
        "        print('RUNNING')\n"
        "    else:\n"
        "        print('PAUSED')\n"
        "except Exception as e:\n"
        "    print(f'ERROR:{e}')\n"
    )
    try:
        r = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             "-p", str(ssh_port), ssh_host,
             "python3", "-"],
            input=qmp_script,
            capture_output=True, text=True, timeout=15,
        )
        out = r.stdout.strip()
        if "RUNNING" in out:
            return True
        if "PAUSED" in out:
            return False
        return None
    except Exception:
        return None


def _send_gdb_continue(
    gdb_port: int = 1234,
    *,
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    setup_tunnels: bool = False,
    max_retries: int = 5,
    remote_wait_timeout: int = 90,
    instance: int = 20,
) -> bool:
    """Send GDB 'continue' to the kernel via raw GDB-RSP protocol.

    When the VM is launched with ``gdb_run.sh``, QEMU waits for a
    debugger to connect and send *continue* before the kernel boots.

    Key insight: when using an SSH tunnel, ``create_connection`` to the
    *local* tunnel port succeeds immediately (SSH accepts locally) even
    when the *remote* GDB port isn't open yet.  This causes
    ``BrokenPipeError`` when we try to send data.  To avoid this, we
    first wait for the GDB port to open *on the remote host* via an SSH
    ``nc -z`` probe, then set up the tunnel and connect.

    Protocol observed from QEMU's GDB stub:
    - No initial stop-reply packet (recv times out).
    - Send ``+`` (ACK sync) then ``$c#63`` (continue).
    - Stub replies with ``+`` (ACK).

    After sending continue, verifies QEMU state via QMP to confirm the
    VM is actually running.  If paused, retries.
    """
    import socket

    tunnel_proc: Optional[subprocess.Popen] = None
    local_port = gdb_port if not setup_tunnels else 11234 + (gdb_port % 1000)

    try:
        # ── 1. Wait for GDB port on the remote host ─────────────────
        # This is critical: the SSH tunnel will accept local connections
        # even if the remote port isn't open, causing BrokenPipe.  We
        # probe the remote port directly via SSH before proceeding.
        if ssh_host and _is_remote_host(ssh_host) and setup_tunnels:
            console.print(
                f"  [dim]Waiting for GDB port {gdb_port} on "
                f"{ssh_host} (up to {remote_wait_timeout}s)…[/]"
            )
            probe_cmd = (
                f"for i in $(seq 1 {remote_wait_timeout}); do "
                f"  if nc -z localhost {gdb_port} 2>/dev/null; then "
                f"    echo OPEN; exit 0; "
                f"  fi; "
                f"  sleep 1; "
                f"done; echo TIMEOUT; exit 1"
            )
            try:
                probe_result = subprocess.run(
                    ["ssh", "-o", "StrictHostKeyChecking=no",
                     "-p", str(ssh_port), ssh_host,
                     probe_cmd],
                    capture_output=True, text=True,
                    timeout=remote_wait_timeout + 15,
                )
                probe_out = probe_result.stdout.strip()
                if "OPEN" in probe_out:
                    console.print(
                        f"  [green]GDB port {gdb_port} is open on "
                        f"{ssh_host}[/]"
                    )
                else:
                    console.print(
                        f"  [red]GDB port {gdb_port} did NOT open on "
                        f"{ssh_host} within {remote_wait_timeout}s[/]"
                    )
                    return False
            except subprocess.TimeoutExpired:
                console.print(
                    f"  [red]Timeout probing GDB port on {ssh_host}[/]"
                )
                return False
            except Exception as exc:
                console.print(
                    f"  [yellow]Cannot probe remote GDB port: {exc} "
                    f"— will attempt tunnel anyway[/]"
                )

        # ── 2. Set up SSH tunnel ─────────────────────────────────────
        if ssh_host and _is_remote_host(ssh_host) and setup_tunnels:
            # Kill any stale SSH tunnel occupying the local port.
            # Previous runs may leave zombie tunnels that prevent
            # the new tunnel from binding and forward to a dead stub.
            _kill_stale_tunnels(local_port)

            console.print(
                f"  [dim]Setting up GDB tunnel: "
                f"localhost:{local_port} → {ssh_host}:{gdb_port}[/]"
            )
            tunnel_cmd = [
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-N", "-L", f"{local_port}:localhost:{gdb_port}",
                ssh_host,
            ]
            tunnel_proc = subprocess.Popen(
                tunnel_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            time.sleep(2)
        elif not setup_tunnels:
            # Local connection — wait for port directly
            console.print(
                f"  [dim]Waiting for GDB port localhost:{local_port}…[/]"
            )
            deadline = time.time() + remote_wait_timeout
            while time.time() < deadline:
                try:
                    probe = socket.create_connection(
                        ("localhost", local_port), timeout=2,
                    )
                    probe.close()
                    console.print("  [dim]GDB port is open[/]")
                    break
                except (ConnectionRefusedError, OSError):
                    time.sleep(1)
            else:
                console.print("  [yellow]Timeout waiting for GDB port[/]")
                return False
            time.sleep(1)  # brief settle after port opens

        # ── 3. Connect and send continue (with retries) ──────────────
        for attempt in range(1, max_retries + 1):
            continue_sent = False
            sock: Optional[socket.socket] = None
            try:
                console.print(
                    f"  [dim]Connecting to GDB stub at "
                    f"localhost:{local_port} "
                    f"(attempt {attempt}/{max_retries})…[/]"
                )
                sock = socket.create_connection(
                    ("localhost", local_port), timeout=10,
                )
                sock.settimeout(5)

                # Read any initial data from the stub.  QEMU on
                # Cuttlefish typically sends nothing (timeout), but
                # some builds send a stop-reply like $T05...#XX.
                try:
                    initial_data = sock.recv(512)
                    if initial_data:
                        console.print(
                            f"  [dim]GDB stub initial: "
                            f"{initial_data[:80]!r}[/]"
                        )
                except socket.timeout:
                    pass  # expected — no initial packet

                # Sync ACK then continue
                sock.send(b"+")
                time.sleep(0.1)
                sock.send(b"$c#63")
                continue_sent = True

                # Wait for ACK
                got_ack = False
                try:
                    response = sock.recv(64)
                    if response and b"+" in response:
                        console.print(
                            "  [green]GDB stub acknowledged "
                            "continue (+)[/]"
                        )
                        got_ack = True
                    elif response:
                        console.print(
                            f"  [dim]GDB response: "
                            f"{response[:60]!r}[/]"
                        )
                    else:
                        console.print(
                            "  [dim]Empty response[/]"
                        )
                except socket.timeout:
                    console.print(
                        "  [dim]No ACK received (timeout)[/]"
                    )

                # Just close the socket — do NOT send $D#44 detach.
                # QEMU 6.2 re-pauses the VM when it receives a detach
                # packet, which prevents the kernel from booting.
                sock.close()

                # ── Verify QEMU is actually running via QMP ──────
                # If no ACK was received the continue may not have
                # taken effect.  Check QMP and retry if paused.
                if not got_ack:
                    time.sleep(2)
                    qmp_state = _qmp_check_running(
                        ssh_host, ssh_port, instance,
                    )
                    if qmp_state is True:
                        console.print(
                            "  [green]QMP confirms VM is running[/]"
                        )
                        return True
                    elif qmp_state is False:
                        console.print(
                            "  [yellow]QMP says VM is paused — "
                            "retrying continue…[/]"
                        )
                        time.sleep(2)
                        continue  # retry loop
                    else:
                        # QMP unavailable — trust the send
                        console.print(
                            "  [dim]QMP unavailable — "
                            "assuming continue worked[/]"
                        )
                        return True

                console.print(
                    "  [green]GDB continue sent successfully[/]"
                )
                return True

            except (ConnectionResetError, BrokenPipeError) as exc:
                kind = type(exc).__name__
                if continue_sent:
                    console.print(
                        f"  [dim]{kind} after continue "
                        f"(VM likely resumed)[/]"
                    )
                    return True
                else:
                    backoff = min(2 ** attempt, 10)
                    console.print(
                        f"  [yellow]{kind} before continue "
                        f"(attempt {attempt}/{max_retries}, "
                        f"retrying in {backoff}s)[/]"
                    )
                    time.sleep(backoff)
            except Exception as exc:
                backoff = min(2 ** attempt, 10)
                console.print(
                    f"  [yellow]GDB attempt {attempt} failed: "
                    f"{exc} (retrying in {backoff}s)[/]"
                )
                time.sleep(backoff)
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass

        console.print(
            f"  [red]All GDB continue attempts failed "
            f"({max_retries} retries exhausted)[/]"
        )
        return False

    finally:
        if tunnel_proc is not None:
            tunnel_proc.terminate()
            try:
                tunnel_proc.wait(timeout=2)
            except Exception:
                tunnel_proc.kill()


# ── Target system information collection ──────────────────────────────


def collect_target_system_info(
    *,
    ssh_host: str,
    ssh_port: int = 22,
    adb_port: int = 6520,
    use_adb: bool = True,
    instance: Optional[int] = None,
    start_cmd: Optional[str] = None,
    stop_cmd: Optional[str] = None,
    gdb_port: int = 1234,
    setup_tunnels: bool = True,
    work_dir: Optional[str] = None,
    keep_alive: bool = False,
    kernel_image: Optional[str] = None,
) -> Dict[str, Any]:
    """Boot the target VM and collect system information.

    This is used when only a CVE ID or blog URL was provided — we have
    no crash report, so we need to discover the target kernel version,
    available symbols, KASAN status, etc. from the running system.

    Workflow:
        1. Start VM (if start_cmd provided)
        2. GDB continue (if gdb_run.sh)
        3. Set up ADB tunnel
        4. Wait for ADB
        5. Collect kernel version, arch, Android props, kallsyms, modules
        6. Save kallsyms to a local file for symbol checking
        7. Clean up (stop VM if not persistent)

    Returns a dict with all collected info suitable for constructing
    a ``TargetSystemInfo`` model.
    """
    from ..core.models import TargetSystemInfo
    import tempfile

    info: Dict[str, Any] = {}
    actual_adb_port = _calc_adb_port(instance, adb_port)
    vm_proc: Optional[subprocess.Popen] = None
    adb_tunnel: Optional[subprocess.Popen] = None

    try:
        # ── Step 0: Stop any stale instance ──────────────────────────
        # A previous run (or Ctrl+C) may have left the VM running.
        # If we start a new one without stopping first, the GDB port
        # (1234) and ADB port may still be held by the old process,
        # causing the new instance to fail silently.
        if start_cmd and stop_cmd:
            console.print("  [dim]collect_target_info: stopping stale instance…[/]")
            _run_stop_cmd(
                stop_cmd, ssh_host=ssh_host, ssh_port=ssh_port, timeout=30,
            )
            time.sleep(2)

        # ── Step 1: Start VM ─────────────────────────────────────────
        if start_cmd:
            console.print("  [dim]collect_target_info: starting VM…[/]")
            ok, vm_proc = _run_start_cmd(
                start_cmd, ssh_host=ssh_host, ssh_port=ssh_port,
            )
            if not ok:
                info["error"] = "failed to start VM"
                return info
            time.sleep(10)

        # ── Step 2: GDB continue ─────────────────────────────────────
        if start_cmd and _is_gdb_start(start_cmd) and gdb_port:
            console.print("  [dim]collect_target_info: sending GDB continue…[/]")
            gdb_ok = _send_gdb_continue(
                gdb_port, ssh_host=ssh_host, ssh_port=ssh_port,
                setup_tunnels=setup_tunnels,
                instance=instance or 20,
            )
            if gdb_ok:
                console.print("  [dim]collect_target_info: waiting for boot…[/]")
                time.sleep(30)
            else:
                info["notes"] = ["GDB continue failed — VM may not boot"]

        # ── Step 3: ADB tunnel ───────────────────────────────────────
        if use_adb and setup_tunnels and ssh_host:
            console.print(f"  [dim]collect_target_info: ADB tunnel port {actual_adb_port}…[/]")
            adb_tunnel = _setup_adb_tunnel(actual_adb_port, ssh_host, ssh_port)
            if adb_tunnel:
                time.sleep(3)

        # ── Step 4: Wait for ADB ─────────────────────────────────────
        # GDB-started VMs use 1 CPU and boot slowly (~7 min wall clock
        # on ARM64 QEMU).  Allow up to 10 min for GDB boots and 4 min
        # for normal boots.
        gdb_boot = bool(start_cmd and _is_gdb_start(start_cmd) and gdb_port)
        max_adb_polls = 60 if gdb_boot else 24  # 10 min vs 4 min
        adb_alive = False
        if use_adb:
            console.print(
                f"  [dim]collect_target_info: waiting for ADB "
                f"(up to {max_adb_polls * 10}s)…[/]"
            )
            for attempt in range(max_adb_polls):
                if _adb_is_alive(actual_adb_port):
                    adb_alive = True
                    console.print("  [dim]collect_target_info: ADB connected[/]")
                    break
                if attempt % 6 == 5:
                    console.print(
                        f"  [dim]  still waiting… ({(attempt + 1) * 10}s)[/]"
                    )
                time.sleep(10)
            if not adb_alive:
                console.print(
                    "  [yellow]ADB failed — falling back to SSH via build host[/]"
                )

        # ── Step 5: Collect system info ──────────────────────────────
        # Use ADB if alive, otherwise fall back to SSH commands on build host
        def _run_cmd(cmd: str) -> str:
            if adb_alive:
                rc, out, _ = _adb_run(cmd, actual_adb_port, timeout=15)
                return out.strip() if rc == 0 else ""
            else:
                # Run through SSH on the build host
                # For Android VMs, 'adb shell' may not work but we can
                # try direct SSH to the VM or run the command on the host
                try:
                    ok, output = _run_lifecycle_cmd(
                        cmd, ssh_host=ssh_host, ssh_port=ssh_port,
                        timeout=15,
                    )
                    return output.strip() if ok else ""
                except Exception:
                    return ""

        console.print("  [dim]collect_target_info: collecting system info…[/]")

        # uname
        info["uname_a"] = _run_cmd("uname -a")
        info["kernel_release"] = _run_cmd("uname -r")
        info["arch"] = _run_cmd("uname -m")
        info["kernel_version"] = _run_cmd("uname -v")

        # Android properties
        info["android_version"] = _run_cmd("getprop ro.build.version.release")
        info["security_patch"] = _run_cmd("getprop ro.build.version.security_patch")
        info["build_type"] = _run_cmd("getprop ro.build.type")
        info["device_model"] = _run_cmd("getprop ro.product.model")

        # SELinux
        selinux_raw = _run_cmd("getenforce")
        info["selinux_mode"] = selinux_raw.lower()
        info["selinux_enforcing"] = selinux_raw.lower() == "enforcing"

        # Loaded kernel modules
        lsmod_out = _run_cmd("lsmod 2>/dev/null || cat /proc/modules 2>/dev/null")
        if lsmod_out:
            mod_lines = lsmod_out.strip().splitlines()
            info["loaded_modules"] = [l.split()[0] for l in mod_lines if l.strip()]
        else:
            info["loaded_modules"] = []

        # KASAN check (from dmesg or /proc/version)
        version_str = _run_cmd("cat /proc/version")
        kasan_enabled = "kasan" in version_str.lower()
        dmesg_head = _run_cmd("dmesg | head -200")
        if "kasan" in dmesg_head.lower():
            kasan_enabled = True
        info["kasan_enabled"] = kasan_enabled
        info["dmesg_boot_excerpt"] = dmesg_head[:5000]

        # /proc/config.gz availability
        config_gz = _run_cmd("test -f /proc/config.gz && echo yes || echo no")
        info["config_gz_available"] = config_gz == "yes"

        # ── Step 6: Fetch and save kallsyms ──────────────────────────
        console.print("  [dim]collect_target_info: fetching kallsyms…[/]")
        kallsyms_text = ""
        if adb_alive:
            rc, ks_out, _ = _adb_run("cat /proc/kallsyms", actual_adb_port, timeout=60)
            if rc == 0 and len(ks_out) > 100:
                kallsyms_text = ks_out
            else:
                rc2, ks_out2, _ = _adb_run(
                    "su -c 'cat /proc/kallsyms'", actual_adb_port, timeout=60,
                )
                if rc2 == 0 and len(ks_out2) > 100:
                    kallsyms_text = ks_out2
        else:
            # SSH fallback — run on build host (which can SSH to VM)
            ok, ks_out = _run_lifecycle_cmd(
                "cat /proc/kallsyms",
                ssh_host=ssh_host, ssh_port=ssh_port, timeout=60,
            )
            if ok and len(ks_out) > 100:
                kallsyms_text = ks_out

        # Check if addresses are zeroed (kptr_restrict enabled)
        if kallsyms_text:
            sample_lines = [l for l in kallsyms_text.splitlines()[:20] if l.strip()]
            all_zeroed = sample_lines and all(
                l.strip().startswith("0000000000000000") for l in sample_lines
            )
            if all_zeroed and not adb_alive:
                # SSH fallback — try to disable kptr_restrict via SSH
                console.print(
                    "  [dim]collect_target_info: kallsyms addresses zeroed "
                    "(kptr_restrict) — attempting to disable via SSH…[/]"
                )
                _run_lifecycle_cmd(
                    "echo 0 > /proc/sys/kernel/kptr_restrict",
                    ssh_host=ssh_host, ssh_port=ssh_port, timeout=10,
                )
                # Re-fetch
                ok_ks, ks_retry = _run_lifecycle_cmd(
                    "cat /proc/kallsyms",
                    ssh_host=ssh_host, ssh_port=ssh_port, timeout=60,
                )
                if ok_ks and len(ks_retry) > 100:
                    retry_lines = [l for l in ks_retry.splitlines()[:5] if l.strip()]
                    if retry_lines and not all(
                        l.strip().startswith("0000000000000000") for l in retry_lines
                    ):
                        kallsyms_text = ks_retry
                        console.print(
                            "  [dim]  kptr_restrict disabled via SSH[/]"
                        )
            elif all_zeroed and adb_alive:
                console.print(
                    "  [dim]collect_target_info: kallsyms addresses zeroed "
                    "(kptr_restrict) — attempting to disable…[/]"
                )

                adb = _adb_exe()
                target = _adb_target(actual_adb_port)

                def _kptr_is_disabled() -> bool:
                    """Read kptr_restrict value to verify it is 0."""
                    rc_v, out_v, _ = _adb_run(
                        "cat /proc/sys/kernel/kptr_restrict",
                        actual_adb_port, timeout=10,
                    )
                    return rc_v == 0 and out_v.strip() == "0"

                kptr_disabled = False

                # Method 0: adb root — restarts adbd as root (userdebug/eng)
                if not kptr_disabled:
                    try:
                        console.print(
                            "  [dim]  Trying adb root…[/]"
                        )
                        rr = subprocess.run(
                            [adb, "-s", target, "root"],
                            capture_output=True, text=True, timeout=15,
                        )
                        root_out = (rr.stdout + rr.stderr).strip().lower()
                        if "already" in root_out or "restarting" in root_out:
                            import time as _t0
                            _t0.sleep(3)  # wait for adbd restart
                            # Reconnect ADB after root restart
                            subprocess.run(
                                [adb, "connect", target],
                                capture_output=True, text=True, timeout=10,
                            )
                            _t0.sleep(1)
                            # Now try writing as root shell
                            _adb_run(
                                "echo 0 > /proc/sys/kernel/kptr_restrict",
                                actual_adb_port, timeout=10,
                            )
                            if _kptr_is_disabled():
                                console.print(
                                    "  [dim]  kptr_restrict disabled "
                                    "via adb root[/]"
                                )
                                kptr_disabled = True
                    except Exception as _e:
                        console.print(
                            f"  [dim]  adb root failed: {_e}[/]"
                        )

                # Methods 1-4: shell commands with various su invocations
                # Pass args as separate list items so ADB correctly forwards
                # the shell redirection to the device.
                if not kptr_disabled:
                    disable_arg_lists = [
                        # su -c (common rooted devices)
                        [adb, "-s", target, "shell",
                         "su", "-c",
                         "echo 0 > /proc/sys/kernel/kptr_restrict"],
                        # su root -c
                        [adb, "-s", target, "shell",
                         "su", "root", "-c",
                         "echo 0 > /proc/sys/kernel/kptr_restrict"],
                        # Direct (if already root)
                        [adb, "-s", target, "shell",
                         "echo", "0", ">",
                         "/proc/sys/kernel/kptr_restrict"],
                        # su with sh -c wrapper
                        [adb, "-s", target, "shell",
                         "su", "-c",
                         "sh -c 'echo 0 > /proc/sys/kernel/kptr_restrict'"],
                    ]
                    for i, argv in enumerate(disable_arg_lists, 1):
                        try:
                            console.print(
                                f"  [dim]  Trying method {i}…[/]"
                            )
                            subprocess.run(
                                argv, capture_output=True, text=True,
                                timeout=10,
                            )
                            if _kptr_is_disabled():
                                console.print(
                                    f"  [dim]  kptr_restrict disabled "
                                    f"via method {i}[/]"
                                )
                                kptr_disabled = True
                                break
                        except Exception:
                            pass

                if kptr_disabled:
                    import time as _time
                    _time.sleep(0.5)
                    # Re-read kallsyms now that kptr_restrict is disabled
                    rc3, ks_out3, _ = _adb_run(
                        "su -c 'cat /proc/kallsyms'", actual_adb_port,
                        timeout=60,
                    )
                    if rc3 == 0 and len(ks_out3) > 100:
                        kallsyms_text = ks_out3
                    else:
                        rc4, ks_out4, _ = _adb_run(
                            "cat /proc/kallsyms", actual_adb_port, timeout=60,
                        )
                        if rc4 == 0 and len(ks_out4) > 100:
                            kallsyms_text = ks_out4
                else:
                    console.print(
                        "  [yellow]collect_target_info: could not disable "
                        "kptr_restrict — all methods failed[/]"
                    )

        if kallsyms_text:
            info["kallsyms_available"] = True
            # Count non-zero-address symbols
            info["symbol_count"] = sum(
                1 for line in kallsyms_text.splitlines()
                if line.strip() and not line.strip().startswith("0000000000000000")
            )
            # Save to file
            save_dir = work_dir or tempfile.mkdtemp(prefix="syzploit_target_info_")
            kallsyms_path = os.path.join(save_dir, "kallsyms")
            with open(kallsyms_path, "w") as f:
                f.write(kallsyms_text)
            info["kallsyms_path"] = kallsyms_path
            console.print(
                f"  [dim]collect_target_info: saved {info['symbol_count']} "
                f"symbols to {kallsyms_path}[/]"
            )
        else:
            info["kallsyms_available"] = False
            info["symbol_count"] = 0
            info["notes"] = info.get("notes", []) + [
                "kallsyms not readable (kernel may restrict /proc/kallsyms to root)"
            ]

        # ── Fallback: Extract kallsyms from kernel Image via vmlinux-to-elf ──
        # If we have no usable kallsyms but have a kernel Image file,
        # try to extract the embedded kallsyms table using vmlinux-to-elf.
        if (
            not info.get("kallsyms_available")
            and kernel_image
        ):
            extracted = _extract_vmlinux_from_image(
                kernel_image, ssh_host, ssh_port, work_dir
            )
            if extracted:
                vmlinux_p, kallsyms_p, sym_count = extracted
                info["kallsyms_available"] = True
                info["symbol_count"] = sym_count
                info["kallsyms_path"] = kallsyms_p
                info["vmlinux_path"] = vmlinux_p
                info.setdefault("notes", [])
                info["notes"] = [
                    n for n in info.get("notes", [])
                    if "kallsyms not readable" not in n
                ]
                info["notes"].append(
                    f"Symbols extracted from kernel Image via vmlinux-to-elf "
                    f"({sym_count} symbols)"
                )
                console.print(
                    f"  [dim]collect_target_info: extracted {sym_count} "
                    f"symbols from kernel Image[/]"
                )

        # Save config.gz if available
        if info.get("config_gz_available") and adb_alive:
            save_dir = work_dir or os.path.dirname(info.get("kallsyms_path", "")) or tempfile.mkdtemp(prefix="syzploit_target_info_")
            config_gz_path = os.path.join(save_dir, "config.gz")
            adb = _adb_exe()
            target = _adb_target(actual_adb_port)
            try:
                subprocess.run(
                    [adb, "-s", target, "pull", "/proc/config.gz", config_gz_path],
                    capture_output=True, timeout=30,
                )
                if os.path.isfile(config_gz_path):
                    info["config_gz_path"] = config_gz_path
            except Exception:
                pass

    finally:
        # ── Cleanup ──────────────────────────────────────────────────
        # When keep_alive=True, leave the VM and ADB tunnel running
        # so subsequent run_target_command calls can reuse them.
        if keep_alive:
            # Export to source_tools module globals for reuse
            try:
                from ..orchestrator import source_tools as _st
                if adb_tunnel is not None:
                    _st._adb_tunnel_proc = adb_tunnel
                if vm_proc is not None:
                    _st._vm_proc = vm_proc
                _st._adb_port_active = actual_adb_port
            except Exception:
                pass  # best-effort
            console.print(
                "  [dim]collect_target_info: VM and ADB tunnel "
                "kept alive for further investigation[/]"
            )
        else:
            if adb_tunnel is not None:
                _kill_proc(adb_tunnel)
            if vm_proc is not None:
                if stop_cmd:
                    _run_stop_cmd(stop_cmd, ssh_host=ssh_host, ssh_port=ssh_port)
                else:
                    _kill_proc(vm_proc)

    return info


# ── Verification wrapper ──────────────────────────────────────────────


def _build_verify_wrapper(
    exploit_remote_path: str,
    remote_dir: str,
    timeout: int,
) -> str:
    """Build a shell script that runs the exploit and checks UID *from
    within the exploit's own process*.

    Kernel privilege-escalation exploits modify the *current process's*
    ``struct cred``.  Running ``id`` in a parent shell before/after the
    exploit will always report the shell's (unchanged) UID.  We need to
    read the UID from the exploit process itself.

    Strategy:
      1. Record the shell's UID as SYZPLOIT_UID_BEFORE (baseline — the
         UID the exploit *starts* with, which equals the shell's UID
         because the exploit inherits it).
      2. Run the exploit in the **background**.
      3. Immediately and periodically read ``/proc/<pid>/status`` to get
         the exploit process's *real, effective, saved, fs* UIDs.
      4. After the exploit exits, report whatever the last-seen UID was
         as SYZPLOIT_UID_AFTER.

    The exploit itself may also print ``SYZPLOIT_UID_AFTER=0`` if it was
    generated with the injected UID-reporting code (see exploit generator
    prompt), which is the most reliable signal.
    """
    return f"""#!/bin/sh
# DO NOT use set -e — we must always reach the AFTER section even if
# the exploit crashes or returns non-zero.
cd {remote_dir}

echo "=== BEFORE EXPLOIT ==="
# Baseline UID — the exploit inherits this from the shell.
BEFORE_UID=$(id -u)
echo "SYZPLOIT_UID_BEFORE=$BEFORE_UID"
echo "uid=$BEFORE_UID"
id

echo "=== RUNNING EXPLOIT ==="
# Run exploit in the background so we can poll /proc/<pid>/status.
# The exploit's stdout/stderr will be interleaved with the wrapper's
# output — the parser looks for SYZPLOIT_UID tags regardless of order.
timeout {timeout} {exploit_remote_path} &
EXPLOIT_PID=$!

# Poll the exploit's UID from /proc — this reflects the kernel's
# view of the process's cred struct, which is what privesc changes.
# We check ALL FOUR uid fields: real, effective, saved, fs.
# Also check child processes — many exploits fork() and change
# credentials in a child rather than the parent.
LAST_UID="$BEFORE_UID"
while kill -0 "$EXPLOIT_PID" 2>/dev/null; do
    # Check the main exploit process
    if [ -f "/proc/$EXPLOIT_PID/status" ]; then
        UID_LINE=$(grep '^Uid:' /proc/$EXPLOIT_PID/status 2>/dev/null || true)
        if [ -n "$UID_LINE" ]; then
            PROC_REAL=$(echo "$UID_LINE" | awk '{{print $2}}')
            PROC_EFF=$(echo "$UID_LINE" | awk '{{print $3}}')
            PROC_SAVED=$(echo "$UID_LINE" | awk '{{print $4}}')
            if [ "$PROC_REAL" = "0" ] || [ "$PROC_EFF" = "0" ] || [ "$PROC_SAVED" = "0" ]; then
                if [ "$BEFORE_UID" != "0" ]; then
                    echo "SYZPLOIT_UID_AFTER=0"
                    echo "[+] Detected UID change to 0 via /proc/$EXPLOIT_PID/status"
                    echo "[+] Uid line: $UID_LINE"
                    LAST_UID=0
                fi
            else
                LAST_UID="$PROC_REAL"
            fi
        fi
    fi
    # Also check child processes (forking exploits)
    # Method 1: /proc/PID/task/PID/children (needs CONFIG_PROC_CHILDREN)
    # Method 2: pgrep -P (works on all Linux/Android)
    # Method 3: check for listening root shell port (exploit-specific)
    if [ "$LAST_UID" != "0" ]; then
        # Try children file first
        CHILDREN=$(cat /proc/$EXPLOIT_PID/task/$EXPLOIT_PID/children 2>/dev/null || true)
        # Fallback: pgrep for child processes
        if [ -z "$CHILDREN" ]; then
            CHILDREN=$(pgrep -P $EXPLOIT_PID 2>/dev/null || true)
        fi
        # Also check grandchildren (exploit forks multiple levels)
        ALL_CHILDREN="$CHILDREN"
        for C in $CHILDREN; do
            GC=$(pgrep -P $C 2>/dev/null || true)
            ALL_CHILDREN="$ALL_CHILDREN $GC"
        done
        for CHILD in $ALL_CHILDREN; do
            if [ -f "/proc/$CHILD/status" ]; then
                CHILD_UID=$(grep '^Uid:' /proc/$CHILD/status 2>/dev/null || true)
                if [ -n "$CHILD_UID" ]; then
                    C_REAL=$(echo "$CHILD_UID" | awk '{{print $2}}')
                    C_EFF=$(echo "$CHILD_UID" | awk '{{print $3}}')
                    if [ "$C_REAL" = "0" ] || [ "$C_EFF" = "0" ]; then
                        if [ "$BEFORE_UID" != "0" ]; then
                            echo "SYZPLOIT_UID_AFTER=0"
                            echo "[+] Detected UID change to 0 in child/grandchild $CHILD"
                            echo "[+] Child Uid line: $CHILD_UID"
                            LAST_UID=0
                            break
                        fi
                    fi
                fi
            fi
        done
        # Method 3: check for listening root shell port (common in exploit payloads)
        if [ "$LAST_UID" != "0" ]; then
            if ss -tlnp 2>/dev/null | grep -q ':1340 '; then
                echo "SYZPLOIT_UID_AFTER=0"
                echo "[+] Detected root shell listening on port 1340"
                LAST_UID=0
            fi
        fi
    fi
    sleep 1
done

# Collect exit status — use || true so the script doesn't abort
# if the exploit exited with non-zero / was killed by a signal.
wait "$EXPLOIT_PID" 2>/dev/null || true
EXPLOIT_EXIT=$?

echo "=== AFTER EXPLOIT (exit code: $EXPLOIT_EXIT) ==="
echo "SYZPLOIT_UID_AFTER=$LAST_UID"
if [ "$LAST_UID" = "0" ] && [ "$BEFORE_UID" != "0" ]; then
    echo "uid=0"
    echo "[+] SUCCESS: privilege escalation confirmed (UID $BEFORE_UID -> 0)"
else
    echo "uid=$LAST_UID"
    echo "[-] UID did not change to 0 (stayed $LAST_UID)"
fi
echo "=== EXPLOIT COMPLETE ==="
"""


# ── Core verification functions ───────────────────────────────────────


def verify_exploit(
    binary_path: str,
    *,
    ssh_host: str,
    ssh_port: int = 22,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
    instance: Optional[int] = None,
    start_cmd: Optional[str] = None,
    stop_cmd: Optional[str] = None,
    exploit_start_cmd: Optional[str] = None,
    gdb_port: int = 1234,
    setup_tunnels: bool = False,
    persistent: bool = True,
    timeout: int = 120,
    remote_dir: str = "/data/local/tmp",
    use_adb: bool = False,
    adb_port: int = 6520,
    # GDB monitoring parameters (new)
    vmlinux_path: Optional[str] = None,
    kallsyms_path: Optional[str] = None,
    monitor_functions: Optional[List[str]] = None,
    arch: str = "arm64",
    # ExploitMonitor integration
    keep_alive: bool = False,
    monitor_script_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Deploy and run an exploit binary, checking for privilege escalation.

    When *use_adb* is True (auto-set when *instance* is given), all
    interaction with the **Cuttlefish VM** goes through ADB — not SSH.
    SSH is only used to reach the **build host** for start/stop
    commands and (optionally) to set up port-forward tunnels.

    GDB monitoring (new):
      If *monitor_functions* is provided (or auto-populated from default
      exploit-relevant functions) AND *kallsyms_path* or *vmlinux_path*
      is available, GDB breakpoints are set on those functions DURING
      exploit execution.  This provides concrete diagnostic data about
      which kernel code paths the exploit actually reaches.

      If the exploit causes a crash and the device becomes unreachable,
      ``capture_crash_state()`` tries to capture registers + backtrace
      from the halted QEMU stub.
    """
    # ── Resolve ADB port from instance ────────────────────────────────
    adb_port = _calc_adb_port(instance, adb_port)

    result: Dict[str, Any] = {
        "success": False,
        "uid_before": None,
        "uid_after": None,
        "privilege_escalated": False,
        "crash_occurred": False,
        "crash_pattern": "",
        "crash_severity": "none",  # "fatal", "sanitizer", "warning", "none"
        "kernel_warnings": [],
        "kernel_log": "",  # logcat -b kernel / cuttlefish kernel.log
        "exploit_output": "",
        "dmesg_new": "",
        "device_stable": True,
        "failure_reason": "",
        "feedback": "",
        # GDB diagnostic fields (new)
        "gdb_functions_hit": [],
        "gdb_functions_missed": [],
        "gdb_crash_info": None,
        # Pre/post kernel state (new)
        "kernel_state_pre": {},
        "kernel_state_post": {},
        "kernel_state_diff": "",
        # ExploitMonitor rich diagnostics (new)
        "monitor_results": {},
    }

    binary = Path(binary_path)
    if not binary.exists():
        result["failure_reason"] = f"Binary not found: {binary_path}"
        result["feedback"] = (
            "The exploit binary does not exist on disk. "
            "Ensure compilation succeeded before verification."
        )
        return result

    # Track processes we need to clean up at the end
    start_proc: Optional[subprocess.Popen] = None
    tunnel_proc: Optional[subprocess.Popen] = None
    gdb_monitor = None  # must be set before try so finally can always reference it
    gdb_tunnel_proc: Optional[subprocess.Popen] = None

    try:  # Ensure cleanup even on exceptions
        # ── 1. Optionally restart instance ────────────────────────────
        if not persistent and stop_cmd:
            console.print("  [dim]Stopping instance…[/]")
            _run_stop_cmd(stop_cmd, ssh_host=ssh_host, ssh_port=ssh_port)
            time.sleep(2)

        # When GDB monitoring is requested (kallsyms/vmlinux available),
        # prefer start_cmd (gdb_run.sh) so the GDB stub is present.
        # If no GDB monitoring, use exploit_start_cmd (run.sh) for speed.
        want_gdb = bool(kallsyms_path or vmlinux_path) and bool(monitor_functions)
        if want_gdb and start_cmd and _is_gdb_start(start_cmd):
            actual_start = start_cmd
            console.print(
                "  [dim]Using GDB-enabled start (for kernel path monitoring)…[/]"
            )
        else:
            actual_start = exploit_start_cmd or start_cmd
        if not persistent and actual_start:
            console.print("  [dim]Starting instance…[/]")
            ok, start_proc = _run_start_cmd(
                actual_start, ssh_host=ssh_host, ssh_port=ssh_port,
            )
            if not ok:
                result["failure_reason"] = "Failed to launch start command"
                result["feedback"] = (
                    "The target instance failed to start. Check that start_cmd "
                    "is correct and the kernel image exists."
                )
                return result
            console.print("  [dim]Waiting for VM to boot…[/]")
            time.sleep(10)

        # ── 1b. Set up SSH tunnel for ADB (if needed) ────────────────
        if use_adb and setup_tunnels and _is_remote_host(ssh_host):
            tunnel_proc = _setup_adb_tunnel(
                adb_port, ssh_host, ssh_port,
            )
            if tunnel_proc is None:
                result["failure_reason"] = "Failed to set up ADB SSH tunnel"
                result["feedback"] = (
                    "Could not create the SSH port-forward tunnel for ADB. "
                    "Check that you can SSH to the build host."
                )
                return result

        # ── 1c. Send GDB continue (BEFORE ADB poll) ──────────────────
        # When started with gdb_run.sh the kernel halts at the GDB stub
        # and won't boot until we send 'continue'.  This MUST happen
        # before the ADB connectivity check or we'll deadlock.
        if _is_gdb_start(actual_start):
            console.print("  [bold]GDB start detected — sending continue…[/]")
            gdb_ok = _send_gdb_continue(
                gdb_port,
                ssh_host=ssh_host,
                ssh_port=ssh_port,
                setup_tunnels=setup_tunnels,
                instance=instance or 20,
            )
            if gdb_ok:
                console.print(
                    "  [dim]Waiting 30 s for VM to start booting…[/]"
                )
                time.sleep(30)
            else:
                console.print(
                    "  [yellow]GDB continue may have failed — "
                    "will attempt ADB anyway[/]"
                )
                time.sleep(30)

        # ── 2. Wait for device connectivity ───────────────────────────
        if use_adb:
            console.print(
                f"  [dim]Waiting for ADB device at localhost:{adb_port}…[/]"
            )
            _last_diag_attempt = -1  # track when we last ran diagnostics
            for attempt in range(120):
                if _adb_is_alive(adb_port):
                    console.print(
                        f"  [green]ADB connected (attempt {attempt + 1})[/]"
                    )
                    break

                # ── Periodic diagnostics (every 30 s) ─────────────────
                if attempt % 6 == 5:
                    elapsed = (attempt + 1) * 5
                    console.print(
                        f"  [dim]  still waiting… ({elapsed}s)[/]"
                    )

                    # Diagnose only every 30s to avoid spam
                    if attempt - _last_diag_attempt >= 6:
                        _last_diag_attempt = attempt

                        # A) Is the SSH tunnel process still alive?
                        if tunnel_proc is not None:
                            rc = tunnel_proc.poll()
                            if rc is not None:
                                # Tunnel died — read stderr
                                _, stderr_bytes = tunnel_proc.communicate(
                                    timeout=2,
                                )
                                err = (
                                    stderr_bytes.decode(errors="replace").strip()
                                    if stderr_bytes else "(no stderr)"
                                )
                                console.print(
                                    f"  [red]⚠ SSH tunnel DIED "
                                    f"(exit {rc}): {err[:200]}[/]"
                                )
                            else:
                                console.print(
                                    "  [dim]  tunnel process: alive "
                                    f"(pid {tunnel_proc.pid})[/]"
                                )

                        # B) Can we TCP-connect to the local forwarded port?
                        tcp_ok = _tcp_port_open("localhost", adb_port, timeout=3)
                        if tcp_ok:
                            console.print(
                                f"  [dim]  TCP localhost:{adb_port}: "
                                f"open (something listening)[/]"
                            )
                        else:
                            console.print(
                                f"  [yellow]  TCP localhost:{adb_port}: "
                                f"CLOSED/REFUSED — tunnel may not "
                                f"be forwarding[/]"
                            )

                        # C) Check remote side: is the port open on the
                        #    build host (where Cuttlefish is running)?
                        if setup_tunnels and _is_remote_host(ssh_host):
                            remote_status = _check_remote_port(
                                adb_port, ssh_host, ssh_port,
                            )
                            if remote_status == "not_listening":
                                console.print(
                                    f"  [yellow]  Remote {ssh_host}:{adb_port}: "
                                    f"NOT LISTENING — VM may not have "
                                    f"started ADB yet[/]"
                                )
                            elif remote_status:
                                console.print(
                                    f"  [dim]  Remote {ssh_host}:{adb_port}: "
                                    f"{remote_status}[/]"
                                )
                            else:
                                console.print(
                                    f"  [dim]  Remote port check: "
                                    f"SSH to build host failed[/]"
                                )

                time.sleep(5)
            else:
                # Final diagnostic dump before giving up
                console.print("  [red]ADB connection timed out — final diagnostics:[/]")
                tcp_ok = _tcp_port_open("localhost", adb_port, timeout=3)
                console.print(
                    f"    TCP localhost:{adb_port}: "
                    f"{'OPEN' if tcp_ok else 'CLOSED/REFUSED'}"
                )
                if tunnel_proc is not None:
                    rc = tunnel_proc.poll()
                    console.print(
                        f"    Tunnel process: "
                        f"{'alive (pid ' + str(tunnel_proc.pid) + ')' if rc is None else 'DEAD (exit ' + str(rc) + ')'}"
                    )
                if setup_tunnels and _is_remote_host(ssh_host):
                    remote_status = _check_remote_port(
                        adb_port, ssh_host, ssh_port,
                    )
                    console.print(
                        f"    Remote {ssh_host}:{adb_port}: "
                        f"{remote_status or 'check failed'}"
                    )

                result["failure_reason"] = (
                    f"Cannot reach device via ADB at localhost:{adb_port}"
                )
                result["feedback"] = (
                    "The Cuttlefish VM is unreachable over ADB. "
                    f"Tried localhost:{adb_port} for 600 s. "
                    "Check: (1) VM started correctly, (2) instance number "
                    "is correct, (3) --setup-tunnels was passed for remote "
                    "hosts, (4) for GDB starts, ensure the GDB continue "
                    "packet was acknowledged."
                )
                return result

            ssh = SSHSession(
                host=ssh_host, port=ssh_port, user=ssh_user,
                key=ssh_key, timeout=timeout,
            )
        else:
            # Non-ADB path: SSH directly to VM
            ssh = SSHSession(
                host=ssh_host, port=ssh_port, user=ssh_user,
                key=ssh_key, timeout=timeout,
            )
            console.print("  [dim]Waiting for SSH…[/]")
            for attempt in range(24):
                if ssh.is_alive():
                    break
                time.sleep(5)
            else:
                result["failure_reason"] = "Cannot reach target via SSH"
                result["feedback"] = (
                    "The target is unreachable over SSH. The instance may not "
                    "have finished booting, or SSH is not configured."
                )
                return result

        # ── 3. Push binary to target ─────────────────────────────────────
        remote_path = f"{remote_dir}/exploit"
        console.print(f"  [dim]Uploading exploit → {remote_path}[/]")

        if use_adb:
            if not _adb_push(binary_path, remote_path, adb_port):
                result["failure_reason"] = "ADB push failed"
                result["feedback"] = "Failed to push exploit via ADB."
                return result
            _adb_run(f"chmod 755 {remote_path}", adb_port, timeout=10)
        else:
            if not ssh.upload(binary_path, remote_path):
                result["failure_reason"] = "SCP upload failed"
                result["feedback"] = (
                    "Failed to upload exploit binary via SCP. "
                    "Check SSH credentials and permissions."
                )
                return result
            ssh.run(f"chmod 755 {remote_path}")

        # ── 3b. Generate and push wrapper script ─────────────────────
        # Push the wrapper BEFORE setting GDB breakpoints.  GDB hardware
        # breakpoints cause constant stop/continue cycles on monitored
        # kernel functions which can make ADB unresponsive.  By pushing
        # everything first, we guarantee scripts are on-device before
        # the VM slows down from breakpoint overhead.
        verify_wrapper = _build_verify_wrapper(remote_path, remote_dir, timeout)
        wrapper_path = f"{remote_dir}/verify_wrapper.sh"
        _wrapper_pushed = False

        if use_adb:
            import tempfile

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".sh", delete=False
            ) as f:
                f.write(verify_wrapper)
                _tmp_wrapper_path = f.name
            if _adb_push(_tmp_wrapper_path, wrapper_path, adb_port, timeout=60):
                _wrapper_pushed = True
                _adb_run(f"chmod 755 {wrapper_path}", adb_port, timeout=10)
                console.print("  [dim]Wrapper script pushed (before GDB setup)[/]")
            else:
                console.print(
                    "  [yellow]Wrapper pre-push failed — will retry after "
                    "GDB setup[/]"
                )
            Path(_tmp_wrapper_path).unlink(missing_ok=True)
        else:
            ssh.run(
                f"cat > {wrapper_path} << 'SYZPLOIT_WRAPPER_EOF'\n"
                f"{verify_wrapper}\nSYZPLOIT_WRAPPER_EOF"
            )
            ssh.run(f"chmod 755 {wrapper_path}")
            _wrapper_pushed = True
            console.print("  [dim]Wrapper script pushed (before GDB setup)[/]")

        # ── 4. Capture dmesg BEFORE ──────────────────────────────────
        if use_adb:
            _, dmesg_before, _ = _adb_run("dmesg", adb_port, timeout=30)
        else:
            _, dmesg_before, _ = ssh.run("dmesg", timeout=30)

        # ── 4a. Capture pre-exploit kernel state ─────────────────────
        # Collect kernel state BEFORE the exploit runs so we can diff
        # slab caches, security context, and object counts afterward.
        kernel_state_pre = _capture_kernel_state(
            use_adb=use_adb, adb_port=adb_port,
            ssh=ssh if not use_adb else None,
        )
        if kernel_state_pre:
            result["kernel_state_pre"] = kernel_state_pre
            console.print(
                f"  [dim]Pre-exploit kernel state captured "
                f"({len(kernel_state_pre)} fields)[/]"
            )

        # ── 4b. Start GDB monitoring (if configured) ─────────────────
        _exploit_gdb_functions = monitor_functions
        if _exploit_gdb_functions is None:
            # Default: monitor exploit-relevant kernel functions.
            # NOTE: copy_creds is intentionally excluded — it fires on
            # every fork/clone in the kernel, producing hundreds of
            # noise hits that overwhelm GDB and make ADB unresponsive.
            _exploit_gdb_functions = [
                "commit_creds",
                "prepare_kernel_cred",
                "override_creds",
                "revert_creds",
                "sel_write_enforce",        # SELinux disable
                "selinux_state",
                "__sys_setresuid",
                "__sys_setresgid",
            ]

        gdb_tunnel_proc: Optional[subprocess.Popen] = None
        if (
            _exploit_gdb_functions
            and (kallsyms_path or vmlinux_path)
            and _is_gdb_start(actual_start)
        ):
            console.print(
                "  [dim]Setting up GDB breakpoint monitoring before "
                "running exploit…[/]"
            )
            try:
                from .gdb import GDBController
                gdb_host = "localhost"
                gdb_actual_port = gdb_port

                # Set up GDB tunnel if remote
                if setup_tunnels and _is_remote_host(ssh_host):
                    gdb_actual_port = 11234 + (gdb_port % 1000)
                    console.print(
                        f"  [dim]Setting up GDB tunnel for monitor: "
                        f"localhost:{gdb_actual_port} → "
                        f"{ssh_host}:{gdb_port}[/]"
                    )
                    gdb_tunnel_proc = subprocess.Popen(
                        [
                            "ssh", "-o", "StrictHostKeyChecking=no",
                            "-N", "-L",
                            f"{gdb_actual_port}:localhost:{gdb_port}",
                            ssh_host,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    time.sleep(2)  # let tunnel establish

                gdb_ctrl = GDBController(
                    vmlinux=vmlinux_path,
                    arch=arch,
                )
                ok = gdb_ctrl.start_monitoring(
                    _exploit_gdb_functions,
                    host=gdb_host,
                    port=gdb_actual_port,
                    kallsyms_path=kallsyms_path,
                    custom_script_dir=monitor_script_dir,
                )
                if ok:
                    gdb_monitor = gdb_ctrl
                    console.print(
                        f"  [dim]GDB monitoring {len(_exploit_gdb_functions)} "
                        f"exploit-relevant functions…[/]"
                    )
                    # Give the kernel a moment to resume after GDB continue
                    time.sleep(3)
                    # Re-check ADB connectivity (GDB pauses VM briefly)
                    if use_adb:
                        for _retry in range(10):
                            if _adb_is_alive(adb_port):
                                break
                            time.sleep(2)
                else:
                    console.print("  [dim]GDB monitoring setup failed, continuing without[/]")
                    # The failed GDB connection may have left the kernel
                    # paused.  Send a bare continue via a throwaway GDB
                    # session so the VM resumes and ADB stays reachable.
                    try:
                        _recovery_port = gdb_actual_port  # type: ignore[possibly-undefined]
                        console.print(
                            f"  [dim]Sending recovery continue to GDB stub "
                            f"(port {_recovery_port})…[/]"
                        )
                        subprocess.run(
                            [
                                "gdb-multiarch", "-batch", "-nx",
                                "-ex", f"target remote localhost:{_recovery_port}",
                                "-ex", "set architecture aarch64",
                                "-ex", "continue",
                                "-ex", "disconnect",
                                "-ex", "quit",
                            ],
                            capture_output=True, timeout=15,
                        )
                        time.sleep(5)  # let kernel resume
                        # Re-check ADB after recovery
                        if use_adb:
                            for _retry in range(10):
                                if _adb_is_alive(adb_port):
                                    break
                                time.sleep(2)
                    except Exception as _re:
                        console.print(f"  [dim]Recovery continue failed: {_re}[/]")
            except Exception as exc:
                console.print(f"  [dim]GDB monitoring unavailable: {exc}[/]")
        elif _exploit_gdb_functions and (kallsyms_path or vmlinux_path):
            console.print(
                "  [dim]GDB monitoring skipped — VM not started with "
                "gdb_run.sh (no GDB stub available)[/]"
            )

        # ── 5. Execute exploit ─────────────────────────────────────────
        # The wrapper was already pushed in step 3b (before GDB setup).
        # If that push failed (rare), retry here with tolerance for the
        # GDB-induced slowdown.

        if use_adb:
            if not _wrapper_pushed:
                import tempfile

                console.print(
                    "  [dim]Retry-pushing wrapper (pre-push failed)…[/]"
                )
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".sh", delete=False
                ) as f:
                    f.write(verify_wrapper)
                    _tmp_wrapper_retry = f.name
                _push_ok = False
                for _push_try in range(3):
                    if _adb_push(
                        _tmp_wrapper_retry, wrapper_path,
                        adb_port, timeout=60,
                    ):
                        _push_ok = True
                        break
                    console.print(
                        f"  [dim]Push attempt {_push_try + 1}/3 failed, "
                        f"retrying in 5s...[/]"
                    )
                    time.sleep(5)
                    if not _adb_is_alive(adb_port):
                        time.sleep(10)
                Path(_tmp_wrapper_retry).unlink(missing_ok=True)
                if not _push_ok:
                    console.print(
                        "  [red]Failed to push wrapper after 3 attempts[/]"
                    )
                _adb_run(f"chmod 755 {wrapper_path}", adb_port, timeout=10)

            console.print("  [bold]Running exploit on target (via ADB)…[/]")
            rc, stdout, stderr = _adb_run(
                wrapper_path, adb_port, timeout=timeout + 60,
            )
        else:
            if not _wrapper_pushed:
                ssh.run(
                    f"cat > {wrapper_path} << 'SYZPLOIT_WRAPPER_EOF'\n"
                    f"{verify_wrapper}\nSYZPLOIT_WRAPPER_EOF"
                )
                ssh.run(f"chmod 755 {wrapper_path}")

            console.print("  [bold]Running exploit on target…[/]")
            rc, stdout, stderr = ssh.run(wrapper_path, timeout=timeout + 60)

        exploit_output = stdout + stderr
        result["exploit_output"] = exploit_output

        # ── 5b. Stop GDB monitoring and collect results ───────────────
        if gdb_monitor:
            try:
                gdb_hits = gdb_monitor.stop_monitoring()
                result["gdb_functions_hit"] = [
                    f for f, hit in gdb_hits.items() if hit
                ]
                result["gdb_functions_missed"] = [
                    f for f, hit in gdb_hits.items() if not hit
                ]
                if result["gdb_functions_hit"]:
                    console.print(
                        f"  [green]GDB: functions reached: "
                        f"{', '.join(result['gdb_functions_hit'])}[/]"
                    )
                if result["gdb_functions_missed"]:
                    console.print(
                        f"  [dim]GDB: functions NOT reached: "
                        f"{', '.join(result['gdb_functions_missed'])}[/]"
                    )
            except Exception as exc:
                console.print(f"  [dim]GDB stop_monitoring failed: {exc}[/]")

        # ── 6. Parse UIDs from wrapper output ─────────────────────────
        uid_before = _parse_uid(exploit_output, "=== BEFORE EXPLOIT ===")
        uid_after = _parse_uid(exploit_output, "=== AFTER EXPLOIT")

        result["uid_before"] = uid_before
        result["uid_after"] = uid_after

        if uid_before is not None and uid_after is not None:
            if uid_after == 0 and uid_before != 0:
                result["privilege_escalated"] = True
        if _detect_success(exploit_output):
            result["privilege_escalated"] = True

        # ── 7. Capture dmesg AFTER ────────────────────────────────────
        if use_adb:
            alive = _adb_is_alive(adb_port)
        else:
            alive = ssh.is_alive()

        if alive:
            result["device_stable"] = True
            if use_adb:
                _, dmesg_after, _ = _adb_run("dmesg", adb_port, timeout=30)
                # Also try logcat kernel buffer for extra coverage
                # Cuttlefish QEMU pipes serial console through logcat
                _, _klog, _ = _adb_run(
                    "logcat -b kernel -d -t 200 2>/dev/null || cat /proc/last_kmsg 2>/dev/null || true",
                    adb_port, timeout=15,
                )
                if _klog and _klog.strip():
                    result["kernel_log"] = _klog[-3000:]
            else:
                _, dmesg_after, _ = ssh.run("dmesg", timeout=30)
            new_dmesg = _dmesg_diff(dmesg_before, dmesg_after)
            result["dmesg_new"] = new_dmesg
            crash, pattern = _detect_crash(new_dmesg)
            result["crash_occurred"] = crash
            result["crash_pattern"] = pattern
            result["crash_severity"] = _classify_crash_severity(new_dmesg)
            # Also capture non-fatal warnings for diagnostic context
            result["kernel_warnings"] = _detect_warnings(new_dmesg)
            # Check kernel log too for crash evidence dmesg may have missed
            if not crash and result.get("kernel_log"):
                klog_crash, klog_pat = _detect_crash(result["kernel_log"])
                if klog_crash:
                    result["crash_occurred"] = True
                    result["crash_pattern"] = f"{klog_pat} (from kernel log)"
                    result["crash_severity"] = _classify_crash_severity(
                        result["kernel_log"]
                    )
        else:
            result["device_stable"] = False
            result["crash_occurred"] = True
            result["crash_pattern"] = "device unreachable after exploit"
            result["crash_severity"] = "fatal"
            result["dmesg_new"] = "(device not reachable)"

            # Try to grab kernel log from the host if Cuttlefish runtime
            # directory is accessible (the kernel log survives VM crash)
            if ssh_host and instance:
                try:
                    _cf_logdir = f"/tmp/cf_avd_{instance}"
                    _, _cf_klog, _ = SSHSession(
                        host=ssh_host, port=ssh_port,
                    ).run(
                        f"tail -200 {_cf_logdir}/kernel.log 2>/dev/null "
                        f"|| tail -200 {_cf_logdir}/cuttlefish_kernel.log 2>/dev/null "
                        f"|| tail -200 /tmp/android-cuttlefish/instances/cvd-{instance}/logs/kernel.log 2>/dev/null "
                        f"|| echo '(no cuttlefish kernel log found)'",
                        timeout=15,
                    )
                    if _cf_klog and "(no cuttlefish" not in _cf_klog:
                        result["kernel_log"] = _cf_klog[-3000:]
                        # Re-check for specific crash patterns in kernel log
                        klog_crash, klog_pat = _detect_crash(_cf_klog)
                        if klog_crash:
                            result["crash_pattern"] = klog_pat
                            result["crash_severity"] = _classify_crash_severity(
                                _cf_klog
                            )
                        result["dmesg_new"] = _cf_klog[-2000:]
                        console.print(
                            f"  [yellow]Recovered kernel log from "
                            f"Cuttlefish runtime dir[/]"
                        )
                except Exception as _kl_exc:
                    console.print(
                        f"  [dim]Cuttlefish kernel log recovery "
                        f"failed: {_kl_exc}[/]"
                    )

            # Attempt crash-site capture via GDB stub on halted kernel
            if gdb_monitor:
                try:
                    crash_info = gdb_monitor.capture_crash_state(
                        host="localhost", port=gdb_port,
                    )
                    if crash_info and crash_info.get("backtrace"):
                        result["gdb_crash_info"] = crash_info
                        console.print(
                            f"  [yellow]GDB crash capture: "
                            f"{crash_info.get('crash_function', '?')} "
                            f"at {crash_info.get('crash_address', '?')}[/]"
                        )
                except Exception as exc:
                    console.print(
                        f"  [dim]GDB crash capture failed: {exc}[/]"
                    )

        # ── 7b. Capture post-exploit kernel state and compute diff ────
        if alive:
            kernel_state_post = _capture_kernel_state(
                use_adb=use_adb, adb_port=adb_port,
                ssh=ssh if not use_adb else None,
            )
            if kernel_state_post:
                result["kernel_state_post"] = kernel_state_post
            # Compute kernel state diff (slab changes, security context, etc.)
            if kernel_state_pre and kernel_state_post:
                diff_text = _diff_kernel_state(kernel_state_pre, kernel_state_post)
                if diff_text:
                    result["kernel_state_diff"] = diff_text
                    console.print(
                        f"  [dim]Kernel state diff ({len(diff_text)} chars)[/]"
                    )

        # ── 7c. Parse ExploitMonitor results (heap/phase/snapshot) ────
        if monitor_script_dir:
            try:
                from ..exploit.gdb_exploit_monitor import ExploitMonitor
                _parser = ExploitMonitor(arch=arch)
                _monitor_results = _parser.parse_monitor_results(
                    monitor_script_dir,
                )
                if _monitor_results and (
                    _monitor_results.get("bp_hits")
                    or _monitor_results.get("snapshots")
                    or _monitor_results.get("events")
                ):
                    result["monitor_results"] = _monitor_results
                    _monitor_text = _parser.format_results_for_prompt(
                        _monitor_results,
                    )
                    result["monitor_feedback"] = _monitor_text
                    console.print(
                        f"  [dim]ExploitMonitor: "
                        f"{len(_monitor_results.get('events', []))} events, "
                        f"{len(_monitor_results.get('snapshots', []))} snapshots, "
                        f"phases: {_monitor_results.get('phase_history', [])}[/]"
                    )
            except Exception as _me:
                console.print(
                    f"  [dim]ExploitMonitor result parsing failed: {_me}[/]"
                )

        # ── 8. Determine overall success and generate feedback ────────
        # Helper: build GDB diagnostic summary for feedback
        _gdb_diag_parts = []
        if result["gdb_functions_hit"]:
            _gdb_diag_parts.append(
                f"GDB: functions REACHED: {', '.join(result['gdb_functions_hit'])}"
            )
        if result["gdb_functions_missed"]:
            _gdb_diag_parts.append(
                f"GDB: functions NOT reached: {', '.join(result['gdb_functions_missed'])}"
            )
        if result.get("gdb_crash_info"):
            ci = result["gdb_crash_info"]
            _gdb_diag_parts.append(
                f"GDB crash site: {ci.get('crash_function', '?')} "
                f"at {ci.get('crash_address', '?')}"
            )
            if ci.get("backtrace"):
                _gdb_diag_parts.append(
                    f"Backtrace:\n{ci['backtrace'][:800]}"
                )
            if ci.get("registers"):
                _gdb_diag_parts.append(
                    f"Registers:\n{ci['registers'][:500]}"
                )
        if result.get("kernel_warnings"):
            _gdb_diag_parts.append(
                f"Kernel warnings (non-fatal): {', '.join(result['kernel_warnings'])}"
            )
        if result.get("kernel_log"):
            _gdb_diag_parts.append(
                f"Kernel log (last 500 chars):\n"
                f"{result['kernel_log'][-500:]}"
            )
        # Append pre/post kernel state diff (slab, SELinux, memory)
        if result.get("kernel_state_diff"):
            _gdb_diag_parts.append(result["kernel_state_diff"])
        # Append ExploitMonitor rich diagnostics (heap, phases, snapshots)
        if result.get("monitor_feedback"):
            _gdb_diag_parts.append(result["monitor_feedback"])
        _gdb_diag = "\n".join(_gdb_diag_parts)

        # ── 8a. Sanity-check privilege_escalated against crash state ──
        # If the device crashed / became unreachable, the UID data is
        # unreliable (could be garbled output, stale /proc reads, etc.).
        # Do NOT claim success if the device is dead.
        if result["privilege_escalated"] and not result["device_stable"]:
            console.print(
                "  [yellow]UID=0 detected but device crashed — "
                "NOT counting as success (unreliable)[/]"
            )
            result["privilege_escalated"] = False
            result["success"] = False

        # Also require at least one of the structured UID tags to be
        # present in the output.  Bare "uid=0" from error messages,
        # usage text, or unrelated output must not trigger success.
        if result["privilege_escalated"]:
            _has_structured_uid = (
                "SYZPLOIT_UID_AFTER=0" in exploit_output
                or (uid_before is not None and uid_after == 0
                    and uid_before != 0)
            )
            _has_success_phrase = _detect_success(exploit_output)
            if not _has_structured_uid and not _has_success_phrase:
                console.print(
                    "  [yellow]privilege_escalated set but no structured "
                    "UID tag or success phrase found — demoting[/]"
                )
                result["privilege_escalated"] = False

        if result["privilege_escalated"]:
            result["success"] = True
            fb = (
                f"Exploit succeeded. UID changed from {uid_before} to "
                f"{uid_after}. Privilege escalation confirmed."
            )
            if _gdb_diag:
                fb += f"\n\n{_gdb_diag}"
            result["feedback"] = fb
        elif not result["device_stable"]:
            result["failure_reason"] = (
                f"Device crashed / became unreachable "
                f"(severity: {result['crash_severity']})"
            )
            fb = (
                "The exploit caused the device to crash or become unreachable. "
                f"Crash severity: {result['crash_severity']}. "
                f"Crash pattern: {result['crash_pattern']}. "
            )
            # Give targeted advice based on whether the vuln was reached
            if result["gdb_functions_hit"]:
                fb += (
                    "The vulnerable code path WAS reached (good), but the "
                    "exploit destabilised the kernel. Consider: "
                    "(1) improving heap spray timing / count, "
                    "(2) adding delay between free and reclaim, "
                    "(3) using a data-only attack (overwrite cred) instead "
                    "of control-flow hijacking. "
                )
            else:
                fb += (
                    "The vulnerable code path was NOT reached according to "
                    "GDB. The crash is likely unrelated to the target CVE — "
                    "the exploit is hitting something else. Consider: "
                    "(1) verify the trigger mechanism is correct for this CVE, "
                    "(2) check that the right subsystem/syscall is being used, "
                    "(3) review the root cause analysis. "
                )
            if _gdb_diag:
                fb += f"\n\n{_gdb_diag}"
            result["feedback"] = fb
        elif result["crash_occurred"]:
            result["failure_reason"] = (
                f"Kernel crash detected ({result['crash_severity']}): "
                f"{result['crash_pattern']}"
            )
            fb = (
                "The exploit triggered a kernel crash but did not achieve "
                "privilege escalation. The vulnerability is being reached, "
                "but the corruption is not controlled. Review the dmesg log "
                "and adjust: (1) object layout / target struct, (2) heap "
                "spray parameters, (3) ROP/JOP chain if applicable. "
                f"Dmesg excerpt:\n{result['dmesg_new'][:1000]}"
            )
            if _gdb_diag:
                fb += f"\n\n{_gdb_diag}"
            result["feedback"] = fb
        elif (
            uid_before is not None
            and uid_after is not None
            and uid_before == uid_after
        ):
            result["failure_reason"] = (
                f"No privilege change (UID stayed {uid_after})"
            )
            fb = (
                f"The exploit ran without crashing but UID remained "
                f"{uid_after}. Possible issues: (1) the vulnerability was "
                "not triggered — check race conditions or timing, "
                "(2) the overwrite target is wrong — verify struct offsets "
                "for this kernel version, (3) the exploit exited before "
                "completing — check for early error returns in the code. "
                f"Exploit output:\n{exploit_output[:1000]}"
            )
            if _gdb_diag:
                fb += f"\n\n{_gdb_diag}"
            result["feedback"] = fb
        else:
            # Analyze why UID parsing failed — common causes:
            # 1. Exploit hung (timeout) — no UID tags in output
            # 2. Exploit crashed early — partial output
            # 3. Exploit produced wrong output format
            hung = len(exploit_output.strip()) == 0 or (
                "SYZPLOIT_UID" not in exploit_output
                and exploit_output.count("\n") < 5
            )
            if hung:
                result["failure_reason"] = (
                    "Exploit appears to have hung or produced no output — "
                    "likely blocked on a syscall (e.g. ioctl on binder, "
                    "read on pipe). Add timeout handling and debug printf()."
                )
                fb = (
                    "The exploit appears to have HUNG — it did not produce "
                    "SYZPLOIT_UID markers and output was minimal. Common "
                    "causes: (1) binder ioctl blocked indefinitely — add "
                    "timeout or use poll() before blocking reads, (2) pipe "
                    "read blocked waiting for data — ensure all pipe ends "
                    "are properly managed, (3) child process deadlocked — "
                    "add timeout to waitpid() calls. Add printf() at each "
                    "step to identify where the hang occurs."
                    f"\nRaw output (last 500 chars):\n"
                    f"{exploit_output[-500:]}"
                )
                if _gdb_diag:
                    fb += f"\n\n{_gdb_diag}"
                result["feedback"] = fb
            else:
                result["failure_reason"] = (
                    "Could not determine UID — output parsing failed"
                )
                fb = (
                    "Could not parse UID from exploit output. The exploit "
                    "ran but did not print the expected SYZPLOIT_UID_BEFORE "
                    "and SYZPLOIT_UID_AFTER tags. Ensure both tags are "
                    "printed with printf(\"SYZPLOIT_UID_BEFORE=%%d\\n\", "
                    "getuid()) and similar for AFTER. Check for early "
                    "error returns, unexpected output format, or the tags "
                    "being on stderr instead of stdout."
                    f"\nRaw output:\n{exploit_output[:1000]}"
                )
                if _gdb_diag:
                    fb += f"\n\n{_gdb_diag}"
                result["feedback"] = fb

    finally:
        # ── 9. Cleanup ──────────────────────────────────────────────
        if gdb_monitor and gdb_monitor._process is not None:
            try:
                gdb_monitor.stop_monitoring()
            except Exception:
                pass
        _kill_proc(gdb_tunnel_proc)
        if keep_alive:
            try:
                from ..orchestrator import source_tools as _st
                if start_proc is not None:
                    _st._vm_proc = start_proc
                if tunnel_proc is not None:
                    _st._adb_tunnel_proc = tunnel_proc
                _st._adb_port_active = adb_port
            except Exception:
                pass
            console.print(
                "  [dim]verify_exploit: VM kept alive for "
                "interactive investigation[/]"
            )
        else:
            if not persistent and stop_cmd:
                _run_stop_cmd(stop_cmd, ssh_host=ssh_host, ssh_port=ssh_port)
            _kill_proc(start_proc)
            _kill_proc(tunnel_proc)

    return result


def verify_reproducer(
    binary_path: str,
    *,
    ssh_host: str,
    ssh_port: int = 22,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
    instance: Optional[int] = None,
    expected_crash_type: str = "",
    expected_functions: Optional[List[str]] = None,
    start_cmd: Optional[str] = None,
    stop_cmd: Optional[str] = None,
    gdb_port: int = 1234,
    setup_tunnels: bool = False,
    persistent: bool = True,
    timeout: int = 60,
    remote_dir: str = "/data/local/tmp",
    use_adb: bool = False,
    adb_port: int = 6520,
    vmlinux_path: Optional[str] = None,
    kallsyms_path: Optional[str] = None,
    arch: str = "arm64",
    keep_alive: bool = False,
) -> Dict[str, Any]:
    """Deploy and run a reproducer, checking for expected crash.

    When *use_adb* is True, all VM interaction goes via ADB.

    On non-instrumented kernels (no KASAN), a UAF or OOB won't produce
    a crash.  When GDB is available (``gdb_port`` is set and the start
    command is a GDB launch), we additionally set breakpoints on the
    expected vulnerable functions and check whether the code path was
    reached even without a crash.  This provides a ``path_reached``
    result so the agent can distinguish "reproducer hit the vulnerable
    code" from "reproducer had no effect".
    """
    adb_port = _calc_adb_port(instance, adb_port)

    result: Dict[str, Any] = {
        "crash_triggered": False,
        "crash_type_match": False,
        "crash_log_excerpt": "",
        "matched_functions": [],
        "device_stable": True,
        "failure_reason": "",
        "feedback": "",
        # GDB path-verification fields (for non-instrumented kernels)
        "path_reached": False,
        "gdb_functions_hit": [],
        "gdb_functions_missed": [],
        "reproducer_output": "",
    }

    binary = Path(binary_path)
    if not binary.exists():
        result["failure_reason"] = f"Binary not found: {binary_path}"
        result["feedback"] = "Reproducer binary does not exist."
        return result

    start_proc: Optional[subprocess.Popen] = None
    tunnel_proc: Optional[subprocess.Popen] = None
    gdb_monitor = None  # initialized here so finally can always reference it
    gdb_tunnel_proc: Optional[subprocess.Popen] = None

    try:
        # Optionally restart
        if not persistent and stop_cmd:
            _run_stop_cmd(stop_cmd, ssh_host=ssh_host, ssh_port=ssh_port)
            time.sleep(2)
        if not persistent and start_cmd:
            ok, start_proc = _run_start_cmd(
                start_cmd, ssh_host=ssh_host, ssh_port=ssh_port,
            )
            if not ok:
                result["failure_reason"] = "Failed to launch start command"
                result["feedback"] = "Target instance could not be started."
                return result
            time.sleep(10)

        # Set up ADB tunnel if needed
        if use_adb and setup_tunnels and _is_remote_host(ssh_host):
            tunnel_proc = _setup_adb_tunnel(adb_port, ssh_host, ssh_port)
            if tunnel_proc is None:
                result["failure_reason"] = "Failed to set up ADB SSH tunnel"
                result["feedback"] = (
                    "Could not create ADB tunnel. Check SSH to build host."
                )
                return result

        # Send GDB continue BEFORE ADB poll (same as verify_exploit)
        if _is_gdb_start(start_cmd):
            console.print("  [bold]GDB start detected — sending continue…[/]")
            gdb_ok = _send_gdb_continue(
                gdb_port,
                ssh_host=ssh_host,
                ssh_port=ssh_port,
                setup_tunnels=setup_tunnels,
                instance=instance or 20,
            )
            if gdb_ok:
                console.print(
                    "  [dim]Waiting 30 s for VM to start booting…[/]"
                )
                time.sleep(30)
            else:
                console.print(
                    "  [yellow]GDB continue may have failed — "
                    "will attempt ADB anyway[/]"
                )
                time.sleep(30)

        # Wait for connectivity
        # GDB-started VMs use 1 CPU and boot slowly (~7 min wall clock).
        if use_adb:
            max_polls = 120 if _is_gdb_start(start_cmd) else 30
            console.print(
                f"  [dim]Waiting for ADB device at localhost:{adb_port} "
                f"(up to {max_polls * 5}s)…[/]"
            )
            for attempt in range(max_polls):
                if _adb_is_alive(adb_port):
                    console.print(
                        f"  [green]ADB connected (attempt {attempt + 1})[/]"
                    )
                    break
                time.sleep(5)
            else:
                result["failure_reason"] = (
                    f"Cannot reach device via ADB at localhost:{adb_port}"
                )
                result["feedback"] = "Cuttlefish VM unreachable via ADB."
                return result
        else:
            ssh = SSHSession(
                host=ssh_host, port=ssh_port, user=ssh_user,
                key=ssh_key, timeout=timeout,
            )
            for _ in range(24):
                if ssh.is_alive():
                    break
                time.sleep(5)
            else:
                result["failure_reason"] = "SSH unreachable"
                result["feedback"] = "Cannot connect to target via SSH."
                return result

        # Push binary
        remote_path = f"{remote_dir}/reproducer"
        if use_adb:
            if not _adb_push(binary_path, remote_path, adb_port):
                result["failure_reason"] = "ADB push failed"
                result["feedback"] = "Failed to push reproducer via ADB."
                return result
            _adb_run(f"chmod 755 {remote_path}", adb_port, timeout=10)
        else:
            if not ssh.upload(binary_path, remote_path):
                result["failure_reason"] = "Failed to upload reproducer"
                result["feedback"] = "SCP upload of reproducer failed."
                return result
            ssh.run(f"chmod 755 {remote_path}")

        # Capture dmesg before
        if use_adb:
            _, dmesg_before, _ = _adb_run("dmesg", adb_port, timeout=30)
        else:
            _, dmesg_before, _ = ssh.run("dmesg", timeout=30)

        # ── Start GDB monitoring BEFORE running the reproducer ────────
        # On non-instrumented kernels (no KASAN), a UAF won't crash.
        # Set breakpoints on vulnerable functions and monitor DURING the
        # reproducer execution so we can detect code path reachability.
        gdb_monitor = None
        gdb_monitor_active = False
        want_gdb_monitor = (
            expected_functions
            and _is_gdb_start(start_cmd)
            and gdb_port
        )
        if want_gdb_monitor:
            console.print(
                "  [dim]Setting up GDB breakpoint monitoring before "
                "running reproducer…[/]"
            )
            try:
                from .gdb import GDBController

                gdb_host = "localhost"
                actual_gdb_port = gdb_port

                # If remote, we need an SSH tunnel for GDB
                # (the one from _send_gdb_continue was already torn down)
                if setup_tunnels and _is_remote_host(ssh_host):
                    actual_gdb_port = 11234 + (gdb_port % 1000)
                    console.print(
                        f"  [dim]Setting up GDB tunnel for monitor: "
                        f"localhost:{actual_gdb_port} → "
                        f"{ssh_host}:{gdb_port}[/]"
                    )
                    gdb_tunnel_proc = subprocess.Popen(
                        [
                            "ssh", "-o", "StrictHostKeyChecking=no",
                            "-N", "-L",
                            f"{actual_gdb_port}:localhost:{gdb_port}",
                            ssh_host,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    time.sleep(2)  # let tunnel establish

                gdb_monitor = GDBController(
                    vmlinux=vmlinux_path,
                    arch=arch,
                )
                gdb_monitor_active = gdb_monitor.start_monitoring(
                    expected_functions[:10],
                    host=gdb_host,
                    port=actual_gdb_port,
                    kallsyms_path=kallsyms_path,
                )
                if gdb_monitor_active:
                    console.print(
                        "  [dim]GDB monitor active — kernel will resume "
                        "after breakpoints are set[/]"
                    )
                    # Give the kernel a moment to resume after GDB continue
                    time.sleep(3)
                    # Re-check ADB connectivity (GDB pauses VM briefly)
                    if use_adb:
                        for _retry in range(10):
                            if _adb_is_alive(adb_port):
                                break
                            time.sleep(2)
                else:
                    console.print(
                        "  [yellow]GDB monitor could not start — "
                        "will proceed without path verification[/]"
                    )
            except Exception as gdb_exc:
                console.print(
                    f"  [yellow]GDB monitor setup failed: {gdb_exc}[/]"
                )
                gdb_monitor = None

        # Run reproducer
        console.print("  [bold]Running reproducer on target…[/]")
        run_cmd = f"cd {remote_dir} && timeout {timeout} {remote_path}"
        if use_adb:
            rc, stdout, stderr = _adb_run(
                run_cmd, adb_port, timeout=timeout + 30,
            )
        else:
            rc, stdout, stderr = ssh.run(run_cmd, timeout=timeout + 30)

        time.sleep(3)  # Let kernel log any crash

        # ── Stop GDB monitoring and collect results ───────────────────
        gdb_hits: dict = {}
        if gdb_monitor_active and gdb_monitor is not None:
            console.print(
                "  [dim]Stopping GDB monitor and reading breakpoint hits…[/]"
            )
            try:
                gdb_hits = gdb_monitor.stop_monitoring()
            except Exception as gdb_exc:
                console.print(
                    f"  [yellow]GDB monitor stop failed: {gdb_exc}[/]"
                )

        # Capture dmesg after
        if use_adb:
            alive = _adb_is_alive(adb_port)
        else:
            alive = ssh.is_alive()

        if alive:
            result["device_stable"] = True
            if use_adb:
                _, dmesg_after, _ = _adb_run("dmesg", adb_port, timeout=30)
            else:
                _, dmesg_after, _ = ssh.run("dmesg", timeout=30)
            new_dmesg = _dmesg_diff(dmesg_before, dmesg_after)
            result["crash_log_excerpt"] = new_dmesg[:2000]
            crash, pattern = _detect_crash(new_dmesg)
            result["crash_triggered"] = crash

            if expected_crash_type and crash:
                if expected_crash_type.lower() in new_dmesg.lower():
                    result["crash_type_match"] = True
            if expected_functions:
                matched = [fn for fn in expected_functions if fn in new_dmesg]
                result["matched_functions"] = matched
        else:
            result["device_stable"] = False
            result["crash_triggered"] = True
            result["crash_log_excerpt"] = (
                "(device became unreachable — hard crash)"
            )

        # Generate feedback
        result["reproducer_output"] = (stdout + stderr)[:3000]

        if result["crash_triggered"]:
            match_info = ""
            if expected_crash_type:
                match_info = (
                    f" Crash type match: "
                    f"{'yes' if result['crash_type_match'] else 'no'}."
                )
            fn_info = ""
            if expected_functions:
                fn_info = (
                    f" Functions matched: {result['matched_functions']} "
                    f"of {expected_functions}."
                )
            result["feedback"] = (
                f"Reproducer triggered a crash.{match_info}{fn_info} "
                f"Device stable: {result['device_stable']}."
            )
        else:
            # ── Process GDB monitoring results ────────────────────────
            # GDB was monitoring during reproducer execution.
            gdb_attempted = gdb_monitor_active
            if gdb_hits:
                hit_funcs = [fn for fn, hit in gdb_hits.items() if hit]
                miss_funcs = [
                    fn for fn in (expected_functions or [])
                    if fn not in gdb_hits or not gdb_hits.get(fn)
                ]
                result["gdb_functions_hit"] = hit_funcs
                result["gdb_functions_missed"] = miss_funcs
                result["path_reached"] = len(hit_funcs) > 0

                if hit_funcs:
                    console.print(
                        f"  [green]GDB: vulnerable path reached! "
                        f"Hit: {hit_funcs}[/]"
                    )
                else:
                    console.print(
                        "  [dim]GDB monitored but no breakpoints were hit[/]"
                    )

            # Build detailed feedback
            if result["path_reached"]:
                result["failure_reason"] = "No crash but vulnerable path reached"
                result["feedback"] = (
                    "The reproducer ran without triggering a kernel crash, "
                    "BUT GDB confirms the vulnerable code path was reached "
                    f"(functions hit: {result['gdb_functions_hit']}). "
                    "This is expected on a non-instrumented kernel (no KASAN) — "
                    "the bug IS being triggered but memory corruption doesn't "
                    "cause an immediate crash. The reproducer is WORKING. "
                    "Proceed to exploit development. "
                    f"Missing functions: {result['gdb_functions_missed']}. "
                    f"Reproducer output:\n{(stdout + stderr)[:500]}"
                )
            else:
                # Check dmesg for any interesting kernel messages even without crash
                interesting_dmesg = ""
                if result.get("crash_log_excerpt"):
                    dmesg = result["crash_log_excerpt"]
                    # Look for binder/driver messages, warnings, etc.
                    interesting_lines = [
                        l for l in dmesg.splitlines()
                        if any(kw in l.lower() for kw in [
                            "binder", "warning", "bug", "error",
                            "fault", "oops", "panic", "rcu",
                            "use-after-free", "slab",
                        ])
                    ]
                    if interesting_lines:
                        interesting_dmesg = (
                            "\nInteresting dmesg lines:\n"
                            + "\n".join(interesting_lines[:10])
                        )

                gdb_note = ""
                if gdb_attempted and not result["path_reached"]:
                    gdb_note = (
                        " GDB path verification was attempted but no "
                        "vulnerable functions were hit. "
                    )
                elif not gdb_attempted:
                    gdb_note = (
                        " NOTE: This kernel appears to be non-instrumented "
                        "(no KASAN). A UAF/OOB may not produce a crash. "
                        "Consider using GDB-based dynamic verification "
                        "(check_feasibility_dynamic) to confirm the "
                        "vulnerability is being reached. "
                    )

                result["failure_reason"] = "No crash detected"
                result["feedback"] = (
                    "The reproducer ran but did not trigger a kernel crash. "
                    f"{gdb_note}"
                    "Possible causes: (1) the vulnerability may be patched "
                    "on this kernel, (2) race conditions may need adjusted "
                    "timing/iterations, (3) the reproducer may need to run "
                    "as a different user or with different privileges, "
                    "(4) on non-instrumented kernels, the bug may be "
                    "triggered but not crash — use GDB to verify. "
                    f"Reproducer output:\n{(stdout + stderr)[:500]}"
                    f"{interesting_dmesg}"
                )

    finally:
        # Clean up GDB monitor if still running
        if gdb_monitor is not None and gdb_monitor._process is not None:
            try:
                gdb_monitor.stop_monitoring()
            except Exception:
                pass
        _kill_proc(gdb_tunnel_proc)
        if keep_alive:
            # Export VM and tunnel procs to source_tools module globals
            # so run_target_command / gdb_session can reuse them.
            try:
                from ..orchestrator import source_tools as _st
                if start_proc is not None:
                    _st._vm_proc = start_proc
                if tunnel_proc is not None:
                    _st._adb_tunnel_proc = tunnel_proc
                _st._adb_port_active = adb_port
            except Exception:
                pass
            console.print(
                "  [dim]verify_reproducer: VM kept alive for "
                "interactive investigation[/]"
            )
        else:
            if not persistent and stop_cmd:
                _run_stop_cmd(stop_cmd, ssh_host=ssh_host, ssh_port=ssh_port)
            _kill_proc(start_proc)
            _kill_proc(tunnel_proc)

    return result
