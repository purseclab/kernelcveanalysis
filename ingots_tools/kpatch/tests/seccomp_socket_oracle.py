"""Independent concrete and Linux socket-filter oracles; never installs seccomp."""

import ctypes
import sys
import unittest
import socket
import struct


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


def interpret_concrete(program: bytes, words: tuple[int, ...]) -> int:
    """Concrete uint32 interpreter independent of the abstract evaluator."""
    instructions: tuple[tuple[int, int, int, int], ...] = tuple(struct.iter_unpack("<HBBI", program))
    pc, accumulator = 0, 0
    for _ in range(len(instructions) + 1):
        code, jt, jf, k = instructions[pc]
        if code == 0x20:
            accumulator = words[k // 4]
            pc += 1
        elif code == 0x06:
            return k
        elif code == 0x05:
            pc += 1 + k
        else:
            if code == 0x15:
                result = accumulator == k
            elif code == 0x25:
                result = accumulator > k
            elif code == 0x35:
                result = accumulator >= k
            elif code == 0x45:
                result = bool(accumulator & k)
            else:
                raise ValueError("concrete oracle opcode unsupported")
            pc += 1 + (jt if result else jf)
    raise ValueError("concrete oracle did not terminate")


def interpret_kernel_socket(program: bytes, words: tuple[int, ...]) -> int:
    """Run classic BPF on a private AF_UNIX datagram socket.

    Each seccomp-native uint32 word becomes a big-endian packet word, so socket
    LD W ABS sees the same integer. Every RET K is replaced with a distinct
    positive packet length; this observes even KILL/ERRNO/ALLOW as plain labels.
    No seccomp mode/filter is installed in this process or any child.
    """
    if sys.platform != "linux":
        raise unittest.SkipTest("Linux classic socket-filter oracle required")
    if not program or len(program) % 8 or len(words) != 16:
        raise ValueError("oracle requires integral instructions and16 uint32 words")
    raw: tuple[tuple[int, int, int, int], ...] = tuple(struct.iter_unpack("<HBBI", program))
    returns = sorted({k for code, _, _, k in raw if code == 0x06})
    labels = {value: 65 + index for index, value in enumerate(returns)}
    inverse = {length: value for value, length in labels.items()}
    array = (_SockFilter * len(raw))(*(_SockFilter(code, jt, jf, labels[k] if code == 0x06 else k)
                                     for code, jt, jf, k in raw))
    native = _SockFprog(len(raw), array)
    libc = ctypes.CDLL(None, use_errno=True)
    attach = libc.setsockopt
    attach.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
    attach.restype = ctypes.c_int
    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    with receiver, sender:
        # SO_ATTACH_FILTER=26, from Linux UAPI asm-generic/socket.h.
        if attach(receiver.fileno(), socket.SOL_SOCKET, 26, ctypes.byref(native), ctypes.sizeof(native)) != 0:
            error = ctypes.get_errno()
            if error in {1, 13, 92, 95}:
                raise unittest.SkipTest("Classic socket-filter oracle unavailable: " + str(error))
            raise OSError(error, "SO_ATTACH_FILTER rejected oracle program")
        receiver.settimeout(1)
        payload = b"".join(struct.pack("!I", value) for value in words) + bytes(8192 - 64)
        sender.sendall(payload)
        result = len(receiver.recv(8192))
    if result not in inverse:
        raise ValueError("unexpected packet length from kernel oracle")
    return inverse[result]
