"""
infra — Infrastructure management for kernel testing environments.

Provides:
    vm              QEMU and Cuttlefish VM lifecycle
    gdb             GDB integration (attach, breakpoints, tracing)
    ssh             SSH session management
    adb             ADB utilities for Cuttlefish/Android instances
    verification    Deploy, run, and verify exploits/reproducers on target
"""

from .adb import calculate_adb_port, get_adb_target, ADB_BASE_PORT
from .gdb import GDBController, InteractiveGDB
from .ssh import SSHSession
from .verification import verify_exploit, verify_reproducer
from .vm import VMConfig, VMController
from .device_profile import DeviceProfile, DeviceProfileRegistry

__all__ = [
    "calculate_adb_port",
    "get_adb_target",
    "ADB_BASE_PORT",
    "GDBController",
    "InteractiveGDB",
    "SSHSession",
    "VMConfig",
    "VMController",
    "verify_exploit",
    "verify_reproducer",
    "DeviceProfile",
    "DeviceProfileRegistry",
]
