import subprocess
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from time import sleep
from typing import Optional, Self


DEFAULT_REMOTE_ADDR = "0.0.0.0:6532"


class Tools(StrEnum):
    READ_FILE = "/data/local/tmp/tools/read_file"
    DUMP_SECCOMP_FILTER = "/data/local/tmp/tools/dump_seccomp_filter"
    RUNAS = "/data/local/tmp/tools/runas"
    EXPAND_BINARY = "/data/local/tmp/tools/expand_binary"


@dataclass
class Permissions:
    uid: int
    gid: int
    selabel: str

    @classmethod
    def root(cls):
        return cls(
            uid=0,
            gid=0,
            selabel="u:r:su:s0",
        )


@dataclass
class ExpandBinaryResult:
    load_addr: int
    expanded_binary: bytes


class AdbClient:
    remote_addr: str

    def __init__(self, remote_addr: str = DEFAULT_REMOTE_ADDR):
        self.remote_addr = remote_addr

    def run_adb_command(self, command: str, root: bool = False) -> Optional[str]:
        """Executes an ADB command and returns its output."""
        try:
            command = f"su root {command}" if root else command
            result = subprocess.run(
                f'adb -s {self.remote_addr} shell "{command}" 2>&1',
                shell=True,
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"Error executing ADB command `{command}`, root={root}: {e.stderr}")
            return None
        except FileNotFoundError:
            print("Error: 'adb' command not found. Is Android Debug Bridge installed and in your PATH?")
            return None

    def upload_file(self, src_path: Path, dst_path: Path, executable: bool = False):
        subprocess.run(
            ["adb", "-s", self.remote_addr, "push", str(src_path), str(dst_path)],
            check=True,
        )

        if executable:
            self.run_adb_command(f"chmod +x {dst_path}", root=True)

    def install_app(self, app: Path):
        subprocess.run(
            ["adb", "-s", self.remote_addr, "install", str(app)],
            check=True,
        )

    def upload_tools(self):
        self.run_adb_command("mkdir -p /data/local/tmp/tools")
        self.upload_file(Path("./tools/read_file"), Path(Tools.READ_FILE), executable=True)
        self.upload_file(Path("./tools/dump_seccomp_filter"), Path(Tools.DUMP_SECCOMP_FILTER), executable=True)
        self.upload_file(Path("./tools/runas"), Path(Tools.RUNAS), executable=True)
        self.upload_file(Path("./tools/expand_binary"), Path(Tools.EXPAND_BINARY), executable=True)

    def read_file(self, file: str, offset: int = 0, count: int = -1) -> bytes:
        out = self.run_adb_command(f"{Tools.READ_FILE} {file} {offset} {count}", root=True)
        assert out is not None
        return bytes.fromhex(out)

    def runas(self, command: str, permissions: Permissions) -> Optional[str]:
        return self.run_adb_command(
            f"{Tools.RUNAS} {permissions.uid} {permissions.gid} '{permissions.selabel}' '{command}'"
        )

    def expand_binary(self, binary: str) -> ExpandBinaryResult:
        output = self.run_adb_command(f"{Tools.EXPAND_BINARY} {binary}", root=True)
        assert output is not None
        lines = output.splitlines()
        assert len(lines) == 2

        load_addr = int(lines[0].strip(), 16)
        data = bytes.fromhex(lines[1].strip())

        return ExpandBinaryResult(
            load_addr=load_addr,
            expanded_binary=data,
        )

    def get_all_process(self) -> list["Process"]:
        output = self.run_adb_command("ps -A")
        assert output is not None
        return [Process.from_ps_line(self, line) for line in output.split("\n")[1:] if line.strip()]

    def get_processes_by_name(self, name: str) -> list["Process"]:
        return [process for process in self.get_all_process() if process.name == name]

    def get_single_process_by_name(self, name: str) -> Optional["Process"]:
        processes = self.get_processes_by_name(name)
        if len(processes) == 1:
            return processes[0]
        else:
            return None

    def get_process_by_pid(self, pid: int) -> Optional["Process"]:
        matches = [process for process in self.get_all_process() if process.pid == pid]
        if len(matches) == 1:
            return matches[0]
        else:
            return None

    def start_activity_name(self, activity_name: str):
        self.run_adb_command(f"am start -n {activity_name}")

    def start_activity_action(self, action: str):
        self.run_adb_command(f"am start -a {action}")


@dataclass
class Process:
    adb: AdbClient = field(repr=False, compare=False)
    name: str
    pid: int

    @classmethod
    def from_ps_line(cls, adb: AdbClient, line: str) -> Self:
        parts = line.split()
        return cls(adb=adb, name=parts[8], pid=int(parts[1]))

    def kill(self, force: bool = False):
        if force:
            self.adb.run_adb_command(f"kill -9 {self.pid}", root=True)
        else:
            self.adb.run_adb_command(f"kill {self.pid}", root=True)

    def await_kill(self, force: bool = False):
        self.kill(force)

        while True:
            process = self.adb.get_process_by_pid(self.pid)
            if process is None or process.name != self.name:
                return

            sleep(0.2)

    def cmdline(self) -> str:
        output = self.adb.run_adb_command(f"cat /proc/{self.pid}/cmdline", root=True)
        assert output is not None
        return output.replace("\0", " ").strip()

    def read_memory(self, address: int, count: int) -> bytes:
        return self.adb.read_file(f"/proc/{self.pid}/mem", address, count)


class AdbProcess:
    command: str
    popen: subprocess.Popen
    process: Process
    is_root: bool
    adb: AdbClient

    def __init__(self, adb: AdbClient, command: str, root: bool = False):
        self.adb = adb
        self.command = command
        self.is_root = root

        launch_command = f"su root {command}" if root else command
        self.popen = subprocess.Popen(
            ["adb", "-s", self.adb.remote_addr, "shell", launch_command],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        sleep(0.2)

        command_name = command.split()[0].split("/")[-1]
        target_cmdline = " ".join(command.split())

        for process in self.adb.get_processes_by_name(command_name):
            if process.cmdline() == target_cmdline:
                self.process = process
                return

        assert False, "could not find launched process"

    def finish(self) -> Optional[str]:
        """Wait for process to finish and return its output (or None on error)."""
        try:
            stdout, stderr = self.popen.communicate()
            if self.popen.returncode != 0:
                error_output = "" if stderr is None else stderr.strip()
                print(f"Error executing ADB command `{self.command}`, root={self.is_root}: {error_output}")
                return None
            return stdout.strip()
        except FileNotFoundError:
            print("Error: 'adb' command not found. Is Android Debug Bridge installed and in your PATH?")
            return None

    def stop(self) -> Optional[str]:
        """Forcefully stop the process and return whatever output it produced."""
        if self.popen.poll() is None:
            self.process.await_kill()
        try:
            stdout, _stderr = self.popen.communicate()
            return stdout.strip()
        except Exception as e:
            print(f"Error stopping ADB command: {e}")
            return None


@dataclass
class StraceSyscall:
    name: str
    args: list[str]


class Strace:
    p: AdbProcess
    trace_process: Process
    adb: AdbClient

    def __init__(self, adb: AdbClient, process: Process):
        self.adb = adb
        self.trace_process = process
        self.p = AdbProcess(self.adb, f"strace -f -p {process.pid} -s 8192", root=True)

    def stop(self) -> list[StraceSyscall]:
        output = self.p.stop()
        assert output is not None

        out = []
        for line in output.split("\n"):
            if "(" not in line or ")" not in line:
                continue

            args_start = line.find("(")
            args_end = line.rfind(")")

            name = line[:args_start].split()[-1]
            args = line[args_start + 1:args_end]

            out.append(
                StraceSyscall(
                    name=name.strip(),
                    args=[arg.strip() for arg in args.split(",")],
                )
            )

        return out
