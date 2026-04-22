import subprocess
import tempfile
from dataclasses import dataclass, field
from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from posixpath import normpath
from shutil import copyfileobj
from shlex import quote
from time import sleep
from typing import Optional, Self
from zipfile import ZipFile


DEFAULT_REMOTE_ADDR = "0.0.0.0:6532"
TOOLS_PATH = Path(__file__).parent.parent.parent / 'tools'


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


@dataclass(frozen=True)
class BundleObbFile:
    source_path: Path
    device_path: Path


@dataclass(frozen=True)
class ExtractedAppBundle:
    apk_paths: tuple[Path, ...]
    obb_files: tuple[BundleObbFile, ...]


class AdbCommandError(RuntimeError):
    def __init__(self, command: str, stdout: bytes | str = b"", stderr: bytes | str = b""):
        self.command = command
        self.stdout = stdout
        self.stderr = stderr

        stdout_text = stdout if isinstance(stdout, str) else stdout.decode("utf-8", errors="replace")
        stderr_text = stderr if isinstance(stderr, str) else stderr.decode("utf-8", errors="replace")
        super().__init__(
            f"ADB command failed: {command}\nstdout: {stdout_text}\nstderr: {stderr_text}"
        )


class AdbClient:
    remote_addr: str

    def __init__(self, remote_addr: str = DEFAULT_REMOTE_ADDR):
        self.remote_addr = remote_addr

    def adb_args(self, *args: str) -> list[str]:
        return ["adb", "-s", self.remote_addr, *args]

    def connect_args(self) -> list[str]:
        return ["adb", "connect", self.remote_addr]

    def disconnect_args(self) -> list[str]:
        return ["adb", "disconnect", self.remote_addr]

    def run_adb(self, *args: str, check: bool = True, text: bool = False) -> subprocess.CompletedProcess:
        return subprocess.run(
            self.adb_args(*args),
            check=check,
            capture_output=True,
            text=text,
        )

    def connect(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            self.connect_args(),
            check=True,
            capture_output=True,
            text=True,
        )

    def disconnect(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            self.disconnect_args(),
            check=True,
            capture_output=True,
            text=True,
        )

    def wait_for_device(self, timeout_sec: float | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            self.adb_args("wait-for-device"),
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )

    def wait_for_boot_completed(
        self,
        timeout_sec: float = 180.0,
        poll_interval_sec: float = 1.0,
    ) -> None:
        deadline = None if timeout_sec is None else timeout_sec
        elapsed = 0.0
        while True:
            try:
                if self.shell_text("getprop sys.boot_completed").strip() == "1":
                    return
            except AdbCommandError:
                pass

            if deadline is not None and elapsed >= deadline:
                raise TimeoutError(
                    f"timed out waiting for {self.remote_addr} boot completion"
                )
            sleep(poll_interval_sec)
            elapsed += poll_interval_sec

    def run_shell(
        self,
        command: str,
        root: bool = False,
        check: bool = True,
        text: bool = False,
    ) -> subprocess.CompletedProcess:
        remote_command = f"su root sh -c {quote(command)}" if root else command
        return self.run_adb("shell", remote_command, check=check, text=text)

    def shell_bytes(self, command: str, root: bool = False) -> bytes:
        result = self.run_shell(command, root=root, check=False, text=False)
        if result.returncode != 0:
            raise AdbCommandError(command, result.stdout or b"", result.stderr or b"")
        return result.stdout or b""

    def shell_text(self, command: str, root: bool = False) -> str:
        return self.shell_bytes(command, root=root).decode("utf-8", errors="replace")

    def run_adb_command(self, command: str, root: bool = False) -> Optional[str]:
        """Executes an ADB command and returns its output."""
        try:
            result = self.run_shell(command, root=root, check=True, text=True)
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
        suffix = app.suffix.lower()
        if suffix == ".apk":
            self._install_apk(app)
            return
        if suffix in {".xapk", ".apkm"}:
            self._install_bundle_archive(app)
            return
        raise ValueError(f"unsupported app format: {app}")

    def install_multiple_apps(self, apps: list[Path]):
        if not apps:
            raise ValueError("install_multiple_apps requires at least one apk")
        subprocess.run(
            ["adb", "-s", self.remote_addr, "install-multiple", *map(str, apps)],
            check=True,
        )

    def _install_apk(self, app: Path) -> None:
        subprocess.run(
            ["adb", "-s", self.remote_addr, "install", str(app)],
            check=True,
        )

    def _install_bundle_archive(self, app: Path) -> None:
        with self._extract_app_bundle(app) as extracted:
            if len(extracted.apk_paths) == 1:
                self._install_apk(extracted.apk_paths[0])
            else:
                self.install_multiple_apps(list(extracted.apk_paths))

            for obb_file in extracted.obb_files:
                parent_dir = str(obb_file.device_path.parent)
                self.run_adb_command(f"mkdir -p {quote(parent_dir)}")
                self.upload_file(obb_file.source_path, obb_file.device_path)

    @contextmanager
    def _extract_app_bundle(self, app: Path):
        with tempfile.TemporaryDirectory(prefix=f"{app.stem}-") as tempdir:
            yield self._extract_app_bundle_contents(app, Path(tempdir))

    def _extract_app_bundle_contents(
        self,
        app: Path,
        destination_dir: Path,
    ) -> ExtractedAppBundle:
        apk_paths: list[Path] = []
        obb_files: list[BundleObbFile] = []
        with ZipFile(app) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                member_path = self._normalized_archive_path(member.filename)
                target_path = destination_dir / member_path
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as src, target_path.open("wb") as dst:
                    copyfileobj(src, dst)

                if target_path.suffix.lower() == ".apk":
                    apk_paths.append(target_path)
                elif self._is_obb_archive_path(member_path):
                    obb_files.append(
                        BundleObbFile(
                            source_path=target_path,
                            device_path=Path("/sdcard") / member_path,
                        )
                    )

        ordered_apks = tuple(sorted(apk_paths, key=self._apk_install_sort_key))
        if not ordered_apks:
            raise ValueError(f"app bundle does not contain any APK files: {app}")
        return ExtractedAppBundle(
            apk_paths=ordered_apks,
            obb_files=tuple(sorted(obb_files, key=lambda file: str(file.device_path))),
        )

    def _normalized_archive_path(self, member_name: str) -> Path:
        normalized = normpath(member_name.replace("\\", "/"))
        if normalized in {"", "."}:
            raise ValueError(f"invalid archive member path: {member_name!r}")
        normalized_path = Path(normalized)
        if normalized_path.is_absolute() or ".." in normalized_path.parts:
            raise ValueError(f"unsafe archive member path: {member_name!r}")
        return normalized_path

    def _is_obb_archive_path(self, path: Path) -> bool:
        return (
            len(path.parts) >= 4
            and path.parts[:2] == ("Android", "obb")
            and path.suffix.lower() == ".obb"
        )

    def _apk_install_sort_key(self, path: Path) -> tuple[int, str]:
        lower_name = path.name.lower()
        is_base = 0 if lower_name == "base.apk" else 1
        return (is_base, lower_name)

    def upload_tools(self):
        self.run_adb_command("mkdir -p /data/local/tmp/tools")
        self.upload_file(TOOLS_PATH / "read_file", Path(Tools.READ_FILE), executable=True)
        self.upload_file(TOOLS_PATH / "dump_seccomp_filter", Path(Tools.DUMP_SECCOMP_FILTER), executable=True)
        self.upload_file(TOOLS_PATH / "runas", Path(Tools.RUNAS), executable=True)
        self.upload_file(TOOLS_PATH / "expand_binary", Path(Tools.EXPAND_BINARY), executable=True)

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
