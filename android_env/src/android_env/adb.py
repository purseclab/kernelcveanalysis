import subprocess
from typing import Optional, Self
from dataclasses import dataclass
from time import sleep
from pathlib import Path
from enum import StrEnum

def run_adb_command(command: str, root: bool = False) -> Optional[str]:
    """Executes an ADB command and returns its output."""
    try:
        command = f'su root {command}' if root else command
        result = subprocess.run(
            f"adb -s 0.0.0.0:6532 shell \"{command}\" 2>&1",
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

def upload_file(src_path: Path, dst_path: Path, executable: bool = False):
    subprocess.run(
        ['adb', '-s', '0.0.0.0:6532', 'push', str(src_path), str(dst_path)],
        check=True,
    )

    if executable:
        run_adb_command(f'chmod +x {str(dst_path)}', root=True)

def install_app(app: Path):
    subprocess.run(
        ['adb', '-s', '0.0.0.0:6532', 'install', str(app)],
        check=True,
    )

class Tools(StrEnum):
    READ_FILE = '/data/local/tmp/tools/read_file'
    DUMP_SECCOMP_FILTER = '/data/local/tmp/tools/dump_seccomp_filter'
    RUNAS = '/data/local/tmp/tools/runas'
    EXPAND_BINARY = '/data/local/tmp/tools/expand_binary'

def upload_tools():
    run_adb_command('mkdir -p /data/local/tmp/tools')
    upload_file(Path('./tools/read_file'), Path(Tools.READ_FILE), executable=True)
    upload_file(Path('./tools/dump_seccomp_filter'), Path(Tools.DUMP_SECCOMP_FILTER), executable=True)
    upload_file(Path('./tools/runas'), Path(Tools.RUNAS), executable=True)
    upload_file(Path('./tools/expand_binary'), Path(Tools.EXPAND_BINARY), executable=True)

def read_file(file: str, offset: int = 0, count: int = -1) -> bytes:
    out = run_adb_command(f'{Tools.READ_FILE} {file} {offset} {count}', root=True)
    return bytes.fromhex(out)

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
            selabel='u:r:su:s0',
        )


def runas(command: str, permissions: Permissions) -> Optional[str]:
    return run_adb_command(f'{Tools.RUNAS} {permissions.uid} {permissions.gid} \'{permissions.selabel}\' \'{command}\'')

@dataclass
class ExpandBinaryResult:
    load_addr: int
    expanded_binary: bytes

def expand_binary(binary: str) -> ExpandBinaryResult:
    output = run_adb_command(f'{Tools.EXPAND_BINARY} {binary}', root=True)
    lines = output.splitlines()
    assert len(lines) == 2

    load_addr = int(lines[0].strip(), 16)
    data = bytes.fromhex(lines[1].strip())

    return ExpandBinaryResult(
        load_addr=load_addr,
        expanded_binary=data,
    )

@dataclass
class Process:
    name: str
    pid: int

    @classmethod
    def from_ps_line(cls, line: str) -> Self:
        parts = line.split()
        return cls(name=parts[8], pid=parts[1])
    
    def kill(self, force: bool = False):
        if force:
            run_adb_command(f'kill -9 {self.pid}', root=True)
        else:
            run_adb_command(f'kill {self.pid}', root=True)
    
    def await_kill(self, force: bool = False):
        self.kill(force)

        while True:
            p = get_process_by_pid(self.pid)
            if p is None or p.name != self.name:
                return
            
            sleep(0.2)
    
    def cmdline(self) -> str:
        return run_adb_command(f'cat /proc/{self.pid}/cmdline', root=True).replace('\0', ' ').strip()
    
    def read_memory(self, address: int, count: int) -> bytes:
        return read_file(f'/proc/{self.pid}/mem', address, count)

def get_all_process() -> list[Process]:
    return [Process.from_ps_line(line) for line in run_adb_command('ps -A').split('\n')[1:]]

def get_processes_by_name(name: str) -> list[Process]:
    return [process for process in get_all_process() if process.name == name]

def get_single_process_by_name(name: str) -> Optional[Process]:
    processes = get_processes_by_name(name)
    if len(processes) == 1:
        return processes[0]
    else:
        return None

def get_process_by_pid(pid: int) -> Optional[Process]:
    matches = [process for process in get_all_process() if process.pid == pid]
    if len(matches) == 1:
        return matches[0]
    else:
        return None

class AdbProcess:
    command: str
    popen: subprocess.Popen
    process: Process
    is_root: bool
    
    def __init__(self, command: str, root: bool = False):
        self.command = command
        self.is_root = root

        launch_command = f'su root {command}' if root else command
        self.popen = subprocess.Popen(
            ["adb", "-s", "0.0.0.0:6532", "shell", launch_command],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        # wait for command to start
        sleep(0.2)

        # cmdline has no spaces, and is trail end of absolute path
        command_name = command.split()[0].split('/')[-1]

        # remove duplicate space
        target_cmdline = ' '.join(command.split())

        # search for matching process to command based on cmdline
        for p in get_processes_by_name(command_name):
            if p.cmdline() == target_cmdline:
                self.process = p
                return
        
        assert False, "could not find launched process"
    
    def finish(self) -> Optional[str]:
        """Wait for process to finish and return its output (or None on error)."""
        try:
            stdout, stderr = self.popen.communicate()
            if self.popen.returncode != 0:
                print(f"Error executing ADB command `{self.command}`, root={self.is_root}: {stderr.strip()}")
                return None
            return stdout.strip()
        except FileNotFoundError:
            print("Error: 'adb' command not found. Is Android Debug Bridge installed and in your PATH?")
            return None

    def stop(self) -> Optional[str]:
        """Forcefully stop the process and return whatever output it produced."""
        if self.popen.poll() is None:  # still running
            self.process.await_kill()
        try:
            # stderr is piped to stdout
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

    def __init__(self, process: Process):
        self.trace_process = process
        self.p = AdbProcess(f'strace -f -p {process.pid} -s 8192', root=True)
    
    def stop(self) -> list[StraceSyscall]:
        output = self.p.stop()
        assert output is not None

        # FIXME: naive parsing, some syscalls are split and resumed
        out = []
        for line in output.split('\n'):
            if not '(' in line or not ')' in line:
                continue

            args_start = line.find('(')
            args_end = line.rfind(')')

            name = line[:args_start].split()[-1]
            args = line[args_start+1:args_end]

            out.append(StraceSyscall(
                name=name.strip(),
                args=[arg.strip() for arg in args.split(',')],
            ))
        
        return out

def start_activity_name(activity_name: str):
    run_adb_command(f'am start -n {activity_name}')

def start_activity_action(action: str):
    run_adb_command(f'am start -a {action}')