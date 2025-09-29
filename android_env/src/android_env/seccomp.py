from time import sleep
from tempfile import NamedTemporaryFile
from typing import Optional
import subprocess
import argparse
from pathlib import Path
import json

from .adb import get_single_process_by_name, Strace, start_activity_action, run_adb_command, AdbProcess, Tools, Process
from .syscalls import get_syscall_map

class SeccompDumper:
    command: AdbProcess

    def __init__(self, process: Process, mode: str):
        self.command = AdbProcess(f'{Tools.DUMP_SECCOMP_FILTER} {process.pid} {mode}', root=True)
    
    def get_filter(self) -> Optional[bytes]:
        output = self.command.stop().strip()
        if len(output) == 0:
            return None
        else:
            return bytes.fromhex(output)


def extract_seccomp_allowed_syscalls(dumper: SeccompDumper) -> Optional[dict[str, bool]]:
    allowed_syscalls = {}

    filter = dumper.get_filter()
    if filter is None:
        return None
    else:
        print(disasm_filter(filter))
        
        for syscall, number in get_syscall_map().items():
            allowed = eval_filter(filter, number)
            allowed_syscalls[syscall] = allowed
            print(f'{syscall}: {'ALLOWED' if allowed else 'BLOCKED'}')
    
        return allowed_syscalls

def disasm_filter(filter: bytes) -> str:
    with NamedTemporaryFile() as f:
        f.write(filter)
        f.flush()
        try:
            return subprocess.run(
                # ['bundle', 'exec', 'seccomp-tools', 'disasm', f.name],
                ['bundle', 'exec', 'seccomp-tools', 'disasm', str(f.name), '-a', 'aarch64'],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        except subprocess.CalledProcessError as e:
            print('error dissasembling seccomp filter')
            print(e.stderr.strip())

# returns true if syscall allowed
def eval_filter(filter: bytes, syscall_number: int) -> bool:
    with NamedTemporaryFile() as f:
        f.write(filter)
        f.flush()
        try:
            output = subprocess.run(
                ['bundle', 'exec', 'seccomp-tools', 'emu', '-a', 'aarch64', str(f.name), str(syscall_number)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            # last line has output, it has format of:
            # return ALLOW at line 0049 for example
            output = output.split('\n')[-1].split()

            assert output[0] == 'return'
            return output[1].lower() == 'allow'
        except subprocess.CalledProcessError as e:
            print('error evaluating seccomp filter')
            print(e.stderr.strip())
            return False

def parse_args():
    parser = argparse.ArgumentParser(
        description="Dump allowed syscalls by seccomp policy on android vm."
    )
    parser.add_argument(
        "json_file",
        type=Path,
        help="Path information about allowed syscalls will be saved"
    )
    return parser.parse_args()

def dump_seccomp():
    args = parse_args()
    save_file = args.json_file

    zygote32 = get_single_process_by_name('zygote')
    zygote64 = get_single_process_by_name('zygote64')

    dumper32 = SeccompDumper(zygote32, 'arm32')
    dumper64 = SeccompDumper(zygote64, 'arm64')

    # kill settings if it exists
    settings = get_single_process_by_name('com.android.settings')
    if settings is not None:
        settings.await_kill(force=True)
    
    # start settings to trigger zygote to spawn it
    start_activity_action('android.settings.SETTINGS')
    # wait for settings to start
    while get_single_process_by_name('com.android.settings') is None:
        sleep(0.5)

    allowed_syscalls32 = extract_seccomp_allowed_syscalls(dumper32)
    allowed_syscalls64 = extract_seccomp_allowed_syscalls(dumper64)
    
    allowed_syscalls = allowed_syscalls32 or allowed_syscalls64
    if allowed_syscalls is None:
        print('no secomp filter detected')
    else:
        with open(save_file, 'w') as f:
            json.dump({'system_app': allowed_syscalls}, f, indent=4, sort_keys=True)
        
