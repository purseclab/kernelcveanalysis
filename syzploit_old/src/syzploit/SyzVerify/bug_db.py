from typing import Optional, Self, List, Dict
from dataclasses import dataclass
from pathlib import Path
import os
import shutil
import sqlite3
import json
import yaml
import re
from datetime import datetime

@dataclass
class CrashReport:
    time: datetime
    kernel: str
    commit: str
    title: str
    report_url: Optional[str]
    syz_repro_url: Optional[str]
    c_repro_url: Optional[str]
    console_log_url: Optional[str]
    disk_image_url: Optional[str]
    disk_image_non_bootable_url: Optional[str]
    vmlinux_url: Optional[str]
    kernel_image_url: Optional[str]
    report_text: Optional[str]  # The actual content of the report

    def to_json(self) -> str:
        return json.dumps({
            'time': self.time.isoformat(),
            'kernel': self.kernel,
            'commit': self.commit,
            'title': self.title,
            'report_url': self.report_url,
            'syz_repro_url': self.syz_repro_url,
            'c_repro_url': self.c_repro_url,
            'console_log_url': self.console_log_url,
            'disk_image_url': self.disk_image_url,
            'disk_image_non_bootable_url': self.disk_image_non_bootable_url,
            'vmlinux_url': self.vmlinux_url,
            'kernel_image_url': self.kernel_image_url,
            'report_text': self.report_text
        })

    @classmethod
    def from_json(cls, json_str: str) -> Self:
        data = json.loads(json_str)
        data['time'] = datetime.fromisoformat(data['time'])
        return cls(**data)

import requests

from .run_bug import syz_to_c
from ..data import syzkaller_db_dir

@dataclass
class BugMetadata:
    bug_id: str
    title: str
    description: str
    subsystems: list[str]
    crash_time: datetime

    # name of kernel pulled from syzkaller
    kernel_name: str
    # link to git commit with kernel src
    kernel_url: Optional[str]
    kernel_config_url: Optional[str]

    # Primary crash report (one with C reproducer if available)
    crash_report: str
    syz_repro_url: str
    c_repro_url: str
    disk_image_url: Optional[str]
    disk_image_is_bootable: bool
    kernel_image_url: Optional[str]
    vmlinux_url: Optional[str]

    # All crash reports for this bug
    crash_reports: List[CrashReport] = None  # Will be initialized as empty list in __post_init__

    def __post_init__(self):
        if self.crash_reports is None:
            self.crash_reports = []

    # returns a path to the artifact with the given name
    def artifact_path(self, artifact_name: str) -> Path:
        artifact_folder = Path(os.path.join(syzkaller_db_dir(), self.bug_id))
        artifact_folder.mkdir(parents=True, exist_ok=True)

        return Path(os.path.join(artifact_folder, artifact_name))

    def save_url_to_artifact_folder(self, artifact_name: str, url: str) -> Path:
        artifact_path = self.artifact_path(artifact_name)
        # if artifact already exists, don't redownload
        if artifact_path.exists():
            return artifact_path
        
        response = requests.get(url)
        with open(artifact_path, 'wb') as f:
            f.write(response.content)
        
        return artifact_path
    
    def save_syz_repro(self) -> Path:
        return self.save_url_to_artifact_folder('repro.syz', self.syz_repro_url)
    
    def save_c_repro(self) -> Path:
        return self.save_url_to_artifact_folder('repro.c', self.c_repro_url)
    
    def parse_syzkaller_options(self, raw_block: str) -> dict:
        pairs = re.findall(r'(\w+):(true|false|-?\d+|none|)', raw_block)

        result = {}
        for key, value in pairs:
            key = key.lower()
            if value == "" or value.lower() == "none":
                result[key] = None
            elif value.lower() == "true":
                result[key] = True
            elif value.lower() == "false":
                pass
            else:
                try:
                    result[key] = int(value)
                except ValueError:
                    result[key] = value
        return result

    # FIXME: don't use str for arch
    def generate_c_repro(self, arch: str) -> Path:
        # First, try to use the pre-generated C repro from syzkaller if available
        # This is more reliable as it doesn't require syz-prog2c to support all syscalls
        if self.c_repro_url:
            try:
                c_repro_path = self.save_c_repro()
                # Copy to arch-specific path for consistency
                c_code_path = self.artifact_path(f'repro_{arch}.c')
                if c_repro_path != c_code_path:
                    shutil.copy(c_repro_path, c_code_path)
                return c_code_path
            except Exception as e:
                print(f"Failed to download C repro, falling back to syz-prog2c: {e}")
        
        # Fall back to converting from syz repro using syz-prog2c
        syz_repro = self.save_syz_repro()
        with open(syz_repro, 'r') as f:
            syz_data = f.read()
        
        options_start = syz_data.find('#{')
        options_end = syz_data.find('}\n')
        assert options_start != -1 and options_end != -1
        
        options_raw = syz_data[options_start + 1 : options_end + 1]
        
        # Known valid option keys in syzkaller repros (lowercase for comparison)
        valid_option_keys = {
            'threaded', 'collide', 'repeat', 'procs', 'sandbox', 'fault', 
            'faultcall', 'faultnth', 'enabletun', 'usetmpdir', 'handlesegv',
            'waitrepeat', 'debug', 'repro', 'slowdown', 'leak', 'netinjection',
            'netdevices', 'resetnet', 'usb', 'vhci', 'wifi', 'ieee802154',
            'sysctl', 'cgroups', 'binfmt_misc', 'close_fds', 'devlinkpci',
            'nicvf', 'swap', 'csuminet'
        }
        
        # Try YAML first (newer format), validate the result has valid keys
        options = None
        try:
            parsed = yaml.safe_load(options_raw)
            if isinstance(parsed, dict):
                # Check if at least some known keys are present (lowercase comparison)
                parsed_keys_lower = {k.lower() for k in parsed.keys()}
                if parsed_keys_lower & valid_option_keys:
                    options = parsed
        except Exception:
            pass
        
        # Fall back to parsing old-style format: Key:value Key2:value2 ...
        if options is None:
            options = self.parse_syzkaller_options(options_raw)
        
        options['arch'] = arch

        c_code = syz_to_c(syz_repro, options)
        c_code_path = self.artifact_path(f'repro_{arch}.c')
        with open(c_code_path, 'w') as f:
            f.write(c_code)
        
        return c_code_path

    def download_artifacts(self, source_dir: str):
        artifact_folder = os.path.join(source_dir, self.bug_id)
        os.makedirs(artifact_folder, exist_ok=True)
        disk_path = None
        kernel_path = None
        if self.disk_image_url:
            disk_path = self.save_url_to_artifact_folder(os.path.join(artifact_folder, 'disk.raw.xz'), self.disk_image_url)
            # unxz disk image
            os.system(f'unxz -k "{disk_path.absolute()}"')
            disk_path = str(disk_path)
            disk_path = disk_path[:-3] if disk_path else None
        if self.kernel_image_url:
            kernel_path = self.save_url_to_artifact_folder(os.path.join(artifact_folder, 'bzImage.xz'), self.kernel_image_url)
            os.system(f'unxz -k "{kernel_path.absolute()}"')
            kernel_path = str(kernel_path)
            kernel_path = kernel_path[:-3] if kernel_path else None
        return disk_path, kernel_path

    def compile_repro(self, arch: str, use_llm_fix: bool = True) -> Path:
        """
        Compile the reproducer for the target architecture.
        
        If compilation fails due to arch-specific syscall issues (e.g., __NR_epoll_create 
        missing on ARM64), this will attempt to fix the C code using quick fixes and 
        optionally LLM-based fixes.
        
        Args:
            arch: Target architecture ('arm64', 'x86_64')
            use_llm_fix: Whether to use LLM to fix compilation errors
            
        Returns:
            Path to the compiled binary
        """
        c_repro_path = self.generate_c_repro(arch)
        repro_bin_path = self.artifact_path('repro')
        
        # Try normal compilation first
        compile_result = os.system(f'./compile_{arch}.sh "{c_repro_path.absolute()}" "{repro_bin_path.absolute()}"')
        
        if compile_result == 0 and repro_bin_path.exists():
            return repro_bin_path
        
        # If compilation failed, try to fix syscall compatibility issues
        print(f"[INFO] Initial compilation failed for {arch}, attempting fixes...")
        
        try:
            from .syscall_fixer import compile_with_fix
            success = compile_with_fix(
                c_repro_path, 
                repro_bin_path, 
                arch, 
                use_llm=use_llm_fix
            )
            if success and repro_bin_path.exists():
                print(f"[INFO] Compilation succeeded after applying fixes")
                return repro_bin_path
        except ImportError:
            print("[WARN] syscall_fixer module not available, cannot auto-fix")
        except Exception as e:
            print(f"[WARN] Auto-fix failed: {e}")
        
        # Final assertion - compilation must succeed
        assert repro_bin_path.exists(), f"Failed to compile reproducer for {arch}"
        return repro_bin_path
    
    def run_repro(self, arch: str):
        repro_path = self.compile_repro(arch)

    @classmethod
    def from_db_tuple(cls, data: tuple) -> Self:
        # Initialize with empty crash_reports list - will be populated separately
        return cls(
            bug_id=data[0],
            title=data[1],
            description=data[2],
            subsystems=data[3].split(','),
            crash_time=data[4],
            kernel_name=data[5],
            kernel_url=data[6],
            kernel_config_url=data[7],
            crash_report=data[8],
            syz_repro_url=data[9],
            c_repro_url=data[10],
            disk_image_url=data[11],
            disk_image_is_bootable=(data[12] == 1),
            kernel_image_url=data[13],
            vmlinux_url=data[14],
            crash_reports=[]  # Initialize empty, will be populated when loading
        )
    
    def to_db_tuple(self) -> tuple:
        return (
            self.bug_id,
            self.title,
            self.description,
            ','.join(self.subsystems),
            self.crash_time,
            self.kernel_name,
            self.kernel_url,
            self.kernel_config_url,
            self.crash_report,
            self.syz_repro_url,
            self.c_repro_url,
            self.disk_image_url,
            self.disk_image_is_bootable,
            self.kernel_image_url,
            self.vmlinux_url,
        )

class SyzkallBugDatabase:
    base_folder: Path
    metadata_db: sqlite3.Connection

    def __init__(self, kernel: str = "android-5.10"):
        self.base_folder = syzkaller_db_dir()

        self.metadata_db = sqlite3.connect(os.path.join(self.base_folder, f'{kernel}_metadata_db.sqlite'))
        
        # Create main bugs table
        self.metadata_db.execute('''
        CREATE TABLE IF NOT EXISTS bugs (
            id TEXT PRIMARY KEY,
            title TEXT,
            description TEXT,
            subsystems TEXT,
            crash_time TIMESTAMP,
            kernel_name TEXT,
            kernel_url TEXT,
            kernel_config_url TEXT,
            crash_report TEXT,
            syz_repro_url TEXT,
            c_repro_url TEXT,
            disk_image_url TEXT,
            disk_image_is_bootable INTEGER,
            kernel_image_url TEXT,
            vmlinux_url TEXT
        )
        ''')
        
        # Create crash reports table
        self.metadata_db.execute('''
        CREATE TABLE IF NOT EXISTS crash_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bug_id TEXT,
            crash_data TEXT,
            FOREIGN KEY(bug_id) REFERENCES bugs(id)
        )
        ''')
    
    def close(self):
        self.metadata_db.close()
    
    def save_bug_metadata(self, metadata: BugMetadata):
        # First insert the main bug info
        self.metadata_db.execute('''
        INSERT INTO bugs (
            id,
            title,
            description,
            subsystems,
            crash_time,
            kernel_name,
            kernel_url,
            kernel_config_url,
            crash_report,
            syz_repro_url,
            c_repro_url,
            disk_image_url,
            disk_image_is_bootable,
            kernel_image_url,
            vmlinux_url
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', metadata.to_db_tuple())
        
        # Then save all crash reports
        for crash in metadata.crash_reports:
            self.metadata_db.execute('''
            INSERT INTO crash_reports (bug_id, crash_data)
            VALUES (?, ?)
            ''', (metadata.bug_id, crash.to_json()))
        
        self.metadata_db.commit()
    
    def get_bug_metadata(self, id: str) -> Optional[BugMetadata]:
        # Get main bug info
        result = self.metadata_db.execute('SELECT * FROM bugs WHERE id = ?', (id,)).fetchone()
        if result is None:
            return None
        
        # Get all crash reports for this bug
        crash_reports = []
        for row in self.metadata_db.execute('SELECT crash_data FROM crash_reports WHERE bug_id = ?', (id,)).fetchall():
            crash_reports.append(CrashReport.from_json(row[0]))
        
        bug = BugMetadata.from_db_tuple(result)
        bug.crash_reports = crash_reports
        return bug
    
    def get_all_bugs(self) -> list[BugMetadata]:
        results = self.metadata_db.execute('SELECT * FROM bugs').fetchall()

        return [BugMetadata.from_db_tuple(row) for row in results]
