from enum import StrEnum
from collections import defaultdict
from dataclasses import dataclass
import os

from .git import GitRepo

class ConfigValue(StrEnum):
    ENABLED = "y"
    MODULE = "m"
    DISABLED = "n"

class KernelConfig:
    values: dict[str, ConfigValue]

    def __init__(self, config: str):
        self.values = defaultdict(lambda: ConfigValue.DISABLED)

        for line in config.splitlines():
            parts = line.split()

            # handle is not set comments
            if len(parts) == 5 and parts[0] == "#" and parts[2:] == ["is", "not", "set"]:
                self.values[parts[1]] = ConfigValue.DISABLED

            # strip comments
            line = line.split("#")[0].strip()
            if len(line) == 0:
                continue

            parts = line.split("=")
            if len(parts) == 2:
                try:
                    value = ConfigValue(parts[1])
                except ValueError:
                    # there are integer, and string keys, for now just treat as enabled
                    value = ConfigValue.ENABLED

                self.values[parts[0]] = value

    def get(self, key: str) -> ConfigValue:
        return self.values[key]


CODE_FILES = [".c", ".S"]
HEADER_FILES = [".h"]

class KbuildMakefile:
    def __init__(self, contents: str):
        pass

    def get(self, file: str) -> ConfigValue | None:
        pass

    def includes(self, file: str) -> bool:
        pass

@dataclass
class KbuildCacheEntry:
    makefile: KbuildMakefile
    children_present_folders: set[str]

class ConfigFilter:
    repo: GitRepo
    config: KernelConfig
    base_commit: str

    # mapping from folder to kbuild file inside it
    kbuild_cache: dict[str, KbuildCacheEntry]

    def __init__(self, repo: GitRepo, config: KernelConfig, base_commit: str):
        self.repo = repo
        self.config = config
        self.base_commit = base_commit
        self.kbuild_cache = {}

    @staticmethod
    def _split_path_parts(file: str) -> list[str]:
        parts = file.split("/")
        return ["/".join(parts[:i+1]) for i in range(len(parts))]

    def _kbuild_cache_add(self, folder: str, makefile: KbuildMakefile):
        parent, _ = os.path.split(folder)
        parent_entry = self.kbuild_cache.get(parent)

        if parent_entry is not None:
            parent_entry.children_present_folders.add(folder)

        self.kbuild_cache[folder] = KbuildCacheEntry(
            makefile=makefile,
            children_present_folders=set(),
        )

    def _kbuild_cache_get(self, folder: str) -> KbuildMakefile | None:
        entry = self.kbuild_cache.get(folder)
        if entry is None:
            return None
        else:
            return entry.makefile

    def _path_included(self, path: str) -> bool:
        # folder in root dir always included
        if "/" not in path:
            return True

        parent, child = os.path.split(path)
        makefile = self._kbuild_cache_get(parent)
        if makefile is None:
            if not self._path_included(parent):
                return False

            # use Kbuild if it exists, otherwise Makefile
            try:
                contents = self.repo.read_file(self.base_commit, os.path.join(parent, "Kbuild"))
            except Exception:
                contents = self.repo.read_file(self.base_commit, os.path.join(parent, "Makefile"))

            makefile = KbuildMakefile(contents.decode())
            self._kbuild_cache_add(parent, makefile)

        return makefile.includes(child)

    def remove_kbuild_makefile(self, path: str):
        if path not in self.kbuild_cache:
            return

        cache_entry = self.kbuild_cache.pop(path)
        for child in cache_entry.children_present_folders:
            self.remove_kbuild_makefile(child)

    def invalidate_kbuild_makefile(self, path: str, new_contents: str):
        cache_entry = self.kbuild_cache.get(path)
        if cache_entry is None:
            return

        new_makefile = KbuildMakefile(new_contents)
        new_children: set[str] = set()
        for child in cache_entry.children_present_folders:
            if new_makefile.includes(child):
                new_children.add(child)
            else:
                self.remove_kbuild_makefile(child)

        cache_entry.makefile = new_makefile
        cache_entry.children_present_folders = new_children

    def file_included(self, file: str) -> bool:
        extension = os.path.splitext(file)[-1]

        if extension in CODE_FILES:
            return self._path_included(file)
        elif extension in HEADER_FILES:
            # FIXME: actually trace header changes
            # the hypothesis is header only changes are very rare for vuln fixes
            # so just ignore them for now so we can be lazy
            return False
        else:
            # other files we ignore
            return False
