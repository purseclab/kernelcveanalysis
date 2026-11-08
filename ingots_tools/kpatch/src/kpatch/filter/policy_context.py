"""Revision-pinned compiler inputs and deletion-safe, bounded TU fact caching."""

from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
from typing import Literal
import zlib

from pydantic import BaseModel, ConfigDict

from .policy_clang import ClangAnalyzer, ClangByteExclusion, CompileCommand, PreprocessorFingerprint, SourceOverlay, TranslationUnitFacts, load_compilation_database
from .repository_file import RepositoryFileReader
from ..git import GitRepo


_CONTEXT_VERSION = "clang-policy-context-v4-seccomp-entry"
_MAX_OVERLAYS = 256
_MAX_OVERLAY_BYTES = 8 * 1024 * 1024
_MAX_SOURCE_BYTES = 4 * 1024 * 1024
_MAX_PREPROCESSING_PAYLOAD = 16 * 1024 * 1024
_MAX_PREPROCESSING_CACHE_BYTES = 1024 * 1024 * 1024


def _digest(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def _immutable_input(path: Path, source: Path, build: Path) -> bool:
    resolved = path.resolve()
    return any(resolved.is_relative_to(root) for root in (source, build, Path("/nix/store")))


def _validate_search_environment() -> None:
    for name in ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH", "SDKROOT"):
        if os.environ.get(name):
            raise ValueError("Unset implicit compiler search environment " + name)


def _validate_search_inputs(command: CompileCommand, source: Path, build: Path) -> tuple[Path, ...]:
    """No mutable implicit include roots or hidden response-file options.

    Positive dependency hashes alone cannot detect newly appearing shadow
    headers. Kernel commands use -nostdinc; explicit roots must be frozen or
    content-addressed. More general SDKs need a pinned include-root snapshot.
    """
    arguments = command.frontend_arguments()[1:]
    if "-nostdinc" not in arguments:
        raise ValueError("Policy compiler commands require -nostdinc and explicit pinned include paths")
    _validate_search_environment()
    paths = ("-isystem", "-iquote", "-idirafter", "-isysroot", "--sysroot", "-resource-dir",
             "--gcc-toolchain", "-include", "-imacros", "-I", "-F", "-iframework", "-B")
    pending = False
    search_option = ""
    forced: list[Path] = []
    for argument in arguments:
        if pending:
            value = argument
            pending = False
        else:
            if argument.startswith(("@", "-Wp,", "-Xclang", "--config", "-ivfsoverlay", "-iprefix", "-iwithprefix",
                                    "-include-pch", "-fmodule", "-fplugin", "-Xpreprocessor")):
                raise ValueError("Unsupported hidden compiler input option: " + argument)
            if argument in paths:
                pending = True
                search_option = argument
                continue
            option = next((prefix for prefix in paths if argument.startswith(prefix) and len(argument) > len(prefix)), None)
            if option is None:
                continue
            search_option = option
            value = argument[len(option):].removeprefix("=")
        if not value or value.startswith(("=", "$")):
            raise ValueError("Unresolved compiler input path")
        path = Path(value)
        if search_option in {"-include", "-imacros"}:
            if not path.is_absolute() or not path.is_file():
                raise ValueError("Forced includes require an explicit absolute existing text-header path")
            if path.suffix in {".pch", ".gch", ".pcm"} or any(Path(str(path) + suffix).exists() for suffix in (".pch", ".gch")):
                raise ValueError("Precompiled header inputs are not supported by policy contexts")
            forced.append(path)
        if not path.is_absolute():
            path = command.directory / path
        if not _immutable_input(path, source, build):
            raise ValueError("Compiler include/search input is outside pinned roots: " + str(path))
        if search_option not in {"-include", "-imacros"} and path.exists() and not path.is_dir():
            raise ValueError("Directory search options cannot reference header maps or mutable files")
    if pending:
        raise ValueError("Missing compiler input path")
    return tuple(forced)


class InputDigest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    path: Path
    sha256: str


class PolicyBuildContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    schema_version: Literal[1] = 1
    source_root: Path
    build_root: Path
    base_revision: str
    compilation_database: Path
    config_file: Path
    config_sha256: str
    compiler_version: str
    generated_inputs: tuple[InputDigest, ...]
    compilation_database_sha256: str
    build_membership_sha256: str

    @classmethod
    def capture(cls, source_root: Path, build_root: Path, compilation_database: Path,
                config_file: Path) -> "PolicyBuildContext":
        source_root, build_root = source_root.resolve(), build_root.resolve()
        source_repo = GitRepo(source_root)
        revision = source_repo._run_git(["rev-parse", "HEAD"]).decode().strip()
        if source_repo._run_git(["status", "--porcelain", "--untracked-files=all", "--ignored=matching"]):
            raise ValueError("Policy compiler context requires a clean source tree without untracked include inputs")
        if build_root == source_root or build_root.is_relative_to(source_root):
            raise ValueError("Keep the prepared build directory outside the source checkout")
        commands = load_compilation_database(compilation_database)
        if not commands:
            raise ValueError("Compilation database is empty")
        for command in commands:
            _validate_search_inputs(command, source_root, build_root)
            _command_key(command.file, source_root, build_root)
        compilers = {command.arguments[0] for command in commands}
        if len(compilers) != 1:
            raise ValueError("Use one explicit compiler toolchain per policy context")
        compiler = next(iter(compilers))
        version = subprocess.check_output([compiler, "--version"], text=True, timeout=10).splitlines()[0]
        if "clang" not in version.lower():
            raise ValueError("Use a Clang-prepared compilation database; GCC flags are not guessed")
        generated = tuple(InputDigest(path=path.resolve(), sha256=_digest(path.read_bytes()))
                          for path in sorted(build_root.rglob("*"))
                          if path.is_file() and not path.is_symlink()
                          and path.suffix in {".h", ".inc", ".lds", ".c", ".S", ".s"})
        return cls(source_root=source_root, build_root=build_root, base_revision=revision,
                   compilation_database=compilation_database.resolve(), config_file=config_file.resolve(),
                   config_sha256=_digest(config_file.read_bytes()), compiler_version=version,
                   generated_inputs=generated,
                   compilation_database_sha256=_digest(compilation_database.read_bytes()),
                   build_membership_sha256=_membership(build_root))

    @classmethod
    def load(cls, path: Path) -> "PolicyBuildContext":
        context = cls.model_validate_json(path.read_text())
        root = path.resolve().parent
        def resolve(value: Path) -> Path:
            return value if value.is_absolute() else (root / value).resolve()
        updates = {"source_root": resolve(context.source_root), "build_root": resolve(context.build_root),
                   "compilation_database": resolve(context.compilation_database), "config_file": resolve(context.config_file),
                   "generated_inputs": tuple(item.model_copy(update={"path": resolve(item.path)}) for item in context.generated_inputs)}
        return context.model_copy(update=updates)

    @property
    def fingerprint(self) -> str:
        return _digest(self.model_dump_json().encode())


class _CachedFacts(BaseModel):
    model_config = ConfigDict(extra="forbid")
    facts: TranslationUnitFacts
    inputs: tuple[InputDigest, ...]


class _CachedPreprocessing(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fingerprint: PreprocessorFingerprint
    inputs: tuple[InputDigest, ...]


@dataclass(frozen=True, slots=True)
class _Snapshot:
    overlays: tuple[SourceOverlay, ...]
    names_key: str
    failure: str = ""


@dataclass(slots=True)
class PolicyCompilerStats:
    requests: int = 0
    extractions: int = 0
    cache_hits: int = 0
    unknown_cache_hits: int = 0
    incomplete: int = 0
    preprocessing_requests: int = 0
    preprocessing_extractions: int = 0
    preprocessing_cache_hits: int = 0
    preprocessing_cache_budget_skips: int = 0


def _build_input(path: str) -> bool:
    name = Path(path).name
    contracts = {"kernel/capability.c", "security/commoncap.c", "security/security.c", "security/selinux/hooks.c",
                 "security/selinux/avc.c", "include/linux/security.h", "include/linux/capability.h",
                 "include/linux/perf_event.h", "include/linux/lsm_hook_defs.h", "include/linux/export.h", "include/linux/init.h",
                 "include/linux/btf_ids.h", "include/linux/tracepoint.h", "include/uapi/linux/capability.h",
                 "include/uapi/linux/bpf.h", "include/linux/syscalls.h", "include/linux/compat.h"}
    contracts.update({"kernel/seccomp.c", "include/linux/seccomp.h", "include/uapi/linux/seccomp.h",
                      "include/uapi/linux/audit.h", "include/uapi/linux/elf-em.h",
                      "net/core/filter.c", "kernel/bpf/core.c", "include/linux/filter.h",
                      "arch/arm64/net/bpf_jit_comp.c", "arch/arm64/include/asm/seccomp.h",
                      "include/linux/entry-common.h", "kernel/entry/common.c", "kernel/entry/syscall-common.c",
                      "arch/arm64/kernel/syscall.c", "arch/arm64/kernel/ptrace.c", "arch/arm64/kernel/entry-common.c",
                      "arch/arm64/kernel/entry.S", "arch/arm64/include/asm/syscall.h",
                      "arch/arm64/include/asm/thread_info.h", "arch/arm64/kernel/alternative.c",
                      "arch/arm64/include/asm/alternative.h"})
    return (name in {"Makefile", "Kbuild", ".config"} or name.startswith("Kconfig")
            or path in contracts
            or path.endswith("/include/asm/syscall_wrapper.h")
            or path.startswith(("scripts/", "include/generated/"))
            or "/include/generated/" in path or path.endswith((".lds", ".lds.S", ".mk")))


def _membership(root: Path) -> str:
    return _digest("\n".join(str(path.relative_to(root)) + ("->" + str(path.readlink()) if path.is_symlink() else "")
                              for path in sorted(root.rglob("*")) if path.is_file() or path.is_symlink()).encode())


def _command_key(path: Path, source: Path, build: Path) -> str:
    if path.is_relative_to(source):
        return path.relative_to(source).as_posix()
    if path.is_relative_to(build):
        return "@build/" + path.relative_to(build).as_posix()
    raise ValueError("Compilation source is outside pinned source/build roots: " + str(path))


class RevisionCompiler:
    """Compile real snapshots via overlays; masks never alter compiler inputs.

    Context changes and unsupported deltas retain the candidate. Fact reuse is
    checked against every recorded preprocessing dependency. Added/deleted paths
    also change the key, covering previously unsuccessful/shadowed includes.
    """

    def __init__(self, repo: GitRepo, build: PolicyBuildContext, analyzer: ClangAnalyzer,
                 *, cache_path: Path | None = None) -> None:
        self.repo, self.build, self.analyzer = repo, build, analyzer
        self.stats = PolicyCompilerStats()
        self.commands: dict[str, CompileCommand] = {}
        self._forced_includes: set[Path] = set()
        for command in load_compilation_database(build.compilation_database):
            self._forced_includes.update(_validate_search_inputs(command, build.source_root, build.build_root))
            path = _command_key(command.file, build.source_root, build.build_root)
            if path in self.commands and self.commands[path] != command:
                raise ValueError("Multiple build variants of one TU require separate policy contexts")
            self.commands[path] = command
        self.reader = RepositoryFileReader(repo)
        self._git_digests: OrderedDict[tuple[str, str], str] = OrderedDict()
        self._digest_epoch = self.reader.cache_epoch
        self._verified_baseline_sources: set[Path] = set()
        try:
            algorithm = repo._run_git(["rev-parse", "--show-object-format"]).strip()
            self._revision_width = {b"sha1": 40, b"sha256": 64}.get(algorithm, 0)
        except (OSError, ValueError, subprocess.SubprocessError):
            self._revision_width = 0
        self._snapshots: OrderedDict[str, _Snapshot] = OrderedDict()
        self._facts: OrderedDict[str, _CachedFacts] = OrderedDict()
        self._preprocessed: OrderedDict[str, _CachedPreprocessing] = OrderedDict()
        self._preprocessed_baselines: set[str] = set()
        self._unknown: OrderedDict[str, TranslationUnitFacts] = OrderedDict()
        self._database: sqlite3.Connection | None = None
        self._generated = {item.path: item.sha256 for item in build.generated_inputs}
        self._worker_identity = _digest(analyzer.worker_path.read_bytes())
        self._preprocessing_context = _digest(("expanded-input-cache-v2:" + self._worker_identity + build.fingerprint).encode())
        self._preprocessing_bytes = 0
        if cache_path is not None:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._database = sqlite3.connect(cache_path, timeout=10)
            self._database.execute("CREATE TABLE IF NOT EXISTS policy_tus (family TEXT, fingerprint TEXT PRIMARY KEY, payload TEXT NOT NULL, checksum TEXT NOT NULL, used INTEGER NOT NULL)")
            self._database.execute("CREATE INDEX IF NOT EXISTS policy_tus_family ON policy_tus(family)")
            self._database.execute("CREATE TABLE IF NOT EXISTS policy_unknown_tus (cache_key TEXT PRIMARY KEY, payload TEXT NOT NULL, checksum TEXT NOT NULL, used INTEGER NOT NULL)")
            self._database.execute("CREATE TABLE IF NOT EXISTS compiler_preprocessed_v2 (context TEXT NOT NULL, unit TEXT NOT NULL, family TEXT NOT NULL, fingerprint TEXT PRIMARY KEY, payload BLOB NOT NULL, checksum TEXT NOT NULL, baseline INTEGER NOT NULL, used INTEGER NOT NULL)")
            self._database.execute("CREATE INDEX IF NOT EXISTS compiler_preprocessed_v2_family ON compiler_preprocessed_v2(context,family)")
            self._database.execute("CREATE INDEX IF NOT EXISTS compiler_preprocessed_v2_unit ON compiler_preprocessed_v2(context,unit,baseline,used)")
            self._preprocessing_bytes = self._database.execute("SELECT COALESCE(SUM(LENGTH(payload)),0) FROM compiler_preprocessed_v2").fetchone()[0]
        self._initial_failure = self._validate_context()
        self._single_tu: bool | None = None

    def close(self) -> None:
        self.reader.close()
        if self._database is not None:
            self._database.close()
            self._database = None

    def is_single_translation_unit(self) -> bool:
        """A narrow complete static-call closure, useful for isolated fixtures.

        A partial compilation database never certifies whole-kernel caller
        closure. General multi-TU callback/include closure is retained unknown.
        """
        if self._single_tu is None:
            paths = self.repo._run_git(["ls-tree", "-r", "--name-only", self.build.base_revision]).decode().splitlines()
            code = {path for path in paths if Path(path).suffix in {".c", ".cc", ".cpp", ".cxx", ".S", ".s", ".rs"}}
            self._single_tu = len(code) == 1 and code == set(self.commands)
        return self._single_tu

    def _validate_context(self) -> str:
        try:
            _validate_search_environment()
            # New automatic PCH siblings would otherwise change preprocessing
            # without changing a positive textual-header dependency hash.
            for path in self._forced_includes:
                if any(Path(str(path) + suffix).exists() for suffix in (".pch", ".gch")):
                    return "precompiled_header_input_appeared"
            if _digest(self.build.config_file.read_bytes()) != self.build.config_sha256:
                return "build_configuration_changed"
            if self.build.compilation_database_sha256 and _digest(self.build.compilation_database.read_bytes()) != self.build.compilation_database_sha256:
                return "compilation_database_changed"
            if self.build.build_membership_sha256 and _membership(self.build.build_root) != self.build.build_membership_sha256:
                return "prepared_build_membership_changed"
            source_repo = GitRepo(self.build.source_root)
            if source_repo._run_git(["rev-parse", "HEAD"]).decode().strip() != self.build.base_revision:
                return "source_checkout_revision_changed"
            if source_repo._run_git(["status", "--porcelain", "--untracked-files=all", "--ignored=matching"]):
                return "source_checkout_modified_or_untracked"
            compilers = {command.arguments[0] for command in self.commands.values()}
            if len(compilers) != 1:
                return "ambiguous_compiler_context"
            compiler = next(iter(compilers))
            if shutil.which(compiler) is None and not Path(compiler).is_file():
                return "compiler_unavailable"
            version = subprocess.check_output([compiler, "--version"], text=True, timeout=10).splitlines()[0]
            if version != self.build.compiler_version:
                return "compiler_version_changed"
            if self.analyzer.compiler_version != self.build.compiler_version:
                return "worker_frontend_version_mismatch"
            self.repo._run_git(["cat-file", "-e", self.build.base_revision + "^{commit}"])
            for path, expected in self._generated.items():
                if _digest(path.read_bytes()) != expected:
                    return "generated_build_input_changed"
            if any(command.file.is_relative_to(self.build.build_root) and command.file not in self._generated
                   for command in self.commands.values()):
                return "generated_compilation_source_not_pinned"
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            return "invalid_build_context: " + str(error)[:256]
        return ""

    def _snapshot(self, revision: str) -> _Snapshot:
        if revision in self._snapshots:
            self._snapshots.move_to_end(revision)
            return self._snapshots[revision]
        try:
            raw = self.repo._run_git(["diff", "--no-renames", "--name-status", "-z", self.build.base_revision, revision])
            fields = raw.decode().split("\0")
            changes = list(zip(fields[0:-1:2], fields[1:-1:2], strict=True))
            if len(changes) > _MAX_OVERLAYS:
                return _Snapshot((), "", "snapshot_file_budget")
            if any(_build_input(path) for _, path in changes):
                return _Snapshot((), "", "build_epoch_changed")
            overlays: list[SourceOverlay] = []
            names: list[str] = []
            total = 0
            for status, path in changes:
                if status != "M":
                    # Deletion-aware VFS hiding is deliberately not guessed.
                    return _Snapshot((), "", "snapshot_added_or_deleted_path")
                # Preprocessing can include any filename, even a .txt/.rst
                # file. Never let a suffix heuristic hide a real Git delta.
                # Other formats may be generator inputs; retain those epochs.
                if not (path.endswith((".c", ".h", ".S", ".s", ".inc", ".rst", ".md", ".txt"))
                        or path.startswith("Documentation/")):
                    return _Snapshot((), "", "unsupported_snapshot_input")
                data = self.reader.read_file(revision, path)
                total += len(data)
                if total > _MAX_OVERLAY_BYTES:
                    return _Snapshot((), "", "snapshot_byte_budget")
                overlays.append(SourceOverlay(self.build.source_root / path, data.decode()))
                names.append(status + ":" + path)
            snapshot = _Snapshot(tuple(overlays), _digest("\n".join(names).encode()))
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as error:
            snapshot = _Snapshot((), "", "snapshot_unavailable: " + str(error)[:256])
        self._snapshots[revision] = snapshot
        if len(self._snapshots) > 8:
            self._snapshots.popitem(last=False)
        return snapshot

    def _input(self, revision: str, path: Path) -> InputDigest:
        if path.is_relative_to(self.build.source_root):
            relative = path.relative_to(self.build.source_root).as_posix()
            epoch = self.reader.cache_epoch
            if epoch != self._digest_epoch:
                self._git_digests.clear()
                self._verified_baseline_sources.clear()
                self._digest_epoch = epoch
            cacheable = (epoch is not None and len(revision) == self._revision_width
                         and re.fullmatch(r"[0-9a-fA-F]+", revision) is not None)
            key = (revision, relative)
            if cacheable and key in self._git_digests:
                self._git_digests.move_to_end(key)
                return InputDigest(path=path, sha256=self._git_digests[key])
            contents = self.reader.read_file(revision, relative)
            digest = _digest(contents)
            if self.reader.cache_epoch != self._digest_epoch:
                self._git_digests.clear()
                self._verified_baseline_sources.clear()
                self._digest_epoch = self.reader.cache_epoch
            if cacheable and self.reader.cache_epoch is not None:
                self._git_digests[key] = digest
                self._git_digests.move_to_end(key)
                while len(self._git_digests) > 65536:
                    self._git_digests.popitem(last=False)
            return InputDigest(path=path, sha256=digest)
        else:
            if not _immutable_input(path, self.build.source_root, self.build.build_root):
                raise ValueError("External compiler dependency is not immutable")
            contents = path.read_bytes()
            if path.is_relative_to(self.build.build_root) and self._generated.get(path) != _digest(contents):
                raise ValueError("Unpinned or changed generated input")
        return InputDigest(path=path, sha256=_digest(contents))

    def _main_source(self, revision: str, command: CompileCommand) -> bytes:
        if command.file.is_relative_to(self.build.source_root):
            return self.reader.read_file(revision, command.file.relative_to(self.build.source_root).as_posix())
        contents = command.file.read_bytes()
        if self._generated.get(command.file) != _digest(contents):
            raise ValueError("Unpinned or changed generated compilation source")
        return contents

    def changed_paths(self, revision: str) -> frozenset[str]:
        """Source paths changed from the pinned context, or a hard epoch error."""
        if failure := self._initial_failure or self._validate_context():
            raise ValueError(failure)
        snapshot = self._snapshot(revision)
        if snapshot.failure:
            raise ValueError(snapshot.failure)
        return frozenset(item.path.relative_to(self.build.source_root).as_posix() for item in snapshot.overlays)

    def _source_pinned_to_baseline(self, path: Path) -> bool:
        if self.reader.cache_epoch is None or path not in self._verified_baseline_sources:
            baseline = self._input(self.build.base_revision, path)
            if _digest(path.read_bytes()) != baseline.sha256:
                return False
            self._verified_baseline_sources.add(path)
        return True

    def _valid(self, cached: _CachedFacts, revision: str) -> bool:
        return self._valid_inputs(cached.inputs, revision)

    def _valid_inputs(self, inputs: tuple[InputDigest, ...], revision: str) -> bool:
        try:
            return all(self._input(revision, item.path).sha256 == item.sha256 for item in inputs)
        except (OSError, ValueError, subprocess.SubprocessError):
            return False

    def facts(self, revision: str, path: str) -> TranslationUnitFacts:
        self.stats.requests += 1
        if self._initial_failure:
            return TranslationUnitFacts.failure(self._initial_failure)
        changed_context = self._validate_context()
        if changed_context:
            return TranslationUnitFacts.failure(changed_context)
        command = self.commands.get(path)
        if command is None:
            return TranslationUnitFacts.failure("missing_compilation_command")
        snapshot = self._snapshot(revision)
        if snapshot.failure:
            return TranslationUnitFacts.failure(snapshot.failure)
        try:
            source = self._main_source(revision, command)
            if len(source) > _MAX_SOURCE_BYTES:
                return TranslationUnitFacts.failure("source_size_budget")
            family = _digest(json.dumps((_CONTEXT_VERSION, self._worker_identity, self.build.fingerprint, path,
                                        command.arguments, _digest(source))).encode())
            unknown_key = _digest((family + revision).encode())
            if (unknown := self._cached_unknown(unknown_key)) is not None:
                self.stats.cache_hits += 1
                self.stats.unknown_cache_hits += 1
                return unknown
            candidates: list[_CachedFacts] = []
            if family in self._facts:
                candidates.append(self._facts[family])
            if self._database is not None:
                for payload, checksum in self._database.execute("SELECT payload,checksum FROM policy_tus WHERE family=? ORDER BY used DESC LIMIT 8", (family,)):
                    if _digest(payload.encode()) == checksum:
                        candidates.append(_CachedFacts.model_validate_json(payload))
            for cached in candidates:
                if self._valid(cached, revision):
                    self.stats.cache_hits += 1
                    self._remember(family, cached)
                    return cached.facts
            self.stats.extractions += 1
            result = self.analyzer.analyze(command, overlays=snapshot.overlays, tracked_paths=(command.file,))
            if not result.complete:
                self.stats.incomplete += 1
                self._remember_unknown(unknown_key, result)
                return result
            if result.compiler_version != self.build.compiler_version:
                return TranslationUnitFacts.failure("extracted_frontend_version_mismatch")
            changed_context = self._validate_context()
            if changed_context:
                return TranslationUnitFacts.failure("build_inputs_changed_during_extraction: " + changed_context)
            paths = set(result.dependencies) | {command.file}
            inputs = tuple(self._input(revision, dependency) for dependency in sorted(paths))
            # Verify disk source dependencies still match the pinned baseline:
            # untracked include shadowing is not silently accepted.
            for item in inputs:
                if item.path.is_relative_to(self.build.source_root):
                    if not self._source_pinned_to_baseline(item.path):
                        return TranslationUnitFacts.failure("source_dependency_not_pinned_to_baseline")
            cached = _CachedFacts(facts=result, inputs=inputs)
            self._remember(family, cached)
            if self._database is not None:
                payload = cached.model_dump_json()
                fingerprint = _digest((family + payload).encode())
                self._database.execute("INSERT OR REPLACE INTO policy_tus VALUES (?,?,?,?,strftime('%s','now'))",
                                       (family, fingerprint, payload, _digest(payload.encode())))
                self._database.execute("DELETE FROM policy_tus WHERE rowid IN (SELECT rowid FROM policy_tus ORDER BY used DESC LIMIT -1 OFFSET 512)")
                self._database.commit()
            return result
        except (OSError, ValueError, UnicodeError, sqlite3.Error, subprocess.SubprocessError) as error:
            return TranslationUnitFacts.failure("compiler_context_failure: " + str(error)[:256])

    def _remember(self, family: str, cached: _CachedFacts) -> None:
        self._facts[family] = cached
        self._facts.move_to_end(family)
        if len(self._facts) > 8:
            self._facts.popitem(last=False)

    def _cached_unknown(self, key: str) -> TranslationUnitFacts | None:
        if key in self._unknown:
            self._unknown.move_to_end(key)
            return self._unknown[key]
        if self._database is not None:
            row = self._database.execute("SELECT payload,checksum FROM policy_unknown_tus WHERE cache_key=?", (key,)).fetchone()
            if row is not None and _digest(row[0].encode()) == row[1]:
                facts = TranslationUnitFacts.model_validate_json(row[0])
                # A negative cache is never permitted to certify an exclusion.
                if not facts.complete:
                    self._remember_unknown(key, facts, persist=False)
                    return facts
        return None

    def _remember_unknown(self, key: str, facts: TranslationUnitFacts, *, persist: bool = True) -> None:
        if facts.complete:
            raise ValueError("Negative compiler cache accepts only incomplete facts")
        # Diagnostic-only entries stay small even for large, partially extracted
        # kernel TUs. Reuse can only retain extra commits after a transient error.
        diagnostic = facts.model_copy(update={"functions": (), "address_taken": (), "dependencies": (), "file_scope_assembly": ()})
        self._unknown[key] = diagnostic
        self._unknown.move_to_end(key)
        if len(self._unknown) > 8:
            self._unknown.popitem(last=False)
        if persist and self._database is not None:
            payload = diagnostic.model_dump_json()
            self._database.execute("INSERT OR REPLACE INTO policy_unknown_tus VALUES (?,?,?,strftime('%s','now'))",
                                   (key, payload, _digest(payload.encode())))
            self._database.execute("DELETE FROM policy_unknown_tus WHERE rowid IN (SELECT rowid FROM policy_unknown_tus ORDER BY used DESC LIMIT -1 OFFSET 512)")
            self._database.commit()

    def fingerprint(self, revision: str, path: str,
                    excluded_spans: tuple[ClangByteExclusion, ...]) -> PreprocessorFingerprint:
        if (failure := self._validate_context()):
            return PreprocessorFingerprint.failure(failure)
        command = self.commands.get(path)
        snapshot = self._snapshot(revision)
        if command is None or snapshot.failure:
            return PreprocessorFingerprint.failure(snapshot.failure or "missing_compilation_command")
        result = self.analyzer.fingerprint(command, overlays=snapshot.overlays, excluded_spans=excluded_spans)
        if (failure := self._validate_context()):
            return PreprocessorFingerprint.failure("build_inputs_changed_during_preprocessing: " + failure)
        if result.compiler_version != self.build.compiler_version:
            return PreprocessorFingerprint.failure("preprocessor_frontend_version_mismatch")
        return result

    def preprocess(self, revision: str, path: str) -> PreprocessorFingerprint:
        """Cached whole-TU expanded tokens under this declared build context."""

        self.stats.preprocessing_requests += 1
        if failure := self._initial_failure or self._validate_context():
            return PreprocessorFingerprint.failure(failure)
        command = self.commands.get(path)
        if command is None:
            return PreprocessorFingerprint.failure("missing_compilation_command")
        snapshot = self._snapshot(revision)
        if snapshot.failure:
            return PreprocessorFingerprint.failure(snapshot.failure)
        try:
            source = self._main_source(revision, command)
            if len(source) > _MAX_SOURCE_BYTES:
                return PreprocessorFingerprint.failure("source_size_budget")
            family = _digest(json.dumps(("expanded-compiler-input-v1", self._worker_identity,
                                        self.build.fingerprint, path, command.arguments, _digest(source))).encode())
            if cached := self._preprocessing_cache(family, revision, path):
                self.stats.preprocessing_cache_hits += 1
                return cached.fingerprint
            self.stats.preprocessing_extractions += 1
            result = self.analyzer.preprocess(command, overlays=snapshot.overlays)
            if not result.complete:
                return result
            if failure := self._validate_context():
                return PreprocessorFingerprint.failure("build_inputs_changed_during_preprocessing: " + failure)
            if result.compiler_version != self.build.compiler_version:
                return PreprocessorFingerprint.failure("preprocessor_frontend_version_mismatch")
            inputs = tuple(self._input(revision, dependency)
                           for dependency in sorted(set(result.dependencies) | {command.file}))
            for item in inputs:
                if item.path.is_relative_to(self.build.source_root):
                    if not self._source_pinned_to_baseline(item.path):
                        return PreprocessorFingerprint.failure("source_dependency_not_pinned_to_baseline")
            self._remember_preprocessing(family, _CachedPreprocessing(fingerprint=result, inputs=inputs), path, revision)
            return result
        except (OSError, ValueError, UnicodeError, sqlite3.Error, subprocess.SubprocessError) as error:
            return PreprocessorFingerprint.failure("preprocessing_context_failure: " + str(error)[:256])

    def _preprocessing_cache(self, family: str, revision: str, path: str) -> _CachedPreprocessing | None:
        candidates = [(self._preprocessed[family], family in self._preprocessed_baselines)] if family in self._preprocessed else []
        if self._database is not None:
            for payload, checksum, baseline in self._database.execute(
                "SELECT payload,checksum,baseline FROM compiler_preprocessed_v2 WHERE context=? AND family=? ORDER BY used DESC LIMIT 8",
                (self._preprocessing_context, family),
            ):
                if cached := self._decode_preprocessing(payload, checksum):
                    candidates.append((cached, bool(baseline)))
        for cached, baseline in candidates:
            if cached.fingerprint.complete and self._valid_inputs(cached.inputs, revision):
                self._retain_preprocessing(family, cached, baseline=baseline or revision == self.build.base_revision)
                if revision == self.build.base_revision and not baseline:
                    self._store_preprocessing(family, cached, path, baseline=True)
                return cached
        return None

    @staticmethod
    def _decode_preprocessing(payload: bytes, checksum: str) -> _CachedPreprocessing | None:
        try:
            decoder = zlib.decompressobj()
            raw = decoder.decompress(payload, _MAX_PREPROCESSING_PAYLOAD + 1)
            if (len(raw) > _MAX_PREPROCESSING_PAYLOAD or not decoder.eof or decoder.unused_data
                    or _digest(raw) != checksum):
                return None
            return _CachedPreprocessing.model_validate_json(raw)
        except (TypeError, ValueError, zlib.error):
            return None

    def _retain_preprocessing(self, family: str, cached: _CachedPreprocessing, *, baseline: bool) -> None:
        self._preprocessed[family] = cached
        self._preprocessed.move_to_end(family)
        if baseline:
            self._preprocessed_baselines.add(family)
        else:
            self._preprocessed_baselines.discard(family)
        while len(self._preprocessed) > 32:
            expired, _ = self._preprocessed.popitem(last=False)
            self._preprocessed_baselines.discard(expired)

    def _remember_preprocessing(self, family: str, cached: _CachedPreprocessing, path: str, revision: str) -> None:
        self._retain_preprocessing(family, cached, baseline=revision == self.build.base_revision)
        self._store_preprocessing(family, cached, path, baseline=revision == self.build.base_revision)

    def _store_preprocessing(self, family: str, cached: _CachedPreprocessing, path: str, *, baseline: bool) -> None:
        if self._database is None:
            return
        raw = cached.model_dump_json().encode()
        if len(raw) > _MAX_PREPROCESSING_PAYLOAD:
            self.stats.preprocessing_cache_budget_skips += 1
            return
        payload = zlib.compress(raw, level=3)
        identity = _digest(family.encode() + raw)
        existing = self._database.execute("SELECT LENGTH(payload),baseline FROM compiler_preprocessed_v2 WHERE fingerprint=?", (identity,)).fetchone()
        if existing is not None:
            self._database.execute("UPDATE compiler_preprocessed_v2 SET used=strftime('%s','now'),baseline=MAX(baseline,?) WHERE fingerprint=?",
                                   (int(baseline), identity))
            self._database.commit()
            return
        if self._preprocessing_bytes + len(payload) > _MAX_PREPROCESSING_CACHE_BYTES:
            # Reclaim history/older contexts before declining a new record.
            # Current baseline records never evict one another during bootstrap.
            removable = self._database.execute(
                "SELECT fingerprint,LENGTH(payload) FROM compiler_preprocessed_v2 WHERE context<>? OR baseline=0 ORDER BY used,rowid",
                (self._preprocessing_context,),
            )
            for fingerprint, size in removable:
                self._database.execute("DELETE FROM compiler_preprocessed_v2 WHERE fingerprint=?", (fingerprint,))
                self._preprocessing_bytes -= size
                if self._preprocessing_bytes + len(payload) <= _MAX_PREPROCESSING_CACHE_BYTES:
                    break
        if self._preprocessing_bytes + len(payload) > _MAX_PREPROCESSING_CACHE_BYTES:
            self.stats.preprocessing_cache_budget_skips += 1
            self._database.commit()
            return
        self._database.execute("INSERT INTO compiler_preprocessed_v2 VALUES (?,?,?,?,?,?,?,strftime('%s','now'))",
                               (self._preprocessing_context, path, family, identity, payload, _digest(raw), int(baseline)))
        self._preprocessing_bytes += len(payload)
        old = list(self._database.execute(
            "SELECT fingerprint,LENGTH(payload) FROM compiler_preprocessed_v2 WHERE context=? AND unit=? AND baseline=0 ORDER BY used DESC,rowid DESC LIMIT -1 OFFSET 4",
            (self._preprocessing_context, path),
        ))
        for fingerprint, size in old:
            self._database.execute("DELETE FROM compiler_preprocessed_v2 WHERE fingerprint=?", (fingerprint,))
            self._preprocessing_bytes -= size
        self._database.commit()
