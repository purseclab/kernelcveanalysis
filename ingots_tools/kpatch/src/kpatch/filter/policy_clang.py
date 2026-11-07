"""Bounded persistent Clang CFG extraction, independent of policy evaluation.

Real compile commands and generated inputs are required. Unsupported flags,
compiler diagnostics, worker failures and budgets yield incomplete facts; callers
must retain changes whose proof depends on those facts. No GCC flags are guessed
or dropped to make an extraction succeed.
"""

from dataclasses import dataclass
import hashlib
import json
import os
import platform
from pathlib import Path
import selectors
import shlex
import shutil
import subprocess
from tempfile import TemporaryDirectory
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


class _Fact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class SourcePoint(_Fact):
    path: Path
    line: int
    column: int
    offset: int


class ClangSpan(_Fact):
    """File spans use start/end; macro spans additionally retain spelling points."""

    start: SourcePoint
    end: SourcePoint
    macro: bool = False
    spelling_start: SourcePoint | None = None
    spelling_end: SourcePoint | None = None

    def covers_line(self, path: Path, line: int) -> bool:
        return self.start.path == path and self.end.path == path and self.start.line <= line <= self.end.line


class ClangArgument(_Fact):
    expression: str
    integer: int | None = None
    parameter: int | None = None
    declaration_usr: str | None = None


class ClangConstraint(_Fact):
    parameter: int
    integer: int
    relation: Literal["eq"] = "eq"


class ClangGuard(_Fact):
    callee: str
    callee_usr: str
    arguments: tuple[ClangArgument, ...]
    outcome: Literal["zero", "nonzero", "negative", "nonnegative"]
    span: ClangSpan
    call_block: int | None = None
    call_order: int | None = None


class ClangStatement(_Fact):
    kind: str
    block: int
    span: ClangSpan
    guards: tuple[ClangGuard, ...] = ()
    constraints: tuple[ClangConstraint, ...] = ()


class ClangCall(_Fact):
    callee: str | None = None
    callee_usr: str | None = None
    arguments: tuple[ClangArgument, ...] = ()
    span: ClangSpan
    guards: tuple[ClangGuard, ...] = ()
    constraints: tuple[ClangConstraint, ...] = ()
    block: int | None = None
    order: int | None = None


class ClangWriteEffect(_Fact):
    kind: Literal["assignment", "increment", "atomic"]
    block: int
    order: int
    span: ClangSpan
    guards: tuple[ClangGuard, ...] = ()


class ClangCFGBlock(_Fact):
    block: int
    successors: tuple[int, ...] = ()


class ClangMetadataSpan(_Fact):
    """Protected physical source bytes; macro expansion events remain separate."""

    path: Path
    start: int = Field(ge=0, strict=True)
    end: int = Field(ge=0, strict=True)

    @model_validator(mode="after")
    def _valid_range(self) -> Self:
        if self.end <= self.start:
            raise ValueError("Invalid physical metadata coordinates")
        return self


class ClangFunction(_Fact):
    name: str
    usr: str
    span: ClangSpan
    body_span: ClangSpan
    is_static: bool
    statements: tuple[ClangStatement, ...] = ()
    calls: tuple[ClangCall, ...] = ()
    unknowns: tuple[str, ...] = ()
    modified_parameters: tuple[int, ...] = ()
    write_effects: tuple[ClangWriteEffect, ...] = ()
    write_coverage_complete: bool = False
    cfg_blocks: tuple[ClangCFGBlock, ...] = ()
    cfg_entry: int | None = None
    declaration_coverage_complete: bool = False
    body_translation_effects: tuple[str, ...] = ()
    body_metadata_coverage_complete: bool = False
    body_metadata_spans: tuple[ClangMetadataSpan, ...] = ()


class ClangReference(_Fact):
    name: str
    usr: str
    span: ClangSpan


class ClangAssembly(_Fact):
    span: ClangSpan
    text: str
    kind: Literal["readonly_export", "readonly_initcall", "readonly_btf", "readonly_tracepoint", "unknown"]
    symbols: tuple[str, ...] = ()


class ClangInlineAssembly(_Fact):
    span: ClangSpan
    text: str
    kind: Literal["empty_barrier", "opaque"]


class ClangSyscallBinding(_Fact):
    number: int
    callee_usr: str
    callee_name: str


class ClangSyscallTable(_Fact):
    """Resolved initializer slots; proof also requires complete enclosing TU facts."""

    name: str
    source_path: Path
    audit_arch: int
    complete: bool = False
    status_reason: str
    bindings: tuple[ClangSyscallBinding, ...] = ()


class TranslationUnitFacts(_Fact):
    complete: bool
    diagnostics: tuple[str, ...] = ()
    functions: tuple[ClangFunction, ...] = ()
    unknowns: tuple[str, ...] = ()
    reused_tu: bool = False
    fresh_parse_fallback: bool = False
    dependencies: tuple[Path, ...] = ()
    address_taken: tuple[ClangReference, ...] = ()
    file_scope_assembly: tuple[ClangAssembly, ...] = ()
    syscall_tables: tuple[ClangSyscallTable, ...] = ()
    inline_assembly_coverage_complete: bool = False
    inline_assembly: tuple[ClangInlineAssembly, ...] = ()
    indirect_call_coverage_complete: bool = False
    indirect_calls: tuple[ClangSpan, ...] = ()
    compiler_major: int = 0
    compiler_version: str = ""

    @classmethod
    def failure(cls, reason: str) -> Self:
        return cls(complete=False, diagnostics=(reason,), unknowns=(reason,))


@dataclass(frozen=True, slots=True)
class ClangByteExclusion:
    path: Path
    start: int
    end: int


class PreprocessorFingerprint(_Fact):
    complete: bool
    digest: str | None = None
    diagnostics: tuple[str, ...] = ()
    tokens: int = 0
    events: int = 0
    dependencies: tuple[Path, ...] = ()
    compiler_major: int = 0
    compiler_version: str = ""

    @classmethod
    def failure(cls, reason: str) -> Self:
        return cls(complete=False, diagnostics=(reason,))


@dataclass(frozen=True, slots=True)
class SourceOverlay:
    path: Path
    contents: str


@dataclass(frozen=True, slots=True)
class CompileCommand:
    directory: Path
    file: Path
    arguments: tuple[str, ...]

    @classmethod
    def for_source(cls, file: Path, *, flags: tuple[str, ...] = ()) -> Self:
        source = file.resolve()
        return cls(source.parent, source, ("clang", "-std=gnu11", *flags, "-fsyntax-only", str(source)))

    def frontend_arguments(self) -> tuple[str, ...]:
        """Remove output/dependency writes, preserving all semantic build flags."""
        kept: list[str] = []
        skip = False
        for argument in self.arguments:
            if skip:
                skip = False
                continue
            if argument in {"-o", "-MF", "-MT", "-MQ", "-MJ", "--serialize-diagnostics"}:
                skip = True
            elif argument.startswith(("-MF", "-MT", "-MQ", "-MJ", "--serialize-diagnostics=")):
                continue
            elif argument.startswith("-o") and len(argument) > 2:
                continue
            elif argument not in {"-c", "-S", "-MD", "-MMD", "-MP", "-MG", "-M", "-MM"} and not argument.startswith(("-Wp,-MMD,", "-Wp,-MD,")):
                kept.append(argument)
        if skip:
            raise ValueError("Missing compile-command option argument")
        return (*kept, "-fsyntax-only")


class _CompilationRecord(BaseModel):
    directory: Path
    file: Path
    arguments: tuple[str, ...] | None = None
    command: str | None = None
    output: str | None = None


def load_compilation_database(path: Path) -> tuple[CompileCommand, ...]:
    from pydantic import TypeAdapter

    records = TypeAdapter(tuple[_CompilationRecord, ...]).validate_json(path.read_bytes())
    commands: list[CompileCommand] = []
    for record in records:
        directory = record.directory.resolve()
        source = record.file if record.file.is_absolute() else directory / record.file
        arguments = record.arguments
        if arguments is None:
            if record.command is None:
                raise ValueError("Compilation record needs arguments or command")
            arguments = tuple(shlex.split(record.command))
        if not arguments:
            raise ValueError("Empty compilation command")
        commands.append(CompileCommand(directory, source.resolve(), arguments))
    return tuple(commands)


class ClangUnavailable(RuntimeError):
    """The required matching Clang C++ headers/libraries are unavailable."""


class _WorkerFailure(RuntimeError):
    pass


class ClangVersion(_Fact):
    major: int
    compiler: str


@dataclass(frozen=True, slots=True)
class ClangToolchain:
    compiler: Path
    clang_include: Path
    llvm_include: Path
    clang_library: Path
    llvm_library_directory: Path
    llvm_library: str
    cxx_library_directory: Path

    @classmethod
    def discover(cls) -> Self:
        compiler = shutil.which("clang++") or shutil.which("c++")
        if compiler is None:
            raise ClangUnavailable("A C++ compiler is required for the CFG worker")
        llvm_configs = [Path(value) for value in [shutil.which("llvm-config")] if value]
        nix_store = Path("/nix/store")
        if nix_store.is_dir():
            llvm_configs.extend(sorted(nix_store.glob("*-llvm-*-dev/bin/llvm-config"), reverse=True))
        explicit_llvm = os.environ.get("KPATCH_LLVM_CONFIG")
        if explicit_llvm:
            llvm_configs.insert(0, Path(explicit_llvm))
        for config in llvm_configs:
            try:
                include = Path(subprocess.check_output([str(config), "--includedir"], text=True, timeout=10).strip())
                libdir = Path(subprocess.check_output([str(config), "--libdir"], text=True, timeout=10).strip())
                version = subprocess.check_output([str(config), "--version"], text=True, timeout=10).strip().split(".")[0]
                target = subprocess.check_output([str(config), "--host-target"], text=True, timeout=10).strip()
                if target.split("-")[0] != platform.machine():
                    continue
            except (OSError, subprocess.SubprocessError):
                continue
            candidates = [include]
            explicit_clang = os.environ.get("KPATCH_CLANG_INCLUDE")
            if explicit_clang:
                candidates.insert(0, Path(explicit_clang))
            if nix_store.is_dir():
                candidates.extend(sorted(nix_store.glob(f"*-clang-{version}.*-dev/include"), reverse=True))
            clang_include = next((p for p in candidates if (p / "clang/Analysis/CFG.h").is_file()), None)
            libraries = list(libdir.glob("libclang-cpp.so*"))
            if nix_store.is_dir():
                libraries.extend(sorted(nix_store.glob(f"*-clang-{version}.*-lib/lib/libclang-cpp.so*"), reverse=True))
            library = next((p for p in libraries if p.is_file()), None)
            if clang_include is not None and library is not None and (include / "llvm/Support/JSON.h").is_file():
                cxx_directory = libdir
                cxx = shutil.which("g++")
                if cxx:
                    candidate = Path(subprocess.check_output([cxx, "-print-file-name=libstdc++.so"], text=True, timeout=10).strip())
                    if candidate.is_absolute() and candidate.is_file():
                        cxx_directory = candidate.parent
                return cls(Path(compiler), clang_include, include, library, libdir, f"LLVM-{version}", cxx_directory)
        raise ClangUnavailable("Matching Clang/LLVM development headers and libclang-cpp are required")

    def build(self, directory: Path | None = None) -> Path:
        source = Path(__file__).with_name("policy_clang_worker.cpp")
        contents = source.read_bytes()
        identity = hashlib.sha256(b"immutable-clang-worker-v1\0" + contents + repr(self).encode()).hexdigest()[:24]
        base = directory or Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "kpatch" / "policy-clang"
        base.mkdir(parents=True, exist_ok=True)
        binary = base / f"worker-{identity}"
        if binary.is_file():
            return binary
        try:
            with TemporaryDirectory(prefix=f".{binary.name}-", dir=base) as temporary_directory:
                snapshot = Path(temporary_directory) / source.name
                snapshot.write_bytes(contents)
                temporary = Path(temporary_directory) / "worker"
                arguments = [str(self.compiler), "-std=c++20", "-O1", f"-I{self.clang_include}", f"-I{self.llvm_include}",
                             str(snapshot), str(self.clang_library), f"-L{self.llvm_library_directory}", f"-l{self.llvm_library}",
                             f"-L{self.cxx_library_directory}",
                             f"-Wl,-rpath,{self.clang_library.parent}", f"-Wl,-rpath,{self.llvm_library_directory}",
                             "-o", str(temporary)]
                result = subprocess.run(arguments, capture_output=True, text=True, timeout=180)
                if result.returncode:
                    raise ClangUnavailable(result.stderr[-8000:])
                temporary.replace(binary)
        except (OSError, subprocess.SubprocessError) as error:
            raise ClangUnavailable(str(error)) from error
        return binary


class ClangAnalyzer:
    """One sequential worker with at most two live AST/preamble contexts."""

    def __init__(self, worker_path: Path | None = None, *, timeout_seconds: float = 45.0) -> None:
        self.worker_path = worker_path or ClangToolchain.discover().build()
        self.timeout_seconds = timeout_seconds
        self._process: subprocess.Popen[bytes] | None = None
        self._version: ClangVersion | None = None

    @property
    def version(self) -> ClangVersion:
        if self._version is None:
            try:
                self._version = ClangVersion.model_validate_json(self._exchange(b'{"mode":"version"}\n'))
            except (OSError, ValueError, _WorkerFailure) as error:
                self.close()
                raise ClangUnavailable(str(error)) from error
        return self._version

    @property
    def compiler_major(self) -> int:
        return self.version.major

    @property
    def compiler_version(self) -> str:
        return self.version.compiler

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        process, self._process = self._process, None
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()

    def analyze(self, command: CompileCommand, *, overlays: tuple[SourceOverlay, ...] = (),
                tracked_paths: tuple[Path, ...] = (), function_names: tuple[str, ...] = ()) -> TranslationUnitFacts:
        try:
            request = json.dumps({"directory": str(command.directory), "file": str(command.file),
                                  "arguments": command.frontend_arguments(),
                                  "overlays": [{"path": str(item.path), "contents": item.contents} for item in overlays],
                                  "tracked_paths": [str(path) for path in tracked_paths], "function_names": function_names}).encode() + b"\n"
            return TranslationUnitFacts.model_validate_json(self._exchange(request))
        except (OSError, ValueError, ValidationError, _WorkerFailure) as error:
            self.close()
            return TranslationUnitFacts.failure(f"clang_worker_failure: {error}")

    def fingerprint(self, command: CompileCommand, *, overlays: tuple[SourceOverlay, ...] = (),
                    excluded_spans: tuple[ClangByteExclusion, ...] = ()) -> PreprocessorFingerprint:
        """Fresh PP stream outside exclusions, retaining all directive effects.

        Macro definitions, undefinitions and expansion arguments are hashed even
        inside exclusions, as are pragma events. This can conservatively retain
        macro-heavy edits, but never assumes C-unreachable directives are inert.
        """
        try:
            request = json.dumps({"mode": "pp_fingerprint", "directory": str(command.directory),
                                  "file": str(command.file), "arguments": command.frontend_arguments(),
                                  "overlays": [{"path": str(item.path), "contents": item.contents} for item in overlays],
                                  "excluded_spans": [{"path": str(item.path), "start": item.start, "end": item.end} for item in excluded_spans]}).encode() + b"\n"
            return PreprocessorFingerprint.model_validate_json(self._exchange(request))
        except (OSError, ValueError, ValidationError, _WorkerFailure) as error:
            self.close()
            return PreprocessorFingerprint.failure(f"clang_worker_failure: {error}")

    def _exchange(self, request: bytes) -> bytes:
        if len(request) > 8 * 1024 * 1024:
            raise _WorkerFailure("request_budget")
        if self._process is None:
            self._process = subprocess.Popen([str(self.worker_path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                             stderr=subprocess.DEVNULL, bufsize=0)
        process = self._process
        assert process.stdin is not None and process.stdout is not None
        remaining = memoryview(request)
        while remaining:
            written = process.stdin.write(remaining)
            if written is None or written == 0:
                raise _WorkerFailure("worker_input_failure")
            remaining = remaining[written:]
        process.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(self.timeout_seconds):
                raise _WorkerFailure("clang_timeout")
        response = process.stdout.readline(16 * 1024 * 1024 + 1)
        if not response.endswith(b"\n") or len(response) > 16 * 1024 * 1024:
            raise _WorkerFailure("response_budget_or_worker_failure")
        return response
