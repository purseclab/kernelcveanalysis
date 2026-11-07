"""Pinned target profiles and conservative offline SELinux permission facts.

An absent allow is useful negative evidence only under enforcing mode and a
nonpermissive concrete subject. All conditional branches are included and
constraints are ignored deliberately: either can restrict an allow, but neither
can make absence of every allow authorize an operation. This models policy
permissions, not callers, delegated resources or service reachability.
"""

from collections.abc import Iterator
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


_EVALUATOR_VERSION = "selinux-allow-overapprox-v2-polcaps"
_MAX_POLICY_BYTES = 64 * 1024 * 1024
_MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
_NAME_PATTERN = r"^[A-Za-z_][A-Za-z_0-9]*$"
_KNOWN_POLICYCAPS = frozenset({
    "network_peer_controls", "open_perms", "extended_socket_class", "always_check_network",
    "cgroup_seclabel", "nnp_nosuid_transition", "genfs_seclabel_symlinks", "ioctl_skip_cloexec",
    "userspace_initial_context", "netlink_xperm", "netif_wildcard", "genfs_seclabel_wildcard",
    "functionfs_seclabel", "memfd_class", "bpf_token_perms",
})


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class AnalysisScope(StrEnum):
    DIRECT_APP = "direct_app"
    APP_WITH_SERVICES = "app_with_services"


class SeccompDenial(_FrozenModel):
    """A universal syscall denial established from an exact filter, not a probe."""

    architecture: str
    syscall_number: int = Field(ge=0)
    syscall_name: str
    filter_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    all_arguments: Literal[True]


class SeccompProfile(_FrozenModel):
    mode: int | None = Field(default=None, ge=0, le=2, strict=True)
    architecture: str | None = None
    filter_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    filter_file: Path | None = None
    denials: tuple[SeccompDenial, ...] = ()

    @model_validator(mode="after")
    def _consistent_denials(self) -> "SeccompProfile":
        if self.filter_file is not None and (self.mode != 2 or self.filter_sha256 is None):
            raise ValueError("A raw filter requires a pinned mode-2 filter hash")
        if self.denials and (self.mode != 2 or self.filter_sha256 is None):
            raise ValueError("Universal denials require a pinned mode-2 filter")
        if any(item.filter_sha256 != self.filter_sha256
               or self.architecture is not None and item.architecture != self.architecture for item in self.denials):
            raise ValueError("Seccomp denial provenance does not match the filter")
        return self


class PolicyTargetProfile(_FrozenModel):
    schema_version: Literal[1] = 1
    name: str
    policy_file: Path
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    subject_context: str
    selinux_enforcing: bool | None = Field(default=None, strict=True)
    uid: int | None = Field(default=None, ge=0, strict=True)
    gid: int | None = Field(default=None, ge=0, strict=True)
    groups: tuple[int, ...] = ()
    cap_effective: int | None = Field(default=None, ge=0, lt=1 << 64, strict=True)
    cap_permitted: int | None = Field(default=None, ge=0, lt=1 << 64, strict=True)
    cap_bounding: int | None = Field(default=None, ge=0, lt=1 << 64, strict=True)
    user_namespaces_enabled: bool | None = Field(default=None, strict=True)
    kernel_release: str | None = None
    architecture: str | None = None
    scope: AnalysisScope = AnalysisScope.APP_WITH_SERVICES
    modeled_subject_types: tuple[str, ...] = ()
    mediation_complete: bool = Field(default=False, strict=True)
    seccomp: SeccompProfile = SeccompProfile()

    @field_validator("subject_context")
    @classmethod
    def _context(cls, context: str) -> str:
        parts = context.split(":", 3)
        if len(parts) != 4 or not all(parts):
            raise ValueError("Expected a complete SELinux user:role:type:range context")
        return context

    @field_validator("groups")
    @classmethod
    def _groups(cls, groups: tuple[int, ...]) -> tuple[int, ...]:
        if any(group < 0 for group in groups):
            raise ValueError("Group IDs must be nonnegative")
        return groups

    @model_validator(mode="after")
    def _mediation_subjects(self) -> "PolicyTargetProfile":
        if self.mediation_complete and self.subject_type not in self.modeled_subject_types:
            raise ValueError("A complete mediation model must include the app subject")
        return self

    @property
    def subject_type(self) -> str:
        return self.subject_context.split(":", 3)[2]

    @property
    def fingerprint(self) -> str:
        # Machine-local artifact placement is not part of policy semantics.
        payload = self.model_dump(mode="json", exclude={"policy_file": True, "seccomp": {"filter_file": True}})
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    @classmethod
    def load(cls, path: Path) -> "PolicyTargetProfile":
        profile = cls.model_validate_json(path.read_text())
        policy_file = profile.policy_file
        if not policy_file.is_absolute():
            policy_file = path.resolve().parent / policy_file
        if hashlib.sha256(policy_file.read_bytes()).hexdigest() != profile.policy_sha256:
            raise ValueError("SELinux binary does not match the target profile hash")
        seccomp = profile.seccomp
        if seccomp.filter_file is not None:
            from .policy_seccomp import PinnedSeccompFilter

            filter_file = seccomp.filter_file
            if not filter_file.is_absolute():
                filter_file = path.resolve().parent / filter_file
            assert seccomp.filter_sha256 is not None
            PinnedSeccompFilter.load(filter_file, seccomp.filter_sha256)
            seccomp = seccomp.model_copy(update={"filter_file": filter_file.resolve()})
        return profile.model_copy(update={"policy_file": policy_file.resolve(), "seccomp": seccomp})


class SELinuxDecision(StrEnum):
    DENIED = "denied"
    POSSIBLY_ALLOWED = "possibly_allowed"
    UNKNOWN = "unknown"


class SELinuxPermissionQuery(_FrozenModel):
    """One access-vector check on one object; all permissions are required."""

    subject_type: str = Field(pattern=_NAME_PATTERN)
    object_class: str = Field(pattern=_NAME_PATTERN)
    permissions: frozenset[str] = Field(min_length=1)
    target_type: str | None = Field(default=None, pattern=_NAME_PATTERN)


@dataclass(frozen=True, slots=True)
class SELinuxEvidence:
    target_type: str
    permissions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SELinuxResult:
    decision: SELinuxDecision
    reason: str
    policy_sha256: str
    evidence: tuple[SELinuxEvidence, ...] = ()


class _ClassPermissions(_FrozenModel):
    name: str
    permissions: frozenset[str]


class _AllowFact(_FrozenModel):
    object_class: str
    targets: frozenset[str]
    permissions: frozenset[str]


class _PolicySnapshot(_FrozenModel):
    complete: Literal[True]
    policy_sha256: str
    subject_type: str
    subject_permissive: bool
    setools_version: str
    types: frozenset[str]
    classes: tuple[_ClassPermissions, ...]
    allows: tuple[_AllowFact, ...]
    policy_capabilities: frozenset[str]


class _PolicyCapabilities(_FrozenModel):
    complete: Literal[True]
    policy_sha256: str
    setools_version: str
    policy_capabilities: frozenset[str]


class _RuntimeVersion(_FrozenModel):
    setools_version: str


@dataclass(frozen=True, slots=True)
class SEToolsRuntime:
    """Interpreter matching SETools' extension ABI; independent of kpatch Python."""

    python: Path
    module_paths: tuple[Path, ...] = ()

    def run(self, program: str, arguments: tuple[str, ...], *, timeout: float) -> str:
        paths = json.dumps([str(path) for path in self.module_paths])
        bootstrap = "import site,sys,json\nfor p in json.loads(sys.argv[1]): site.addsitedir(p)\ndel sys.argv[1]\n"
        try:
            completed = subprocess.run([str(self.python), "-I", "-c", bootstrap + program, paths, *arguments],
                                       check=False, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise ValueError("SETools worker exceeded its time limit") from error
        if completed.returncode:
            error_line = completed.stderr.strip().splitlines()
            raise ValueError("SETools worker failed: " + (error_line[-1][:512] if error_line else str(completed.returncode)))
        if len(completed.stdout.encode()) > _MAX_SNAPSHOT_BYTES:
            raise ValueError("SETools snapshot exceeds the configured size bound")
        return completed.stdout


_SNAPSHOT_PROGRAM = r'''
import hashlib,json,sys
import setools
source = sys.argv[1]
subject = sys.argv[2]
policy = setools.SELinuxPolicy(source)
subject_symbol = policy.lookup_type(subject)
classes = []
for item in policy.classes():
    permissions = set(item.perms)
    try:
        permissions.update(item.common.perms)
    except setools.exception.NoCommon:
        pass
    classes.append({"name": str(item), "permissions": sorted(permissions)})
allows = []
# No enabled/boolean filter: retain every branch of every conditional rule.
query = setools.TERuleQuery(policy, ruletype=["allow"], source=subject, source_indirect=True)
for rule in query.results():
    allows.append({"object_class": str(rule.tclass),
                   "targets": sorted(str(target) for target in rule.target.expand()),
                   "permissions": sorted(str(permission) for permission in rule.perms)})
with open(source, "rb") as stream:
    digest = hashlib.sha256(stream.read()).hexdigest()
print(json.dumps({"complete": True, "policy_sha256": digest,
                  "subject_type": str(subject_symbol), "subject_permissive": subject_symbol.ispermissive,
                  "setools_version": setools.__version__,
                  "types": sorted(str(item) for item in policy.types()),
                  "classes": classes, "allows": allows,
                  "policy_capabilities": sorted(str(item) for item in policy.polcaps())}, separators=(",", ":")))
'''

_VERSION_PROGRAM = 'import json,setools\nprint(json.dumps({"setools_version":setools.__version__}))\n'
_CAPABILITIES_PROGRAM = r'''
import hashlib,json,sys
import setools
policy = setools.SELinuxPolicy(sys.argv[1])
with open(sys.argv[1], "rb") as stream:
    digest = hashlib.sha256(stream.read()).hexdigest()
print(json.dumps({"complete": True, "policy_sha256": digest,
                  "setools_version": setools.__version__,
                  "policy_capabilities": sorted(str(item) for item in policy.polcaps())}))
'''


@dataclass(slots=True)
class SELinuxEvaluatorStats:
    snapshot_extractions: int = 0
    snapshot_cache_hits: int = 0
    permission_queries: int = 0
    permission_cache_hits: int = 0


class SELinuxPolicyEvaluator:
    """Lazy per-subject snapshots; permission queries require no tool subprocess."""

    def __init__(self, policy_file: Path, *, enforcing: bool | None,
                 cache_path: Path | None = None, runtime: SEToolsRuntime | None = None) -> None:
        self.policy_file, self.enforcing = policy_file, enforcing
        self.cache_path, self.runtime = cache_path, runtime
        self.stats = SELinuxEvaluatorStats()
        self._snapshots: OrderedDict[str, _PolicySnapshot] = OrderedDict()
        self._query_cache: OrderedDict[SELinuxPermissionQuery, SELinuxResult] = OrderedDict()
        self._capabilities: frozenset[str] | None = None
        self._runtime_error: str | None = None
        self._version: str | None = None
        self._binary: bytes | None = None
        self.policy_sha256 = ""
        try:
            with policy_file.open("rb") as source:
                self._binary = source.read(_MAX_POLICY_BYTES + 1)
            if len(self._binary) > _MAX_POLICY_BYTES:
                raise ValueError("SELinux binary exceeds the configured size bound")
            self.policy_sha256 = hashlib.sha256(self._binary).hexdigest()
        except (OSError, ValueError) as error:
            self._binary = None
            self._runtime_error = str(error)

    def _runtime_version(self) -> str:
        if self._version is not None:
            return self._version
        candidates = [self.runtime] if self.runtime is not None else self._default_runtimes()
        errors: list[str] = []
        for runtime in candidates:
            try:
                version = _RuntimeVersion.model_validate_json(runtime.run(_VERSION_PROGRAM, (), timeout=10))
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                errors.append(str(error))
                continue
            self.runtime, self._version = runtime, version.setools_version
            return self._version
        raise ValueError("No usable SETools Python runtime: " + "; ".join(errors))

    @staticmethod
    def _default_runtimes() -> list[SEToolsRuntime]:
        interpreters = [Path(sys.executable)]
        system_python = shutil.which("python3")
        if system_python is not None and Path(system_python) not in interpreters:
            interpreters.append(Path(system_python))
        return [SEToolsRuntime(path) for path in interpreters]

    @contextmanager
    def _cache(self) -> Iterator[sqlite3.Connection | None]:
        database: sqlite3.Connection | None = None
        try:
            if self.cache_path is not None:
                self.cache_path.parent.mkdir(parents=True, exist_ok=True)
                database = sqlite3.connect(self.cache_path, timeout=5)
                database.execute("CREATE TABLE IF NOT EXISTS selinux_snapshots (cache_key TEXT PRIMARY KEY, payload TEXT NOT NULL, sha256 TEXT NOT NULL)")
        except (OSError, sqlite3.Error):
            if database is not None:
                database.close()
            database = None
        try:
            yield database
        finally:
            if database is not None:
                database.close()

    def _snapshot(self, subject: str) -> _PolicySnapshot:
        if subject in self._snapshots:
            self.stats.snapshot_cache_hits += 1
            self._snapshots.move_to_end(subject)
            return self._snapshots[subject]
        version = self._runtime_version()
        key = json.dumps((self.policy_sha256, subject, _EVALUATOR_VERSION, version))
        snapshot: _PolicySnapshot | None = None
        with self._cache() as database:
            if database is not None:
                snapshot = self._load_cached(database, key)
                if snapshot is not None and not self._provenance_matches(snapshot, subject, version):
                    snapshot = None
            if snapshot is None:
                snapshot = self._extract_snapshot(subject)
                if not self._provenance_matches(snapshot, subject, version):
                    raise ValueError("SETools snapshot provenance mismatch")
                if database is not None:
                    payload = snapshot.model_dump_json()
                    try:
                        database.execute("INSERT OR REPLACE INTO selinux_snapshots VALUES (?, ?, ?)",
                                         (key, payload, hashlib.sha256(payload.encode()).hexdigest()))
                        database.commit()
                    except sqlite3.Error:
                        pass
            else:
                self.stats.snapshot_cache_hits += 1
        self._snapshots[subject] = snapshot
        self._capabilities = snapshot.policy_capabilities
        if len(self._snapshots) > 32:
            self._snapshots.popitem(last=False)
        return snapshot

    def _provenance_matches(self, snapshot: _PolicySnapshot, subject: str, version: str) -> bool:
        return (snapshot.policy_sha256 == self.policy_sha256 and snapshot.subject_type == subject
                and snapshot.setools_version == version)

    @staticmethod
    def _load_cached(database: sqlite3.Connection, key: str) -> _PolicySnapshot | None:
        try:
            row = database.execute("SELECT payload, sha256 FROM selinux_snapshots WHERE cache_key=?", (key,)).fetchone()
            if row is not None and hashlib.sha256(row[0].encode()).hexdigest() == row[1]:
                return _PolicySnapshot.model_validate_json(row[0])
        except (sqlite3.Error, ValueError):
            pass
        return None

    def _extract_snapshot(self, subject: str) -> _PolicySnapshot:
        payload = self._policy_program(_SNAPSHOT_PROGRAM, (subject,))
        snapshot = _PolicySnapshot.model_validate_json(payload)
        self.stats.snapshot_extractions += 1
        return snapshot

    def _policy_program(self, program: str, arguments: tuple[str, ...]) -> str:
        assert self.runtime is not None and self._binary is not None
        # Freeze exactly the bytes whose hash identifies this evaluator. Source
        # artifact replacement cannot race extraction into a mismatched snapshot.
        with TemporaryDirectory(prefix="kpatch-sepolicy-") as directory:
            path = Path(directory) / "policy"
            path.write_bytes(self._binary)
            return self.runtime.run(program, (str(path), *arguments), timeout=45)

    def capability_enabled(self, name: str) -> bool | None:
        """Read a recognized policy capability; unknown symbols never mean false.

        SETools enumerates enabled bitmap entries. Enumeration failures or any
        capability name outside our modeled namespace invalidate absence proofs.
        This also protects against unknown numeric entries from newer policies.
        """
        if name not in _KNOWN_POLICYCAPS or self._binary is None:
            return None
        if self._capabilities is None:
            try:
                version = self._runtime_version()
                key = json.dumps((self.policy_sha256, "policy-capabilities", _EVALUATOR_VERSION, version))
                with self._cache() as database:
                    snapshot: _PolicyCapabilities | None = None
                    if database is not None:
                        row = database.execute("SELECT payload,sha256 FROM selinux_snapshots WHERE cache_key=?", (key,)).fetchone()
                        if row is not None and hashlib.sha256(row[0].encode()).hexdigest() == row[1]:
                            snapshot = _PolicyCapabilities.model_validate_json(row[0])
                    if snapshot is None:
                        snapshot = _PolicyCapabilities.model_validate_json(self._policy_program(_CAPABILITIES_PROGRAM, ()))
                        if database is not None:
                            payload = snapshot.model_dump_json()
                            database.execute("INSERT OR REPLACE INTO selinux_snapshots VALUES (?,?,?)",
                                             (key, payload, hashlib.sha256(payload.encode()).hexdigest()))
                            database.commit()
                if snapshot.policy_sha256 != self.policy_sha256 or snapshot.setools_version != version:
                    return None
                self._capabilities = snapshot.policy_capabilities
            except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError):
                return None
        if not self._capabilities <= _KNOWN_POLICYCAPS:
            return None
        return name in self._capabilities

    def query(self, query: SELinuxPermissionQuery) -> SELinuxResult:
        self.stats.permission_queries += 1
        if self.enforcing is True and query in self._query_cache:
            self.stats.permission_cache_hits += 1
            self._query_cache.move_to_end(query)
            return self._query_cache[query]
        result = self._query(query)
        # Transient extraction/runtime failures can recover in the same run.
        if self.enforcing is True and result.decision is not SELinuxDecision.UNKNOWN:
            self._query_cache[query] = result
            if len(self._query_cache) > 4096:
                self._query_cache.popitem(last=False)
        return result

    def _query(self, query: SELinuxPermissionQuery) -> SELinuxResult:
        if self._binary is None:
            return self._result(SELinuxDecision.UNKNOWN, "Cannot read pinned policy: " + str(self._runtime_error))
        if self.enforcing is None:
            return self._result(SELinuxDecision.UNKNOWN, "Runtime enforcement state is unknown")
        if not self.enforcing:
            return self._result(SELinuxDecision.POSSIBLY_ALLOWED, "SELinux is not enforcing")
        try:
            snapshot = self._snapshot(query.subject_type)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            return self._result(SELinuxDecision.UNKNOWN, "Policy extraction failed: " + str(error))
        if snapshot.subject_permissive:
            return self._result(SELinuxDecision.POSSIBLY_ALLOWED, "The subject domain is permissive")
        return self._query_snapshot(snapshot, query)

    def _query_snapshot(self, snapshot: _PolicySnapshot, query: SELinuxPermissionQuery) -> SELinuxResult:
        classes = {item.name: item.permissions for item in snapshot.classes}
        if query.subject_type not in snapshot.types or query.target_type is not None and query.target_type not in snapshot.types:
            return self._result(SELinuxDecision.UNKNOWN, "Query names an unknown concrete type")
        if query.object_class not in classes or not query.permissions <= classes[query.object_class]:
            return self._result(SELinuxDecision.UNKNOWN, "Query names an unknown class or permission")
        grants: dict[str, set[str]] = {}
        for rule in snapshot.allows:
            if rule.object_class != query.object_class:
                continue
            targets = rule.targets if query.target_type is None else rule.targets & {query.target_type}
            for target in targets:
                grants.setdefault(target, set()).update(rule.permissions)
        examples = tuple(SELinuxEvidence(target, tuple(sorted(permissions)))
                         for target, permissions in sorted(grants.items()) if query.permissions <= permissions)
        if examples:
            return SELinuxResult(SELinuxDecision.POSSIBLY_ALLOWED,
                                 "An allow exists; conditional branches and constraints are overapproximated",
                                 self.policy_sha256, examples[:8])
        return self._result(SELinuxDecision.DENIED,
                            "No target has all requested permissions in the complete allow overapproximation")

    def _result(self, decision: SELinuxDecision, reason: str) -> SELinuxResult:
        return SELinuxResult(decision, reason, self.policy_sha256)
