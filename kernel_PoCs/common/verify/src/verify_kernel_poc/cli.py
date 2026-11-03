from __future__ import annotations

import hashlib
import json
import posixpath
import re
import secrets
import shlex
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

import typer

from .adb import AdbError
from .cuttlefish import Guest, attach_guest, start_guest
from .metadata import MetadataScan, scan_metadata_file
from .models import (
    Metadata,
    PayloadSpec,
    RunPlan,
    UnsupportedError,
    VerificationResult,
    VerifyError,
)
from .report import print_human_result
from .rootcheck import (
    RootFlag,
    build_root_check_lines,
    cleanup_root_flag,
    collect_identity,
    provision_root_flag,
    root_uid_seen,
    token_matched,
)
from .runner import RunOutcome, build_run_command, run_payload

@dataclass(frozen=True, slots=True)
class AppVariant:
    name: str
    package: str
    apk: Path


APP_VARIANTS = (
    AppVariant(
        name="1",
        package="com.purdue.kpoc.verify.one",
        apk=Path(__file__).parent / "assets" / "kpoc-verify-1.apk",
    ),
    AppVariant(
        name="2",
        package="com.purdue.kpoc.verify.two",
        apk=Path(__file__).parent / "assets" / "kpoc-verify-2.apk",
    ),
)
APP_VARIANTS_BY_NAME = {variant.name: variant for variant in APP_VARIANTS}

app = typer.Typer(add_completion=False, no_args_is_help=True)

VALID_ROOT_CHECKS = {"auto", "flag", "command", "regex", "none"}
VALID_ARTIFACTS = {"auto", "executable", "shared", "jni"}
VALID_PAYLOADS = {"auto", "shell", "listening-shell", "reverse-shell"}
PAYLOAD_KIND_BY_OPTION = {
    "shell": "shell",
    "listening-shell": "listening_shell",
    "reverse-shell": "reverse_shell",
}


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")
    return cleaned[:48] or "poc"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_metadata(
    scan: MetadataScan,
    *,
    artifact: str,
    payload: str,
    payload_ip: str | None,
    payload_port: int | None,
    root_check: str,
    run_command: str | None,
) -> tuple[Metadata | None, str, str, PayloadSpec, str, str | None]:
    metadata = scan.metadata

    resolved_artifact = artifact
    if resolved_artifact == "auto":
        resolved_artifact = metadata.artifact if metadata else "executable"
    if resolved_artifact not in {"executable", "shared", "jni"}:
        raise UnsupportedError(f"unsupported artifact: {resolved_artifact}")

    resolved_run_mode = {
        "executable": "exec",
        "shared": "ld_preload",
        "jni": "jni",
    }[resolved_artifact]

    if payload == "auto":
        resolved_payload = metadata.payload if metadata else PayloadSpec()
    else:
        kind = PAYLOAD_KIND_BY_OPTION[payload]
        base = metadata.payload if metadata else PayloadSpec()
        resolved_payload = PayloadSpec(
            kind=kind,
            ip=payload_ip if payload_ip is not None else base.ip,
            port=payload_port if payload_port is not None else base.port,
        )
    if payload_ip is not None or payload_port is not None:
        resolved_payload = PayloadSpec(
            kind=resolved_payload.kind,
            ip=payload_ip if payload_ip is not None else resolved_payload.ip,
            port=payload_port if payload_port is not None else resolved_payload.port,
        )
    # Re-validate after overrides.
    resolved_payload = PayloadSpec.from_dict(resolved_payload.to_dict())

    resolved_root_check = root_check
    if resolved_root_check == "auto":
        metadata_mode = metadata.root_check_mode if metadata else "shell"
        if metadata_mode in {"shell", "flag", "auto"}:
            resolved_root_check = "flag"
        elif metadata_mode in {"command", "regex", "none"}:
            resolved_root_check = metadata_mode
        else:
            resolved_root_check = "flag"

    resolved_run_command = run_command
    if resolved_run_command is None and metadata and metadata.run == "ld_preload":
        resolved_run_command = None

    return (
        metadata,
        resolved_artifact,
        resolved_run_mode,
        resolved_payload,
        resolved_root_check,
        resolved_run_command,
    )


def _build_plan(
    *,
    poc: Path,
    remote_path: str,
    metadata: Metadata | None,
    artifact: str,
    run_mode: str,
    payload: PayloadSpec,
    root_check: str,
    run_command: str | None,
    root_check_command: str | None,
    root_check_regex: str | None,
    poc_args: list[str],
    from_app: bool = False,
    app_package: str | None = None,
    app_apk: str | None = None,
    app_path: str | None = None,
    app_port: int | None = None,
    app_mode: str | None = None,
) -> RunPlan:
    if root_check == "command" and not root_check_command:
        raise VerifyError("--root-check command requires --root-check-command")
    if root_check == "regex" and not root_check_regex:
        raise VerifyError("--root-check regex requires --root-check-regex")
    if from_app and artifact not in {"shared", "jni"}:
        raise UnsupportedError(
            "--from-app only supports shared or jni artifacts; build with "
            "--shared or --jni, or use --run-command for a custom app runner"
        )
    if artifact == "jni" and not run_command and not from_app:
        raise UnsupportedError(
            "JNI artifacts need --from-app or --run-command with a device-side "
            "host command"
        )
    plan = RunPlan(
        artifact=artifact,
        run_mode=run_mode,
        payload=payload,
        run_command=run_command,
        poc_args=tuple(poc_args),
        root_check_mode=root_check,
        root_check_command=root_check_command,
        root_check_regex=root_check_regex,
        remote_path=remote_path,
        local_path=str(poc),
        metadata=metadata,
        from_app=from_app,
        app_package=app_package,
        app_apk=app_apk,
        app_path=app_path,
        app_port=app_port,
        app_mode=app_mode,
    )
    # Check that the run command can be constructed before starting a guest.
    # App mode needs the installed APK path, which is only known after install.
    if not from_app:
        build_run_command(plan)
    return plan


def _write_logs(log_dir: Path, result: VerificationResult, command: str) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "result.json").write_text(
        json.dumps(result.to_dict(), indent=2) + "\n"
    )
    (log_dir / "output.txt").write_text(result.output)
    (log_dir / "command.txt").write_text(command + "\n")


def _install_app(adb, package: str, apk: Path) -> str:
    try:
        adb.install(apk)
    except AdbError:
        # Signature mismatch or a stale install: replace the helper app.
        adb.uninstall(package)
        adb.install(apk)

    apk_path = adb.package_path(package)
    local_apk_hash = _sha256(apk)
    remote = adb.shell(
        f"sha256sum {shlex.quote(apk_path)}",
        timeout=30.0,
        check=False,
    )
    if remote.returncode == 0 and remote.stdout.strip():
        remote_apk_hash = remote.stdout.split(maxsplit=1)[0]
        if remote_apk_hash != local_apk_hash:
            raise VerifyError(
                "installed helper APK does not match the local helper APK: "
                f"local {local_apk_hash}, installed {remote_apk_hash}. "
                "Run the verifier from the common/verify project with uv run."
            )
    # A stale Activity would receive the new Intent in onNewIntent instead of
    # starting a fresh loader thread.
    adb.shell(
        f"am force-stop {shlex.quote(package)}",
        timeout=30.0,
        check=False,
    )
    identity = adb.shell(
        f"run-as {shlex.quote(package)} id",
        timeout=30.0,
        check=False,
    )
    if identity.returncode != 0:
        raise VerifyError(
            f"helper app {package} is not debuggable or run-as failed: "
            f"{identity.stdout.strip()}"
        )
    match = re.search(r"uid=(\d+)", identity.stdout)
    if match is None:
        raise VerifyError(
            f"could not determine app UID from run-as: {identity.stdout.strip()}"
        )
    uid = int(match.group(1))
    if uid < 10000:
        raise VerifyError(
            f"app mode did not enter an app UID (got uid={uid}); refusing to "
            "run with shell/root privileges"
        )
    return apk_path


def _install_helper_app(adb, plan: RunPlan) -> str:
    if not plan.app_apk or not plan.app_package:
        raise VerifyError("app mode requires a helper app package and APK")
    return _install_app(adb, plan.app_package, Path(plan.app_apk))


def _copy_poc_into_app(adb, plan: RunPlan) -> None:
    if not plan.from_app or not plan.app_package or not plan.app_path:
        return
    prefix = f"/data/data/{plan.app_package}/"
    if not plan.app_path.startswith(prefix):
        raise VerifyError(f"unexpected app-local PoC path: {plan.app_path}")
    relative_path = plan.app_path.removeprefix(prefix)
    script = (
        "mkdir -p files && "
        f"cp {shlex.quote(plan.remote_path)} {shlex.quote(relative_path)} && "
        f"chmod 755 {shlex.quote(relative_path)}"
    )
    result = adb.shell(
        f"run-as {shlex.quote(plan.app_package)} sh -c {shlex.quote(script)}",
        timeout=60.0,
        check=False,
    )
    if result.returncode != 0:
        raise VerifyError(
            f"failed to copy PoC into app data: {result.stdout.strip()}"
        )

    hash_result = adb.shell(
        f"run-as {shlex.quote(plan.app_package)} sha256sum "
        f"{shlex.quote(plan.app_path)}",
        timeout=30.0,
        check=False,
    )
    if hash_result.returncode == 0:
        remote_hash = hash_result.stdout.split(maxsplit=1)[0]
        local_hash = _sha256(Path(plan.local_path))
        if remote_hash != local_hash:
            raise VerifyError(
                "app-local PoC hash mismatch: "
                f"local {local_hash}, app {remote_hash}"
            )


def _run_verification(
    *,
    poc: Path,
    template: str | None,
    adb_target: str | None,
    instance_name: str | None,
    keep_instance: bool,
    cpus: int | None,
    selinux: bool | None,
    timeout: float,
    attempts: int,
    root_flag_path: str | None,
    require_selinux: str,
    force: bool,
    plan_factory,
    existing_guest: Guest | None = None,
    stop_guest: bool = True,
    run_only: bool = False,
    on_output: Callable[[str], None] | None = None,
) -> VerificationResult:
    started = time.monotonic()
    scan = scan_metadata_file(poc)
    plan = plan_factory(scan)
    warnings = list(scan.warnings)

    if plan.metadata and plan.metadata.target not in {"android", "unknown"} and not force:
        raise UnsupportedError(
            f"metadata target is {plan.metadata.target!r}, not 'android'; "
            "pass --force to run it anyway"
        )

    guest: Guest | None = None
    flag: RootFlag | None = None
    remote_directory = plan.remote_path.rsplit("/", 1)[0]
    before = None
    after = None
    output = ""
    command = ""
    passed = False
    reason = ""
    attempts_used = 0
    root_token = False
    root_uid = False

    try:
        if existing_guest is not None:
            guest = existing_guest
            warnings.extend(guest.warnings)
        elif template:
            guest = start_guest(
                template,
                name=instance_name or f"kpoc-verify-{_safe_name(poc.stem)}-{int(time.time())}",
                cpus=cpus,
                selinux=selinux,
            )
            warnings.extend(guest.warnings)
        elif adb_target:
            guest = attach_guest(adb_target)
        else:
            raise VerifyError("one of --template or --adb is required")

        adb = guest.adb
        before = collect_identity(adb)
        if before.uid_id.startswith("uid=0("):
            raise VerifyError(
                "ADB shell is already root; run the PoC from a non-root shell "
                "so the root check is meaningful"
            )

        if plan.from_app:
            plan = replace(plan, app_apk_path=_install_helper_app(adb, plan))

        adb.shell(
            f"mkdir -p {shlex.quote(remote_directory)} && chmod 755 {shlex.quote(remote_directory)}",
            timeout=30.0,
        )
        adb.push(poc, plan.remote_path)
        adb.shell(f"chmod 755 {shlex.quote(plan.remote_path)}", timeout=30.0)
        remote_hash = adb.sha256sum(plan.remote_path)
        local_hash = _sha256(poc)
        if remote_hash != local_hash:
            raise VerifyError(
                f"pushed PoC hash mismatch: local {local_hash}, remote {remote_hash}"
            )

        if plan.from_app:
            _copy_poc_into_app(adb, plan)

        needs_flag = plan.root_check_mode in {"flag", "auto"} or (
            plan.root_check_command is not None
            and "{flag}" in plan.root_check_command
        )
        if needs_flag:
            flag = provision_root_flag(adb, path_override=root_flag_path)

        lines = build_root_check_lines(
            flag,
            command=plan.root_check_command,
            regex=plan.root_check_regex,
        )
        if plan.root_check_mode == "none":
            lines = []

        outcome: RunOutcome | None = None
        for attempt in range(1, attempts + 1):
            attempts_used = attempt
            outcome = run_payload(
                adb,
                plan,
                lines=lines,
                timeout=timeout,
                on_output=on_output,
                run_only=run_only,
            )
            output = outcome.output
            command = outcome.command
            root_token = token_matched(output, flag.token if flag else None)
            root_uid = root_uid_seen(output)

            if plan.root_check_mode == "regex":
                try:
                    regex_match = bool(
                        re.search(plan.root_check_regex or "", output, re.MULTILINE)
                    )
                except re.error as exc:
                    raise VerifyError(f"invalid root-check regex: {exc}") from exc
            else:
                regex_match = False

            if run_only:
                passed = True
                reason = (
                    f"run-only: payload started (stopped after {timeout:.0f}s)"
                    if outcome.timed_out
                    else "run-only: payload started"
                )
                break
            if plan.root_check_mode == "none":
                passed = False
                reason = "no root check requested (--root-check none)"
                break
            if root_token or regex_match:
                passed = True
                reason = (
                    "root-only flag token matched"
                    if root_token
                    else "root-check regex matched"
                )
                break
            if outcome.timed_out:
                reason = f"timed out after {timeout:.0f}s"
            elif root_uid:
                reason = (
                    "uid=0 was printed but the root-only flag was not read; "
                    "treating this as unverified"
                )
            else:
                reason = (
                    f"root proof not found (exit code {outcome.returncode})"
                )
            if attempt < attempts:
                time.sleep(1.0)

        after = collect_identity(adb)

        if require_selinux != "any":
            actual = after.selinux.lower()
            if require_selinux == "enforcing" and actual != "enforcing":
                passed = False
                reason = f"SELinux is {after.selinux!r}, expected Enforcing"
            elif require_selinux == "permissive" and actual != "permissive":
                passed = False
                reason = f"SELinux is {after.selinux!r}, expected Permissive"

        if after.selinux.lower() == "permissive":
            warnings.append("SELinux is Permissive on the guest")

        return VerificationResult(
            passed=passed,
            exit_code=0 if passed else 1,
            reason=reason,
            template=guest.template,
            template_selinux=guest.template_selinux,
            instance_name=guest.instance_name,
            instance_id=guest.instance_id or None,
            adb_target=guest.adb_target,
            local_poc=str(poc),
            remote_poc=plan.app_path or plan.remote_path,
            poc_sha256=local_hash,
            metadata=plan.metadata,
            plan=plan,
            before=before,
            after=after,
            root_flag_path=flag.path if flag else None,
            root_token_matched=root_token,
            root_uid_seen=root_uid,
            attempts=attempts_used,
            duration_sec=time.monotonic() - started,
            output=output,
            command=command,
            warnings=warnings,
        )
    finally:
        if guest is not None:
            try:
                if flag is not None:
                    cleanup_root_flag(guest.adb, flag)
                if plan.from_app and plan.app_package and plan.app_path:
                    guest.adb.shell(
                        f"run-as {shlex.quote(plan.app_package)} rm -f "
                        f"{shlex.quote(plan.app_path)}",
                        timeout=30.0,
                        check=False,
                    )
                    guest.adb.shell(
                        f"am force-stop {shlex.quote(plan.app_package)}",
                        timeout=30.0,
                        check=False,
                    )
                guest.adb.shell(
                    f"rm -rf {shlex.quote(remote_directory)}",
                    timeout=30.0,
                    check=False,
                )
            except Exception:
                pass
            if guest.created and stop_guest and not keep_instance:
                try:
                    guest.stop()
                except Exception:
                    pass


def _run_all_apps(
    *,
    poc: Path,
    template: str,
    instance_name: str | None,
    keep_instance: bool,
    cpus: int | None,
    selinux: bool | None,
    timeout: float,
    attempts: int,
    root_flag_path: str | None,
    require_selinux: str,
    force: bool,
    variants: tuple[AppVariant, ...],
    plan_factory_for_variant,
    run_only: bool = False,
    on_output: Callable[[str], None] | None = None,
) -> list[tuple[str, VerificationResult]]:
    guests: list[Guest] = []
    results: list[tuple[str, VerificationResult]] = []
    base_name = instance_name or f"kpoc-verify-{_safe_name(poc.stem)}-{int(time.time())}"
    try:
        for vm_index in (1, 2):
            guest = start_guest(
                template,
                name=f"{base_name}-vm{vm_index}",
                cpus=cpus,
                selinux=selinux,
            )
            guests.append(guest)
            # Install both variants on every VM so both app UIDs and paths exist.
            for variant in variants:
                _install_app(guest.adb, variant.package, variant.apk)

        for vm_index, guest in enumerate(guests, 1):
            for variant in variants:
                label = f"vm{vm_index}-app{variant.name}"
                typer.echo(f"[verify] running {label}", err=True)
                result = _run_verification(
                    poc=poc,
                    template=template,
                    adb_target=None,
                    instance_name=guest.instance_name,
                    keep_instance=keep_instance,
                    cpus=cpus,
                    selinux=selinux,
                    timeout=timeout,
                    attempts=attempts,
                    root_flag_path=root_flag_path,
                    require_selinux=require_selinux,
                    force=force,
                    plan_factory=plan_factory_for_variant(variant),
                    existing_guest=guest,
                    stop_guest=False,
                    run_only=run_only,
                    on_output=on_output,
                )
                results.append((label, result))
        return results
    finally:
        if not keep_instance:
            for guest in guests:
                try:
                    guest.stop()
                except Exception:
                    pass


def _print_metadata(scan: MetadataScan) -> None:
    payload: dict[str, object] = {
        "found": scan.found,
        "metadata": scan.metadata.to_dict() if scan.metadata else None,
        "raw_json": scan.raw_json,
        "warnings": scan.warnings,
    }
    typer.echo(json.dumps(payload, indent=2))


@app.command()
def run(
    poc: Path = typer.Argument(..., help="Path to the wrapped PoC binary."),
    template: str | None = typer.Option(
        None, "--template", "-t", help="Cuttlefish template to launch."
    ),
    adb_target: str | None = typer.Option(
        None, "--adb", help="Reuse an existing ADB target instead of launching."
    ),
    name: str | None = typer.Option(
        None, "--name", help="Optional Cuttlefish instance name."
    ),
    keep_instance: bool = typer.Option(
        False, "--keep-instance", help="Leave a launched instance running."
    ),
    cpus: int | None = typer.Option(None, "--cpus", help="Cuttlefish CPU override."),
    selinux: bool | None = typer.Option(
        None, "--selinux", help="Cuttlefish SELinux override."
    ),
    timeout: float = typer.Option(180.0, "--timeout", help="Per-attempt timeout."),
    attempts: int = typer.Option(1, "--attempts", help="Attempts for racy PoCs."),
    artifact: str = typer.Option(
        "auto",
        "--artifact",
        help="executable, shared, jni, or auto from embedded metadata.",
    ),
    payload: str = typer.Option(
        "auto",
        "--payload",
        help="shell, listening-shell, reverse-shell, or auto.",
    ),
    payload_ip: str | None = typer.Option(None, "--payload-ip"),
    payload_port: int | None = typer.Option(None, "--payload-port"),
    run_command: str | None = typer.Option(
        None,
        "--run-command",
        help='Device command template; "{poc}" expands to the remote/app path.',
    ),
    from_app: str | None = typer.Option(
        None,
        "--from-app",
        help="App mode: random, 1, 2, or all (2 VMs, both apps each).",
    ),
    run_only: bool = typer.Option(
        False,
        "--run-only",
        help="Run the payload and stream stdout; skip root checks.",
    ),
    poc_arg: list[str] = typer.Option([], "--poc-arg", help="Argument for the PoC."),
    root_check: str = typer.Option(
        "auto",
        "--root-check",
        help="auto, flag, command, regex, or none.",
    ),
    root_flag_path: str | None = typer.Option(
        None, "--root-flag-path", help="Override the root-only flag file path."
    ),
    root_check_command: str | None = typer.Option(
        None,
        "--root-check-command",
        help='Command run after the payload starts; "{flag}" expands to the flag path.',
    ),
    root_check_regex: str | None = typer.Option(
        None, "--root-check-regex", help="Pass when this regex matches output."
    ),
    allow_no_root_check: bool = typer.Option(
        False, "--allow-no-root-check", help="Allow --root-check none to exit 0."
    ),
    require_selinux: str = typer.Option(
        "any", "--require-selinux", help="any, enforcing, or permissive."
    ),
    force: bool = typer.Option(
        False, "--force", help="Run even when metadata target is not Android."
    ),
    print_metadata: bool = typer.Option(
        False, "--print-metadata", help="Print embedded metadata and exit."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print the resolved plan and exit."
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON result."),
    log_dir: Path | None = typer.Option(
        None, "--log-dir", help="Write result, output, and command logs here."
    ),
) -> None:
    """Verify that a kernel_PoCs/common wrapped PoC obtains root on Cuttlefish."""
    if not poc.is_file():
        raise typer.BadParameter(f"PoC is not a file: {poc}")

    if print_metadata:
        try:
            _print_metadata(scan_metadata_file(poc))
        except VerifyError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=exc.exit_code) from exc
        return

    if artifact not in VALID_ARTIFACTS:
        raise typer.BadParameter(f"invalid --artifact: {artifact}")
    if payload not in VALID_PAYLOADS:
        raise typer.BadParameter(f"invalid --payload: {payload}")
    if root_check not in VALID_ROOT_CHECKS:
        raise typer.BadParameter(f"invalid --root-check: {root_check}")
    if run_only and (
        root_check not in {"auto", "none"}
        or root_flag_path is not None
        or root_check_command is not None
        or root_check_regex is not None
    ):
        raise typer.BadParameter(
            "--run-only cannot be combined with root-check options"
        )
    if require_selinux not in {"any", "enforcing", "permissive"}:
        raise typer.BadParameter(f"invalid --require-selinux: {require_selinux}")
    if not dry_run and bool(template) == bool(adb_target):
        raise typer.BadParameter("pass exactly one of --template or --adb")
    if attempts < 1:
        raise typer.BadParameter("--attempts must be at least 1")
    if timeout <= 0:
        raise typer.BadParameter("--timeout must be positive")

    poc = poc.resolve()
    local_hash = _sha256(poc)
    remote_path = (
        f"/data/local/tmp/kpoc-verify-{local_hash[:12]}/{_safe_name(poc.name)}"
    )

    if from_app is not None and from_app not in {"random", "1", "2", "all"}:
        raise typer.BadParameter("--from-app must be random, 1, 2, or all")
    if from_app == "all" and adb_target:
        raise typer.BadParameter("--from-app all launches 2 VMs; do not pass --adb")

    run_all = from_app == "all"
    if run_all:
        selected_variants = APP_VARIANTS
    elif from_app is not None:
        variant_name = (
            secrets.choice([variant.name for variant in APP_VARIANTS])
            if from_app == "random"
            else from_app
        )
        selected_variants = (APP_VARIANTS_BY_NAME[variant_name],)
    else:
        selected_variants = ()

    for variant in selected_variants:
        if not variant.apk.is_file():
            raise typer.BadParameter(f"helper APK is not a file: {variant.apk}")

    def make_plan_factory(variant: AppVariant | None):
        app_library_path = (
            f"/data/data/{variant.package}/files/kpoc-{local_hash[:12]}.so"
            if variant is not None
            else None
        )
        app_port = 20000 + secrets.randbelow(40000) if variant is not None else None

        def plan_factory(scan: MetadataScan) -> RunPlan:
            (
                metadata,
                resolved_artifact,
                resolved_run_mode,
                resolved_payload,
                resolved_root_check,
                resolved_run_command,
            ) = _resolve_metadata(
                scan,
                artifact=artifact,
                payload=payload,
                payload_ip=payload_ip,
                payload_port=payload_port,
                root_check=root_check,
                run_command=run_command,
            )
            if run_only:
                resolved_root_check = "none"
                root_check_command_value = None
                root_check_regex_value = None
            else:
                root_check_command_value = root_check_command
                root_check_regex_value = root_check_regex
            return _build_plan(
                poc=poc,
                remote_path=remote_path,
                metadata=metadata,
                artifact=resolved_artifact,
                run_mode=resolved_run_mode,
                payload=resolved_payload,
                root_check=resolved_root_check,
                run_command=resolved_run_command,
                root_check_command=root_check_command_value,
                root_check_regex=root_check_regex_value,
                poc_args=list(poc_arg),
                from_app=variant is not None,
                app_package=variant.package if variant is not None else None,
                app_apk=str(variant.apk) if variant is not None else None,
                app_path=app_library_path,
                app_port=app_port,
                app_mode=(
                    "jni" if variant is not None and resolved_artifact == "jni"
                    else "preload" if variant is not None else None
                ),
            )

        return plan_factory

    def stream_output(chunk: str) -> None:
        target = sys.stderr if json_output else sys.stdout
        target.write(chunk)
        target.flush()

    try:
        if dry_run:
            scan = scan_metadata_file(poc)
            if run_all:
                runs = [
                    {
                        "app": variant.name,
                        "plan": make_plan_factory(variant)(scan).to_dict(),
                    }
                    for variant in APP_VARIANTS
                ]
                typer.echo(
                    json.dumps(
                        {"runs": runs, "warnings": scan.warnings},
                        indent=2,
                    )
                )
            else:
                variant = selected_variants[0] if selected_variants else None
                plan = make_plan_factory(variant)(scan)
                payload = {
                    "plan": plan.to_dict(),
                    "warnings": scan.warnings,
                }
                if variant is not None:
                    payload["app"] = variant.name
                typer.echo(json.dumps(payload, indent=2))
            return

        if run_all:
            if not template:
                raise VerifyError("--from-app all requires --template")
            results = _run_all_apps(
                poc=poc,
                template=template,
                instance_name=name,
                keep_instance=keep_instance,
                cpus=cpus,
                selinux=selinux,
                timeout=timeout,
                attempts=attempts,
                root_flag_path=root_flag_path,
                require_selinux=require_selinux,
                force=force,
                variants=APP_VARIANTS,
                plan_factory_for_variant=make_plan_factory,
                run_only=run_only,
                on_output=stream_output,
            )
        else:
            variant = selected_variants[0] if selected_variants else None
            result = _run_verification(
                poc=poc,
                template=template,
                adb_target=adb_target,
                instance_name=name,
                keep_instance=keep_instance,
                cpus=cpus,
                selinux=selinux,
                timeout=timeout,
                attempts=attempts,
                root_flag_path=root_flag_path,
                require_selinux=require_selinux,
                force=force,
                plan_factory=make_plan_factory(variant),
                run_only=run_only,
                on_output=stream_output,
            )
            label = f"app{variant.name}" if variant is not None else "shell"
            results = [(label, result)]

        for _label, result in results:
            if (
                not run_only
                and result.plan.root_check_mode == "none"
                and allow_no_root_check
            ):
                result.passed = True
                result.exit_code = 0
                result.reason = (
                    "no root check requested; allowed by --allow-no-root-check"
                )
    except VerifyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=exc.exit_code) from exc
    except AdbError as exc:
        typer.echo(f"adb error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if log_dir is not None:
        for label, result in results:
            target = log_dir if len(results) == 1 else log_dir / _safe_name(label)
            _write_logs(target, result, result.command)

    if json_output:
        if len(results) == 1:
            typer.echo(json.dumps(results[0][1].to_dict(), indent=2))
        else:
            typer.echo(
                json.dumps(
                    {
                        "runs": [
                            {"label": label, "result": result.to_dict()}
                            for label, result in results
                        ]
                    },
                    indent=2,
                )
            )
    else:
        for index, (label, result) in enumerate(results):
            if len(results) > 1:
                if index:
                    typer.echo("")
                typer.echo(f"===== {label} =====")
            print_human_result(result, show_output=False)

    raise typer.Exit(code=0 if all(result.passed for _, result in results) else 1)


def _normalize_from_app_args(argv: list[str]) -> list[str]:
    """Allow bare --from-app by rewriting it to --from-app random."""
    normalized: list[str] = []
    allowed = {"random", "1", "2", "all"}
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "--from-app":
            if index + 1 < len(argv) and argv[index + 1] in allowed:
                normalized.extend([argument, argv[index + 1]])
                index += 2
            else:
                normalized.extend([argument, "random"])
                index += 1
            continue
        normalized.append(argument)
        index += 1
    return normalized


def main() -> None:
    sys.argv[1:] = _normalize_from_app_args(sys.argv[1:])
    app()


if __name__ == "__main__":
    main()
