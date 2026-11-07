"""CLI for pinned binary policy facts and compiler-backed policy audit runs."""

from collections import Counter
from contextlib import closing
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3
import subprocess
from typing import Annotated

import typer

from .filter import FilterContext, FilterPipeline, MergeCommitFilter, WhitespaceFilter
from .filter.policy_analysis import PolicyCommitDecision, PolicyFilter
from .filter.policy_clang import ClangUnavailable
from .filter.policy_context import PolicyBuildContext
from .filter.output_paths import repository_input_roots, validate_output_paths
from .filter.policy_profile import AnalysisScope, PolicyTargetProfile, SELinuxPermissionQuery, SELinuxPolicyEvaluator, SEToolsRuntime
from .git import GitRepo


policy_app = typer.Typer(help="Inspect binary SELinux policy and audit source exclusions with pinned compiler inputs.")


def policy_profile_inputs(profile: PolicyTargetProfile) -> tuple[Path, ...]:
    if profile.seccomp.filter_file is None:
        return (profile.policy_file,)
    return (profile.policy_file, profile.seccomp.filter_file)


def validate_policy_outputs(outputs: tuple[Path, ...], build: PolicyBuildContext,
                            protected: tuple[Path, ...]) -> None:
    validate_output_paths(
        outputs, protected=(*protected, build.compilation_database, build.config_file),
        protected_roots=(*repository_input_roots(build.source_root), build.build_root),
    )


def setools_runtime(python: Path | None, module_paths: list[Path] | None) -> SEToolsRuntime | None:
    if python is None:
        if module_paths:
            raise ValueError("--setools-module-path requires --setools-python")
        return None
    return SEToolsRuntime(python.resolve(), tuple(path.resolve() for path in module_paths or []))


@policy_app.command("inspect")
def inspect_policy(
    policy: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="Compiled binary policy, e.g. exported /sys/fs/selinux/policy.")],
    subject: Annotated[str, typer.Option(help="Concrete SELinux subject type.")],
    object_class: Annotated[str, typer.Option("--class", help="SELinux object class.")],
    permission: Annotated[list[str], typer.Option("--permission", help="Required permission; repeat to require several.")],
    target: Annotated[str | None, typer.Option(help="Concrete object type; omitted tests all possible targets.")] = None,
    enforcing: Annotated[bool | None, typer.Option("--enforcing/--permissive", help="Captured runtime enforcement state; omitted is unknown.")] = None,
    cache: Annotated[Path | None, typer.Option(help="Persistent policy snapshot cache.")] = None,
    setools_python: Annotated[Path | None, typer.Option(exists=True, dir_okay=False)] = None,
    setools_module_path: Annotated[list[Path] | None, typer.Option(exists=True, file_okay=False)] = None,
) -> None:
    try:
        if cache is not None and cache.resolve() == policy.resolve():
            raise ValueError("Policy cache must differ from the policy binary")
        evaluator = SELinuxPolicyEvaluator(policy, enforcing=enforcing, cache_path=cache,
                                           runtime=setools_runtime(setools_python, setools_module_path))
        result = evaluator.query(SELinuxPermissionQuery(subject_type=subject, object_class=object_class,
                                                       permissions=frozenset(permission), target_type=target))
    except (OSError, ValueError) as error:
        typer.echo(f"Policy inspection failed: {error}", err=True)
        raise typer.Exit(1) from error
    typer.echo(json.dumps(asdict(result), indent=2))


@policy_app.command("build-context")
def capture_build_context(
    source_root: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    build_root: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    compile_commands: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    config: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option(help="Context JSON outside source/build roots, which remain immutable.")],
) -> None:
    try:
        if output.resolve().is_relative_to(source_root.resolve()) or output.resolve().is_relative_to(build_root.resolve()):
            raise ValueError("Store the context outside the frozen source and build roots")
        if output.resolve() in {compile_commands.resolve(), config.resolve()}:
            raise ValueError("Context output must differ from compiler inputs")
        context = PolicyBuildContext.capture(source_root, build_root, compile_commands, config)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(context.model_dump_json(indent=2) + "\n")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        typer.echo(f"Build-context capture failed: {error}", err=True)
        raise typer.Exit(1) from error
    typer.echo(f"Pinned compiler context at {context.base_revision}: {output}")


@policy_app.command("analyze")
def analyze_policy(
    commit: Annotated[list[str], typer.Option("--commit", help="Commit or Git revision range; repeat for multiple inputs.")],
    profile: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    build_context: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option(help="JSON audit report; source repositories/databases are not changed.")],
    repo: Annotated[Path, typer.Option(exists=True, file_okay=False)] = Path("linux"),
    limit: Annotated[int, typer.Option(min=1, help="Maximum commits per bounded audit.")] = 100,
    direct_app: Annotated[bool, typer.Option(help="Explicitly restrict scope to synchronous direct app context, excluding service mediation.")] = False,
    cache: Annotated[Path | None, typer.Option(help="Persistent compiler/policy cache database.")] = None,
    setools_python: Annotated[Path | None, typer.Option(exists=True, dir_okay=False)] = None,
    setools_module_path: Annotated[list[Path] | None, typer.Option(exists=True, file_okay=False)] = None,
) -> None:
    try:
        target = PolicyTargetProfile.load(profile)
        build = PolicyBuildContext.load(build_context)
        if direct_app:
            target = target.model_copy(update={"scope": AnalysisScope.DIRECT_APP})
        validate_policy_outputs((output,) + ((cache,) if cache is not None else ()), build,
                                (profile, build_context) + policy_profile_inputs(target))
        evaluator = SELinuxPolicyEvaluator(target.policy_file, enforcing=target.selinux_enforcing, cache_path=cache,
                                           runtime=setools_runtime(setools_python, setools_module_path))
        decisions: list[PolicyCommitDecision] = []
        stage = PolicyFilter(target, build, evaluator, cache_path=cache, on_decision=decisions.append)
        repository = GitRepo(repo)
        commits = []
        seen: set[str] = set()
        for revision in commit:
            # A bare hash denotes that commit, not its entire ancestor history.
            selection = revision if ".." in revision or revision.endswith("^!") else revision + "^!"
            with closing(repository.iter_commits_from_revision(selection)) as selected:
                for item in selected:
                    if item.commit_id not in seen:
                        commits.append(item)
                        seen.add(item.commit_id)
                    if len(commits) >= limit:
                        break
            if len(commits) >= limit:
                break
        pipeline = FilterPipeline([MergeCommitFilter(), WhitespaceFilter(), stage])
        retained = pipeline.filter_commits(commits, FilterContext(repository), show_progress=False)
        counts = Counter(item.status for item in decisions)
        report = {"profile_sha256": target.fingerprint, "policy_sha256": target.policy_sha256,
                  "scope": target.scope, "input_commits": len(commits), "output_commits": len(retained),
                  "decision_counts": dict(counts), "compiler_stats": asdict(stage.compiler.stats) if stage.compiler else {},
                  "pre_policy_removed": len(commits) - len(decisions),
                  "policy_stats": asdict(evaluator.stats),
                  "decisions": [item.model_dump(mode="json") for item in decisions]}
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
    except (OSError, ValueError, RuntimeError, sqlite3.Error, subprocess.SubprocessError, ClangUnavailable) as error:
        typer.echo(f"Policy analysis failed: {error}", err=True)
        raise typer.Exit(1) from error
    typer.echo(f"Policy exclusions: {counts['excluded']}; direct-app candidates retained: {counts['direct_app_candidate']}; audit: {output}")
