# Pruning work: summary and future work

This file replaces the agent notes that used to live next to the README
(`FUTURE_PRUNING_WORK.md`, `PRUNING_SAMPLE_REVIEW_2026_11_06.md`,
`FILTER_MASKING.md`, `WHITESPACE_PRUNING.md`, `DIAGNOSTIC_STRING_PRUNING.md`,
`UNUSED_CODE_AND_REORDER_PRUNING.md`, `SOURCE_INPUT_ROLE_ASSUMPTIONS.md`,
`TARGET_PREPROCESSING.md`). The full originals, with every per-experiment
measurement, are in git at commit `8910b51`:

```sh
git show 8910b51:ingots_tools/kpatch/FUTURE_PRUNING_WORK.md
```

Most `benchmarks/<experiment>/` output directories cited by those notes
(~17 GB) were deleted on 2026-11-10. See [Kept artifacts](#kept-artifacts).

## Goal

Reduce the ~26,670 commits that survive the original file/config filters
(`db/filtered_after_2025.sqlite`) to ones that can matter to the target, an
Android untrusted app on a 6.x ARM64 kernel. The rule throughout is to keep a
commit unless every remaining change is shown to be irrelevant. A failure,
timeout or unknown input keeps the change. Riskier assumptions are opt-in
"lossy" modes, and each one needs an audit report.

## Pipeline as it stands

`filter config` runs these stages:

```
merge → config (Kbuild model) → ifdef → [constant branches] → dead code
      → whitespace → final comparison (RenameFilter)
      → [target preprocessing] → [policy gates]
```

Brackets mark opt-in stages. The stages never rewrite the patch.
`FilteredCommit.original_diff` keeps the original, immutable patch. Stages add
typed masks against original line coordinates:

- **`EditMask`**: ignore one modification. The child source is rebuilt with
  the parent's text in its place.
- **`CodeMask`**: these whole lines are irrelevant on one side. They are
  blanked in full-source views, with byte lengths and CR/LF characters kept.

A commit is removed only when masks cover all of its changes. A rejected
candidate publishes no masks.

### Flags

| Flag | Default | What it enables | Risk |
| --- | --- | --- | --- |
| `--config` | on with a config | Removes C/header/asm edits that are absent from the modeled build on both revisions. | Assumes ordinary kbuild rules; vendor inputs need `--build-inputs` |
| `--build-inputs FILE` | — | Adds positive build membership (path, `y`/`m`, origin). | None (it can only add membership) |
| `--config-observations` | off | Diagnostic only: records configuration decisions without excluding anything. | — |
| `--source-pruning` | off | Unused definitions, whitespace/comment, consistent renames, diagnostic wording. | Strict |
| `--constant-branches` | off | Numeric `#if 0` / `#elif` folding. | Strict, but costly for small yield |
| `--source-pruning-lossy --source-pruning-report F` | off | Function-body binding renames, static-helper and switch-arm reorders, assumed macro-discovery gaps. | **Lossy**: code addresses can change |
| `--whitespace-line-numbers-lossy --whitespace-report F` | off | Allows physical line-number differences. | **Lossy**: `__LINE__` observers |
| `--unresolved-inputs-lossy --input-role-report F` | off | Assumes unresolved Make/asm expressions do not read the changed source. | **Lossy**: no error bound |
| `--preprocess-build-context F --preprocess-report F [--preprocess-cache F]` | off | Compares compiler-expanded inputs for every affected consumer. | Strict; needs a prepared build |
| `--policy-profile F --policy-build-context F --policy-report F` | off | Compiler-backed seccomp/SELinux/capability gates. | Direct-app scope only |

The `kpatch policy inspect | build-context | analyze` subcommands build the
inputs for the last two rows.

## Work done

### Masking framework
- Immutable original patch, typed masks, and complete masked source views that
  every later stage shares.
- Shared raw-input veto. Before any source-based mask is published, both
  revisions are checked for raw consumers of the file: `.incbin`/`.include`,
  Make generator prerequisites, and similar. For example, `lib/build_OID_registry`
  reads OIDs out of header comments. If a consumer is found, or the scan fails,
  the change is kept.
- A lazy reference index keyed per revision, cached in Git's
  `kpatch-references-v8.sqlite` and updated from deltas. It uses a bounded
  binary parser for `git grep` rows. The whole-kernel include index bootstraps
  in about 90 s with about 735 MB peak memory.

### Configuration / build model (`config_filter.py`, `build_inputs.py`)
- Normal config runs exclude again. For a while they had become diagnostic
  only. Literal includes, forced headers, observed raw consumers and supplied
  vendor inputs keep a file in the build.
- Advisory Kbuild preparation is skipped in normal runs. Live vendor modules on
  Cuttlefish showed that the base config cannot authorize exclusions by itself.

### Source pruning (`source_pruning.py`, `source_filter.py`, `syntax.py`, `binding_renames.py`, `reordering.py`, `switch_reordering.py`)
- **Unused definitions:** static and global functions, prototypes, simple
  macros, typedefs, and whole structs, unions and enums with no references in
  either revision, including configured-out consumers. Unused functions in a
  file can be masked individually (up to 8 per file). Global functions must be
  call-free leaves. Otherwise an uncalled global can still emit an inline
  helper's boot-time registration, and a native control reproduced that.
  Address-taking, strings, `asm`, token pasting and directives inside a
  definition all count as uses.
- **Whitespace/comments** (`whitespace/`): accepted only when token kinds and
  spellings, logical gaps, and physical line/column of every token are equal.
  Comparing tokens alone is unsound because of stringification and macros that
  expand to `__LINE__`. Comment context inside macro definitions and
  directive-ending lines is handled.
- **Renames:** consistent identifier substitutions and prototype parameter
  names, using Tree-sitter C plus reference checks outside the changed files.
  Exports, meaningful strings, `__func__`, and observed macro hazards are kept.
  Function-body local/parameter renames are lossy only.
- **Diagnostic wording:** wording changes in standalone `pr_*`, `dev_*` and
  `printk` calls. The `pr_debug`, `dev_dbg` and `pr_cont` families, format
  specifier changes, argument changes, and custom `pr_fmt` or logger overrides
  are kept.
- **Reorders** (lossy only): adjacent independent static leaf helpers, and
  adjacent `switch` arms that each `return` immediately. Compiled controls
  showed that reorders change observable function and return addresses, which
  is why they moved behind the lossy flag.
- **Constant branches:** numeric preprocessor conditions only. Files over 256
  eligible sources pass through untouched.
- **Source file modes:** regular Git file modes are required on both sides.
  This fixed a symlink false-pruning case.

### Compiler-backed stages
- **Target preprocessing** (`preprocessing.py`): uses the real parent/child
  sources and recorded compile commands to compare expanded tokens and
  semantic pragmas. It covers redundant includes, equivalent guards and unused
  macro changes. Each revision may overlay at most 256 files / 8 MiB; build
  description changes need a new context. A 130-unit native control
  recompiled only the one dirty unit, and a warm cache rerun did zero
  extractions.
- **Policy gates** (`policy_*.py`, `policy_clang_worker.cpp`): checks a
  pinned binary SELinux policy plus the raw installed seccomp BPF, resolves
  ARM64 native and compat syscall slots from compiler facts, and requires
  universal denial. It follows denied entries into closed static helpers and
  keeps changes with emission effects, such as inline helpers that register
  boot callbacks. Cross-TU LTO emission is unsupported.
  - Real result: original commit `fde591dad109` is excluded in **direct-app**
    scope (about 57 s). The service-inclusive control keeps it.
- **Seccomp capture:** the exact app seccomp filter was captured from a live
  Cuttlefish 6.6.46 instance with a native ptrace observer.
  `PTRACE_SECCOMP_GET_FILTER` is unavailable there because
  `CONFIG_CHECKPOINT_RESTORE=n`.

### Measured results (honest summary)
These are small. None is a whole-pipeline pruning rate.

| Experiment | Result |
| --- | --- |
| Whitespace, 515 comment candidates, strict | 0 removed by default once the raw-input veto applies. Earlier pre-veto numbers were 172. |
| Same, `--unresolved-inputs-lossy` | 175 removed (0.66% of 26,670); 394 with line-number lossy as well (1.48%) |
| Source rename/reorder, 85 candidates | 7 removed by default, 11 in lossy mode |
| Diagnostic wording | 11 predicted / 108 broad candidates (0.04%) |
| Constant branches, full 26,670 | +1 whole removal, and it needs line-lossy |
| Unused definitions, 7-original replay | 0 additional removals |
| Policy gate | 1 confirmed direct-app exclusion |
| `likely`/`unlikely` census | 20 candidates (0.075%); no filter shipped |
| Reference build (upstream 6.6.46, kcmp) | Object differs in 12/34 sections, so 0 removals |

Manual 100-commit sample (2026-11-06) of what still survives:

| Category | Share |
| --- | ---: |
| Retain (no exclusion found) | 45% |
| Strong direct-entry policy candidates | 15% |
| Absent hardware / resources / CPU features | 10% |
| Small semantic/dataflow cleanups | 8% |
| Unused header definitions/declarations | 6–7% |
| Includes / preprocessing / declaration cleanup | 6% |
| Conditional service/resource policy | 5% |
| Renames, reorders, file moves | 3% |
| Boot/setup lifecycle | 1% |

The takeaway: source-level equivalence rules are close to exhausted. The
remaining volume is in **policy reachability**, **hardware absence**, and
**configuration absence**.

### Tests and state (verified 2026-11-10)
- `uv run --with pytest python -m pytest tests`: 1494 passed, 3 skipped. The
  skipped tests need env vars, for example `KPATCH_TEST_SEPOLICY`.
- `uv run mypy src/kpatch`: clean. Running `uv run mypy kpatch` from the
  workspace root used to crash on frozen copies inside `benchmarks/`. Those
  copies are now deleted.
- Source changes are committed through `8910b51`. The matching test changes
  (16 modified and about 50 new files under `tests/`) were **not committed** by
  the previous agent.

## Future work (rough priority)

1. **Configuration-absence yield.** Reassessing a 500-original Jan 2025 sample
   left 268/500 (53.6%) as whole-commit candidates under the config model. The
   blockers:
   - The 500-original config replay never finishes. It hits a 465 s limit in
     history preparation across 251 independent roots. Facts need to be reused
     across roots, and prepared decisions published earlier.
   - `modeled_inclusion()` returns a mode or `None`, and
     `KbuildDirectory._read_optional()` merges "absent" with "git failed". A
     typed membership result with failure provenance is needed before
     absence can be trusted more.
2. **Policy reachability beyond direct-app scope.** Add a service/broker
   mediation model, delegated FDs, callbacks, workers and timers, with a
   three-way result: excluded, reachable or unknown. Cache TU facts and
   function summaries per source/build/profile, and validate incremental
   results against full recomputation. Clang summaries or Infer are the
   preferred backends; SVF/PhASAR only if indirect calls require them.
3. **Hardware/resource inventory** (~10% of the sample). Build device, driver
   and feature presence from the live target, and handle hotplug and lifecycle.
   Absence in one snapshot is not enough.
4. **Header-use tracking** (~6–7%). Track uses of changed header definitions
   in active compilation units, including type and layout dependencies. Today
   any inclusion counts as use.
5. **Local semantic equivalence** (~8%). SSA/use-def, aliasing, constant and
   range reasoning for small cleanups.
6. **`likely`/`unlikely` filter.** Compare parsed operator trees (erasing
   tokens is unsound; a counterexample is in the old notes), allow only
   Boolean-use contexts, and resolve annotation bindings and position effects.
7. **Lossy-mode error bounds.** None of the lossy assumptions (input roles,
   line numbers, reorders/addresses) has a measured false-removal rate.
8. **UX:** each stage owns its own Rich progress bar. A shared display with
   explicit preparation tasks would be clearer.
9. **Boot/setup exclusions:** stay conservative. Init-time state can affect
   later app behavior.

## Kept artifacts

- `benchmarks/filter_pipeline.py`: tracked benchmark harness (see README).
- `benchmarks/ast_pruning/`: `verify.py` is imported by
  `tests/test_source_pruning.py`; the README links to its `REPORT.md` files.
- `benchmarks/seccomp_capture/2026-11-07/live/`: captured Cuttlefish 6.6.46
  `sepolicy`, app seccomp BPF (`attempt3-fork-flags/pid5750-install1.bpf`),
  `profile.json`, kernel config and manifest. Recreating these requires a live
  device. `profile.json` uses absolute paths into this directory.
- `benchmarks/policy_reachability/2026-10-25/`: the original 100-commit sample,
  manual assessments, and the challenge-6 `live/sepolicy`.

`benchmarks/` is gitignored apart from `filter_pipeline.py`, so these copies
exist only locally.
