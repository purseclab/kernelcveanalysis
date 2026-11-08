# Future pruning work

## Configured build, unused definitions and compiler filtering — 2026-11-08

These changes extend existing filters. Configured-build exclusion and
preprocessing checks were already present; the former had become effectively
diagnostic-only, and the latter did not provide general expanded-input
equivalence across affected compilation units.

| Filter | Current behavior | Remaining scope |
| --- | --- | --- |
| Configured build | Normal configuration runs exclude regular source/header/assembly changes absent from the modeled build on both revisions. Literal includes, forced headers, observed raw consumers and supplied vendor inputs preserve positive membership. | The model assumes ordinary kernel build rules; it does not infer target hardware or exhaust arbitrary external build scripts. |
| Target preprocessing | A separate compiler stage compares expanded tokens and semantic pragmas for every affected recorded consumer, using real parent/child sources. Redundant includes, equivalent guards and unused macro changes can qualify. | Needs a prepared compiler context and complete commands for modeled live consumers. Build-epoch changes, unsupported overlays and failed compilation retain changes. |
| Unused definitions | The Tree-sitter/reference stage now covers global functions/prototypes, typedefs, unions and complete enum groups, in addition to its existing definitions. References in configured-out consumers can be disregarded under the build model. | This is zero-reference pruning, not general interprocedural dead-code elimination. Exports, callbacks, escaping names and actual preprocessing effects remain relevant. |
| Policy gates | Compiler proofs can follow denied syscall entries into closed static helpers. Target-specific callback compatibility and ARM64 assembly classification avoid treating every unrelated callback or instruction as an unknown entry. | Direct app scope remains separate from service-mediated reachability. Unsupported calls, real address escapes and incomplete facts retain changes. |

Cosmetic BTF/debug metadata is outside the selected relevance scope. It no
longer provides a blanket veto on runtime policy exclusion or ordinary
identifier/prototype-name equivalence. Structure layout, expanded values,
semantic pragmas, registrations and real compiler/preprocessing effects remain
relevant.

Positive vendor/module inputs can be supplied through `--build-inputs FILE`.
Each entry records a repository-relative source path, `y`/`m` mode and origin.
Entries add consumers; an omitted entry never proves absence. The same inputs
reach configuration, source-reference and target-preprocessing analysis.
`--config-observations` remains an explicit diagnostic-only mode.

The new compiler stage is independent of a policy profile:
`--preprocess-build-context FILE --preprocess-report JSONL`, with optional
`--preprocess-cache FILE`. Its dependency index bootstraps the recorded build
once and updates affected units from revision deltas. A native 130-unit control
indexes 130 baseline units, recompiles one dirty unit and compares that one
consumer. A fresh run using its persistent cache performs zero new compiler
extractions and records 131 cache hits. This demonstrates incremental behavior;
it is not a kernel-population yield measurement. See
[target preprocessing](TARGET_PREPROCESSING.md) for cache budgets and limits.

The real original `fde591dad109` policy candidate is excluded in **direct app**
scope using the captured Android app seccomp filter and a prepared historical
source/compiler context. The service-inclusive control remains a candidate and
publishes no masks. This finding uses the explicit unresolved-input assumption
and its audit; it does not claim exact identity with the distributed Android
kernel binary. One successful candidate does not establish a population rate.
The final compiler-worker refresh takes 56.55 s in direct-app scope and 19.46 s
for the retained service-inclusive control. It reuses recorded full raw-input
observations after rechecking their 178 source coordinates; it is not a cold
inventory timing. Results and frozen identities are saved in
`benchmarks/policy_runtime_recovery/2026-11-08/final-emission-complete/`.

Runtime exclusion also checks positive compilation effects in the transitive
helper closure. Native controls demonstrate that an inline helper can emit a
boot-time callback even when its syscall never runs; adding its call or changing
its controlling constant must retain the patch. The final worker inventories
header helpers as well as the main source, preserving those registrations while
accepting local type/debug changes and ordinary local alternative-patch records.
Cross-translation-unit LTO emission remains unsupported.

All **1,480 tests pass**, including the captured binary SELinux policy. Mypy
passes all 71 Python files, and all 72 Python/C++ package sources match the
built wheel. The complete test run records unchanged source/test hashes.
Verification artifacts are in
`benchmarks/runtime_relevance_checkpoint/2026-11-08/final/`.

Historical sample percentages below remain opportunity estimates, not new
automatic pruning rates. Large configuration and unused-definition replays are
reported only after their complete original-patch runs finish; preparation
timeouts provide no exclusion count.

Large configuration and unused-definition replays remain incomplete. The
seven-original strict source replay retains all seven; its lossy profiles have
no completed gain measurement. The 500-original configuration replay has not
finished preparation, so its zero published decisions are not a zero-removal
result. Include-hint transport is the remaining measured performance problem:
whole-line output exceeded 1 GB; matched fragments reduce payload but still
produce millions of repeated path/line records. These checkpoint results do
not establish a new population pruning percentage.

## Previous whitespace checkpoint — 2026-11-08

The current 515-original whitespace replay removes **zero whole commits without
the explicit input-role assumption**, including in line-number mode. Recognized
raw consumers and unresolved input roles retain changes by default. With
`--unresolved-inputs-lossy` and its mandatory report, strict lines remove **175**;
also enabling the audited line-number assumption removes **394**. These are
**0.66% / 1.48% of the original 26,670 legacy survivors**, not additional
whole-pipeline rates. Neither assumption has a measured false-removal bound.

The latest precision change proves lexical macro-definition comment context,
adding **6 / 15 whole removals** over `51d0aad` without new flags or assumptions.
It preserves directive-ending lines, token gaps/columns and observed consumer
barriers. All **1,362 tests** pass, mypy checks 68 Python sources, and 69 packaged
Python/C++ sources match the wheel. See
[the latest results](#macro-definition-comment-precision--2026-11-08),
[the preceding directive repair](#directive-ending-lines-and-multiline-comments--2026-11-08)
and [the assumption contract](SOURCE_INPUT_ROLE_ASSUMPTIONS.md).

The supplied local Linux tree now also supports an isolated upstream 6.6.46
reference build. One calibrated parent/child object experiment completes, but
changes machine code and establishes **zero new removals**. A separate likelihood
annotation census finds 20 syntactic candidates, also unpruned. See
[the reference experiment](#local-reference-build-and-differential-compilation--2026-11-08)
and [the annotation inventory](#boolean-likelihood-annotations--2026-11-08).

The following checkpoint and later experiment sections preserve historical
results from their own implementations; their default counts are superseded by
the current raw-input guard and must not be added to the current totals.

## Historical checkpoint — 2026-11-07

All source reorders now require the explicit source-lossy option and an audit
callback. Compiled public-pipeline controls show that unchanged code can observe
changed function or return addresses after a reorder. Those risks are now
recorded; default filtering retains reorders. See
[the code-address repair](#source-reordering-and-code-address-observations--2026-11-07).

Normal configuration filtering now skips advisory Kbuild preparation while
input closure is unknown. The exact 500-original replay preserves every patch
and mask with no preparation/source reads. Advisory collection is explicit
through `--config-observations`; live vendor modules demonstrate why the base
config cannot authorize exclusions. See
[the configuration and device checkpoint](#configuration-observations-and-live-module-closure--2026-11-07).

Numeric branch folding is available separately through
`--source-pruning --constant-branches`. A complete 26,670-original replay adds
**one whole removal and one partial file**, both requiring the explicit
line-number assumption; it adds no strict whole removals. Its measured cost is
material, so existing source-pruning runs keep their original stage set.
Source-mode checks also fix a compiled symlink false-pruning case. See
[the implementation and measurements](#numeric-preprocessor-branches-and-source-file-modes--2026-11-07).

The separate **`--whitespace-line-numbers-lossy`** option now removes **381 of
515 complete original comment candidates**, compared with **172 by default**:
**209 additional commits, or 0.784 percentage points of the 26,670 legacy
survivors**. It requires `--whitespace-report` and preserves token spellings,
gaps and byte columns while explicitly assuming changed line observations are
irrelevant. This can remove runtime-relevant changes; the error rate is not
bounded by these measurements. The default stays strict. See
[the lossy checkpoint](#audited-line-number-assumption-and-lexer-performance--2026-11-07).

The whitespace stage now requires complete token, logical-gap and physical
location equivalence. A replay of **515 comment candidates** selected from all
26,670 original legacy patches removes **172 whole commits (0.645%)** and
partially prunes 13 more. An independent audit replays every whole acceptance
from original patches/blobs and checks all 199 files using a separate coordinate
calculation. This is a stage result, not a regenerated whole-pipeline rate or
an additional gain over the previous implementation.

The previous rule removed 418 in the same pool. The stronger rule retains
246 whose equivalence is unproved; this does not mean every one changes runtime
behavior. Compiler controls demonstrate why token equality alone is insufficient.
See [the whitespace checkpoint](#whitespace-layout-proof-and-complete-comment-seed-replay--2026-11-07)
and [the implemented contract](WHITESPACE_PRUNING.md).

The preceding complete **85-candidate original-patch replay** removes seven by
default and eleven in explicit lossy mode. Lazy complete-file macro evidence
adds the hrtimer return-case reorder `3c3af563b317`; the prior accepted set was
seven/ten. This is one additional commit, or **0.00375% of the 26,670 legacy
survivors**, with the existing incomplete-macro assumptions still audited. It
does not establish an 8% automatic gain or a whole-pipeline pruning rate.

Stronger reference-context checks retain compiled tracked-code counterexamples
and run before expensive macro-position queries. The same 85-candidate replay
then uses 49 global macro scans rather than 111; observed lossy time falls from
1,044.21 s to 478.59 s with identical accepted IDs. These are sequential shared-host
measurements, not a controlled end-to-end speedup claim. See the
[latest implementation and measurements](#lazy-complete-file-evidence-and-closed-reference-checks--2026-11-07).

**1,249 full-suite tests pass**, including the captured binary SELinux policy.
Mypy passes all 65 Python files, and all 66 Python/C++ package sources match
the final wheel.
The preceding replay of the eleven previously accepted source candidates preserves
exactly seven default and eleven lossy accepted IDs. The other 74 previously
rejected structural candidates were not replayed for this lexer change.
The earlier v8 [transport repair](#reference-transport-repair--resumed-2026-11-07)
and its 76 overlapping independent scenarios remain verified.

The unused-macro retry completes eleven raw-reference absence checks, but the
production dead-code filter retains all eight tested cases. The
[inventory and remaining guards](#unused-macro-inventory-retry--2026-11-07)
separate those candidates from accepted removals. Earlier estimates and frozen
benchmarks below describe their own snapshots. Full build/input closure remains
unknown; untracked forced inputs and raw-data consumers remain model limits.

## Implementation status

`filter config --source-pruning` now enables experimental Tree-sitter rename
comparison and a lazy revision-specific reference index. Source pruning remains
opt-in. It covers consistent renames and changes confined to eligible
definitions without found active uses. Normal configuration exclusions are
active again. Separate opt-in compiler stages handle expanded-input equivalence
and narrow capability/SELinux/seccomp gates. General reordering, type/layout
dependencies, target hardware detection and broader interprocedural policy
reachability remain future work. Narrow same-file static-helper and immediate
return-case reorder rules require the audited source-lossy mode.

The [masking update](FILTER_MASKING.md) preserves original patch coordinates,
distinguishes ignored edits from excluded code, and runs dead-code pruning
before whitespace cleanup and rename analysis. It also supports bounded
partial pruning of unused functions. The final comparison now accepts adjacent,
unchanged independent static leaf helper reorders after these masks apply.
Unused-definition guards also distinguish actual assembly from harmless `asm`
text in include paths/comments/strings. See
[UNUSED_CODE_AND_REORDER_PRUNING.md](UNUSED_CODE_AND_REORDER_PRUNING.md) for limits
and the measured recheck; the historical tables below remain unchanged.

The [diagnostic-string update](DIAGNOSTIC_STRING_PRUNING.md) adds a narrow
logging-wording policy to the final comparison stage, including renames that
also update a diagnostic label. Formats, debug selectors, trace interfaces,
and strings used by program logic remain significant. This policy exemption
does not change the historical estimates below.

The historical table records the original manual sample and its then-current pipeline;
its percentages are candidate estimates, not measured automatic pruning rates.
See [the implementation and benchmark report](benchmarks/ast_pruning/2026-10-25/REPORT.md)
for the new rules, measured yield, costs, and source-analysis limitations.

## Latest sample recheck — 2026-11-06

A new random-order recheck using seed `20261106` needed 105 draws from the
26,670-commit legacy cohort to obtain 100 survivors of the current source
stages. File/config selection was inherited from the saved database; raw patches
and fresh masks were used for ifdef, unused-definition, whitespace, rename,
and diagnostic filtering. This was not a population-wide Kbuild rerun.

| Remaining category | Approximate share |
| --- | ---: |
| Retain: no additional exclusion established | **45%** |
| Binding-aware rename | 1% |
| Independent reorders / file moves | 2% |
| Small semantic/dataflow cleanups | 8% |
| Includes / preprocessing / declaration cleanup | 6% |
| Unused header definitions / declarations | 6% |
| Unused definitions spanning C and headers | 1% |
| Absent hardware / resources / CPU features | 10% |
| Strong direct-entry policy candidates | 15% |
| Conditional service/resource candidates | 5% |
| Boot/setup lifecycle candidate | 1% |
| **Total** | **100%** |

That is **24% source/build candidates**, **25% hardware/direct-entry policy
candidates**, and **6% more conditional/lifecycle candidates**. These are proof
targets, not demonstrated automatic removals. No residual comment-only or
wording-only commits were found in this sample, and no separately established
source-only unused-definition commit was found; exported new UART helpers were
retained despite lacking in-tree callers.

The five full removals before review were four comment changes and one epoll
type rename. Three retained commits also received partial dead-code masks.
The review found conservative guard gaps, including raw `asm` matches against
include paths/comments and unsupported generated declarations or enum members.
The six candidate headers are already below 64 KiB, so raising the size limit
alone would not resolve them. The mixed C/header case additionally needs
non-static global-function analysis beyond the existing size limit.

See [the complete recheck](PRUNING_SAMPLE_REVIEW_2026_11_06.md) for per-category
definitions, concrete commits, scope and uncertainties, and the frozen evidence.
The retain estimate has an approximate 95% sampling interval of 36–55%; manual
classification and target-model uncertainty are additional. The changed seed
and expanded semantic-cleanup categories prevent treating the historical and
new tables as a controlled before/after population comparison.

## Original scope and estimates — 2026-10-25

These estimates come from a random sample of 100 commits that survived the
existing filter pipeline, drawn from 26,670 commits in
`db/filtered_after_2025.sqlite`, with seed `20261025`. The target is an Android
untrusted app, with supporting observations from the challenge 6 Cuttlefish
environment. They describe this sample of surviving commits, not all kernel
commits or every Android device.

The categories below are mutually exclusive: each sampled commit is assigned
once. Counts are manual assessments of opportunities for further analysis, not
proofs that an automatic filter can safely remove every candidate. A commit can
be removed only when all changes remaining after filtering qualify for removal.

| Category | Count / approximate share | What would justify pruning | Why the current pipeline retains it |
| --- | ---: | --- | --- |
| Predominantly renames | 5 / 5% | Definitions and all effective references change names while preserving relevant behavior and interfaces. Examples include workqueue functions, DRM helpers, and BPF enum constants. | Identifier tokens change; there is no symbol-aware equivalence comparison. Some examples also change exported names or trace strings and need additional qualification. |
| Reorders | 3 / 3% | Moving independent switch cases, includes, or module declarations preserves behavior for the target build. | Token order changes; the filter does not establish independence. Include order and declaration order can matter. |
| Missing hardware, resources, or unsupported features | 6 / 6% | Every path to the changed behavior requires a device, resource, or feature absent throughout the target scenario. | Enabled configuration does not establish device presence or feature support. No device inventory is incorporated; some absence claims still need stronger evidence. |
| Unused header definitions | 5 / 5% | A changed helper, macro, or type has no effective use in the configured build, including through layout or generated metadata. | Enabled files include the header. The filter tracks inclusion, not uses of each changed definition. |
| Unused definitions in source files | 0 separately established / 0% | A changed definition has no live callers, references, registrations, or other observable effects. | Definition-level use analysis is absent, but this sample did not establish a separate source-only example. |
| Boot/setup-only changes | 2 / 2% | The change cannot affect the post-boot target, including through persistent state created during initialization or later reprobe. | There is no lifecycle/state analysis. These candidates are particularly speculative because initialization often governs runtime behavior. |
| Comments/documentation only | 3 / 3% | Complete parent/child token streams are equivalent. | The previous whitespace filter lost block-comment context at hunk boundaries. This is now fixed; existing databases need regeneration. |
| Strong direct policy candidates | 10 / 10% | All relevant paths from the app cross a denying seccomp, SELinux, capability, or ownership check. | No policy-aware reachability stage exists. Current evidence supports direct-app candidates, not complete proofs covering all paths. |
| Conditional policy candidates | 10 / 10% | Further analysis excludes service-mediated access, shared helpers, existing resources, and asynchronous paths. | A denied privileged entry point does not establish that all changed behavior is inaccessible. |
| Remaining changes to retain | 56 / 56% | No adequate exclusion was established. These include ordinary file, memory, networking, and shared subsystem behavior. | Retention is appropriate with the available evidence. This does not imply that these commits are vulnerabilities. |

The candidate pool is approximately 32% excluding boot/setup-only cases, or 34%
including them, with another 10% conditional on substantially more analysis.
Those totals include the 3% comment-only slice already addressed by the fix.
They are investigation targets, not demonstrated safe pruning rates. Broader
behavior-preserving refactors were not exhaustively counted.

Source evidence: [sample](benchmarks/policy_reachability/2026-10-25/sample.json),
[original assessments](benchmarks/policy_reachability/2026-10-25/analysis.json),
and [report](benchmarks/policy_reachability/2026-10-25/report.html). This table
regroups the original assessments: in particular, sample 85 is counted under
renames rather than conditional policy filtering.

## Header uses and dead code

The header cases are not simply headers included only by disabled source files.
Enabled files can include a header without using its changed definitions:

```text
br.c                 [enabled]  -> includes br_private.h
br_vlan_options.c    [disabled] -> uses the new helper in br_private.h
```

The header survives inclusion-based filtering even though the new helper's
consumer is disabled. A header included exclusively by disabled files should
already be removed when the existing filter resolves its inclusion paths.

The five sampled header candidates comprise:

- Three disabled-consumer candidates: bridge VLAN, RDMA, and MPLS
  (samples 39, 53, and 65).
- One inline CAN helper with no call sites found in either revision
  (sample 12).
- One FSL fallback macro whose active uses still require verification
  (sample 42).

Dead code can reside in a header or a source file. Configuring out every caller
is one cause; having no callers in any configuration is another. Searches for a
function name alone do not prove absence of callbacks, macro-generated uses, or
assembly references. A field can matter through `sizeof`, offsets, copying, or
metadata even without a direct field access.

## AST comparison for renames and independent ordering

A constrained AST comparison is a practical first approach to the approximately
8% rename/reorder candidate pool. It can recognize structural equivalence
without solving arbitrary program equivalence. The 8% is an opportunity estimate,
not an established yield: five predominantly rename commits and three reorder
commits were identified, but their safety conditions differ.

The rename candidates are samples 56, 76, 85, 86, and 99. The reorder candidates
are samples 5, 14, and 96. Sample 64, titled as an LSM rename/rework, also changes
logic and must not be classified as a pure rename from its title.

An initial implementation could:

1. Parse parent and child sources, match corresponding definitions, and propose
   consistent symbol mappings from otherwise matching ASTs. Use bindings and
   scopes rather than replacing arbitrary identifier text.
2. Accept renames only when definitions, declarations, references, types, values,
   and relevant attributes match under that mapping. Check unchanged consumers
   outside the diff too; a comparison of changed files alone is insufficient.
3. Preserve expression and statement order by default. Initially allow only
   narrow reorder patterns, such as distinct constant switch labels with
   terminating branches and identical bodies. Do not sort arbitrary AST children.
4. Compare preprocessed forms for include reorders and macro-sensitive cases,
   using the target build's flags and include paths. Retain cases that cannot be
   resolved reliably. A syntax tree of raw source alone does not capture macro
   expansion or build-specific semantics.
5. Emit the matched symbols or reorder rule as an explanation. Retain a commit
   if any remaining change lacks an accepted equivalence rule.

Renaming can affect `__func__`, stringification, assembly labels, exported
symbols, tracing, BTF/debug names, or external consumers. Sample 99 also changes a
trace label string; sample 56 renames exported DRM symbols. Such cases need an
explicit definition of relevant behavior and interface scope, or must be retained.
Similarly, moving module declarations or includes needs checks for macro state,
conditional compilation, and position-dependent expansion.

For performance, cache parsed forms by blob identity, inspect changed definitions
first, and reuse the include/use index. Invalidate dependent results when headers,
macros, configuration, or build flags change. Reserve preprocessing or deeper
binding analysis for plausible equivalence candidates. Validate the initial rules
against these eight samples and counterexamples with actual behavior changes
before measuring a larger independent sample.

## Other future work

- Build a target hardware/resource inventory, including driver bindings and
  supported features. Distinguish permanently absent resources from devices that
  can appear through hotplug or change state. The six sampled candidates are
  2, 21, 41, 61, 66, and 83.
- Track uses of changed header definitions in active compilation units, including
  indirect type/layout dependencies, rather than treating inclusion as use.
- Add policy-aware reachability that accounts for service mediation, resource
  provenance, callbacks, and asynchronous execution. A syscall or capability
  check on one path is insufficient to reject shared downstream code.
- Keep boot/setup exclusions conservative: samples 26 and 82 require proving
  that initialization effects cannot influence the target scenario.

## Dataflow and policy-reachability research — 2026-11-06

Recommendation after reviewing build costs: use a **Clang summary worker** as
the primary prototype for many commits, and benchmark Infer's compilation-
database capture as the packaged alternative. Use CodeQL for selected reference
checks when a suitable extraction exists. Keep Tree-sitter for cheap candidate
selection and source mapping. Dataflow is needed to evaluate check
arguments, credentials and objects; control flow establishes whether a changed
statement actually requires authorization. A list of security functions crossed
on a path cannot establish unreachability.

This research inspected the local kernel at
`f47d223627f80cb7a1eb14c585fe6cb35de5e984`, the frozen reviewed 100 commits,
their relevant historical sources, and current primary tool documentation.
It did not run a whole-kernel dataflow analysis or implement a policy filter.
The Android evidence is the archived 2026-10-25 challenge6 capture, not a new
live measurement. The historical tables above remain unchanged.

### Library comparison and incremental updates

| Tool | Fit for this project | Updating as commits change | Main limitation |
| --- | --- | --- | --- |
| **CodeQL C/C++** | Useful reference prototype when extraction exists: source locations, CFG, global dataflow and `GuardCondition.controls(block, outcome)`. Existing `../object_db/src/object_db/codeql.py` and query pack already integrate CodeQL with kernel types/allocations. | Current C/C++ overlay support exists, but **only for no-build extraction; traced builds are unsupported**. Diff-informed alert reporting is a different optimization. | Need faithful target build extraction and custom kernel/policy/callback models. No-path query results alone are not an unreachability proof. |
| **Clang CFG / dataflow / Static Analyzer** | Good substrate for a focused compiler-backed checker: accurate preprocessing, AST, CFG and source mapping; path-sensitive/CTU facilities are available in the Static Analyzer. | Recompile dependent translation units and maintain our own summaries, call graph and invalidation. | Not an existing incremental whole-kernel policy engine. Exploration limits must produce unknown. |
| **SVF** | Strong specialist candidate for pointer/alias analysis, indirect-call targets and sparse value-flow over LLVM IR; official Python bindings exist. | Mainline documentation does not establish a turnkey deletion-safe Git-diff update workflow. | Requires LLVM IR and kernel models. Current Python binding installation docs list Python 3.8–3.12, while kpatch requires 3.13+: a separate worker or verified newer build would be needed. |
| **PhASAR** | Suitable for a custom interprocedural analysis propagating a finite abstract policy state, using IFDS/IDE and alias/call-graph infrastructure. | Incremental research exists; no turnkey upstream commit-maintenance workflow was established in this review. | LLVM IR plus substantial domain/model work; precision of paths and aliases remains analysis-dependent. |
| **Infer** | Strong candidate when captured-build incrementality is the deciding factor. Uses per-function analysis and summaries. | Official workflow documents reactive capture, marking unchanged sources, and incremental analysis from a changed-files index. | Building this particular policy checker and its kernel models remains substantial work; ordinary issue reports are not reachability certificates. |
| **Joern** | Useful for interactive candidate exploration: CPG, CFG/control-dependence and dataflow traversals; C frontend can accept build/preprocessing inputs. | No documented production incremental C graph-maintenance workflow was established here. | Parser recovery, missing semantics and callback targets must be accounted for; absence of a taint path cannot certify absence of execution paths. |
| **Smatch** | Kernel-oriented flow analysis and custom checks, with a cross-function database; useful for extracting narrow guard summaries. | Selected files can be analyzed against stored facts, but safe dependency/deletion invalidation needs engineering. | No ready-made whole-kernel Android authorization-reachability proof. |

Primary references: [CodeQL guards](https://codeql.github.com/docs/codeql-language-guides/using-the-guards-library-in-cpp/),
[CodeQL incremental CLI](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/incremental-analysis),
[Clang dataflow](https://clang.llvm.org/docs/DataFlowAnalysisIntro.html),
[Clang Static Analyzer](https://clang.llvm.org/docs/ClangStaticAnalyzer.html),
[SVF](https://github.com/SVF-tools/SVF),
[SVF Python requirements](https://github.com/SVF-tools/SVF-Python),
[PhASAR](https://github.com/secure-software-engineering/phasar),
[Infer incremental workflow](https://fbinfer.com/docs/steps-for-ci/),
[Joern C frontend](https://github.com/joernio/joern/blob/master/joern-cli/frontends/c2cpg/README.md),
[Joern semantics](https://docs.joern.io/dataflow-semantics/), and
[kernel testing/static-analysis guide](https://docs.kernel.org/dev-tools/testing-overview.html).
These sources describe mechanisms, not demonstrated kernel-pruning performance.

The installed CodeQL CLI is **2.24.3**; current documentation requires at least
2.25.0 for C/C++ overlays. Upgrading would still leave the no-build restriction.
The existing object_db query pack also explicitly disables overlay evaluation.
Therefore the first experiment should prioritize correct captured builds rather
than assume cheap overlays preserve the target kernel's preprocessing.

[IncSFS (August 2026)](https://arxiv.org/abs/2608.24391) is relevant research on
incremental flow-sensitive pointer analysis with insertions and deletions. Its
evaluation on six projects does not establish maintained upstream SVF support,
kernel-scale costs or a ready policy checker. It is a research option to evaluate
after a correctness baseline, rather than the initial dependency.

### What the kernel checks actually mean

| Concrete pattern in the inspected source | Required analysis |
| --- | --- |
| `kernel/capability.c`: `security_capable(...) == 0` becomes boolean success in `ns_capable_common`; `capable()` uses `init_user_ns`. | Understand return conventions and the successful branch, plus the capability namespace. |
| `file_ns_capable()` checks `file->f_cred`, not necessarily current task credentials. | Track saved opener credentials and file provenance. |
| `fs/inode.c`: `inode_owner_or_capable()` accepts matching `current_fsuid()` **or** mapped `CAP_FOWNER`. | Zero app capabilities do not deny operations on app-owned objects; include FSUID, groups, idmaps and namespace mappings. |
| `io_uring_allowed()` combines disabled sysctl, capability, group and LSM alternatives. | Evaluate the boolean condition and runtime policy facts, not just whether a check occurs. |
| `security_bpf(cmd, ...)` precedes command dispatch; other BPF operations and internal loaders have different paths. | Track command and user/kernel pointer origin. Program-load denial does not exclude runtime execution of already installed programs. |
| `rtnetlink_rcv_msg()` exempts GET kinds from the administrative capability check. | An accessible route-netlink socket and a denied configuration operation can coexist. |
| `security_inode_permission()` has success paths; SELinux decisions depend on subject/object labels, class and permissions. | A `security_*` call is not inherently a denial. Resolve operation/object state and wrapper behavior. |
| `fs/ioctl.c` invokes LSM checks then a `file_operations` callback. | Resolve FD → object → operations, ioctl command and compat ABI. |
| `fs/file.c` and `drivers/android/binder.c` check FD transfer separately; SELinux has receive/use/object checks. | An inability to open a device does not prove an inherited or delegated FD impossible. |
| Workqueues/timers invoke stored function pointers; io_uring can override credentials before issuing work. | Add callback/event edges, resource origins and execution-context summaries. |

The relevant source areas are `kernel/capability.c`, `fs/inode.c`,
`io_uring/io_uring.c`, `kernel/bpf/syscall.c`, `net/core/rtnetlink.c`,
`security/security.c`, `security/selinux/hooks.c`, `fs/ioctl.c`, `fs/file.c`,
`drivers/android/binder.c`, `kernel/workqueue.c` and `kernel/time/timer.c`.
Use the recorded revision when reproducing locations. Supporting primary docs:
[kernel credentials](https://docs.kernel.org/security/credentials.html),
[seccomp semantics](https://docs.kernel.org/userspace-api/seccomp_filter.html), and
[Android app sandbox](https://source.android.com/docs/security/app-sandbox).

For example, in `if (!capable(CAP_SYS_ADMIN)) return -EPERM; changed();`, the
changed call needs capability success. Changes to the check itself, statements
before it, or its failure/cleanup path can still execute and must be retained.
Every alternate caller must also be covered. Check **both parent and child**:
a patch can add the denial precisely because the old version permitted access.

### Sample-based opportunity estimate

All percentages below use the same frozen original 100 reviewed survivors,
before the newest reorder rule removed sample 22. The current denominator is
99, but mixing denominators would obscure comparison with earlier estimates.
These are manually inspected proof targets, **not measured safe removals**.

| Policy family | Primary pool | Additional overlap | Main unresolved proof |
| --- | ---: | ---: | --- |
| io_uring | 5% | 2% | Universal syscall denial, existing rings, SQPOLL, worker/teardown callbacks, service-created resources and layout users. |
| BPF verification/attach | 4% | — | Command-specific SELinux denial, internal loaders, service loading and attachment/program-FD paths. |
| Administrative network/cgroup controls | 2% | — | All control paths and privileged service mediation. |
| Tracing/debugfs controls | 2% | — | Exact file labels/permissions; trace-marker access is not access to all tracing controls. |
| Bluetooth ISO | 1% | — | Socket creation versus delegated sockets or service paths. |
| KVM virtual-GIC | 1% | — | Device/VM provenance, existing guests and virtualization services. |
| **Direct-policy candidate union** | **15%** | **up to 2% more** | **0 proven automatic policy removals so far.** |

The extra two io_uring commits are samples 84 (`dd120bddc43a`, constant
extraction) and 92 (`4e9fda29d66b`, local alias cleanup). The exclusive review
places them in the 8% local-equivalence category. They must not be counted twice
when combining source-equivalence and policy estimates.

Read-only historical source checks distinguish the nine headline io_uring/BPF
candidates more precisely:

| Sample / commit | Changed code | Prototype priority / missing closure |
| --- | --- | --- |
| 14 / `f4e72ad7c161` | Verifier map-field/kfunc/timer checks. | Simpler verifier-load slice; include internal loading and service roots. |
| 49 / `dfb2d4c64b82` | Verifier liveness/state-cache handling. | Simpler verifier-load slice. |
| 60 / `0f6bd5e7a804` | Verifier helpers plus `btf_prepare_func_args` and `bpf_fixup_call_args`. | Searches at that revision find those two helpers' callers in verifier code; shared files alone do not establish shared runtime use. Verify complete closure. |
| 15 / `21bd7b14a32d` | `io_query*`; callers in register dispatch, including fd=-1 blind query. | Simpler syscall-root slice once denial of `io_uring_register` is established universally. |
| 43 / `7d5d94fe9af1` | Lock moves between structs in `zcrx.h`. | Needs type/layout consumers and resource closure; no changed function to trace. |
| 44 / `e1d499590977` | Ring-vector/read-write/cache cleanup. | SQPOLL submission and destruction callbacks. |
| 63 / `2a61e63891ad` | Read/write prep/import helpers. | Function pointers in operation tables, including SQPOLL routes. |
| 80 / `3afcb3b2e3a4` | Request completion. | Worker → issue → completion route. |
| 69 / `bd06659d3b8a` | BTF sleepability/attach-target checks. | Syscall and trampoline/cgroup attachment callers beyond load verification. |

Thus **four of the 100 are the initial simpler proof targets**, with five more
headline candidates requiring richer models. Four is a prioritization count,
not an achieved 4% yield. Other direct-policy samples are 3, 67, 87, 89, 94, 95.

Do not discard all BPF code: sample 8 (`427a36bb5504`) runs on ordinary socket
activity, 35 (`69ab34f705fb`) processes traffic with installed flow dissectors,
56 (`bb2243f4328b`) concerns map cleanup, and 77 (`403e935f9158`) concerns storage
unlink during normal lifetimes. Likewise administrative MGLRU or filesystem
configuration can affect subsequent ordinary reclaim/I/O (samples 99 and 72).

### What remains beyond policy dataflow

| Further mechanism | Original-100 candidate share | Additional machinery |
| --- | ---: | --- |
| Hardware/resource/CPU-feature absence | 10% | Device/driver/feature inventory plus hotplug and resource-lifetime assumptions. Absence in one snapshot is insufficient. |
| Conditional services/resources | 5% | Broker/service model, FunctionFS/ublk/namespace/bridge/eventfs resource lifecycle. |
| Initialization/lifecycle | 1% | State-dependence proof: boot-created registrations/globals can affect later app execution. |
| Local semantic equivalence | 8% | SSA/use-def, alias stability, constant/range/side-effect reasoning; two overlap the additional ring policy candidates. |
| Unused header/C definitions | 7% | Compiled consumers, bindings, generated names, enum/type/layout dependencies and exports. |
| Include/preprocessor/declaration cleanup | 6% | Target preprocessing and build/declaration validity. |
| Binding-aware rename / remaining file move | 2% after latest reorder | Symbol identity, linkage, static state and translation-unit semantics. |

The last four rows are the **23 remaining source/build candidates** after the
one reorder removal. They are not all solved by an entry-point analysis.
The 10% hardware pool is separate from the 15% primary policy pool; the 5% and
1% rows need stronger scenario assumptions. None should be advertised as
confirmed pruning or added to overlapping policy/source percentages.

### Required evidence and a bounded implementation strategy

The saved challenge6 manifest records Android 14 / Linux 6.1.23, enforcing
`untrusted_app`, UID 10109, all capability sets zero, and user namespaces
unconfigured. io_uring probes received SIGSYS and BPF load/map probes EACCES.
TCP, Unix, route-netlink and DRM render access remained usable; perf reached
argument validation. These distinguish direct denials from broad subsystem
exclusions.

**The raw seccomp program was not exported**: `PTRACE_SECCOMP_GET_FILTER`
returned EINVAL with `CONFIG_CHECKPOINT_RESTORE=n`. Selected syscall probes do
not establish a universal decision over ABI/number/arguments. Recover the exact
matching generated filter/build source or another faithful export before
certifying exclusions. The saved compiled SELinux policy and query outputs are
reusable evidence. Some sampled commits postdate the captured kernel, so this
is a policy-profile estimate, not a claim of binary/commit applicability.

SELinux input can be the **compiled binary policy exported by the running
kernel**, normally `/sys/fs/selinux/policy`; AOSP documents obtaining it with
`adb pull` in its [SELinux implementation guide](https://source.android.com/docs/security/features/selinux/implement).
The analyzer should accept that binary directly and query it offline with
SETtools/libsepol, without requiring the policy sources or recompiling policy.
Cache parsed rules and query results by policy hash and evaluator version for
reuse across commits. Record runtime enforcing/permissive and conditional state
alongside the subject/object contexts needed for a decision. A changed policy
invalidates policy-dependent exclusions while leaving compatible compiler facts
reusable. The existing challenge6 archive already contains such a binary
(`live/sepolicy`) and offline query output.

Start with a small target-profile file recording kernel/config/architecture,
ABI support, policy/filter hashes, subject domain/categories, credentials and
namespaces, sysctls, and allowed inherited/delegated/service-created resources.
Missing facts should remain explicit unknowns. No generic UID-only deny rule
can stand in for that profile.

1. Build actual parent/child sources for the selected target, retaining source
   mappings and extraction diagnostics. Masks select remaining changes; do not
   construct a fictional kernel by compiling only the remaining diff or remove
   call edges merely because their edits were ignored.
2. Query backward from changed statements/definitions to relevant entries and
   callers, then propagate policy facts through that slice. Begin with the four
   simpler targets, not a full forward traversal from every possible kernel root.
3. Model exact check outcomes and branch control, constant commands, credential
   source/namespace and object permissions. Keep a three-way result: proven
   excluded, possibly reachable, or unknown. No missing graph edge, timeout,
   parser failure or exhausted search is proof of exclusion.
4. Cover compatible syscalls, file/socket/ioctl/netlink operations, indirect
   tables, callbacks, workers and timers. For app-triggered analysis include
   privileged services, delegated resources and network/event-mediated work;
   keep background/init state unless its influence is also excluded.
5. Remove a whole commit only when every remaining change is excluded on both
   sides, including layout/constants/registration effects. Keep reachable check,
   pre-check and error-path changes. Store proof paths/cut conditions, profile
   fingerprints and unresolved-root counts alongside mask provenance.
6. Cache translation-unit facts and function summaries by source/build/profile
   dependencies. Re-extract affected includes/macros/flags, recompute changed
   call-graph components and propagate changed summaries to callers. Callback
   registrations, deleted edges, policy reloads and header/layout changes can
   invalidate results in unchanged functions. Use actual Git deltas, not only
   the surviving filtered files. Periodically refresh the full baseline.
7. Validate incremental results against full recomputation on a bounded corpus,
   including alternate callers, owner-or-capability alternatives, saved creds,
   namespace changes, delegated FDs, async work and patches that modify checks.
   A dynamic trace can disprove a claimed exclusion; lack of trace coverage
   cannot prove unreachability.

Collect and inspect guard/caller evidence before automatically discarding
commits. Promote individual narrow rules only after their entry/resource closure
and both-revision proof passes. The many-commit investigation below favors
Clang summaries or Infer capture over repeatedly constructing traced CodeQL
databases. Add SVF/PhASAR when unresolved indirect calls and richer policy
propagation justify that cost. The current Tree-sitter pipeline can remain the
cheap first pass; this would be a separate expensive analysis layer.

## Many-commit compiler analysis: design and local probes — 2026-11-06

The practical shortlist is **a small C++ Clang LibTooling worker orchestrated by
Python**, or **Infer with compilation-database capture**. Both can analyze
prepared translation units without generating object code or linking a new
kernel for every commit. Both still require accurate generated headers,
configuration, architecture and compiler inputs. Neither currently supplies our
complete Android policy checker.

### What each backend would actually do

| Backend | Baseline | Ordinary source change | Work we still own |
| --- | --- | --- | --- |
| Clang worker | Prepare configured inputs, parse enabled TUs, store calls/registrations/guards/type dependencies and compact summaries. | Reparse dirty TUs, reusing valid preambles; replace their facts and propagate changed summaries. | Compiler-backed guard/callback extraction, completeness tracking, persistent reverse dependencies, summary solver, policy evaluator and invalidation. |
| Infer | Capture a real compilation database into Infer IR and analyze a baseline. | Syntax-only recapture of affected TUs, followed by incremental summary invalidation/analysis. | A custom policy checker and kernel models, dependency expansion, epoch management and proof/coverage validation. |
| Smatch | Prepare kernel and build its cross-function database. | Stock single-file checker runs Kbuild for that object against the existing DB. | Stronger guard semantics and a safe incremental fact store; stock missing facts cannot certify absence of paths. |

Clang's [compilation database](https://clang.llvm.org/docs/JSONCompilationDatabase.html)
records enough input to run tools on individual source files independently of
the build. [LibTooling](https://clang.llvm.org/docs/LibTooling.html) provides
custom frontend actions and the C++ AST/CFG interfaces. A production worker
should emit compact typed facts, not huge full-AST JSON dumps. The libclang C
API used in the timing probe below demonstrates frontend/preamble costs; it
does not expose everything needed for the proposed CFG-based worker.

Infer's version-pinned
[compilation-database implementation](https://github.com/meta/infer/blob/v1.3.0/infer/src/integration/CaptureCompilationDatabase.ml)
replaces the compiler with its Clang wrapper, adds syntax-only capture, and
selects TU sources from the changed-files set. Its
[incremental dependency code](https://github.com/meta/infer/blob/v1.3.0/infer/src/backend/AnalysisDependencyGraph.ml)
invalidates dependent callers/types and deleted procedures after capture is
refreshed. It also scans stored summary dependencies to reconstruct the reverse
graph: a tiny change does not guarantee constant total analysis overhead.
Neither Infer nor Smatch is installed here; no runtime comparison with them was
performed.

A possible Infer pilot after target preparation is:

```console
infer capture --compilation-database compile_commands.json
infer analyze

infer capture --reactive --mark-if-unchanged \
  --changed-files-index affected-tus.txt \
  --compilation-database compile_commands.json
infer analyze --incremental-analysis --changed-files-index affected-tus.txt
```

The changed-files index must contain the affected **TU source paths**, not just
the filenames printed by Git. A header-only diff can otherwise select no C
consumers. Whole-file deletion, changed enabled-TU membership and custom checker
dependencies need explicit tests. The
[official CI workflow](https://fbinfer.com/docs/steps-for-ci/) documents the
reactive/incremental flags; this proposed kernel invocation has not been run.

Smatch is useful for kernel conventions, but its current
[capability checker](https://github.com/error27/smatch/blob/master/check_capable.c)
records check occurrences/capability numbers without establishing successful
branches or the namespace object. Its database build also
[drops some very common function-pointer relationships](https://github.com/error27/smatch/blob/master/smatch_data/db/delete_too_common_fn_ptr.sh).
The [full-check script](https://github.com/error27/smatch/blob/master/smatch_scripts/test_kernel.sh)
cleans and builds the kernel, while
[DB creation](https://github.com/error27/smatch/blob/master/smatch_data/db/create_db.sh)
recreates the database. Stock scripts also use `--succeed`; a zero exit status
does not establish complete extraction. Therefore stock Smatch is not a cheap,
complete incremental negative-reachability oracle.

### Existing build machinery and required preparation

A reusable example exists at
`/home/jack/.local/share/kexploit/synthesis/6.6.50_x86/compile_commands.json`:
3,544 commands, including 3,476 C and 68 assembly entries, with an existing
configured output directory and generated headers. It is an **x86_64/GCC
6.6.50 context**, not the Android arm64 target. The JSON source paths have been
remapped; some underlying `.cmd` dependency paths still use `/src` and require
normalization.

`make prepare` does less than a full build but still builds host tools and
target generators. It does not necessarily generate every subsystem-specific
source/header. `modules_prepare` also omits `Module.symvers`, as explained in
the [kernel documentation](https://docs.kernel.org/kbuild/modules.html).

Do not assume `make compile_commands.json` is a preparation-only shortcut: in
the inspected kernel its dependencies include `vmlinux.a`, kernel libraries and
`modules.order`. Calling `scripts/clang-tools/gen_compile_commands.py` directly
can reuse existing `.cmd` files, but only for commands actually recorded. Missing
records do not prove a TU is disabled. A new configuration or build-system
transition may need a refreshed baseline or an unknown result.

### Measured frontend and preamble costs

I ran bounded local probes with Clang/libclang **21.1.8** on three files from
that prepared x86 context. Original GCC commands fail directly in Clang. For
this feasibility experiment only, six incompatible GCC driver switches were
removed explicitly; production needs validated target commands. No kernel
sources were edited on disk and no object/kernel build was performed.

Fresh standalone `clang -fsyntax-only` processes succeeded for all three files,
taking 1.38–1.63 seconds for capability/ioctl and 2.44–2.54 seconds for BPF
syscall. Then a separate libclang experiment retained one TU at a time, enabled
precompiled preambles and kept function bodies. Each TU received four in-memory
body edits, alternating a return literal, followed by one included-header edit.
The header edit only added a comment; it tested cache invalidation.

| TU | Included files | Initial parse + preamble | Median body reparse, 4 runs | Included-header reparse |
| --- | ---: | ---: | ---: | ---: |
| `kernel/capability.c` | 637 | 1.961 s | **0.051 s** | 1.811 s |
| `fs/ioctl.c` | 658 | 1.952 s | **0.065 s** | 2.026 s |
| `kernel/bpf/syscall.c` | 821 | 3.373 s | **0.238 s** | 3.386 s |

All initial parses and reparses returned success with no error/fatal diagnostics.
Warnings remain in the standalone logs. This is a **three-file microbenchmark**,
not a measured policy analysis, custom-summary extraction, memory bound or
throughput forecast. The adapted GCC/Clang context is not validated compiler
equivalence or the Android profile. The experiment supports using validated
preamble reuse; it does not justify extrapolating 51 ms across all commits.
OS caches were not flushed: initial parse means a newly created TU/preamble,
not a cold filesystem measurement.
Clang's [preamble documentation](https://clang.llvm.org/docs/PCHInternals.html)
and [libclang API](https://clang.llvm.org/doxygen/group__CINDEX__TRANSLATION__UNIT.html)
describe this reuse. Reparse is still of a TU's main-file contents, not arbitrary
isolated function reparsing.

Evidence and replay scripts are under
`benchmarks/policy_dataflow_performance/2026-11-06/` (the existing ignored
benchmark-artifact area): `clang-frontend-probe.json`, `preamble-probe.json`,
`history-workload.json`, and the corresponding probe scripts.

### Real history limits the warm-cache benefit

Read-only database inspection found 330,676 raw commits, 358,424 parent records
and 26,909 merges. The configured legacy cohort has 26,670 non-merge survivors;
only 15,874 (59.5%) have their direct parent in that cohort. The other 40.5%
require a parent snapshot outside the filtered selection. Processing only
retained patches would miss real intermediate changes.

The first 500 survivors by committer time, starting in January 2025, show:

| Workload measure from original raw patches | Result |
| --- | ---: |
| Commits touching C / headers / build metadata | 458 / 206 / 5, overlapping |
| C-file path touches / distinct C paths | 765 / 485 |
| Repeated C-path touches, ignoring all invalidation | 36.6% |
| Optimistic path-only LRU reuse, 32 slots | 29.2% |
| Direct parent equals previous chronological survivor | 94 / 500 |

The path-LRU figures are **not observed preamble hit rates**. They ignore every
header/config/command/dependency change, DAG divergence and skipped raw commits.
They illustrate cross-commit locality only. A first-touch parent can still share
its preamble with its own child when the change is in the body; that within-pair
benefit is separate. Existing parent summaries can also avoid reparsing the
parent at all.

In the independent reviewed 100, original patches have a median one file and
12 changed lines, but 39 touch headers. Three original build changes disappear
from the selected patch views. Therefore a reduced diff cannot be the source of
cache invalidation. Small edit size alone does not imply a cheap update.

### Proposed history engine

1. **Prepare a baseline per compatible build context.** Pin architecture, resolved
   configuration, compiler, generated files and compile commands. Extract the
   configured TUs once, tracking missing/unsupported units as unknown. A release
   tag locates a baseline; it is not a sufficient cache key.
2. **Keep compact facts on disk.** Record preprocessing dependencies, local guard
   outcomes, calls, registrations, credential effects, type/layout/global uses,
   and extraction coverage. Store per-function summaries plus a persistent
   reverse-dependency graph. Avoid keeping all kernel ASTs resident.
3. **Use the complete Git delta.** Select a real parent/ancestor snapshot, including
   cumulative changes through skipped commits. Replace removed facts atomically;
   do not copy a complete database for every commit. Use a small worktree pool or
   a validated Git-backed VFS snapshot to avoid full-tree checkout costs.
4. **Classify invalidation before scheduling work.** A source-body edit usually
   dirties one TU. Headers dirty their consumer TUs; common headers may dirty many.
   Include additions/deletions, failed header lookups and include-path shadowing
   also matter. Kbuild/Kconfig, generated inputs or compiler changes refresh the
   affected build context or invalidate the epoch conservatively.
5. **Reparse with bounded workers and preamble caches.** Start with a small worker
   pool and measured memory limits. Keep a bounded hot-TU/preamble cache; evaluate
   disk preamble reuse rather than assuming every first-touch TU is warm. Do not
   reuse stale preambles for proof-oriented analysis.
6. **Reuse semantic summaries, not source text alone.** A header can change a
   function's types, bindings or macros without changing its body. Start with
   TU-level invalidation; refine only with validated semantic dependencies.
   Recompute affected call-graph components and propagate changed summaries to
   callers. Pointer registrations and new/deleted edges can affect unchanged
   functions.
7. **Separate parsing from policy evaluation.** Reuse compiler facts across policy
   changes; key exclusions additionally by UID/namespace/SELinux/seccomp profile
   and model versions. Query backward from remaining changed sites. Summaries
   must retain branch alternatives and credential effects, not just sets of
   capability-check names.
8. **Budget expensive work explicitly.** Cheap stages can eliminate commits before
   a policy query. Raw-delta ingestion/invalidation still applies even to commits
   that do not receive a policy query. Defer expensive dirty TUs only while
   marking dependent results unknown; never silently preserve an old exclusion.
   A dirty/unresolved callback caller cannot disappear from the modeled graph.

This targets cost proportional to the **affected translation units and summary
dependencies**, not to changed line count. Common headers, configuration changes
and broad callback/layout changes can legitimately approach baseline costs.
If a correctness-preserving update exceeds budget, retain the commit and refresh
at a checkpoint. That trades pruning coverage for bounded runtime.

### Next performance experiment and decision criteria

Use 200 real commits under one compatible target build context, plus explicit
header/config/deletion/registration stress cases. Compare full required-TU
recomputation against cached TU facts, valid preambles and summary propagation.
Measure preparation/baseline separately from per-commit median/p95/p99, CPU,
process-tree memory, invalidated/parsed TUs, dependency fanout, cache hits,
unknown results and proven exclusions. Include cold caches and branch changes.
Every stress case and periodic ordinary commits should match a full recomputation.
At the research stage, no end-to-end many-commit policy benchmark had been run.
The bounded prototype coverage audit below does not replace that experiment.

Benchmark Infer's compilation-database capture on the same prepared subset,
including its global dependency-scan overhead, before investing in a larger
custom solver. Smatch can supply modeling ideas/positive facts, but its pruned
database and full-rebuild scripts are a poor default for this proof-oriented
history pass. Clang's new
[Scalable Static Analysis summary framework](https://clang.llvm.org/docs/ScalableStaticAnalysis/user-docs/SummaryExtraction.html)
is worth watching; its docs warn that it is rapidly evolving, so this proposal
does not assume it is a mature ready-made backend.

## Compiler-backed policy prototype

Implemented an opt-in `PolicyFilter` after the existing stages. The compiler
backend is Clang LibTooling/CFG, rather than Tree-sitter or a custom C parser.
Tree-sitter remains the backend for the existing source-pruning stages. Binary
SELinux policy is sufficient input: AOSP policy sources are not required.

The prototype compares both actual Git revisions. It never reconstructs a
compiler input by applying only the diff left by earlier filters. Previous code
masks can exempt source ranges from comparison; edit masks do not erase facts
from the compiler's input. It publishes policy edit masks only when every
remaining changed file qualifies. There is no partial-file policy removal yet.

Clang supplies necessary branch outcomes, early-return/short-circuit/goto
handling, simple assigned check results, and unmodified parameter constants
from switch cases. Modeled gates are `capable`, `ns_capable`/`ns_capable_noaudit`
for a proven global initial namespace, `security_bpf` for map creation/program
loading, and `security_perf_event_open`. Perf signatures with or without the
older attribute argument are supported. Unknown APIs, namespaces, saved
credentials and ownership/UID comparisons do not become barriers.

Entry context is limited to physically spelled syscall macro bodies. Unknown
callers, address escapes, indirect calls, credential effects, arbitrary memory
writes, assembly and linker-visible declarations retain changes. Static helper
closure is currently restricted to isolated contexts with exactly one tracked
code translation unit; a partial kernel compilation database never proves
whole-kernel caller closure. Included-header callers also prevent closure.
These restrictions deliberately sacrifice coverage. This is a versioned model
of normal Linux API contracts, not a formal proof for arbitrary C programs or
future API implementations. Contract-source/build-system changes require a new
prepared checkpoint.

Raw tokens outside proven runtime exclusions must match, and fresh preprocessing
fingerprints must match on both revisions. Macro definitions/undefinitions,
expansion inputs, pragmas, `__COUNTER__` and `__LINE__` effects are checked; an
unreachable runtime expression cannot hide a compile-time change elsewhere.
Headers, layouts, declarations, binary/mode changes and unresolved extraction
remain unknown. A cheap entry/gate spelling check skips compiler work for files
outside this modeled subset; that check can only retain additional commits.

The binary-policy evaluator expands type attributes and all conditional allow
branches, and ignores constraints conservatively. It reports a denial only in
enforcing mode for a known nonpermissive subject, known class/permissions and
no possible allow. Unknown object types are tested against all possible target
types. Individual alternative operations must each be denied; unrelated
permissions are not incorrectly combined into an impossible single request.
Policy capabilities are checked, including the BPF token-policy change.

The target profile pins the binary hash, runtime enforcement, subject context,
UID/groups, capability bits, architecture and optional seccomp evidence.
**Seccomp mode alone never proves a syscall denial.** The schema can retain
universal-denial evidence tied to a filter hash, but syscall-number/ABI/filter
analysis is not connected to pruning yet. UID/ownership and resource labels
also need richer value flow.

The default `app_with_services` scope records direct-app candidates and retains
them until mediation is explicitly modeled completely. `--direct-app` selects
a narrower synchronous direct-app analysis and can remove proven changes in
that scope. Neither a Binder permission list nor absence of a direct syscall
path proves that privileged services or asynchronous kernel workers cannot
reach changed code. Do not interpret direct-app counts as complete Android
attack-surface exclusions.

### Inputs, caching and commands

Install matching Clang/LLVM development headers, `libclang-cpp`, `llvm-config`
and a C++ compiler. The worker builds once into the user cache. Optional
`KPATCH_LLVM_CONFIG` and `KPATCH_CLANG_INCLUDE` select development installations.
The worker frontend must exactly match the recorded compiler version. GCC
commands are not made acceptable by stripping incompatible flags.

Prepare a clean kernel source checkout and an out-of-tree build once, using the
target architecture/configuration and Clang. Capture genuine compiler commands
from the prepared build. Calling the kernel's `compile_commands.json` target
may build much more than preparation; reuse recorded `.cmd` files with
`scripts/clang-tools/gen_compile_commands.py` where available. A partial database
is supported, but missing commands mean unknown, not disabled code.

Keep build context JSON, reports and caches outside the frozen source and build
roots. Commands require `-nostdinc` and explicit include/search roots under the
frozen checkout/build or immutable `/nix/store`. Mutable external SDK roots,
implicit include environment variables, response-file options and hidden
frontend include overrides are rejected. General SDK support needs a pinned
include-root snapshot, including failed/shadowed lookups.
Forced includes require absolute text-header paths; explicit and automatically
discovered precompiled headers are rejected.

```sh
uv run kpatch policy build-context \
  --source-root /path/to/clean/linux --build-root /path/to/prepared-output \
  --compile-commands /path/to/compile_commands.json \
  --config /path/to/prepared-output/.config --output /path/to/audit/build.json

uv run kpatch policy inspect /path/to/sepolicy \
  --subject untrusted_app --class bpf --permission prog_load --enforcing

uv run kpatch policy analyze --repo /path/to/linux \
  --commit COMMIT_OR_RANGE --limit 100 --profile /path/to/profile.json \
  --build-context /path/to/audit/build.json --cache /path/to/audit/cache.sqlite \
  --output /path/to/audit/results.json
```

`policy inspect/analyze` use SETools' Python bindings. If those bindings belong
to a different Python environment, pass `--setools-python /path/to/python`
and repeat `--setools-module-path /path/to/site-packages` as needed. Unavailable
or incompatible SETools yields unknown facts. Add `--direct-app` only when that
restricted scope is intended. `policy analyze` is a bounded audit and does not
rewrite the source or filtered commit database. It reports removals by preceding
merge/whitespace stages separately from policy decisions.

For the existing database filtering command, append `--policy-profile FILE
--policy-build-context FILE --policy-report JSONL` to `filter config`; optional
`--policy-cache FILE` and `--policy-direct-app` have the same meanings. Omitting
the policy options preserves the existing pipeline.

TU facts are cached persistently with worker/model/build identities, complete
preprocessing dependencies and their target-revision blob hashes. The worker
keeps at most two TUs/preambles; in-process fact/snapshot caches and the SQLite
TU cache are bounded. Header dependencies invalidate reuse. Configuration,
compiler, generated-input, build membership or source-checkout changes invalidate
the context. Added/deleted paths, build/contract epoch changes and broad history
deltas return unknown rather than reusing stale edges. Current budgets are
256 overlaid paths / 8 MiB per snapshot and 1 MiB per policy-compared source.
The source/build must remain frozen during use; this is not a transactional
filesystem snapshot.
Incomplete results have a separate bounded diagnostic cache keyed by the exact
revision and compiler/build identity. Such entries can only retain commits,
and never certify an exclusion. Clear this cache to retry transient failures.
Fresh full parsing is retried once when compiler preambles report errors;
errors are not suppressed, and a successful fallback disables that TU's
preamble optimization.

### Challenge 7.1 validation

A fresh owned `challenge7.1.2.a` Cuttlefish instance supplied the binary from
`/sys/fs/selinux/policy`, runtime enforcing state and an actual `untrusted_app`
process profile. The clean binary SHA-256 is
`20d30ebb684a5eb3667e7fae5a475e8be023ff11787b7f59172694257d1a7604`.
The device runs ARM64 Linux 6.6.46 with Android 15 SDK metadata. Its app had zero
effective/permitted/bounding capabilities and seccomp mode 2. Exact seccomp
rules could not be exported, so no syscall denials were inferred.

The evaluator confirmed absent `bpf:prog_load` and `bpf:map_create` allows,
while retaining allowed TCP and permissive-domain cases. Real-binary tests feed
that denial into compiler/Git fixtures; positive tests and adversarial retention
cases check both the policy and CFG stages. Cold evaluation of eight queries
over two subjects took 2.14 s; a new evaluator reusing SQLite took 0.337 s;
10,000 in-memory permission-cache hits took 0.022 s. These are permission-query
measurements, not commit-analysis throughput.

Artifacts are under `benchmarks/policy_dataflow/2026-11-06/` (gitignored), with
device commands, hashes, raw observations, policy queries, prepared ARM64 build
commands and audit reports. Initial Frida instrumentation changed the live
policy automatically; that policy was quarantined. The owned instance was
restarted and the original clean policy hash verified before primary evidence
was recaptured. Only the clean binary is used by the test profile.

General multi-TU summaries, callback/async/resource and broker closure, exact
seccomp analysis, UID/ownership value flow and broader Linux hook contracts
remain future work. The earlier 15–17% manual policy candidate estimate is not
an achieved removal rate.

The frozen 100-commit sample was replayed from the original Git patches plus
the saved mask ledger. Its input/output patch hashes matched exactly: **0
additional policy removals, 100 retained as unknown**, in 5.81 s. The partial
three-TU ARM64 context lacked commands for all five source requests that passed
the entry/gate prefilter; other files were headers/unsupported effects or
outside the modeled entry subset. There were no Clang extractions or policy
queries in that audit. This measures conservative coverage handling, not
dataflow throughput or a representative pruning yield. Expanding build coverage
and compatible historical checkpoints is necessary before measuring a useful
real-commit exclusion percentage. The owned challenge instance was stopped after
the final loaded policy hash check; no other instance was touched.

The real ARM64 probe built three objects successfully using recorded commands.
With the final worker, reboot extraction took about 5 s; BPF took about 21.5 s
and returned 231 functions after the full-parse fallback. Both remained unknown
because file-scope assembly is not modeled. Perf exceeded the response-size
bound and also remained unknown. These full CFG measurements are substantially
slower than the earlier syntax/preamble feasibility probe; they are not a
demonstration of fast whole-kernel policy pruning. Narrower extraction, modeled
kernel assembly metadata, and more precise effect summaries are necessary
before broad deployment.
With the diagnostic cache, repeated requests for all three incomplete TUs took
2.12 s from memory or disk, versus 48.17 s cold, including input validation.
These cached entries remain unknown. Validation passed 677 tests with the
captured real binary enabled, plus the final targeted context regressions;
mypy and wheel inclusion of the C++ worker were also checked.

## Source-pruning correctness and binding work

The next iteration is measured against raw commits with Kbuild rerun first.
Legacy filtered patches are discovery material, not evidence that discarded
sources are disabled. Reviewer agents found and reproduced several reasons to
require this distinction:

- Generated header prerequisites could replace an object's implicit `.c`
  source in the Kbuild dependency model. In a real ARM64 revision, this wrongly
  excluded enabled KVM code. Header prerequisites now preserve that source;
  explicit object-to-object/source selection still follows its actual rules.
- Reference scans, bootstrap and incremental deltas excluded `.inc`, `.txt`
  and arbitrary include fragments. The reference vocabulary is now all tracked
  text, with cache version 5. An incomplete include graph cannot bound an
  absence search. The independent spelling verifier uses the same complete
  vocabulary but performs its own searches.
- Three-part token pasting can assemble a live helper or global variable while
  defeating prefix/suffix spelling guards. Literal forward and reverse include
  environments are checked before source-only absence/global-rename proofs.
  Opaque expansions, computed/spliced includes, missing/generated inputs and
  budgets retain candidates. This closes compiled counterexamples where the
  old filter discarded a change although program results changed.
- A macro definition's Tree-sitter end position may include the next physical
  newline. Definition coverage now ends on its actual last token line, avoiding
  accidental inclusion of an adjacent unchanged macro in a changed group.
- Compiler-evaluated location builtins need more than token comparison.
  Whitespace/ifdef/source filters retain these cases conservatively, and the
  compiler fingerprint models supported location effects and rejects unknown
  pragma/source-location cases.

The new binding comparison is a general lexical-scope analysis rather than a
patch-name whitelist. The optional binding mode can ignore parameter declarator names
in ordinary C prototypes, including nested callback prototypes. Complete
source tokens must otherwise match. Dependent bounds, typedef captures,
attributes, duplicate declarations, reserved identifiers and conflicting
tracked macro definitions remain observable. Reserved identifiers include BTF
kfunc annotation spellings such as `buffer__sz`; these are not cosmetic names.
The declared equivalence policy ignores ordinary prototype debug/BTF names,
but preserves implementation-reserved name contracts. These comparisons are
lossy until their complete preprocessing inputs are pinned: a reviewer compiled
an example where tracked `-Dold=arg[2]` turns `int old` into an array parameter,
so changing that name changes the function type. Known literal compiler macro
definitions now block removal. Unmodeled generated/dynamic flags remain an
explicit risk; prototype-name erasure is consequently disabled by default too.

Function-body parameters and automatic variables use the same explicitly
lossy mode. It resolves parameter, block and `for` scopes, tracks initializers
after their declarators, and keeps fields, global/external symbols and types
unchanged. Known macro stringification, pasting and free-name captures retain
the commit. Unknown forced/generated macro bindings, compiler metadata and
debug-name effects are not a complete equivalence proof, so these decisions
remain labeled lossy rather than promoted to the default mode.

```sh
uv run kpatch filter --repo linux --db all_commits --dest source_conservative \
  config --config kernel.config --source-pruning \
  --source-pruning-report /path/to/conservative-decisions.jsonl

uv run kpatch filter --repo linux --db all_commits --dest source_lossy \
  config --config kernel.config --source-pruning --source-pruning-lossy \
  --source-pruning-report /path/to/lossy-decisions.jsonl
```

The lossy flag requires the source-pruning flag and an audit report. Reports
include the rule, affected symbols, masks, `lossy` boolean and risk reasons.
This is permission to evaluate that tradeoff, not a claim of an established
corpus-wide false-removal rate. Known reachable counterexamples remain regression
tests, including in lossy mode. Do not infer a risk rate from zero observed
errors in a small inspected cohort.

The first independently inspected new real removal candidate is
`ab017a15fdb2222002cdc6bdf86699fb21a0721a`, which only changes three declaration
parameter names in `include/linux/device.h`. A separate audit erased exactly
those three names from the complete original blobs and obtained equal
preprocessing tokens. Other callback names/types and all remaining source
tokens were unchanged. This is concrete new coverage; the old global name
mapping rejected it because `dev` also names other parameters. Earlier exploratory
reports classified this as strict; the compiler-flag counterexample supersedes
that classification. Current conservative filtering retains it, and the optional
lossy mode is evaluated separately. The raw-source identity audit still applies,
but is not a complete preprocessing-context proof.

Further useful classes remain: macro-aware use/dependency indexing that avoids
both suffix collisions and hidden pasted uses; unreachable-definition SCCs;
declaration dependency graphs for reorders; complete compiled-TU coverage;
kernel initcall/BTF registration and effect summaries; and device inventory
with explicit hotplug/resource assumptions. Those need measured real removals
and independent reachability audits before being counted as completed work.

### Measured binding tranche: modest gain, experimental mode stays off

The fixed chronological 500-commit cohort was reconstructed from complete raw
patches. Current Kbuild selection was recomputed over 3,047 commits of its full
date-window history, including merges, taking 62.79 s. No inherited legacy
file masks were used. All 500 cohort commits retained configured edits before
the shared ifdef/source tail.

| Mode | Commits retained | Additional removals | Source-tail time |
| --- | ---: | ---: | ---: |
| Shared baseline, new binding comparison disabled | 486 | — | 53.78 s |
| Current conservative mode | 486 | 0 | 53.63 s |
| Explicit lossy binding mode | 485 | 1 / 500 = 0.2% | 267.96 s |

The extra ID is `ab017a15fdb2222002cdc6bdf86699fb21a0721a`. Common surviving
patches were byte-identical across modes. This is a convenience cohort, not a
random estimate of whole-corpus gain or false-removal rate. The extra removal
is roughly 0.21% of the baseline survivors. Its complete-source byte audit is
independent of production normalization, but does not establish full build/ABI
equivalence. The skcipher scoped-rename candidate remains retained.

The cost is dominated by global macro-definition/dependency searches, including
formal-parameter spellings that are not actual replacement dependencies. This
small observed gain does not justify broad deployment of the lossy mode. A
bounded macro-definition/dependency index with revision updates is a cleaner
performance direction than weakening name, expansion or include checks.

Baseline/conservative execution snapshots, latest lossy snapshots and explicit
transfer checks for changes unreachable in conservative mode are saved under
`benchmarks/source_candidate_audit/2026-11-06/`. Full raw patches, recomputed
Kbuild masks, every new decision, independent audits, compiled unsafe-removal
witnesses and source/artifact hashes are retained. Earlier exploratory strict
counts are superseded by `raw500-final-summary.json`.

### Compiler-backed direction remains active

Current compiler extraction recognizes exact readonly export metadata and marks
the exported function as an unknown/address-taken caller. Aliases, assembler
labels and executable/unknown assembly remain barriers. Real reboot/BPF TUs now
identify their exports precisely; initcall and BTF registration records still
prevent complete proofs, while perf remains over a bounded response size. No
additional policy removals are claimed from this compiler work.

A separate copied prepared ARM64 build allowed a vmlinux dry run without
creating objects or changing frozen inputs. Exact printed command records
yielded thousands of planned compiler invocations, including variants and
generated-source gaps. This is promising baseline machinery, not complete
coverage: modules and late generation/link-side inputs require accounting too.

Current-source optimized-IR and object controls reproduce byte-for-byte, but
the historical maple-tree and F2FS candidates fail against current headers with
real API/type mismatches. Matching historical parent checkpoints are necessary.
This target enables BTF and module versions, so deleting all debug metadata
from a comparison would be unsafe. The next experiment must preserve ABI,
registration, BTF/type and source-location effects while proving which compiler
outputs cannot change. Unchanged output across all affected build variants
could remove more general unused-code and cleanup changes without assuming
security caller or service closure.

This is an ongoing pruning goal. The small lossy result above is a measured
milestone, not completion of the requested broader removal progress.

### Resume checks — 2026-11-07

The saved full verification completed with 739 passing tests, including the
captured binary-policy tests. Its before/after source and test hashes match.
That result precedes the further macro-parameter and build-membership work
described below; later edits need their own checks.

Matching historical source checkpoints now replace the earlier current-header
experiments for two cleanup candidates. Neither establishes compiler equivalence:

| Commit | Matching build observation | Decision |
| --- | --- | --- |
| `a2ac9935d330` (Maple Tree redundant store) | Same configuration, compile arguments and 730 dependencies; `.text` shrinks by 8 bytes and a load/GEP/store sequence disappears. | Retain: emitted code changes. |
| `d27e44310237` (F2FS pointer alias cleanup) | Same configuration, compile arguments and 781 dependencies; `.text` shrinks by 4 bytes because a pointer reload disappears. Source-line values and registration metadata also change. | Retain: emitted code changes. |

These are actual full parent/child checkouts in separate owned worktrees, with
one target object built per revision. Equal symbol CRCs or stripped debug data
would not override the changed instructions. The evidence is saved under
`benchmarks/policy_dataflow/2026-11-07/compiler-output/`; neither candidate is
counted as a new removal.

An independent comparison against real printed compiler commands also found
15 configured source inputs that the Kbuild model incorrectly marks unused.
The audit covers 3,277 tracked object commands and 3,253 distinct source paths
under the exact prepared configuration and source revision. Generated inputs
and seven additional already-built VDSO command records are separate; this
denominator is not a complete configured-kernel inventory. Correcting these
false exclusions takes priority over increasing the removal count.

The optional binding pass now separates macro formals from free replacement
identifiers. Actual argument identifiers remain dependency roots, and known
stringification/pasting remains a barrier. This avoids following a formal such
as `arg` into unrelated global macro definitions; it does not add a complete
macro expander or change the pass's lossy classification.

Independent review also compiled six cases where substitution/rescanning makes
a renamed callback spelling into a function-like macro invocation. Each changes
the program's exit value from 1 to 7. Several also fooled the previous guard.
The guard now rejects every known source/compiler macro binding of a renamed
spelling, even if it is not followed by `(` in the raw source. Direct substitution,
outer invocation boundaries, empty macro tails, standard variadics and GNU named
variadics are covered. This deliberately retains uncertain candidates rather
than counting them as a performance or removal gain.

The completed Kbuild repair restores all 15 missed object sources: 8 additive
prerequisite cases, 3 alternate source patterns, 3 direct ancestor-directory
selections and 1 temporary composite-list alias. Prerequisites no longer replace
implicit source possibilities, and composite expansion follows the actual
object-list goal context. All 3,253 audited source paths / 3,277 commands now
resolve, with zero mode mismatches or exceptions. Four additional preparation
inputs are restored too; all five audited preparation inputs and seven separate
VDSO paths resolve. This is positive coverage evidence for one exact context,
not proof that every excluded path in all historical kernels is unused.
Independent GNU Make checks and before/after source snapshots are saved under
`benchmarks/kbuild_positive_coverage/2026-11-07/`.

A new general return-arm rule was reviewed and tested: the initial adjacent switch arms
with exactly one return can be reordered while preserving every label,
expression and surrounding token. Complex arms stay in place as barriers;
tag/enumerator definitions inside return expressions are rejected because they
can bind names for later arms. A second compiled counterexample showed that
an unchanged preceding arm can fall through into a later run; only runs at the
start of the switch are now eligible. Both examples are regression tests, and
earlier verification/evaluation artifacts are preserved as superseded under
`before-fallthrough-fix/`. The rule uses `independent_return_case_reorder` edit masks in the
existing final source stage. It removes `3c3af563b317` (hrtimer) from complete
original sources under exact parent/child Kbuild selection and both macro
guards. A scan of 26,670 legacy survivor IDs found only this accepted match
among 191 case-label patches. This small result is separate from the 500-commit
cohort and is not a whole-cohort fresh configuration rerun.

The fresh 500-commit replay recomputed Kbuild over the complete 3,047-commit raw
history with the corrected parser (42.00 s). All source snapshots stayed fixed;
common surviving patches are byte-identical across modes:

| Historical mode before input-closure/name-observability hardening | Retained | Additional removals | Source-tail time |
| --- | ---: | ---: | ---: |
| Baseline: new bindings and return-arm comparison disabled | 486 | — | 56.65 s |
| Conservative: return-arm comparison enabled | 486 | 0 | 54.77 s |
| Optional lossy bindings and return-arm comparison | 485 | 1 / 500 = 0.2% | 144.80 s |

The same prototype-only commit `ab017a15fdb2` is the extra lossy removal. No
new return-arm candidate occurs in this chronological 500. The optional mode
still has a small measured gain and substantial overhead; it remains disabled
by default. These sequential passes share reference facts, so their timings
are not independent cold-throughput estimates. The complete execution and
source snapshots are under `benchmarks/source_candidate_audit/2026-11-07/`.

The compiler worker now recognizes narrow trusted readonly initcall and BTF
registration grammars, preserving every referenced function as address-taken.
Independent review passed 25 positive/negative metadata cases. Real current
ARM64 reboot and BPF TUs now extract complete inventories (59 / 231 functions,
7.30 / 27.11 s). Function-level effect/caller uncertainty remains; no new policy
removal follows from successful extraction alone. A bounded research capture
showed perf needs a 19.4 MiB response and still has five executable static-call
trampolines, so increasing the production response budget would not establish
its proof. That limit remains unchanged. The source is current mainline 7.3,
not the captured device's 6.6.46 source tree.

Historical verification of this snapshot: **780 tests pass**, including the captured
binary-policy integration, with before/after source/test hashes equal; mypy
passes all 52 Python source files. The wheel contains byte-identical copies of
all 53 Python/C++ package sources. This is further measured progress; the
broader policy/effect/dependency pruning objective remains active.

The next policy proof needs CFG effects at their program points, unique gate
occurrences, and pinned callee/provenance summaries. With user namespaces
disabled, capability denial can apply to legitimate resource user namespaces;
a pointer's type alone does not prove that invariant. A compiled synthetic
owned-child namespace bypass demonstrates the distinction. Supplying reviewed
missing premises to current reboot facts yields 25 exploratory, often nested
runtime spans, but no whole-commit removal. The concrete umount target
`e1ff7aa34dec` additionally needs a composed `may_mount` summary and declaration
effects. See `benchmarks/policy_namespace_feasibility/2026-11-07/`.

No debug-string heuristic was added. A full-original-source inventory found
only two excluded `pr_debug`/`dev_dbg` wording candidates among 26,670 IDs and
no `pr_cont` candidates. Dynamic-debug format matching can select callsites and
change argument evaluation; exact inherited compiler flags remain unpinned for
those two TUs. The small potential gain does not justify dropping the guard.
Evidence is under `benchmarks/excluded_diagnostics/2026-11-07/`.

## Input closure and observable names — resumed 2026-11-07

The earlier counts above do not describe the current implementation. Independent
compiled witnesses found reachable changes that a spelling/include-only model
could discard. Local CONFIG/MODULE/predicate overrides, comment-prefixed and
spliced directives, binary-classified source, generated external symbol names,
and macro-redefined C keywords now receive conservative handling. The reference
cache is version 6 so earlier negative entries cannot hide newly covered uses.
The conditional evaluator follows C integer semantics rather than Python's.
Logical directive normalization preserves original physical line coordinates;
an independent 132-case GCC/Clang oracle found no missing compiled declarations
after the UTF-8 BOM guard. Unsupported preprocessing remains unknown.

Raw identifier renames now require `--source-pruning-lossy` and its audit report.
Six compiled tag/member/enumerator/typedef examples change BTF names, including
through the kernel's DWARF-to-pahole route. An offline CO-RE relocation matches
the old member and finds no matching target after its rename. The captured
Android configuration enables BTF and kallsyms. The default retains these cases;
optional removals identify preprocessing and BTF/kallsyms risks. Seven compiled
behavior-changing macro/linkage examples remain retained even in lossy mode.
Private helper reorder controls still prune without enabling that mode. Evidence:
`benchmarks/source_safety/2026-11-07/review-current/`.

Kbuild membership is positive evidence, not complete build-input closure. Forced
compiler includes, assembler `.include`/`.incbin`, host generators, skipped Make
recipes and approximate expansions can introduce inputs absent from the literal
include graph. `BuildInputClosure.UNKNOWN` therefore prevents absence-based
exclusion and complete CPP-context claims. No user boolean can manufacture a
closed certificate. Fresh sample verification is kept separately under
`benchmarks/source_candidate_audit/2026-11-07/after-input-closure-and-metadata/`;
the historical tables remain preserved rather than transferred to new code.

The broader input-role problem remains open. An assembly file can embed a header
as raw data: changing its comment or text inside `#if 0` then changes an executed
program. The existing whitespace and experimental C-source equivalence policies
are not whole-build proofs for such mixed inputs. Constant-only CPP evaluation
does not solve that problem, so no incomplete-context shortcut was added. A
shared, revision-pinned consumer/role certificate is needed across whitespace,
source and policy stages; unknown or mixed roles must retain changes in a strict
mode. Do not describe the current source-reference model as universally sound.
Compiled evidence and the proposed contract are under
`benchmarks/include_reachability_audit/2026-11-07/review/`.

An actual configured ARM64 `all` build is being traced in an isolated worktree
with two jobs, bounded memory/disk/trace storage and automatic resource stops.
The pilot captures forced inputs, assembler data and failed path lookups that
ordinary compiler dependency scans miss. This is foundation work for reusable
input graphs and incremental invalidation across diffs. A partial trace or dry
run is not a pruning certificate; the full build, generator ancestry, directory
queries, negative lookups and both revisions still need validation. Git-derived
version metadata also needs an explicit equivalence policy. The current mainline
source differs from the captured live Android kernel. Artifacts are under
`benchmarks/compiler_inputs/2026-11-07/`. No new large removal percentage or
automatic policy removal is established by this work yet; the goal remains active.

The completed fresh replay uses frozen current sources and all 3,047 raw history
commits for the selected chronological 500-survivor cohort:

| Current mode | Retained | Removed from 500 | Extra versus current baseline | Source time |
| --- | ---: | ---: | ---: | ---: |
| Baseline without return-arm comparison | 486 | 14 / 2.8% | — | 47.29 s |
| Default conservative source rules | 486 | 14 / 2.8% | 0 | 47.01 s |
| Explicit lossy identifier/binding mode | 486 | 14 / 2.8% | 0 | 57.99 s |

Configuration takes 73.96 s and records no exclusion masks. The 14 removals are
13 whitespace/comment cases and one diagnostic-wording exemption. Common
surviving patches are identical across current modes. This is a selected cohort,
not a population estimate; sequential passes share reference caches. Compared
with the historical default, 369 surviving patches have restored content even
though the retained commit count is unchanged. The formerly extra lossy prototype
candidate `ab017a15fdb2` is now retained: lexical comparison recognizes its three
substitutions, but macro queries remain unknown and cannot certify them. Thus
this tranche adds **zero** sampled removals. The earlier 0.2% extra lossy result
does not apply to the current implementation.

At that frozen pre-seccomp checkpoint, verification passed all **855 tests**,
including the captured binary SELinux policy, with unchanged before/after source
and test hashes. Mypy passed all 53 Python source files, and the wheel matched
all 54 Python/C++ package sources. The complete frozen sources, raw patches, decisions, timings and checks
are in `benchmarks/source_candidate_audit/2026-11-07/after-input-closure-and-metadata/`.
The ongoing goal now needs actual new pruning evidence, not another transfer of
historical yields or a completeness claim from successful parsing alone.

## Exact seccomp capture and entry-proof review — resumed 2026-11-07

A fresh owned `challenge7.1.2.a` instance supplied the actual installed filter
from a newly forked, initially single-threaded untrusted-app process. A native
ptrace observer recorded the non-`CLONE_VM` lineage, private filter buffers,
successful installation, unchanged reread, app identity and clean detach. The
216-instruction filter has SHA-256
`612a6105e3c68563e4f0cbcde954b1a1f19f170fcc17b77c9bb83ac4bb3322ae`.
SELinux stayed enforcing with the same binary hash. The owned instance was
stopped; the capture and cleanup manifests are in
`benchmarks/seccomp_capture/2026-11-07/live/`.

Profiles can now reference the raw bytes with `seccomp.filter_file` and
`filter_sha256`; paths resolve relative to the profile and both binaries are
hash-checked. The bounded classic-BPF evaluator explores arbitrary arguments
and instruction pointers. Unsupported instructions, malformed programs and
budget exhaustion retain. Only universal terminating denials qualify; TRACE,
USER_NOTIF, LOG and ALLOW do not. Independent native classic-filter controls
check the evaluator without installing host seccomp. CLI report/cache outputs
cannot overwrite either policy input, including symlink or hardlink aliases.

Seccomp is a thread/lifecycle premise, not a property of an entire UID or
SELinux domain. `direct_app` refers to the captured filtered thread and its
inheriting descendants, or a separately established synchronized thread set.
Service-inclusive findings remain candidates even when a profile declares
SELinux mediation complete and lists only the same subject type. No process
filter equivalence follows from that list.

Compiler facts now resolve actual native and compat ARM64 dispatch arrays and
inventory body declaration effects. A genuinely prepared historical parent of
`fde591dad109` maps both ABI slots 448 to the generated wrapper, and both real
revisions have matching preprocessing outside the changed syscall body. Exact
readonly tracepoint registration assembly is modeled with strict grammar,
origin and object-reference checks; arbitrary assembly remains opaque. The
worker builder compiles an immutable captured source snapshot so a concurrent
source edit cannot miskey the binary cache.

An exploratory whole-body exclusion was **rejected** during independent review.
An allowed syscall can invoke a denied wrapper through inline assembly, an
indirect table call, or an implicit cleanup callback; ordinary direct-call AST
edges alone miss these paths. Also, changing an automatic variable to an
already defined type can change emitted BTF despite adding no tag definition.
The entry model therefore requires separate whole-TU assembly/indirect-call
coverage, preserves cleanup target references, and keeps declaration, type and
reference spans observable during pairwise comparison. A further compiled
control-dependence witness changes emitted BTF by changing only `if (0)` to
`if (1)`, with all those spellings unchanged. Source carving therefore does
not certify emitted metadata equivalence. Policy analysis now retains every
BTF-enabled candidate with `emitted_btf_equivalence_unproved` until an emitted
metadata certificate is available. This applies to capability/SELinux masks
as well as seccomp masks. Missing legacy coverage cannot certify absence.
Opaque paths retain. Existing preprocessing fingerprints also preserve
location-sensitive compiler builtins and macro events.

The exact-filter triage found 32 syscall-body range candidates among 26,670
legacy survivors (0.120%), of which eight simple-body candidates are 0.030%.
These are selected candidates, not estimated safe removals. The chronological
500-survivor sample has zero such candidates. This tranche establishes **zero
new accepted real-commit removals**; the rejected exploratory result must not be
counted. Evidence is under `benchmarks/seccomp_entry_proof/2026-11-07/`.

A possible general next step is content-cached LLVM MC analysis of emitted
objects, followed by verified KCFI target refinement. Six compiled witnesses show
that relocation absence and objdump text alone miss calls, including local
aliases, raw instruction bytes and indirect branches. The historical MM object
has 15 indirect call sites with differing local KCFI hashes from the wrapper,
but adjacency does not prove check dominance, failure behavior, all revisions
or global closure. These observations are not pruning certificates.

The full traced configured kernel build reached `vmlinux.o` and stopped at
MODPOST because the captured configuration requires a genuine
`abi_symbollist.raw` that is unavailable. Its 3,365 compiler commands, object
inputs and traces are preserved. No empty whitelist or configuration substitute
was used. The trace remains incomplete and cannot close build-input roles.

The historical MM TU illustrates the size of the remaining caller problem:
its complete global AST inventory contains 1,157 inline-assembly records
(884 opaque header records) and 55 indirect call expressions, even though the
tracked main functions have no indirect-call unknowns. Its one main-file asm
is an empty barrier. Restricting the inventory to main-file direct calls would
miss those header paths; marking extraction complete does not close them.

A bounded backend prototype compiles the genuine parent and child MM objects
through exact prepared commands and full-source VFS overlays. Parent output
matches the original prepared object byte for byte. Each compilation takes
about 3.4 seconds and 201 MiB peak RSS; detached BTF extraction takes about
0.04 seconds. Both revisions produce the same 176,698-byte object-local BTF
(SHA-256 `da4cfff5acb02363d2158f39e525e35a0e8f735c386ff6fc1cf6eb3836a53bf2`).
No source, configuration, generated input or prepared-build membership changed.
This is a promising incremental metadata check, not a whole-kernel BTF or
caller-closure certificate. The default retains the commit. Details and
compiler flag deltas are under
`benchmarks/seccomp_entry_proof/2026-11-07/emitted-metadata-prototype/`.

The final protocol uses merged, typed metadata byte intervals instead of full
nested source coordinates. The real BPF syscall TU now returns complete facts
in 14,571,867 wire bytes (13.9 MiB), below the unchanged 16 MiB limit; the earlier
representation needed 20.6 MiB. The bounded extraction takes about 20 seconds.
No large-response exception or custom compatibility decoder was added.

Review also found an existing closed-static-helper error: an untracked header
can invoke the helper through inline assembly, bypassing all guarded C callers.
The safe host witness returns 7 before and 8 after the supposedly irrelevant
change. The shared whole-TU caller audit now gates closed-static-callee proofs
as well as syscall-entry proofs. The same original witness is retained with no
masks after the repair. This does not establish general whole-kernel closure.

Final verification for this resumed checkpoint passes **963 tests**, including
real binary SELinux-policy evaluation, with unchanged before/after source and
test hashes. Mypy passes all 56 Python source files; the wheel matches all 57
Python/C++ package sources. The complete frozen sources, test logs, packaging
checks, worker identity and remaining work are saved in
`benchmarks/seccomp_entry_proof/2026-11-07/verification-current/`.
The goal remains active; passing checks and candidate counts are not new
real-commit removals.

## Partial macro facts and source positions — resumed 2026-11-07

Macro discovery now returns typed observations containing both known definitions
and uncertainty reasons. An unrelated opaque file no longer discards later
known macro bindings. Positive recovery handles unsupported directive layouts,
including embedded NUL, comments and split spellings; those inputs still do not
certify absence. A bounded content-hash cache reuses parsed definitions across
queries and revisions without caching build activity across revisions.

The existing `--source-pruning-lossy --source-pruning-report ...` mode can assume
explicitly listed source-model or budget gaps for rename/reorder comparison.
Every observed binding still passes the applicable capture, numeric-expression
and compiler-definition guards. Failed searches, unreadable files, malformed
rows and unknown uncertainty categories retain the commit. Decisions record
`incomplete_macro_discovery_assumed` and each assumed reason. This is an
assumption about missing preprocessing context, with potential runtime effects;
it is not a proof of name-only metadata differences. The option does not relax
unused-definition analysis or build/CPP input-closure requirements.

Physical line and byte-column comparisons now cover whole source files,
including unchanged code outside reordered regions and multiline/spliced macro
invocations. Known location aliases and observed macro operators that prevent
following them retain the candidate. A logger exemption applies only to exact
callee occurrences whose format arguments the diagnostic normalizer accepted.
Arguments, consumed results and other uses of the same spelling stay observable.
Independent compiled witnesses found and repaired blanket logger-name exemptions
and token-pasted location builtins, in addition to earlier LINE/COLUMN examples.
The final five saved witnesses plus ten extra controls all retain. Evidence is
in `benchmarks/lossy_yield/2026-11-07/provider-review/final-location-review/`.

Full-original-patch inventories examined all 26,670 IDs in the legacy retained
cohort, using actual parent/child Git blobs without inherited legacy masks:

| Bounded inventory | Whole-source candidates | Meaning |
| --- | ---: | --- |
| Current rename/reorder/diagnostic structural comparison | 85 / 0.319% | 23 binding, 51 raw mapping, 10 diagnostic and 1 reorder matches, before repository/macro guards. |
| Macro-only changed definitions | 154 / 0.577% | 114 have no same-file reference; cross-file consumers and generated uses remain unproved. |
| Simple unused scalar locals | 0 | 3,964 seeds, 55 complete-source comparisons; mixed/multiline shapes remain unmeasured. |
| Integer spelling / simple literal concatenation | 2 / 0.0075% | Syntax-only potential, not implemented or certified as new removals. |

These are different overlapping candidate bounds, not percentages to add. The
old roughly 8% manual opportunity estimate does not predict this architecture's
whole-commit yield. Broader helper/return-arm extensions added no accepted
removals; known macro dependencies blocked the few relaxed candidates. Local
unused-scalar controls passed 80 independent GCC/Clang compilations, but the
zero-yield scan does not justify a new production stage. Evidence is under
`benchmarks/lossy_yield/2026-11-07/`, `benchmarks/source_reorder_yield/2026-11-07/`,
`benchmarks/local_unused_yield/2026-11-07/` and `benchmarks/literal_yield/2026-11-07/`.

A build/CPP relaxation initially appeared to add four removals in the fixed
500-commit sample. Inspection rejected all four: headers had genuine includes
from configured core files in both revisions. Directive normalization and
cyclic include caching had lost those positive edges. The shared lexer and
include traversal now preserve them, with linear comment/directive tracking.
Unsupported phase-one spellings also remain unsupported in token fallbacks.
No build-absence assumption flag or removal gain was shipped. The build-input
closure remains unknown. Evidence: `benchmarks/build_yield/2026-11-07/`.

The parsing cache reduced one repeated parsing control from 16 parses to two;
real global discovery still took roughly 8–10 seconds per query. A benchmark-only
persistent macro-headline index passed 18 Git fidelity/error controls but failed
to complete real cold indexing within runtime/memory limits. No indexed speedup
or additional removals was demonstrated, so it stays out of production. A future
implementation needs bounded subprocess memory as well as incremental file/blob
updates. Evidence: `benchmarks/macro_index_performance/2026-11-07/`.

Current frozen validation passes **1,018 tests**, including real binary SELinux
policy evaluation, with unchanged source/test hashes. Mypy passes all 58 Python
source files; the wheel matches all 59 Python/C++ package sources.
`benchmarks/source_macro_assumptions/2026-11-07/verification-current/` contains
logs, hashes, package checks and frozen sources.

The completed current-production replay used fresh views of all 85 complete
original patches, with no inherited masks or assumption shim. Sources stayed
unchanged throughout:

| Current comparison mode | Whole commits removed | Time for 85 candidates |
| --- | ---: | ---: |
| Default | 8 | 49.34 s |
| Explicit lossy | 11 | 874.77 s |

Lossy mode adds three removals versus the current default: `ab017a15fdb2`
(three `device_find_child` prototype parameter names), `7f7a793d71da` and
`3a11167d918a` (two `dev_err` wording changes). Independent inspection covered
all three complete original patches. The two diagnostics were already removed
by the historical ten-removal baseline; they now require explicit macro-context
assumptions because their invocation extents move evaluated arguments. Thus
the genuinely new ID is **one / 26,670 = 0.00375%**, only in lossy mode. This
tranche adds no default removal. The three-removal difference between current
modes is 0.01125 percentage points of the cohort.

The nine other historical binding/reorder sensitivity candidates now retain
under the stronger location and observed-macro guards. Their earlier relaxed
twenty-removal union must not be presented as production yield. No unexpanded
runtime logic change was found in the accepted patches, but incomplete compiler
inputs remain consequential: an unrecorded `-Ddev=arg[2]` changes the prototype's
compiled type. Its removal is explicitly conditional and lossy.

These are final source-comparison measurements after a full-cohort structural
screen, not a fresh end-to-end Kbuild/policy pipeline run. The two modes share a
reader/reference cache. The benchmark rotates Git's reader process after 128
requests between commits, versus production's 8,192-request lifetime, so timing
is specific to that harness. Python peaked at about 138 MiB; the largest child
process reached about 1.13 GiB. Child high-water RSS is not a simultaneous
aggregate memory measurement, and this run does not establish a 512 MiB bound.
Separate interrupted cache/thread/pack-map experiments also failed that combined
RSS target. The small gain and measured cost do not support the old 8% estimate
or a broad performance claim.

Exact IDs, audit reasons, per-commit timings, source snapshots and independent
inspection are in
`benchmarks/lossy_yield/2026-11-07/current-production-replay/`.

## Build identity and reusable observer trials — 2026-11-07

The missing ABI whitelist cannot currently be recovered with matching provenance.
Three contexts must remain separate: the live challenge7.1.2.a kernel is Android
6.6.46/Clang18 with config `ea0c80e5…`; the prepared/traced experiment is upstream
7.3/Clang21 with adapted config `4e6741a1…`; project `kernel.config` is a separate
6.1.23/Clang17 context (`5a374f20…`). The live config already names the relative
`abi_symbollist.raw`; no path rewrite was observed. Its `maybe-dirty` release and
epoch timestamp do not identify the source commit, selected KMI lists or build
manifest. No arbitrary list, empty file or config substitution was supplied.
Recovery requires the original artifact or matching build manifest, selected
lists and generator revisions. Details and pinned official generator sources:
`benchmarks/build-input-recovery/2026-11-07/`.

Completing that adapted build would not automatically recover absence pruning.
The existing positive path/metadata inventory already matches every changed
path in 26,060 of the 26,670 original commits (97.71%). Another 522 have partial
matches; all 88 unmatched commits touch names absent from the current source
tree. Every one of the 780 unmatched distinct historical names is absent there;
no currently existing changed path is unobserved. These are positive spellings,
not content dependencies or a historical absence certificate. Header archiving
(`CONFIG_IKHEADERS=m`) and Git/version generation explain why the footprint is
much broader than the compiler-source list. Content/metadata distinctions and
consumer roles are necessary for a useful finer proof. The independent design,
parent/child invalidation requirements and counterexamples are under
`build-input-recovery/2026-11-07/trace-closure-review/` within `benchmarks/`.

A pinned Riker observer was actually built locally from unmodified source
`bae684b455a4d8fa010fc04b471f5ca9b408f6a8` and its pinned submodules. Command-local
Nix library paths and removal of the obsolete `-lstdc++fs` link option through a
Make variable were needed; no global installation or production change was
made. Its binary hash and exact build commands are saved in
`benchmarks/riker_observer/2026-11-07/provenance.json`.

| Actual small observer control | Result | Certificate status |
| --- | --- | --- |
| Direct compiler: forced include changes | Compiled exit 3 → 6; matches isolated fresh build | Unknown |
| Direct compiler: `__has_include` file creation/deletion | 6 → 14 → 6; matches isolated fresh builds | Unknown |
| Directory wildcard: add a new member | `A` → `AB`; matches isolated fresh execution | Unknown |
| Static program using raw file syscalls | `A` → `B`; matches isolated fresh execution | Unknown |
| Full `make --always-make` recipe | Initial run succeeds; unchanged run exceeds 10-second limit with default injection | Unknown |

All observer cases report spaced `Model Mismatch` / `openat ... UNKNOWN (6)`
warnings despite successful exit status. These must veto a certificate; a
contiguous `ModelMismatch` log check misses the warning. The no-injection full
Make trial also timed out. Earlier plain `make all` trials did not satisfy
Riker's full-build specification contract and must not be called dependency
engine counterexamples. Default unknown-syscall handling and per-exec environment
coverage still need validation. Passing tiny transitions demonstrates useful
incremental observation machinery, not a complete or performant kernel backend.
No full kernel build was run, no input certificate was promoted, and no commits
were removed by this investigation. Logs, isolated fresh comparisons and cleanup
evidence are in `benchmarks/riker_observer/2026-11-07/rikercontrols/`.

## Logger binding repair and further bounds — 2026-11-07

Further inspection found real default false removals in the diagnostic policy
exemption. A caller can override an internal index emitter/forwarding helper or
introduce a local backend function pointer through a macro. Changing only the
message then changes non-log state. Fourteen independently compiled controls
cover helper hooks, comment/digraph/continued directives, a once-log hint with
an included location alias, and local/object/pasted backend declarations. The
repaired filter retains them. Ordinary C declarations and macro bindings are
checked separately; local `file`, `line` and `fmt` variables remain supported.
The modeled 43 API dependency sets and free replacement identifiers were
verified against four kernel snapshots. Opaque caller replacement operators
retain candidates rather than being assumed harmless. This remains a finite
caller model with unobserved input/CPP limitations, not a complete binding proof.

The final repair replays the **11 previously accepted** full-original patches:

| Mode | Removed | Changes from the prior accepted set | Replay time |
| --- | ---: | --- | ---: |
| Default | 7 | GIC wording patch `97c03ec2c0e0` now retained | 18.89 s |
| Explicit lossy | 10 | Same GIC patch now retained | 70.79 s |

The GIC source contains an unrelated token-pasting affinity macro. No logic
change was found in its message typo, but this source model cannot certify
backend bindings through the opaque macro context. There are no other gained
or lost IDs in the selected replay. The prototype rename `ab017a15fdb2` remains
the only newly removed ID versus the historical ten diagnostic removals; losing
the GIC removal leaves **zero net increase** against that historical count.
The wider 85-candidate/full-cohort replay was not repeated after this repair.
Logs, source hashes, audits and exact lost-removal evidence are under
`benchmarks/logging_family_yield/2026-11-07/after-macro-binding-repair/`.

Additional bounded inventories did not justify new production scope:

| Experiment | Candidate evidence | Accepted new removals |
| --- | --- | ---: |
| 33 additional standard nondebug logger names | All 26,670 originals; 68 seeds, three full-source comparisons, zero whole-commit matches | 0 |
| Literal data feeding plain `%s`, including conditional literal branches | 2,506 quote seeds, 103 whole-source comparisons; one structural DRM match retained by both actual macro guards | 0 |
| Complete-file macro evidence before broad discovery | Original hrtimer case removes only in lossy prototype, with the same incomplete-context risks; 65.68 s versus 10.51 s baseline | Not shipped |
| Global references for 114 macro-only candidates | Seven have external references; 107 remain time-budget unknown, no complete absence proof | Unresolved, not zero opportunities |

The logger prototypes preserve their known limitations and compiled controls;
adding family names and `%s` treatment alone provides no accepted gain. The
macro prepass uses complete files because a clean-looking grep row lacks
preceding comment/continuation context. It adds evidence rather than discarding
opaque bindings, but the observed hrtimer comparison costs 6.25 times as much.
The macro-reference inventory also exposed expensive common-name prefetch;
its sampled process-tree RSS exceeded 1 GiB. It does not establish a safe
unused-macro count or a practical memory bound. Exact scopes and incomplete
artifacts are in `benchmarks/macro_row_recovery/2026-11-07/` and
`benchmarks/unused_macro_global_yield/2026-11-07/`.

The final frozen caller-repair snapshot passes **1,025 tests**, including the
real binary SELinux policy; all 58 Python source files pass mypy, and all 59
Python/C++ package sources match the wheel. Before/after source/test hashes are
unchanged. Complete logs and frozen files are in
`benchmarks/logging_family_yield/2026-11-07/verification-current/`. The earlier
1,023-test helper-only snapshot is preserved separately and superseded.

## Reference transport repair — resumed 2026-11-07

An independent query experiment found two real ways the old scanner could miss
references. `color.grep=always` decorated revision/path fields, and newline-based
splitting broke a filename containing a newline before its NUL terminator. Both
could silently become empty reference results. The production scanner now uses
typed binary rows, disables color and column formatting, preserves source NUL
and actual ESC bytes, and rejects malformed, truncated or oversized output.
Reads stay at 64 KiB with a 16 MiB row/record cap; early stop or parse failure
closes, kills and reaps the subprocess. Unrepresentable non-UTF8 paths fail the
string-based consumer model rather than being merged through replacement
characters. Source/include bootstrap failure cannot finish its absence cache.

Both the default SQLite filename and the per-query namespace move to v8.
Explicitly supplied v6/v7 cache files cannot retain the old unsafe
negative results. Include-graph JSON files are regenerated scratch transport
for parallel workers and have no persistent cross-run reuse path. Sixteen
independent actual-Git consumer oracles pass, including a poisoned v6 cache,
shared include/reference bootstrap, unusual paths, partial macro positives and
hard uncertainty after failures. Evidence is in
`benchmarks/reference_transport_review/2026-11-07/`.

The follow-up audit found two more concrete absence hazards. A tracked filename
such as `:(exclude)*` became a negative Git pathspec during an anchor-to-child
query: a real reference disappeared and an empty result was persisted. The
shared Git transport now enables global literal pathspec mode; this also works
under an inherited `GIT_LITERAL_PATHSPECS=1`, where simply prepending
`:(literal)` would itself fail. Conflicting Git environment modes fail rather
than silently omit results. This discovery supersedes the initial v7 transport
checkpoint and requires the final v8 invalidation.

Historical include updates now disable diff colors/text conversion and request
text hunks. They compare the parsed filename set with the authoritative
NUL-delimited changed-path list before mutating the graph. Quoted paths that the
existing diff parser cannot represent return failure without advancing the
revision or adding fictitious paths. Actual Git controls reproduce all of the
old failures; final independent evidence is under
`benchmarks/reference_transport_review/2026-11-07/v8-final/`.

The final pass also overrides `diff.ignoreSubmodules=all` in both diff commands;
otherwise both the patch and its changed-path check can omit a new opaque
gitlink. Source-query transitions between regular files and gitlinks still
report real references, so this final fix affects regenerated include graphs
and does not require a further persistent query-cache version. The consolidated
76-case independent review and precise limits are under
`benchmarks/reference_transport_review/2026-11-07/after-submodule-repair/`.

The experimental exact-word prefilter is not shipped. On the saved common-name
query it reduced output from 32.5 MB to 1.57 MB but changed scan time only from
8.01 s to 7.42 s; the rare-name query was slightly slower. Sampled tree PSS stayed
around 1.3 GiB. Those measurements do not establish a memory improvement or a
whole-pipeline speedup. The correctness repair is independent of that proposal.

The binary framing repair itself was compared with the original newline parser
on unchanged real-kernel queries, with colors disabled in both arms. Two
alternating repetitions produced identical complete row digests. Median common
query time was 19.54 s versus 19.28 s for 202,115 rows; rare-query time was
7.85 s versus 7.86 s. Within-arm variation exceeds that difference. Sampled tree
RSS was about 27 MiB higher for the common query and 18 MiB higher for the rare
query; Git object traversal dominates the totals. This supports similar scan
cost, not a speedup or a memory bound. Measurements precede the additional
literal-pathspec/include-update repair and are in
`benchmarks/git_grep_transport/2026-11-07/performance/`.

A bounded token-paste language prototype would restore the GIC diagnostic
comparison and retains all fourteen earlier compiled controls. It nevertheless
falsely removes a new included-alias witness in default mode: `DECL_##a` produces
`DECL_p`, which rescans through an included macro into `(*_printk)` and binds a
local backend pointer. Compiled GCC and Clang behavior changes from exit 5 to
10. The prototype is not shipped. Direct output-spelling disjointness requires
recursive rescan and binding closure before it can justify absence. Complete
evidence is in `benchmarks/tokenpaste_logging_guard/2026-11-07/` and
`benchmarks/logger_paste_design_review/2026-11-07/`.

## Emitted-code and metadata experiments — 2026-11-07

A bounded LLVM Object/MC prototype now decodes the actual parent/child MM objects
and the six adversarial assembly witnesses. It recovers direct transfers encoded
with `.inst`, `.byte` or local aliases, and keeps numeric/table indirect targets
unknown. Each real object has 15 indirect calls, 17 trap continuations, unknown
runtime patch metadata and 275 external code references. Equal aggregate counts
hide eight changed instruction words. The audit takes about 0.47 s per real
object with about 214 MiB peak RSS; it is not a whole-kernel reachability proof.
No caller closure or removal is authorized. Hash-keyed incremental summaries are
promising after runtime patch, value-flow and entry semantics are specified.
The implementation and precise scope are in
`benchmarks/emitted_mc_audit/2026-11-07/`.

Detached object BTF equality is also insufficient as a linked-metadata proof.
A compiled local-static per-CPU alignment change leaves detached BTF identical
while changing an unchanged suffix variable's linked offset from 8 to 20 and
DATASEC size from 12 to 24. For the real MM pair, ordered ELF symbols and allocated
layout match, and the only decoded DWARF differences are two attributes unused
by the pinned encoder. The configured ARM64 erratum scan cannot gain a match
across these particular changed words. These are narrower positive facts, not
a certificate: complete selected-link inputs/order, encoder projection and build
identity remain unproved. No metadata guard was weakened and zero commits were
removed. The proposed incremental contract and counterexample are in
`benchmarks/btf_equivalence_review/2026-11-07/`.

## Unused-macro inventory retry — 2026-11-07

A bounded retry improves the earlier incomplete 114-candidate inventory. It
rederives original DB patches, full parent/child sources and definition ranges,
then uses the typed v8 scanner with exact raw names and every existing spelling
guard. Every occurrence outside changed-definition ranges remains live;
there are no inherited masks or configuration exclusions.

| Changed-file category | Both-revision name/guard absence complete | Known external reference | Full names complete, guards unfinished | Unresolved |
| --- | ---: | ---: | ---: | ---: |
| Private source/header | 6 | 19 | 1 | 62 |
| UAPI | 5 | 9 | 0 | 12 |
| **Total: 114** | **11** | **28** | **1** | **74** |

The possible final count satisfying this raw-reference contract remains
**11–86**, not a complete estimate of semantically unused macros. Twenty-one
have full-name absence checks, including some with live spelling guards. The
twenty-eight positive cases include seven independently revalidated historical
witnesses. The eleven completed cases cover 0.0412% of the 26,670 legacy
survivors as candidates only; no population pruning rate follows.

The unchanged production `DeadCodeFilter`, default mode with no configuration
exclusions, was run on eight completed originals. It removes **zero** whole
commits and records **zero** partial removals. Observed barriers include opaque
macro environments, unresolved/ambiguous includes and incomplete reverse-include
environments. Two candidates retain before that environment check. Public UAPI
constants additionally require an external-consumer policy; no in-tree reference
does not prove that their interface has no users. No guard was weakened to turn
these raw scan results into exclusions.

The retry finishes within twelve minutes including setup/revalidation. Its two
attempts perform 79 repository scans and 158 incremental updates over about
347.5 worker-seconds; sampled peak process-tree RSS is about 1.58 GiB and PSS
about 1.38 GiB. These are observed peaks, not memory bounds. Completed evidence,
remaining unknowns, source hashes and cleanup are in
`benchmarks/unused_macro_global_yield/2026-11-07/transport-v7-retry/` (the directory
name is historical; its actual cache namespace is v8). The actual eight-commit
production check is in the sibling `production-check/` directory.

Final complete source/test snapshots, test logs, wheel verification and hashes
are in `benchmarks/git_grep_transport/2026-11-07/final-verification/`. The earlier
1,049- and 1,056-test transport checkpoints are historical. The accepted-eleven
replay is in `v8-accepted-replay/`; the final additional submodule flag has
byte-identical changed-path output for all eleven inputs, verified separately.
The wider 85-candidate/full-cohort comparison was not rerun.

## Lazy complete-file evidence and closed reference checks — 2026-11-07

The macro provider now uses its existing broad scan to notice literal requested
definitions after the original file/byte allowance is exhausted. A separate
allowance reads at most 32 complete files / 512 KiB, with an immutable Git-size
precheck. Certain complete-file facts can refine only placeholders newly
introduced by that file's current row. Earlier identical opacity from another
file, compiler bindings, all baseline counters/uncertainties and the row-limit
boundary remain. Incomplete parsing does not promote a row; read/size failures
are nonassumable. Per-discovery state is typed and reset for each scan. No second
repository-wide query, UNKNOWN shim or eligibility waiver is introduced.

This restores one actual full-original removal in explicit lossy mode:
`3c3af563b31766f67106c7549ad084a08ef613f2`, which permutes the first two immediate
return cases in `hrtimer_clockid_to_base()`. Case/return tokens, other arms and
outside code match. Its audit still records `lossy=true` and the same ten risk
reasons, including incomplete macro discovery and unobserved bindings. Default
mode retains it. The initial single-candidate comparison takes 9.62 s → 9.76 s
for retained default runs, and 11.11 s retained → 37.38 s removed for lossy runs.
Passing later guards requires four broad queries instead of one; the additional
complete-file reads themselves total twelve files / 93,496 bytes. This is new
coverage, not a per-candidate speedup claim.

Independent review found and repaired additional real source-model failures:

| Provided tracked-code counterexample | Old behavior | Final behavior |
| --- | --- | --- |
| Phase-two split use of an apparently unused macro | Default pruned; GCC/Clang exit 0 → 1 | Retained; raw splices invalidate source-only absence context |
| Adding an unused definition shifts a live included LINE alias | Default pruned; GCC/Clang exit 2 → 3 | Retained; remaining positions checked with candidate bytes blanked at original offsets |
| Lossy global rename with a split caller and a tracked fallback linker alias | Lossy pruned; GCC/Clang exit 1 → 2 | Retained in both modes; global-reference renames require closed input spelling/include context |

The location check applies to whole groups and individual partial candidates,
keeps other surviving definitions visible, and has no logger/name exemption.
The global-rename context prerequisite runs before global position queries.
This avoids costly proof work for already unsupported renames and closes an
unsafe lossy waiver; unrelated unresolved input cannot bypass that prerequisite.
Untracked forced-input and raw-generator witnesses remain explicit limitations
of the source-only contract. No whole-build/input certificate was issued.

The final replay uses all 85 previously discovered structural candidates with
full original DB patches and exact parent/child Git files, no inherited masks:

| Final mode | Whole commits removed | Replay seconds |
| --- | ---: | ---: |
| Default | 7 | 49.36 |
| Explicit lossy | 11 | 478.59 |

The ten previously accepted lossy IDs remain; hrtimer is the only addition.
The earlier recovery-enabled snapshot with the unsafe context waiver takes
1,044.21 s for the same lossy accepted IDs. The final prerequisite reduces broad
macro scans from 111 to 49 and supplementary reads from 457 / 7,015,364 bytes to
238 / 3,611,703 bytes. Reader rotation is after 128 requests in this harness,
versus 8,192 in production; caches are shared across modes, input order
prioritizes the accepted IDs, and host load differs. The observed 54% time
reduction is not a statistical throughput claim. Final Python peak RSS is about
140 MiB and largest-child peak about 1.09 GiB; these are not aggregate memory
bounds. No full Kbuild/pipeline population replay was performed.

Seventeen new actual-Git provider tests and additional compiled/partial-mask
controls preserve known unsafe cases. The final complete suite has 1,083 passing
tests, all 59 Python files pass mypy, and all 60 package sources match the wheel.
Production sources stay stable during both full replays; final verification
also keeps source/test hashes unchanged. Final
artifacts are under `benchmarks/macro_lazy_recovery/2026-11-07/after-closure-repair/`;
the independent provider and kernel-case reviews are under `production-review/`
and `final-review/`. The compiled rename witness and repaired control are under
`benchmarks/unused_macro_closure/2026-11-07/rename-splice-review/`.

### Indexing and other bounded investigations

A true OID-backed prototype completes one real snapshot: 87,270 blobs / 1.487 GB
of source, 6,631,565 exact headlines, and 67 source-only shards totaling 555 MB.
Original coordinates are separate from searchable bytes; source NUL survives.
An external memory monitor observes about 400 MiB in the initial probe under the
512 MiB budget. Publication takes another 75.98 s and rebuilds all shards, so
per-diff publication is still impractical. The SQLite state is about 2.1 GiB.
The first real warm query does not complete within 40 s (observed peak 230 MiB);
the frozen native provider completes in 11.35 s at about 1.40 GiB under a separate
2 GiB comparison limit. Exact real-query equivalence is therefore unknown.
This index is not integrated. Evidence and scope are under
`benchmarks/macro_oid_index/2026-11-07/completed-attempt/` and `warm-proof/`.

Other prototypes add no accepted removals: integer spelling, joined string
literals and a typed temporary-int cleanup have three whole-source structural
matches, all retained by current context guards; their fifteen GCC/Clang control
pairs preserve known type/stringification/location counterexamples. A bounded
define/undef lifetime certificate is possible, but a screen of all forty
macro-only candidates with local references finds no define/undef-only match.
Evidence is under `benchmarks/syntax_equivalence_yield/2026-11-07/`,
`benchmarks/macro_lifetime_yield/2026-11-07/` and the typed certificate design in
`benchmarks/unused_macro_closure/2026-11-07/review/DESIGN.md`.

## Whitespace layout proof and complete comment-seed replay — 2026-11-07

The whitespace stage now compares complete supported preprocessing-token
spellings, logical whitespace gaps and physical start/end positions for every
real token. It decodes source strictly and maps standard phase-two splices with
right-biased token starts and left-biased ends. Excluded code is blanked at its
original physical lines through `active_sources`, rather than reverted as an
ignored edit. A failed or incomplete certificate retains the change.

This addresses compiled counterexamples involving invalid UTF-8 string bytes,
included line/column aliases, macro stringification gaps and C++ raw literals.
Atomic header handling also avoids duplicate interior tokens and comment-looking
filenames consuming subsequent source. Unmodeled header operators, raw literals,
unsupported spellings and resource-limit overruns retain changes. There is no
fallback to the former unsafe comment-strip or token-value acceptance.

The independent compiler review covers 26 actual Git fixtures: fourteen
behavior-changing cases and one unsupported case are retained; eleven stable
positives are pruned. A mixed mask fixture preserves an included line alias's
runtime change from 5 to 6. Fixed surrounding inputs and the prior edit-mask
contract remain assumptions; raw-source consumers and build metadata are not
certified. See [WHITESPACE_PRUNING.md](WHITESPACE_PRUNING.md).

The cohort inventory examines all 26,670 original patches, not the saved reduced
file lists. It finds one whole-commit hunk-gate positive and 514 ambiguous
comment-interior seeds, selected by comment edit shapes or subject terms. These
terms select the experiment; they are not production pruning rules. All 515
selected originals are replayed with fresh masks and complete parent/child
sources. Other commits failing this experiment's selection are not established
as unprunable.

| Measurement | Previous rule | Complete layout rule |
| --- | ---: | ---: |
| Whole commits removed in the same 515 inputs | 418 | 172 |
| Partially pruned commits | 11 | 13 |
| Files masked | 575 | 254 |
| Additional whole removals versus previous rule | — | 0 |
| Whole removals retained instead | — | 246 |
| Original-patch inventory and hunk gate | 85.78 s | 140.96 s |
| Candidate replay | 33.33 s | 124.37 s |
| Sampled process-tree RSS, including monitor | 321.7 MiB | 370.2 MiB |

These sequential shared-host observations are not a controlled throughput
benchmark. The stronger proof costs more CPU. Hunk rejection still avoids
complete-file scans for ordinary code edits, and the comparison streams tokens
with a 2 MiB / 131,072-token limit. Its digest-fact cache has 512-entry / 16 MiB
represented-input bounds and retains no source buffers. The replay records
1,163 fact scans, 37 cache hits and 124 unsupported scans. A future fast comment
certificate must preserve logical preprocessing behavior, physical coordinates,
complete supported grammar and budgets; a comment mask alone is insufficient.
Avoiding span allocation for hunk-only token consumers is another measured
optimization opportunity, not implemented in this checkpoint.

An independent second pass verifies all 172 whole removals and all 199 original
files: raw patch/blob hashes, complete original file sets, fresh actual-stage
results and direct token/gap/UTF-8 position equality using indexed splice cuts
and bisection rather than the production digest/cursor. There is zero overlap
with the prior 85 structural candidates. Of these files, 193 contain literal
includes and 119 contain standard splices; no accepted file changes LF count or
an include/header directive shape. Retained and partially pruned cases were not
independently audited by this pass. The result is conditional source equivalence,
not a whole-build or policy-reachability theorem.

A separate regression reloads the eleven previously accepted original structural
patches and preserves their exact seven default / eleven lossy accepted sets.
The other 74 prior rejects are not replayed. The final 1,127-test run includes the
captured binary SELinux policy; mypy passes 60 Python files, and every one of the
61 Python/C++ package sources matches the wheel.

Frozen inputs, source snapshots, original patches, full reports and resource
observations remain in ignored benchmark directories:

- `benchmarks/whitespace_layout/2026-11-07/`, including `old-baseline/`,
  `independent-audit/`, `source-regression/` and `verification-final/`.
- `benchmarks/whitespace_layout_review/2026-11-07/after-repair/` for compiled
  controls and independent grammar review.
- `benchmarks/whitespace_token_spans/2026-11-07/` for lexer differential goldens.

No filtered database is written by these experiments. The milestone commit
contains production code and durable documentation only; tests and benchmark
artifacts stay outside the commit as requested.

## Audited line-number assumption and lexer performance — 2026-11-07

A separate `--whitespace-line-numbers-lossy --whitespace-report PATH` option is
now implemented. It does not follow from `--source-pruning-lossy`. The default
still compares complete supported tokens, logical gaps and physical start/end
lines and byte columns. The optional mode omits only the line coordinates;
unknown syntax, budgets, byte columns, stringification gaps and changed tokens
still retain the edit. It requires a decision callback through the API too.

Each complete cached fact now contains a framed token/gap/column digest and an
ordered line digest. Strict comparison checks both; the explicit relaxed method
checks the former. Both share the same bounded complete scan/cache. An
independent helper replay of 515 originals / 688 file pairs finds zero strict
changes against committed `ce89cdd`. It observes 1,337 scans and 144 unsupported
scans in both comparers. Cached relaxed lookups cost no new scans. The split
helper measures 116.60 s versus 114.65 s before, a 1.7% increase in that sequential
helper-only experiment, not a full-pipeline measurement.

| Actual whitespace stage, same 515 originals | Whole removals | Additional versus strict | Share of legacy cohort |
| --- | ---: | ---: | ---: |
| Default strict | 172 | — | 0.645% |
| Explicit line-number assumption | 381 | 209 | 1.429% total; 0.784 points additional |

The actual lossy replay has 20 partially pruned commits and 523 masked files. It
uses complete original patches, no inherited masks or config/file exclusions,
and records every acceptance. All 172 strict whole removals remain included.
The 209 extra whole removals comprise 207 previously classified line-only
retentions plus two more original documentation commits in binder and regmap.
An independent actual-stage audit verifies all 209 incremental acceptances
from original patches/blobs across 227 files, including a separate token/gap
and UTF-8 byte-column comparison. It confirms strict retention and mandatory
lossy risk records for every case; it does not prove runtime equivalence.
The earlier 207 estimate was a mechanical upper bound within the 246 old-rule
retentions, not a bound on all candidates.

The mode is intentionally lossy. Included line-number aliases can affect a
branch, array size, preprocessor condition or generated name. Compiled controls
show a logic return value changing from 0 to 1 despite matching tokens, gaps and
byte columns; a separate control changes diagnostic stdout while retaining its
return value. Both are retained by default and explicitly pruned/audited only
under the new assumption. Neither logging spellings in a file nor a comment-only
patch proves that every line-number observation is diagnostic. There is no
measured false-removal rate bound or whole-build closure claim.

Audit records distinguish strict `whitespace_or_comments` / `lossy=false` from
`whitespace_line_numbers_lossy` / `lossy=true`. Additional removals record
`source_line_number_observations_may_change_runtime_behavior` and
`included_macros_may_observe_changed_lines`. Each record carries only the
current file's masks in original coordinates. Callback failures propagate.
A small real CLI/SQLite integration saves and reloads three original commits:
strict keeps the line-changing and runtime-changing commits, while lossy keeps
only the runtime change and writes separate strict/lossy records. Its source DB
stays unchanged; only database-name path resolution is redirected to fixtures.

A shared lexer factory also avoids allocating `CTokenSpan` objects for token-only
hunk consumers. Token and span recognition still share one generic scanner.
Against committed `ce89cdd`, 10,384 complete token/span comparisons and 2,656
budget/error-prefix comparisons show zero differences. Five paired lexer-only
samples measure 1.18x faster tokenization on 122 original kernel hunk sides and
1.19–1.32x on small toy workloads. The span path has no measured regression in
that experiment. These are tokenizer measurements, not pipeline speed claims.
A new complete 26,670-original-patch hunk-gate pass selects exactly the same
515 IDs and raw-patch checksum in 105.52 s, compared with the preceding 140.96 s
observation. This is a shared-host timing comparison, not a controlled 25%
end-to-end speedup claim.

A final actual default-stage replay removes exactly the same 172 IDs as the
committed strict checkpoint in 113.62 s. Every recorded decision is non-lossy.
This verifies the full current stage, in addition to the helper comparison.

The actual 515-input lossy replay takes 125.07 s with 1,163 complete fact scans,
729 cache hits and 124 unsupported scans; sampled process-tree RSS including the
monitor peaks at 334.7 MiB. The frozen original candidate inventory is reused,
with each selected raw patch hash checked again. It is not a new population-wide
Kbuild rerun. The previous strict replay took 124.37 s on its own snapshot;
shared-host timing and mode differences prevent a controlled speedup claim.

Adding a mandatory report exposed concrete path-validation defects. Source,
whitespace and policy reports/caches are now checked together before any is
initialized. The shared validator protects explicit inputs, raw/destination DBs,
SQLite sidecars, source/build trees and Git/common directories outside linked
checkouts. It rejects output aliasing, parent/child destinations, sidecar
collisions, nonregular files, file parents, hardlinks and destination-name
symlinks. Regression controls preserve a live WAL/readable database, separate
Git HEAD/reference caches, linked-worktree metadata and existing reports. The
common record type is in `pruning_decision.py`; existing source-stage imports
remain available.

The final 1,165-test run includes the real captured binary SELinux policy. Mypy
passes 62 Python files, and all 63 Python/C++ package sources match the wheel.
No target-policy or hardware reachability guard is relaxed by this feature.
Exact matching target build/input metadata remains necessary for those proofs.

A bounded unused-code investigation found no new removal class to implement:
154 original macro-only cases produce no candidates for the literal bounded
reset-lifetime screen. A full 26,670-patch screen selects 16 literal `#if 0`
seeds, ten eligible original-C/default cases; none preserves the outside source
layout when the literal-zero groups are erased. A concrete disabled-code
removal keeps token spellings but shifts later source lines, and the current
stages retain it. Separately, 2,992 return-variable patch seeds produce zero
matches for the narrow scalar-return token-delta screen. These negative screens
do not rule out broader temporary/alias dataflow opportunities and do not
justify weakening macro, location or build-input closure.

Evidence remains in ignored benchmark directories:

- `benchmarks/whitespace_line_numbers_lossy/2026-11-07/` for helper comparison,
  actual replay, CLI integration and full verification.
- `benchmarks/whitespace_recovery_options/2026-11-07/` for the retention
  classification, compiled logic/diagnostic controls and independent audits.
- `benchmarks/whitespace_no_span/2026-11-07/` for lexer differential/performance
  measurements and the new population hunk-gate check.
- `benchmarks/unused_proof_opportunities/2026-11-07/` and
  `benchmarks/scalar_temporaries/2026-11-07/` for the bounded negative screens.

Benchmarks and test files remain outside milestone commits as requested.

## Numeric preprocessor branches and source file modes — 2026-11-07

`--source-pruning --constant-branches` starts its source tail with
`ConstantConditionalFilter`. Constant folding has its own opt-in because its
additional measured yield is small and its cost remains material. Existing
source-pruning runs keep their three-stage tail.
It folds environment-independent numeric CPP conditions, including nested
groups, selected arms and all-false chains. A preceding unknown condition keeps
its chain unresolved; nested numeric groups can still be considered. Macro
conditions, unsupported directives, malformed input and exhausted budgets retain
changes. Assembly files are excluded because their `#` lines have other roles.

The scanner returns candidate ranges, not permission to erase code. The stage
requires supported complete original sources on both sides, composes candidates
with existing code/edit masks in original coordinates, and compares the complete
projected pair. Only a successful whole-file comparison publishes masks. A
failed comparison leaves every candidate in that file unmasked; a different
file in the same commit can still be pruned. Selected-arm macro directives and
other preprocessing effects remain visible. Both physical token coordinates
and stringification-relevant gaps remain significant by default.

The separate whitespace line-number assumption also applies to this comparison.
Strict decisions use `constant_preprocessor_branch`; assumed decisions use
`constant_preprocessor_branch_line_numbers_lossy` and require the whitespace
audit callback/report with both existing line-observation risks. The source
lossy flag alone does not enable this assumption. Callback failures propagate.

`1c4f7235112934232975e6ed08a896a4caa71dd9` ("crypto: drbg - Remove broken
commented-out code") is a verified additional whole removal under the explicit
line-number assumption. Strict mode retains it because deleting the disabled
group shifts later source lines. The full original Git patch matches the stored
patch; all four combinations of source-lossy and line-lossy options confirm
that only the line flag controls this removal. This is an audited lossy example,
not a new default-safe gain or evidence for a low false-removal rate.

A necessary byte precheck avoids parsing source pairs with no possible numeric
group. It removes standard splices and deliberately overcounts comments,
literals and uncertain spellings. It never authorizes pruning. Independent
checks of 16,000 raw/masked inputs find no precheck false negatives. Scanner
facts use a 512-entry / 16 MiB represented-input cache without retaining source
buffers. Individual sources are bounded to 2 MiB, 65,536 LF characters, 128
nesting levels and 2,048 groups.

An explicit per-commit budget now skips the entire constant stage before any
source read or mode lookup when more than 256 source files are eligible. It
publishes no masks and increments `budget_skipped_commits`; such work selection
is not proof coverage. This prevents tree-wide edits from forcing thousands of
extra source reads. Other stages still apply their own rules and budgets.

The completed isolated-stage replay covers **all 26,670 original commits** in
three contiguous ranges with fresh caches at restarts. It takes 1,402.4 seconds
(23.4 minutes) in total, with a 493.4 MiB sampled peak and no OOM. It uses the
frozen proof implementation before the reader cache, file budget and separate
selection flag. One interrupted attempt is retried from its exact uncompleted
index. All eight accepted whole patches match the full original Git/DB patches.

There are five strict whole removals, all already covered by strict whitespace;
three line-lossy whole removals, two already covered by line-lossy whitespace;
and ten partially pruned commits. The **isolated additional whole gain is one
commit**, DRBG, or **0.00375 percentage points** of this cohort. There is no new
strict whole gain. The earlier 14,168-input prefix has zero additional wholes;
the complete replay establishes the small gain rather than extrapolating it.

Actual whitespace-stage comparisons of all ten partial originals find only one
additional file, `net/dccp/output.c`, also under the line-number assumption.
Running constant folding followed by whitespace on all ten full originals in
both modes retains every commit: complementary masks produce no further whole
gain. This is a two-stage comparison without configuration, unused-definition
or target-policy pruning, not a full Kbuild pipeline yield claim.

A separate full original-patch inventory finds only **12 commits (0.045%)**
above the new 256-file budget, containing 20,563 eligible files. All eight
accepted wholes have one eligible file and remain under the limit. The inventory
takes 8.2 seconds without source reads; it measures work selection, not pruning
correctness. All ten partial commits also remain below the cap (maximum 175
eligible files), preserving every accepted file decision structurally. Earlier
pipeline masks can reduce a commit's remaining eligible count.

The exact first 4,600 results match the preceding implementation across eleven
checks, including raw hashes, retained IDs, masks, audit decisions and reads.
The precheck reduces that local elapsed time from 391.6 to 207.5 seconds
(1.89x); about 90% of source pairs skip parsing in the longer run. These are
shared-host observations, not a complete-cohort throughput claim.

A separate actual source-pipeline comparison of the same 100 originals takes
12.01 seconds without the new stage and 17.62 seconds with it, retaining all
100 with identical masks. Git blob-content payload is identical at 28.5 MB;
the new stage adds 602 reader/metadata requests and CPU work. This 47% local
elapsed overhead is material despite the precheck. A separately verified
opportunity does not justify claiming a useful population tradeoff.

These measurements precede the shared-reader metadata cache and the new
per-commit bound. The unbounded replay encounters two tree-wide edits touching
8,016 and 6,673 files; those input blocks take minutes despite bounded memory.
They motivate an explicit work limit rather than a semantic shortcut.

The shared repository reader now keeps a bounded 4,096-entry positive metadata
cache for exact native-width full object IDs and normalized paths. Repeated
reads can return the existing OID-cached bytes without another Git command;
evicted bytes can be requested directly by their known OID. Symbolic revisions,
abbreviations, cross-width hex refs and failed reads retain native resolution.
Content buffers still have one 16 MiB / 4,096-entry owner.

Both metadata and contents expire when the native Git process is replaced.
Git pins its replacement-object map within a process; keeping OID bytes across
restarts previously produced stale results after a blob replacement. The new
epoch rule repairs that case as well as preventing stale commit/path metadata.
Cache hits do no native work and do not trigger rotation; the next native read
rotates after the existing 8,192-read limit. Independent SHA-1/SHA-256 controls
cover mutable refs, empty files, eviction, invalid paths, close behavior and
commit/blob replacements across actual restarts.

The final reader/budget version still takes 13.13 seconds without constant
folding and 18.99 seconds with it on the same 100 originals, with identical
retained IDs and masks. Native requests fall relative to the previous reader,
but correct epoch invalidation increases blob payload at the benchmark's
128-read rotation setting. No wall-time improvement is claimed. The incremental
45% local overhead and thin additional yield are why constant folding requires
the separate `--constant-branches` flag. These shared-host timings do not
predict the normal 8,192-read setting or full-cohort throughput.

The shared layout digest also normalizes the gap immediately following an
explicit semantic newline: that newline already separates preprocessing tokens.
Ordinary gaps remain significant. An actual replay of all 515 original
whitespace candidates preserves the exact **172 strict / 381 line-lossy** whole
sets and all per-file outcomes. Compiler controls retain dangerous gaps and
line observations. Numeric-group preprocessing checks cover 92 trees in 736
GCC/Clang runs without changing output tokens.

An independent safety review found a separate concrete false-pruning case:
Git symlinks named `api.h` or `api.c` can have token-equivalent target strings
such as `./*one*/header.h` and `./*two*/header.h`, while the actual included
headers return different values. Whitespace in a link target is path data.
Whitespace, ifdef and source-analysis filters now require positive regular-file
evidence (`100644` or `100755`) on each existing side. Complete patch modes cost
no extra queries. Missing modes require an exact literal historical tree lookup;
unknown modes, read failures, symlinks and submodules retain changes. Compiled
GCC/Clang controls retain the link changes with both complete and omitted mode
metadata, while regular-file positives still prune.

Evidence remains in ignored directories:

- `benchmarks/constant_conditionals/2026-11-07/`, including production
  integration, compiler/scanner reviews, precheck verification, population
  replay, pipeline cost and whitespace regression.
- `benchmarks/source_file_modes/2026-11-07/symlink-whitespace/` for the original
  failure and repaired real-Git/compiler controls.

Further unused-code investigations produce no certified additional default
whole removals. Scalar-return candidates still have other live edits or require
conversion/alias reasoning. Contextual unused-macro proofs still need complete
translation-unit inputs and macro/paste closure: multi-token arguments can
construct a changed macro from an interior subinterval of a paste chain.
Ignoring unknown forced inputs or metadata consumers remains unsafe.

Target-policy reachability remains blocked on matching target build provenance
and complete caller/metadata closure. A fresh read-only challenge 7.1 template
check provides Image/initramfs paths but no authentic source/config/compiler/ABI
manifest. Re-extracted historical MM translation units still contain opaque
assembly and indirect calls. The current policy filter retains the genuine
`process_mrelease` candidate; neither a captured seccomp denial nor a historical
build establishes complete target reachability. No policy or hardware guard is
relaxed by this milestone.

Verification includes 1,231 passing full-suite tests with the captured binary
SELinux policy before the final stage-selection change, followed by 189 passing
source, CLI, audit and streaming tests on the final selection API. Mypy checks
65 Python sources, and all 66 Python/C++ package sources match the final wheel.
Independent native Git and compiler controls cover the reader, regular-file
evidence, branch scanner, line assumptions and budget boundaries. Source/test
snapshots and manifests remain in ignored verification directories. Tests and
benchmark artifacts remain outside the milestone commit.

## Configuration observations and live module closure — 2026-11-07

The normal `ConfigFilter` now skips expensive Kbuild/include preparation while
build-input closure is unknown. It retains nonempty nonmerge changes, preserves
existing masks and clears stale exclusive preprocessor modes. No additional
exclusion is authorized. Positive advisory modes remain available with
`ConfigFilter(..., collect_observations=True)` or CLI
`--config kernel.config --config-observations`. Only that analysis requires
complete history and uses `--workers`; its modes remain incomplete and cannot
enable configuration-based `#if` masking. The time-range Python helper exposes
the same choice as `config_observations=True`.

This separation addresses a measured cost with no exclusion benefit. In a fresh
deterministic sample of 500 nonmerge raw commits from UTC January 1–8, 2025,
the actual model walks all 1,018 history transitions and retains every one of
the 1,010 changed files. An independent diagnostic records old/new
`modeled_inclusion` without publishing masks:

| Diagnostic observation | Count |
| --- | ---: |
| Whole original commits with all candidate sources absent from the model | 274 / 500 (54.8%) |
| Other partially absent commits | 40 / 500 |
| Candidate C/header/`.S` files absent on both applicable sides | 638 / 763 |
| Other files kept positive | 247 |
| Certified exclusions | **0** |

This is a raw 2025 sample, separate from the 26,670 legacy survivors. It does not
establish a 54.8% safe pruning rate or bound the false-removal rate. Every actual
build-input closure is `UNKNOWN`. Model absence omits arbitrary recipes,
forced/generated inputs, assembly/raw-data consumers and vendor-module builds.
The first preparation attempt reaches the 640 MiB limit and is killed before
any sample observation completes. A retry with command-local Git resource
limits completes in 156.6 seconds, still reaching the memory limit with reclaim
but no OOM. No user/repository Git configuration is changed. These costs belong
to the advisory preparation/model experiment, not the new fast default.

An actual replay of the fast default on the identical 500 originals retains
all patches and masks byte-for-byte against the recorded production decisions.
The direct stage takes 0.112 seconds, with zero preparation calls, repository
reads or native requests. A one-stage pipeline takes 0.119 seconds and starts
one idle shared reader without making requests. Setup/checks included take
1.08 seconds with a 210.4 MiB sampled peak. These are stage measurements after
loading the inputs, not an end-to-end speedup ratio against the separate
diagnostic experiment. Both runs use immutable source snapshots.

Independent small-repository controls compare actual advisory preparation with
the default across source, binary, symlink, gitlink, file-mode and structural
changes. Stale complete modes are cleared; absent/incomplete modes cannot
enable IfdefFilter reads or masks. Eleven full-original paired source-tail
controls preserve exact patches, masks and audit records, with seven removals
in default mode and eleven in explicit source-lossy mode. That isolates
metadata-consumer behavior rather than claiming whole-kernel bootstrap or
population-wide pipeline parity. All 1,247 tests pass on the final source,
including the captured binary policy; mypy and all 66 packaged-source checks
pass. Tests and benchmark artifacts remain outside the commit.

Live challenge 7.1.2.a supplies concrete counterevidence to a base-config-only
lossy rule. Four vendor modules are loaded despite their options being unset or
absent in the running kernel config: `dummy_hcd`, `usbip_core`, `vhci_hcd` and
`virtio_pmem`. Repeated config/boot identity and byte-identical installed/live
GNU build-ID notes establish the observation. At the inspected upstream
revision, nine candidate C inputs behind those object names have no literal
Kbuild membership under that base config. The current uncertainty guard retains
all nine. Their mapping is an upstream observation, not authenticated Android
source provenance. Ten original legacy commits touch those candidate paths;
none is wholly confined to them, so this is not ten demonstrated false removals.

The same environment has virtual USB controllers, persistent-memory namespaces
and simulated Wi-Fi. Current device absence cannot exclude software-created or
later bound resources. The binary policy grants app USB descriptor operations
despite denying direct open, while privileged services can open and transfer
descriptors. Complete source registration/callback, module, resource-creation
and mediation evidence is needed before pruning those paths. Reviewing all ten
hardware candidates in the earlier 100-sample certifies zero new exclusions.
Read-only inspection reused an existing instance; it changed no device state.

The installed modules retain symbols and BTF, but no DWARF or BTF.ext. Their
compiler strings identify Android Clang 18 and provide no authenticated source
tree or build manifest. Exact kernel/vendor source and generated/forced inputs,
commands, available-module universe and link/metadata provenance remain needed
for target-policy and default configuration exclusions. A captured base config,
binary SELinux policy or seccomp denial does not supply those missing premises.

Other bounded investigations also leave their proof obligations explicit:

- An exact whole-cohort screen finds eleven prototype-only removals, nine with
  no same-file outside use, plus static-function removal candidates. The current
  query omits prototypes, but compiler/preprocessing/consumer and location
  evidence is still required. Actual `DeadCodeFilter` retains all 65 checked
  originals. Adding SCC grouping alone would duplicate existing behavior.
- Whole logging-API conversions produce eleven additional structural
  opportunities, mostly severity/rate/once changes. Rate limiting can affect
  availability, argument evaluation and private state. Two `-ENOMEM` probe
  idioms need exact helper/binding/instrumentation proofs; deferred-probe reasons
  are stateful. No new logging rule is enabled from these counts.

Frozen evidence is in ignored directories:

- `benchmarks/config_fastpath/2026-11-07/` for final controls and measurements.
- `benchmarks/kbuild_diagnostic_yield/2026-11-07/` for the exact raw sample,
  complete history, independent verification, both preparation attempts and
  the `default-fast/` replay.
- `benchmarks/device_policy/2026-11-07/` for live modules, devices, policy rules,
  provenance limits and the per-callback analysis proposal.
- `benchmarks/unused_definition_opportunities/2026-11-07/` and
  `benchmarks/logging_call_yield/2026-11-07/` for new candidate pools and actual
  baseline checks.

## Source reordering and code-address observations — 2026-11-07

An independent review found two concrete runtime counterexamples to the former
default reorder rules, using actual public `FilterPipeline([RenameFilter])`
without guard waivers:

- Reordering arms containing `return observe(...)` changes the return address
  inspected by an unchanged callee. GCC and Clang at O0 produce different
  return values, while the former filter removes the change as non-lossy.
- Swapping two call-free static leaf definitions changes an unchanged integer
  comparison of their function addresses. GCC at O0 and O2 changes program
  behavior, while the former filter again removes it as non-lossy.

Checking only for a directly spelled address builtin in the moved code cannot
exclude unchanged observers. Source token equality, isolated control flow,
macro checks and physical LINE/COLUMN checks do not prove emitted code-address
equivalence. Therefore **every source reorder** now requires
`--source-pruning-lossy --source-pruning-report PATH`. The API also requires an
`on_pruned` callback. Default or unaudited reorder candidates publish no new
masks. Every acceptance is marked `lossy=true` and adds these risks:

- `function_and_callsite_addresses_may_change_runtime_behavior`
- `compiler_generated_layout_and_instrumentation_not_proven_equivalent`

Existing macro-discovery risks remain additive. A callback failure propagates;
it does not silently omit the record. This mode deliberately admits the
compiled behavior-changing controls and has no measured false-removal bound.
The default repair does not weaken any source, macro, type or context guard.

The broader braced-arm idea is not implemented. A complete original-patch
screen of all 26,670 legacy IDs finds 2,573 changed case/default-keyword patches
and sixteen whole-patch token permutations. Nine are keyword/comment false
positives; seven actually change labels. No braced-arm candidate qualifies,
and no additional whole switch candidate exists beyond the already measured
hrtimer case. Another Bluetooth arm refactor has live static-data changes in a
second file. All 34 inspected source blobs match native Git contents.

Braces and terminal breaks alone would also be insufficient: an independent
GCC/Clang O0/O2 control places static section records inside arms, then unchanged
code reads the first linker record. Reordering changes its result. Declared
storage/attributes, labels, preprocessing and other opaque effects therefore
remain barriers even to a future source-shape extension.

The latest measured seven strict structural acceptances are all diagnostic
wording changes. The eleven explicit source-lossy acceptances comprise nine
diagnostic changes, a prototype-parameter rename and the call-free hrtimer
constant-return reorder. No accepted helper or call-bearing switch reorder is
claimed safe by that inventory. This repair adds no new pruning class.

Fourteen independent after-repair controls retain both compiled counterexamples
by default and without an audit sink, and record both risks for explicit
audited removal. They also verify propagated callback failure and complete
three-stage source-tail behavior. These are concrete boundary controls, not
a whole-program equivalence theorem.

A complete after-repair kernel replay preserves all eleven default outcomes,
including the seven accepted diagnostic commits, exact masks, audit records and
remaining patches. A separate 640 MiB-bounded lossy replay stops before
completing a macro query; that partial run does not establish an acceptance count.
After checking available host memory, a separately bounded lossy-only run uses
an 896 MiB hard limit, zero swap, the same production four-worker queries and
reader rotation. It completes in 102 seconds with 620.9 MiB sampled combined
RSS. All eleven removals, masks, remaining patches and audits match the prior
complete baseline; the only audit additions are the two hrtimer address/layout
risk labels. The smaller-cap attempts remain preserved as incomplete results.
The final suite passes 1,249 tests, mypy checks 65 Python files and all 66
packaged Python/C++ sources match the wheel. A later test-only coverage
correction supplies the required callback so its macro-rejection fixture still
reaches that guard; all 138 focused source/reorder tests then pass.

An isolated resource comparison completes the exact offending query at four,
two and one Git workers. Each emits the identical ordered 417,925-byte /
3,131-row stream, including all checked row/byte budget prefixes. Four workers
take 8.08 seconds with 451.7 MiB native peak RSS; two take 12.10 seconds with
413.1 MiB; one takes 20.68 seconds with 373.3 MiB. These are local single-query
measurements, not whole-pipeline throughput. Git 2.55's
[versioned implementation](https://github.com/git/git/blob/v2.55.0/builtin/grep.c#L141-L176)
flushes buffered worker results in input order. The measured memory savings do
not justify a default slowdown, so production retains four workers.

A separate current input audit still finds no matching target bundle in the
declared local kernel/artifact stores. The supported challenge 7.1.2.a template
exposes remote Image/initramfs paths, but no pinned source, dirty/generated
inputs, kernel/vendor actions, original ABI list, ordered link inputs or debug
encoder provenance. This is a scoped availability check, not a claim that no
such files exist elsewhere. No source/policy guard is relaxed on that basis.

Evidence remains in ignored directories:

- `benchmarks/switch_block_review/2026-11-07/` for compiled controls and actual
  before/after public-pipeline decisions, including the distinct
  `lossy-only-896MiB/` completed replay.
- `benchmarks/source_reorder_yield/2026-11-07/braced-arm-screen/` for the exact
  original cohort screen and accepted-set classification.
- `benchmarks/reorder_address_guard/2026-11-07/` for final verification.
- `benchmarks/macro_grep_threads/2026-11-07/` for isolated ordered-output,
  memory and timing comparisons without changing production resource flags.
- `benchmarks/proof_input_audit/2026-11-07/` for the current supported-template
  and declared-store check.

## Shared raw-input consumer veto — 2026-11-07

A C-source comparison cannot establish that comments or inactive C text have
no runtime effect when another language or generator reads the original bytes.
Independent compiled controls demonstrate four actual false removals in the
previous committed public pipeline:

| Consumer | Former pruning | Observed behavior with GCC and Clang O2 |
| --- | --- | --- |
| Assembly `.incbin "api.h"` | Whitespace/comment equivalence | Header comment changes exit 7 to 8 |
| C inline assembly `.incbin "api.h"` | Whitespace/comment equivalence | Header comment changes exit 7 to 8 |
| Assembly `.include "api.h"` | Numeric constant-branch equivalence | Text inside C `#if 0` changes exit 7 to 8 |
| Unchanged Linux `lib/build_OID_registry` | Whitespace/comment equivalence | OID comment 1.2 to 1.3 changes generated byte/exit 42 to 43 |

The fourth control uses the actual unchanged kernel Perl generator and its
explicit Make prerequisite. This is evidence about generator semantics, not
an authenticated challenge 7.1 kernel build. The same original commits,
source blobs and binaries are replayed after the repair; all four changes are
retained without new masks or pruning audits. An ordinary C preprocessor
header-comment dependency remains prunable with unchanged exit 0.

All semantic source stages now consult the same typed
`FilterContext.input_roles` provider immediately before publishing masks:
whitespace, numeric constant branches, configured branches, unused definitions,
renames/reorders and policy exclusions. Both original historical sides and
paths are checked. A known raw consumer or unresolved recognized inventory
retains the candidate. Policy exclusions become `unknown` with a specific
reason. Previous masks are preserved, and failure adds no speculative masks.
Selection rules do not claim source equivalence and do not need this lookup.

The default implementation is a positive inventory of assembly inputs and
explicit Make generator prerequisites, with bounded file facts, revisions and
Git streams. It is shared across stages, starts only for an otherwise eligible
candidate and updates from exact historical revision deltas. Standalone batch
wrappers now pass their borrowed reader through the context as pipelines do;
a regression verifies one index and one reader across multiple commits.
Successful scans with no recognized consumers do **not** certify complete
build-input closure. Arbitrary scripts, computed rules, external inputs and
unrecognized language consumers still require stronger evidence. No empty
inventory establishes build absence, safe hardware absence or closed policy
reachability. This repair tightens retention and claims no extra pruning gain.

The first kernel-scale discovery probe is preserved as incomplete. Its global
path-only native Git search crosses a 448 MiB sampled combined-RSS stop at
7.57 seconds (481.03 MiB sampled peak); the 512 MiB hard cgroup records no OOM
and a 129.5 MiB charged peak. Shared mapped pages and differently charged cache
pages make RSS and cgroup accounting distinct. This attempt does not establish
cold-scan completion, candidate outcomes or throughput. The subsequent bounded
implementation and replay are measured separately.

Evidence is local and ignored:
`benchmarks/source_raw_roles/2026-11-07/` contains the frozen before package,
compiled witnesses, unchanged-binary after replay and stage integration checks;
`benchmarks/raw_input_index/2026-11-07/` contains positive-index controls and
bounded kernel probes. Tests and these temporary/benchmark artifacts are
excluded from milestone commits under the user's repository-only commit rule.

Kernel-scale checks also exposed two performance problems in retention. A
local Make expansion-budget failure initially aborted the whole inventory;
it now becomes a cached uncertainty for that fully read file. Other files are
still scanned within the aggregate limits, and the completed positive inventory
can update incrementally. Aggregate input, tree, reference, delta and native
failures still invalidate an incomplete scan.

A second bounded replay was deliberately stopped after 152/515 originals and
241.53 seconds of worker time. It produced no complete cohort count. Sparse
historical revisions exceeded the delta budget often enough to repeat cold
scans, while unchanged unresolved consumers already justified retention.
The retention-only provider now verifies an unchanged regular consumer's
file-local uncertainty witness at each new revision and can retain immediately.
Changed or missing witnesses fall through to the full inventory. Neither empty
observations nor aggregate/operational failures are witness authority. The full
`RawInputIndex.lookup` inventory API remains separate from this shortcut.
All interrupted attempts and their source hashes remain preserved; they are
not counted as complete throughput or pruning measurements.

The next pruning opportunity is to narrow unresolved consumer scope using a
matching build/input inventory, rather than treating a missing reference as
proof. Recognized raw consumers remain a hard veto. A future explicit,
audited assumption about unsupported input roles could offer a separate
tradeoff, but the existing line-number and source-pruning lossy flags do not
waive raw-input uncertainty. Retained candidates must not be relabeled as
confirmed runtime changes merely because their consumer scope is unresolved.

Any future input-role assumption must request the full recognized inventory
before considering removal. The retention-only witness shortcut may omit other
positive consumers because its uncertainty already blocks masks; simply clearing
that uncertainty would lose the hard raw-consumer veto as well.

The final paired replay **completed all 515 unchanged original whitespace
candidates**, using the default provider and fresh masks for both stages:

| Whitespace mode | Historical whole removals before raw-input veto | Current whole removals | Current retained |
| --- | ---: | ---: | ---: |
| Strict | 172 | 0 | 515 |
| Explicit audited line-number-lossy | 381 | 0 | 515 |

Every current output preserves the complete original patch hash and has no
new code masks, edit masks or pruning audits. This fixed candidate set is not a
random sample of all kernel commits or a whole-pipeline regeneration. The
retention is conservative: unresolved consumer scope does not demonstrate
that each formerly pruned change affects runtime. The four compiled controls
are separate positive evidence of real behavior changes.

The completed paired worker takes 365.46 seconds; the external monitor takes
366.45 seconds, with 752.6 MiB sampled combined RSS and a 313.6 MiB cgroup peak
under an 896 MiB hard limit, zero swap and no OOM events. These accounting
measures differ because of shared mappings and cache charging. The run uses
seven cold inventories, 370 witness reads, 364 verified unchanged-witness hits
and 366 revision-veto cache hits. No assertion of additional pruning or preserved
historical throughput follows from this single local measurement.

Final verification passes all 1,296 tests, including captured binary SELinux
policy integration. Mypy checks 66 Python sources, and all 67 packaged Python/C++
sources match the built wheel. Independent review rechecks the retention-only
shortcut, uncertainty recovery, aggregate-failure boundaries and the unchanged
compiled controls. Production/test hashes remain frozen through verification.
The completed replay is in
`benchmarks/source_raw_roles/2026-11-07/whitespace-replay-final/`; final tests and
package evidence are in its sibling `verification/`. Earlier interrupted
attempts and pre-repair verification directories remain separate.

## Audited assumptions for unresolved input expressions — 2026-11-08

The conservative `a58ca20` checkpoint retains all 515 selected whitespace
candidates. A separate opt-in now addresses that known source of lost yield:
`--unresolved-inputs-lossy --input-role-report PATH`. It assumes that specified
unsupported Make/assembly input expressions cannot observe the affected source
changes. It does not silently alter the default or the existing rename and
line-number assumptions.

The inspection estimate before implementation was at most 154 whole strict
removals and 355 with the additional line-number assumption. Those are optimistic
ceilings derived from the prior witness-only observations, not measured recovery.
A subsequent full representative inventory found additional positives, including
an unrelated `device.h` basename consumer, that the shortcut omitted. In that
revision, six of 226 unique historical strict-pruned paths and eight of 418
line-mode paths had positive matches. These are revision-local diagnostics, not
an estimate of how many whole historical commits are safe or removable.

The implementation separates operational scan state, typed semantic unknowns
and hard failures. Assumed removals require full recognized inventories on both
original sides, no observed positive raw consumer and no hard failure. It can
waive only Make operands, assembler operands and bounded Make expression
expansion. Evidence includes the exact consumer path, line, operand and source
SHA. Independently discoverable literals survive a capped expansion and later
rules/ASM still receive inspection. Aggregate references, bytes, paths, files,
tree rows, revision deltas and native/read/parse failures remain hard barriers.

Nine symlinked PowerPC assembly consumers had previously produced opaque-role
facts. Generic bounded historical resolution now verifies regular targets and
refreshes alias facts even when only a target changes. Missing, external,
cyclic or nonregular targets still block. This uses no test-directory or
architecture exemption. Alias unknown evidence identifies the actual target
bytes, and aliases cannot seed the regular-file retention witness.

All six semantic stages carry a typed mask plan to the same publication helper.
It validates role/evidence consistency, writes the mandatory assumption audit
before masks, propagates callback failure, and annotates affected stage records
as lossy. Rename and policy gather every file's role decision before publishing
any of the operation. Unused-code analysis now uses a private preview so chained
unused proofs still work while the real commit remains unchanged until audit.

The existing four compiled raw-consumer counterexamples and two mixed-literal /
129-name expansion controls retain in both modes. An adverse Make-include
control **is removed only by the explicit assumption**, while GCC and Clang
both demonstrate runtime exit 7 changing to 8. Thus the mode is intentionally
lossy and has no measured false-removal bound. No estimate about the low rate
of real changes is inferred from recovered counts.

Actual preflight uses two complete original kernel commits. Binder `2a8f84b5…`
is retained by default and whole-pruned under both assumed modes with mandatory
side evidence. i3c `0d2c022f…` remains retained in all modes because the current
conservative basename index reports the EISA `device.h` consumer. Both originals'
parent/child full inventories have no hard failures after alias resolution;
they retain supported semantic unknowns. The preflight is not a population
result. Full sample outcomes are recorded separately after completed replay.

The implementation/API and CLI are documented in
[SOURCE_INPUT_ROLE_ASSUMPTIONS.md](SOURCE_INPUT_ROLE_ASSUMPTIONS.md). Ignored
artifacts are under `benchmarks/source_role_assumptions/2026-11-07/`,
`benchmarks/typed_input_role_preflight/2026-11-07/` and
`benchmarks/input_role_assumption_characterization/2026-11-07/`. Only code and
durable documentation will be included in the milestone commit.

The population experiment interleaves default strict, default line-number,
assumed-input strict and assumed-input line-number modes for each unchanged
original, sharing a bounded reader/provider. All modes use fresh commit masks.
This measures that paired replay order; it is not an independent CLI throughput
or unconditional per-profile yield promise. Snapshot/delta budgets and cache
history can change conservative retention coverage. The audit output is streamed
rather than retaining every repeated consumer-evidence record in memory.

The completed four-mode replay covers all **515** unchanged originals with
fresh masks. The results below are whole-commit removals in that selected
candidate set; the cohort column divides those identities by the original
26,670 legacy IDs and is not a random-sample extrapolation:

| Mode | Whole removals / 515 | Selected candidates | Original cohort | Additional partial commits |
| --- | ---: | ---: | ---: | ---: |
| Default strict | 0 | 0% | 0% | 0 |
| Default with line-number assumption | 0 | 0% | 0% | 0 |
| Input assumption, strict line checks | 103 | 20.0% | 0.39% | 9 |
| Input assumption plus line-number assumption | 229 | 44.47% | 0.86% | 14 |

The 103 are a subset of the 229. Accepted whole identities remain subsets of
the historical 172/381, respectively. There are 152 and 321 published file
masks, each with one mandatory input-role audit and one decorated stage audit.
Every accepted side has a full recognized inventory, no positive match and no
hard failure. Defaults preserve every original patch and publish no masks or
audits. These are assumption-qualified removals; the adverse compiled control
prevents any claim that their false-removal rate is zero or bounded low.

Of the historical strict wholes now retained, 68 hit the unchanged revision-delta
path budget and one has an observed positive match. The corresponding line-mode
counts are 145 and seven. These are retained because evidence is incomplete or
conservatively matched, not because every one is a demonstrated runtime change.
They identify a concrete next opportunity: stream exact changed-consumer facts
within separate bounded raw-row and consumer budgets instead of letting
irrelevant changed paths trigger repeated cold scans. The current measurement
keeps the existing budget; it has not been widened to achieve these counts.

The paired worker completes in 1,094.73 seconds (1,095.65 including the monitor),
with 743.7 MiB sampled combined RSS and a 778.8 MiB cgroup peak under the fixed
896 MiB hard limit, no swap and no OOM events. Its 23 cold inventories, 460
incremental updates and 1,303 marker queries account for 703.59 seconds of
inventory scanning. This is the measured four-mode experiment, not a single CLI
throughput estimate.

A separate completed structural accepted-set replay records all 33 outcomes
across three modes on eleven original commits. Default source pruning removes
none. The input-assumption profile removes two diagnostic-wording commits;
adding the existing audited source-lossy profile also removes two, with different
identities because the shared index's hard budget history differs. Hrtimer
reordering and the prototype rename remain retained. No 7/11 or 11/11 recovery,
profile monotonicity, additive cohort total or new reorder gain is claimed.
All four accepted records have the required input and source audits.

Final verification passes 1,322 tests, including the captured real SELinux
policy integrations; mypy checks all 68 Python sources and all 69 packaged
Python/C++ sources match the wheel. The compiled and independent integration
controls remain on the same frozen production hashes as the complete replay.
Population artifacts are in the `population/` directory under the source-role
assumption evidence root; `structural-replay/` contains the separate small-set
experiment. Its counts must not be silently added to the paired population run.

Independent final artifact verification covers all 515 original identities and
473 published masks/audits. A separate bounded native Git oracle verifies every
one of the 41,232 distinct historical consumer revision/path coordinates and
all 418 unique path/SHA pairs against actual regular Git blobs. It completes in
38.81 seconds using 535 batched literal tree queries and 418 blob reads
(7.97 MB), with no swap or OOM. This verifies evidence provenance, not the truth
of the deliberately lossy assumption about those unresolved consumers.

## Exact streaming consumer updates — 2026-11-08

The `7491d42` replay recovered 103/229 whitespace wholes under explicit input
assumptions, while 68/145 historical wholes were still retained on the old
1,024 changed-path limit. The index first materialized and counted every changed
path, including ordinary C code and documentation, before checking which paths
could affect the supported consumer inventory. Sparse revisions repeatedly hit
that limit and later forced cold scans.

Updates now stream the complete raw Git diff. Every changed path removes its
old facts, link and alias membership, including deletes and type transitions.
The cold scan and incremental scan share the same dispatch: Make paths and
symlinks are processed directly; only existing recognized C/ASM suffixes go to
marker batches of at most 2,048 paths / 64 KiB. Other regular data/docs are
neither searched nor parsed. Final link/target state is applied to all consumer
aliases before rebuilding the positive/unknown/failure indices.

This removes the all-changes dictionary and its 1,024-path cap. Separate hard
limits of 500,000 raw rows and 16 MiB encoded path bytes bound the stream;
`delta_row_budget` and `delta_path_budget` replace the obsolete failure kind.
Header buffering is limited by native OID width. Both NUL fields, including the
last pathname terminator, normalized UTF-8 paths, modes/OIDs/status and native
success are required. A late producer/marker error or limit leaves the child
incomplete and the anchor unchanged. Existing actual consumer work limits,
global references and content caches remain in force. No new semantic or
lossy assumption is introduced.

Successful recognized data is compared against separate fresh cold indices.
This does not promise identical operational failures: a warm inventory may reuse
facts that a cold inventory must reread within its work budget. The existing
per-update read budgets and global reference limits are unchanged; no new
snapshot-cardinality policy is inferred from this improvement.

Fifty-eight focused tests cover the existing index and the new implementation /
independent delta controls. They include more than 1,024 irrelevant changes with
a late positive consumer, both marker-batch boundaries, aliases through hidden
extensions, target-only changes, renames/deletes/mode transitions, SHA-256 Git
repositories, LF/colon/glob/Unicode names, exact limits, malformed metadata,
truncated final NULs and real producers that exit after valid rows. Every late
failure remains incomplete and reaps its native process. All eight saved compiled
controls retain their prior default/assumed outcomes, reusing the same 32 GCC /
Clang executable runs.

A real original `d60f2280…` (`lib/lockref.c`) provides the first actual recovery.
Starting from the recorded anchor `4477b060…`, the committed baseline retains it
because parent/child inventory updates hit `changed_path_budget`. The new
strict whitespace stage with the same explicit input assumption whole-prunes it
with both required audits. Parent and child inventories each contain 3,322
facts, 62 links and nine aliases and exactly match independent fresh cold data
across files, links, aliases, unknowns, failures and positive maps. The new
pipeline takes 2.57 seconds after a 24.06-second anchor seed; fresh parent/child
oracles take 24.64/24.39 seconds. These local timings are not an independent
throughput benchmark. The one separately bounded comparison finishes in 102.72
seconds, under its 896 MiB hard / 832 MiB RSS limits, without OOM or swap.

All 1,341 tests pass, including captured binary SELinux integration; mypy checks
68 Python sources and all 69 packaged Python/C++ sources match the wheel. The
large paired replay uses the previous experiment's unchanged original order,
four modes, shared cache/reader, fresh masks and resource caps. Final population
counts are recorded only after completion and independent artifact verification.
Evidence lives in ignored `benchmarks/streaming_input_delta/2026-11-08/` and
`benchmarks/input_role_streaming_delta/2026-11-07/` directories.

The completed same-order four-mode replay covers all 515 originals. Only the
index implementation and its typed operational-limit names differ from the
`7491d42` baseline; flags, source proofs, original masks and consumer scope are
unchanged:

| Mode | Before streaming | After streaming | Additional whole removals | Original 26,670 cohort |
| --- | ---: | ---: | ---: | ---: |
| Default strict | 0 | 0 | 0 | 0% |
| Default line-number mode | 0 | 0 | 0 | 0% |
| Explicit input assumption, strict lines | 103 | 168 | 65 | 0.63% total |
| Explicit input plus line-number assumptions | 229 | 369 | 140 | 1.38% total |

The new assumption-qualified totals cover 32.62% / 71.65% of the selected 515,
with 12 / 20 additional retained partial commits and 246 / 503 published file
masks. No previously accepted whole identity is dropped. The 168 remain a subset
of 369, and both remain within the historical 172/381. The four / twelve
historical whole candidates still retained have observed positive consumer
matches. No revision-budget failure accounts for those remaining cases in this
completed sample. A positive includes conservative basename matches, so this is
not a count of proven runtime-changing commits.

The paired worker takes 936.75 seconds versus 1,094.73 before (14.43% lower
elapsed time in these local runs); the monitor takes 937.68 seconds. It performs
one cold inventory instead of 23, and 766 incremental updates instead of 460.
Marker queries fall to 931 from 1,303. Across all updates it validates 560,830 raw rows
and considers 519,041 candidate paths, rebuilding 14,349 consumers. The raw-row
and encoded-path limits apply separately to each revision update, not to these
cumulative counters. Peak sampled combined RSS is 786.5 MiB and the cgroup peak
is 829.0 MiB, under the unchanged 832 MiB RSS / 896 MiB hard limits with no OOM or
swap. Memory is slightly higher than the previous 743.7/778.8 MiB run; streaming
Python metadata does not bound Git's internal diff queue. These are paired
experiment measurements, not a universal speed or memory guarantee.

The separate structural replay fully completes default 0/11 and input-assumed
strict 7/11 (previously 2/11), recovering all seven historical diagnostic-wording
cases. The combined source-lossy profile stops at its original 295-second limit
after six of eleven commits: five whole removals and the positively matched
prototype retained, with five outcomes unresolved. Its hrtimer reorder is
actually removed only with the existing source-lossy flag, recording both
code-address/layout risks and the input-role risk. This partial profile is not
reported as a complete five/eleven result, and no source profiles are added to
the separate population's cohort percentage. No retry or guard override was
used to complete it.

Independent verification checks all 515 original identities, all 749 published
file masks with their mandatory and stage audits, strict/line subset relations,
and zero lost masks or whole removals from `7491d42`. A separate fresh native Git
oracle verifies all 65,142 historical revision/path coordinates and all 477
unique path/SHA pairs from accepted-mask evidence against regular Git blobs.
It uses 845 literal batched tree queries and freshly hashes 477 blobs (10.84 MB),
finishing in 74.33 seconds with no swap or OOM. All production hashes match the
full test suite and packaged wheel. These checks establish evidence provenance
and implementation consistency; they do not establish the truth of the explicit
lossy input assumption or a bound on false removals.

Further basename precision needs typed operand-origin and match-provenance
records before it can justify narrower matching. A name may come from a direct
prerequisite, a harvested variable value or a contextual expansion. Make's
`src`, `obj` and `srctree` bindings, nested includes, assembler search paths, and
generated/external aliases are not pinned by this index. Directory spelling
alone cannot certify an exact-only reference. Removing basename fallback, or
turning a positive match into waivable uncertainty, would change the assumption
boundary rather than provide another exact optimization. Preserve these vetoes
until the relevant invocation and binding evidence is available.

## Directive-ending lines and multiline comments — 2026-11-08

The preceding layout comparator missed a physical directive-ending line when
all real tokens retained their coordinates. In a compiled control, adding a
trailing standard splice to `#line 100` and removing the next blank line changes
GCC's later `__LINE__` from 101 to 100; Clang keeps 101 in this example. The old
strict comparator accepted both. GNU line markers and an included line alias
expose the same issue. These are host language controls, not target-kernel
build-equivalence certificates.

The strict line digest now includes every directive terminator's physical start
line, mapping after removed splices. A synthetic EOF terminator uses that same
anchor, preserving explicit-LF versus implicit-EOF equivalence. Terminator
columns remain irrelevant, so trailing comment widths are not newly significant.
The existing line-number-lossy mode can still waive these line observations
with its mandatory audit; no new flag or assumption was added.

This also permits multiline block comments within directives: the located lexer
already keeps a directive active across a comment's internal newlines. Layout
uses comment normalization only for validity, then compares the complete located
tokens. Shared line-based CPP, macro, include and diagnostic consumers retain
their stricter normalization checks. Token/gap/column, unsupported-input, raw
consumer and resource guards are unchanged. See
[the updated contract](WHITESPACE_PRUNING.md).

All 1,344 tests pass, including the captured binary-policy integrations; mypy
checks 68 Python files, and all 69 packaged Python/C++ sources match the wheel.
Independent validation covers 21 controls and 84 actual public-filter runs.
Strict mode retains the behavior-changing line controls even with the separate
input assumption. A real `.incbin` control observes changed comment bytes and
remains retained in every mode, with zero masks or audits. EOF, CRLF, spliced
comment delimiters, macro spacing, stringification gaps, byte columns and header
ambiguity controls pass. Frozen evidence is under ignored
`benchmarks/directive_layout/2026-11-08/` and
`benchmarks/layout_directive_review/2026-11-08/`.

A targeted actual replay completes all 44 runs over the 11 formerly unsupported
originals and their 39 changed files. Both default profiles remove zero wholes.
With the existing input assumption, strict lines remove one whole (`fc76b596…`,
`exportfs.h` documentation); the line-number assumption removes ten. The
27-file `62451ae…` stays retained in every profile because `mm/memblock.c` has a
positive source-copy consumer; its other 26 files receive partial masks in the
assumed profiles. All 65 published masks retain their mandatory/stage audits,
and independent checks find no dropped prior masks. These are targeted replay
results, not a recomputed 515-candidate total.

The run takes 102.93 seconds with 698.4 MiB sampled combined RSS and 178.5 MiB
cgroup peak, under the 896 MiB hard / 832 MiB RSS limits, with no OOM or swap.
All original patches and 77 distinct historical source coordinates are checked,
and the 69 frozen package sources remain unchanged. No positive consumer or
operational failure is waived. The evidence is in the `preflight/` directory
under the directive-layout root.

The completed same-order 515-original replay uses fresh masks, all four existing
profiles, the shared production reader/provider and the same resource limits:

| Mode | `d87c33c` baseline | After directive repair | Additional wholes |
| --- | ---: | ---: | ---: |
| Default strict | 0 | 0 | 0 |
| Default line-number mode | 0 | 0 | 0 |
| Existing input assumption, strict lines | 168 | 169 | 1 |
| Existing input plus line-number assumptions | 369 | 379 | 10 |

Strict/line profiles publish 248 / 514 file masks and retain 12 / 19 additional
partial commits. No previous whole ID or mask is dropped, and default outputs
remain identical. The whole totals cover 32.82% / 73.59% of the selected 515, or
0.63% / 1.42% of the original 26,670 legacy survivors. The incremental gains are
only 0.00375 / 0.03750 percentage points of that larger cohort. These are
stage-specific, assumption-qualified measurements, not a regenerated complete
pipeline rate or a false-removal bound. The former 172/381 historical sets are
no longer a syntax-support ceiling: new accepted IDs include formerly
unsupported directive-comment files.

The worker completes in 950.80 seconds (951.75 including its monitor), versus
936.75 in the preceding local run. This does not demonstrate a speedup. Peak
sampled combined RSS is 816.6 MiB and cgroup peak 559.6 MiB, within the unchanged
832 / 896 MiB limits, with no OOM or swap. Python/Git shared-page accounting and
host cache state limit comparisons between these sequential experiments. The
worker is reaped, and all 69 production hashes still match the frozen tests/wheel.
Each authorized replay runs once; no guard override or timeout retry is used.

Independent final verification rereads all 515 originals and all 762 published
mask/audit events, reconstructs every materialized patch, checks strict/line
coverage and confirms zero dropped prior masks or removals. A fresh bounded
native Git oracle verifies all 66,526 historical unknown-consumer source
coordinates and all 478 unique path/SHA evidence pairs against regular blobs,
using 862 literal tree queries and 478 freshly hashed blobs. It completes in
72.76 seconds, exits successfully and reaps its worker without OOM or swap.
All source/test hashes still match the completed test and wheel checks. This
establishes evidence provenance and implementation consistency, not the truth
of the explicit input/line assumptions or a bound on false removals.

## Macro-definition comment precision — 2026-11-08

The previous layout validity check treated a `<` in a numeric shift or
comparison inside `#define` as a possible header opener. Comments after it then
made the complete file unsupported, even when the patch only changed wording.
Macro replacement comments are consumed while defining the macro, before later
expansion can give the resulting tokens an include/header role.

Layout now admits such comments only inside complete lexical `#define` /
`%:define` intervals from the shared lexer. Discovery is lazy on the first
ambiguity, finishes before granting any range and reuses that result for the
rest of the scan. The normalizer and lexer each splice the original text once;
logical-character offsets then agree. The private admission callback shares
the existing validator, while its public line-based API always denies these
angles and keeps its old signature and behavior.

The proof counts semantic tokens under the selected ordinary-newline mode and
includes directive/synthetic-EOF terminators. Extra ordinary-newline traversal
is bounded by the original LF count, without increasing the semantic cap.
Only completed layout facts are cached. Token/gap/location, raw-input and all
other unsupported-context guards remain in force; no flag or assumption is added.

Two compiled boundaries prevent a broader shortcut. An included `HAS` alias for
`__has_include` makes an actual `#if HAS(<foo/*x*/bar.h>)` change runtime from
1 to 2 when x becomes y, under both GCC and Clang. A leading-comment construction
also exposes a second apparent splice after the first pass: incorrectly
splicing twice shifts a later definition interval over that same unsafe `#if`.
Both cases remain retained in all four public filter modes. The macro-body
variant is constant 2 to 2 and can qualify. Header/import/conditional/pragma and
computed contexts keep their existing angle/comment refusal.

Independent review passes 34 compiled controls and 136 public-filter mode runs,
including the prior directive-ending-line, raw `.incbin`, byte-column, gap,
CRLF and EOF cases. Seventy-four comparisons against the previous public
normalizer match exact output/None behavior in both strict modes. Eighteen
additional focused tests cover typed offsets, exact-once splicing, complete
discovery, mixed contexts, lazy/empty/failure caching and both token-budget
modes. Evidence is in ignored `benchmarks/define_layout_review/2026-11-08/`
and `benchmarks/whitespace_recovery_options/2026-11-08/angle-context-review/`.

All 1,362 full-suite tests pass, including the captured binary SELinux policy;
mypy checks 68 Python sources, and the wheel matches all 69 packaged Python/C++
sources. All 142 source/test paths remain byte-identical across verification.

Before the actual policy replay, the complete original-source census covers
24 originals / 32 changed files, including every companion file. It predicts
11 strict / 23 line-assumed whole candidates from previously unsupported files.
Exact historical Make/source evidence already blocks two strict and four
line-mode originals, leaving conditional ceilings of nine / nineteen. These
are candidate ceilings, not accepted removals or a low-risk estimate. Consumer
evidence must be tied to each exact revision: a later `fs.h` generator spelling
cannot be projected backward into an earlier source tree. The separate forecast
is in ignored `benchmarks/define_body_policy_forecast/2026-11-08/`.

The actual 24-original / four-mode preflight completes all 96 fresh views.
Default profiles remove zero wholes. Existing input assumptions permit six
strict / fifteen line-mode whole removals, with 10 / 20 file masks and one
retained partial in each profile. Against the previous implementation's exact
24 rows, gains are six / fifteen wholes and seven / sixteen masks, with no drops.
Independent verification reconstructs every resulting patch, checks all 30
stage/mandatory-audit pairs and freshly verifies all 63 distinct historical
changed-source coordinates (64 sides / 32 file pairs).

All four previously known positive-consumer originals remain retained, with
their six observed paths unmasked in every profile. The additional three
strict / four line-mode misses from the forecast also have FULL observed
positive header-install consumers (`tools/lib/perf/Makefile` or
`tools/lib/api/Makefile`), including conservative basename matches. They have no
layout/hunk/mode mismatch or operational failure. These observations are
retention evidence, not a proof that each comment changes runtime. None of
these positives is waived to improve the count.

The worker takes 147.41 seconds (148.58 including its monitor), with 731.8 MiB
sampled combined RSS and 180.0 MiB cgroup peak under the unchanged 896 MiB hard /
832 MiB RSS limits, no OOM or swap. All 69 frozen sources remain identical and
the worker is reaped. These targeted results must not be presented as an updated
515-candidate total; that separate same-order replay is independently audited.
The preflight evidence is under ignored
`benchmarks/define_body_layout/2026-11-08/preflight/`.

The separate full same-order replay completes all 515 originals, preserving the
four profiles, fresh masks, shared actual reader/provider and resource limits:

| Mode | `51d0aad` baseline | Macro-definition precision | Additional wholes |
| --- | ---: | ---: | ---: |
| Default strict | 0 | 0 | 0 |
| Default line-number mode | 0 | 0 | 0 |
| Existing input assumption, strict lines | 169 | 175 | 6 |
| Existing input plus line-number assumptions | 379 | 394 | 15 |

It publishes 255 / 530 file masks in the assumed profiles, including eleven /
seventeen retained partial commits. All six / fifteen whole additions exactly
match the targeted replay, with seven / sixteen additional file masks and no
dropped prior masks or whole IDs. Default outputs remain identical. The totals
cover 33.98% / 76.50% of the selected 515, or 0.66% / 1.48% of the original
26,670 legacy survivors. Incremental gains are 0.02250 / 0.05624 percentage points
of that larger cohort. These are stage-specific results under the existing
explicit assumptions, not whole-pipeline rates or a false-removal bound.

The worker takes 1,039.99 seconds (1,041.03 including its monitor), versus 950.80
before: 9.38% longer in these sequential local experiments. New supported files
require additional proof and consumer queries; this is not a speedup claim.
Peak sampled combined RSS is 814.5 MiB and cgroup peak 847.8 MiB, below the same
832 / 896 MiB limits with no OOM or swap. Cgroup memory is higher than the prior
559.6 MiB run; shared pages and host caches also limit direct comparisons. The
worker exits successfully and is reaped, all 69 executed sources still match the
frozen tests/wheel, and neither replay is retried or given a guard override.

Independent final auditing rereads all 515 original identities and all 785
stage/mandatory mask events, reconstructs every output patch and checks every
known or previously observed positive-consumer path remains unmasked. Strict
results remain covered by the line mode; no prior ID or mask is dropped. A fresh
bounded native oracle verifies all 68,613 historical unknown-source coordinates
and 479 unique path/SHA pairs against regular Git blobs, using 887 literal tree
queries and 479 freshly hashed blobs. It finishes in 78.99 seconds, exits zero
and reaps its worker with no OOM or swap. All 142 source/test hashes still match
the full suite and package checks. These checks establish evidence provenance
and implementation consistency, not a false-removal bound for the existing
explicit assumptions.

A saved-data frontier review finds all 308 measured ambiguous comment sites in
macro definitions and none in pure-numeric `#if` / `#elif` contexts. The remaining
`kernel/sched/debug.c` raw-prefix refusal is a real false alarm on an ordinary
`">R"` string, but removing it in isolation adds zero candidates: the patch also
changes `#define` to `# define`, affecting token gaps and byte columns. No further
guard relaxation is shipped for that zero-gain case. The reviewed broader source
inventories likewise identify no substantial unclaimed exact source-only class;
matching target/compiler inputs and caller closure remain the useful next
frontier for policy, hardware and more general unused-code exclusions. This is
an evidence-scoped assessment, not proof that no other opportunity exists.
The report is in ignored `benchmarks/source_frontier_after_define/2026-11-08/`.

## Local reference build and differential compilation — 2026-11-08

The user supplied the following local tree as the closest available source for
a kernel distributed as a binary:
`/home/jack/Documents/college/purdue/research/linux_src/linux`. The checkout is
upstream Linux 6.6.50 at `ad07a29023cebd40848fce81e6732d671ede5fe6`; its existing
object store also contains the upstream 6.6.46 tag, peeled to
`99fd042016c7489192d05ff21a10620c2142301d`. No network clone or duplicate history
pack was needed. The user's HEAD, index, tracked files and personal untracked
files remain unchanged. Reference identity is recorded independently of the
captured Android kernel's reported 6.6.46 version.

A bounded applicability screen compares 52 complete original patches with both
references. It uses all original hunks and companion files, without earlier
stage masks or a reconstructed partial patch:

| Population / result | Each reference |
| --- | ---: |
| Selected syscall-body originals | 32 |
| Selected single-C static-body originals | 20 |
| Complete context-aligned originals | 10 |
| Inapplicable originals | 36 |
| Originals with missing paths | 6 |

All ten aligned cases are from the syscall population; none of the twenty
static-body originals aligns. These selected counts are applicability evidence,
not a random-cohort pruning estimate. Seven matches use unique exact regions;
three further matches use successful read-only Git checks at 6.6.50 and identical
full blobs/modes at 6.6.46. The process_mrelease original examined earlier does
not apply to these reference snapshots merely because its historical objects
are available. Evidence is in ignored
`benchmarks/source_reference_reuse/2026-11-08/` and
`benchmarks/reference_applicability/2026-11-08/`.

An owned shared clone materializes only the 6.6.46 source, with an external
ARM64 build directory. `olddefconfig` and `prepare` succeed using the captured
Android configuration as input and cached Clang 18.1.8. The resolved reference
configuration differs by **410 symbols**: 203 removed, 194 added and 13 changed.
Compiler resource-directory and Nix host-tool paths are explicit. This is a
reference context, not the original Android compiler/build context. No final
kernel, module link or MODPOST is attempted; the original ABI whitelist remains
unavailable, and neither a replacement whitelist nor disabled symbol trimming
is used. Preparation takes 111.45 seconds and occupies about 1.64 GB including
the owned source, output and evidence. Independent checks verify a clean owned
source and unchanged user checkout. The preparation record also preserves an
initial subprocess HOME override; follow-on execution preserves the actual
HOME and disables compiler default configuration explicitly.

The first paired experiment uses complete original commit
`d1c735d44c12544cea9b04ca88d65c12892c0539`, which adds `unlikely()` around the
existing null-task condition in `kernel/kcmp.c`. Only `kernel/kcmp.o` is requested
from Kbuild. Kbuild also rebuilds normal preparation and vDSO prerequisites after
the recorded compiler-command change; all actual compiler commands are saved.
The original VFS-overlay replay then reproduces the native Kbuild object
**byte for byte**. The child uses the same compiler arguments, working directory,
virtual source, overlay filename and output path. Actual DWARF main-file
checksums establish that each compiler invocation read its intended full source.
Both 625-file dependency sets and all non-main dependency hashes agree.

The child object fails equality: **12 of 34 ELF sections differ**, including
`.text`, text/alternative relocations, symbols and DWARF. Both text sections are
1,520 bytes, but their instructions differ. Inequality does not itself prove
different C-level results; it does rule out claiming object identity. Different
source checksums embedded in DWARF 5 also mean raw whole-ELF equality would reject
source-changing pairs even when instructions matched. Any future projection
that omits this metadata needs its own explicit relevance contract. No BTF
equality or final linked-image equivalence is inferred from this experiment.

The pair takes 29.78 seconds, peaks at 153 MB cgroup memory and adds 21.2 MB of
owned output. The complete capsule occupies 1.66 GB with 9.20 GB free afterward;
there is no OOM or swap use. Native outputs and sidecar presence/absence are
restored, source/config/generated inputs remain unchanged, and all workers are
reaped. The independent audit verifies all 63 artifact hashes and dependency,
source-identity and restoration checks. Evidence and the captured compilation
command are under ignored `benchmarks/reference_build_66/2026-11-08/`, including
`independent-review/kcmp-probe-review.json`.

For future incremental analysis, reuse the prepared source/build and recorded
native commands, check full-patch applicability first, and recompile only affected
translation units plus changed dependencies. Keep reference-patch experiments
distinct from `RevisionCompiler`'s actual revision overlays: its revision IDs
must continue to identify real Git snapshots. The existing build-context API
can describe a frozen reference context, but a single compilation-database entry
does not certify whole-kernel caller or build-input closure. No context was
captured here; extraction would require a matching Clang 18 worker, and missing
TU commands remain unknown. Otherwise eligible policy files with BTF enabled
still retain as `emitted_btf_equivalence_unproved`; kcmp without a raw seccomp
profile is outside the modeled entry-gate subset even before that guard.
The captured binary
policy and live observations remain useful independently. Unknown Android source,
vendor inputs, caller/service paths and emitted metadata cannot be replaced by
the reference version number. No production exclusion guard changes here.

The larger future opportunity remains configuration-model absence. A saved-only
reassessment of the earlier 500-original raw January 2025 sample reduces its
274 diagnostic whole candidates to **268 / 500 (53.6%)** after conservatively
protecting 3,859 distinct paths from recorded compiler inputs, reference kcmp
dependencies, upstream candidate module inputs and known raw consumers. The six
additional vetoes touch `security/lsm_audit.c` and Qualcomm SCM sources. These
positive protections come from several explicitly recorded contexts; their
absence is not negative evidence. The old sample uses a different configuration
and is not the 26,670-survivor population. No new-config replay or pruning occurs,
and no false-removal rate is established.

A prospective audited reference-model scope needs typed membership, semantic
gaps and hard-failure provenance first. Currently `modeled_inclusion()` returns
a mode or `None`, and `KbuildDirectory._read_optional()` collapses optional-file
absence and native Git failure into the same result. Those saved unknowns cannot
be retroactively called complete model evaluations. Keep observed inputs as
positive vetoes, preserve unknown actual build/CPP closure, and distinguish any
chosen model scope from Android absence. Live module names/aliases and
`modules.order` identify targets rather than their exact source members;
candidate upstream mappings are useful conservative protections only. No broad
configuration bypass is shipped. The detailed profile proposal, exact six
vetoes and reproducible saved arithmetic are under ignored
`benchmarks/reference_scope_options/2026-11-08/`.

## Boolean likelihood annotations — 2026-11-08

A separate complete screen of the fixed **26,670 original legacy survivors**
finds 26 whole-hunk likelihood-annotation candidates. A bounded full-source
inspection confirms twenty: fourteen additions, four removals, one prediction
reversal and one move/regroup, all using `likely` or `unlikely`. These twenty are
**0.0750% of the cohort**; the raw 26-case ceiling is 0.0975%. Neither number is an
additional accepted pruning rate. Three macro-replacement cases, one non-Boolean
return case and two cases outside the twenty-case source-read bound remain
unproved. The screen reads forty original blobs, 2.63 MB, in 4.54 seconds after
the 12.09-second hunk census; no whole-kernel analysis is involved.

The candidate rule must compare parsed operator trees. Erasing call tokens and
parentheses is unsound: for `x=1, y=0, z=0`, changing `if (x || y && z)` to
`if (unlikely(x || y) && z)` changes the condition from true to false under the
normal Booleanizing macro. Both have a Boolean-use site, yet different grouping.
GCC and Clang reproduce that difference at both tested optimization levels.
An independent stronger comparator substitutes the argument AST subtree only
after parsing and preserves all other operators, leaves and evaluation order.
It rejects this counterexample and confirms all twenty saved candidates.

The immediate consuming expression must also use truth value only: a condition,
logical negation, AND or OR. Casts, arithmetic, comparisons, arbitrary arguments,
returned values, `sizeof`/`typeof` and ternary value arms remain outside the rule.
The independent controls cover these restrictions in seventeen small programs
across two compilers and two optimization levels.

Actual annotation binding is a separate requirement. Ordinary functions,
custom macros, forced definitions and branch-profiling variants can add effects.
Wrapper insertion also moves argument columns; included location-sensitive
macros can therefore change runtime values despite matching source ASTs. Raw
source consumers, compiler layout, timing/speculation and instrumentation remain
separate obligations. The kcmp object experiment supplies a concrete instruction
layout difference. Existing source/line/input assumptions do not silently grant
a new annotation policy. A future filter needs resolved bindings and positions,
plus a stated treatment of these effects, before measuring accepted incremental
yield. No annotation filter or new lossy flag is shipped. The census and stronger
review are under ignored `benchmarks/likelihood_annotations/2026-11-08/`.
