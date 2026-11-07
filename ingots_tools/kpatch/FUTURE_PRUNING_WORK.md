# Future pruning work

## Implementation status

`filter config --source-pruning` now enables experimental Tree-sitter rename
comparison and a lazy revision-specific reference index. The default pipeline
is unchanged. This implements a subset of the opportunities below: consistent
renames and changes confined to eligible definitions without found active uses.
General reordering, type/layout dependencies, target hardware detection, and
policy-aware reachability remain future work. A narrow same-file static-helper
reorder rule is now implemented.

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
No end-to-end many-commit policy benchmark has yet been run.

Benchmark Infer's compilation-database capture on the same prepared subset,
including its global dependency-scan overhead, before investing in a large custom
solver. Smatch can supply modeling ideas/positive facts, but its pruned database
and full-rebuild scripts are a poor default for this proof-oriented history pass.
Clang's new
[Scalable Static Analysis summary framework](https://clang.llvm.org/docs/ScalableStaticAnalysis/user-docs/SummaryExtraction.html)
is worth watching; its docs warn that it is rapidly evolving, so this proposal
does not assume it is a mature ready-made backend.
