# Pruning sample recheck — 2026-11-06

## Result

In a fresh sample of **100 commits surviving the current source stages**,
**45% had no further exclusion established**. The other **55% are investigation
candidates**, divided into **24% source/build opportunities**, **25% hardware
or direct-entry policy opportunities**, and **6% conditional/resource/lifecycle
opportunities**. These percentages are manual opportunity estimates, not a
demonstrated safe automatic removal rate or a measurement of filter accuracy.

| Mutually exclusive category | Count / approximate share | What could justify pruning | Why retained now |
| --- | ---: | --- | --- |
| Retain with current evidence | **45 / 45%** | No additional exclusion established. | Real shared code, concurrency, layout, interface, or behavioral changes remain. |
| Binding-aware rename | **1 / 1%** | Resolve the same field across definitions and offset-check macros, preserving layout and effective uses. | The current global spelling map cannot distinguish `page.index` from unrelated `folio.index` uses or expand assertion macros. |
| Independent reorders / file moves | **2 / 2%** | Prove independent definitions can move without affecting preprocessing, linkage, initialization, or relevant metadata. | Current comparison preserves file-local token order and structure. |
| Small semantic/dataflow cleanups | **8 / 8%** | Establish redundant stores/aliases, equivalent scope guards, bounded formatting, constant expansion, or integer-range equivalence. | These change expressions, calls, declarations, or control flow; they exceed consistent renaming. |
| Include / preprocessing / declaration cleanup | **6 / 6%** | Compare target-preprocessed effects and declaration dependencies, including build validity. | Masking inactive code does not canonicalize active guards, redundant includes, prototype moves, or macro redefinition diagnostics. |
| Unused header definitions / declarations | **6 / 6%** | Show no active compiled consumers in either revision, including generated names and type dependencies. | Conservative opaque/reference guards, mixed declarations, enum members, and generated guard classes prevent complete pruning. |
| Unused definitions spanning C and headers | **1 / 1%** | Establish that the only callers are disabled and the new global function has no remaining effective use. | The C function is non-static and its file is above the 64 KiB dead-analysis limit; header and C changes must both qualify. |
| Absent hardware / resources / CPU features | **10 / 10%** | Prove all affected paths require a resource absent throughout the target scenario. | No complete hardware/feature inventory or hotplug model is incorporated. |
| Strong direct-entry policy candidates | **15 / 15%** | Show direct entry is denied, then exclude inherited/delegated resources, privileged services, and other callers. | No policy reachability stage exists; direct denial alone does not establish whole-app or whole-system unreachability. |
| Conditional service/resource candidates | **5 / 5%** | Exclude privileged backends, device/namespace lifecycle, kernel registration, and service-mediated work. | Existing resources and indirect activity can reach the changed code. |
| Boot/setup lifecycle candidate | **1 / 1%** | Establish that initialization and its persistent state cannot affect the post-boot scenario. | The changed trace-buffer initialization state can persist into runtime. |
| **Total** | **100 / 100%** | | |

There were **zero remaining comment-only or wording-only logging changes** in
this sample. There were also **zero separately established source-only unused
definition commits**: the unused C example includes a header, while the new UART
helpers without callers are explicitly exported and were retained. Zero in 100
does not establish that a category is absent from the population.

## Sampling and scope

- Baseline: the same **26,670 non-merge commits** in
  `db/filtered_after_2025.sqlite` used for the earlier study.
- New seed: **20261106**. Shuffle the sorted baseline IDs, apply current source
  stages in that random order, and take the first **100 survivors**. This took
  **105 draws**. The reference planner can read ahead; lookahead outside those
  105 draws is excluded from the removal counts and review.
- Load each full original patch from `db/all_commits.sqlite`. Reuse the saved
  filtered file/config selection through edit masks, then apply current ifdef,
  unused-definition, whitespace, rename, and diagnostic-wording stages. Preserve
  the original patch and mask ledger. Saved reduced patches are not treated as
  original source edits.
- **No population-wide Kbuild rerun** was performed. This is a recheck of the
  existing configured cohort, not a newly materialized full output database.
  Reference planning and scope can also differ from a full history/config pass.
- Target: the same Android `untrusted_app` scenario, using the archived
  **2026-10-25 challenge6 policy/probe snapshot**. No new live policy capture was
  made. Some source commits postdate that environment's kernel; policy estimates
  concern a profile, not whether those commits apply to that exact binary.

The new sample is independent of the old seed, and the category scheme now
explicitly counts small semantic and preprocessing cleanups. Differences from
the original 100-commit table cannot be attributed solely to the implemented
filters or interpreted as a before/after population measurement.

Approximate 95% Wilson intervals for sampling uncertainty are **36–55%** for
the retain group, **17–33%** for the source/build group, and **45–64%** for the
combined candidate pool. These intervals do not capture manual classification
error, uncertainty about device/service state, or dependence between related
commits. Individual one- or two-commit categories are particularly uncertain.

## What today's rules actually removed

Five commits disappeared before reviewing the 100 survivors:

| Commit | Reason |
| --- | --- |
| `72ca981dba5e` | SCMI documentation parameter-name typo; the title sounds like a function rename but the retained change is only a comment. |
| `ffe0486b139e` | Console documentation correction. |
| `b6c46600bfb2` | Memory-management comment typos. |
| `4a6cc9655fcc` | Pinctrl comment typos. |
| `463aba809073` | Consistent `epoll_filefd` to `epoll_key` type rename. |

That is **5/105 = 4.8%** of this checked prefix of the legacy survivor pool.
Only one is an additional full removal specifically attributed to the rename
stage; the other four are current whitespace/comment cleanup. This is not a
population-wide pruning-rate measurement.

Unused-definition pruning also removed parts of three retained commits:

- `8375b76517cb`: the old `kho_preserve_phys` fallback definition.
- `05849fc5d842`: the newly introduced unused `mmc_card_blk_no_cmd23` helper.
- `0f70a49f3fa3`: the unused `class_irqdesc_lock_constructor` definition.

All four comment removals have matching complete-source token streams for their
selected files, matching direct line-macro locations, and no direct counter
macros. The independent source/reference audit passed the rename and the three
partial unused-definition decisions. No incorrect removal was identified in
these checks; this small exercise does not measure the system's false-negative
rate or prove whole-program equivalence.

## Concrete remaining opportunities

### Header definitions: 6%

These are not simply headers included only by disabled files. The included
header can remain active while the changed definition is unused:

| Sample | Evidence and required proof |
| --- | --- |
| 2, `d4236f1ef270` | New `MT_S2_AS_S1` aliases have no literal users at introduction. Need token-paste/expansion coverage. |
| 17, `8375b76517cb` | With KEXEC handover disabled, remaining fallback/declaration edits need closure over the guarded memblock caller; an old unused definition was already masked. |
| 36, `8e8678e740ec` | New KVM capability constant is referenced by s390 code and selftests, not the arm64 kernel. |
| 53, `45cd52c44e85` | Parent search finds `grab_cache_page` only in its definition and a comment; child search finds none. |
| 74, `0f70a49f3fa3` | New IRQ guard macros have no literal users yet. Generated types/destructors, moved declarations, and macro effects need joint analysis. |
| 90, `60decab325a4` | Remaining UAPI enum, macro, and new standalone struct have consumers in the unconfigured iommufd implementation. Whole-commit pruning needs enum/type dependency handling. |

All six headers are below 64 KiB at the sampled revisions. Simply increasing
the file-size limit would not address their main limitations.

There is a concrete conservative guard issue: `_OPAQUE_NAMES` searches raw
whole-file text for `asm`. It also matches `<asm/...>` include paths and comments,
which can block unrelated unused-definition proofs. The memory and KVM headers
above hit this guard. Reference guards also conservatively count potential
prefix/suffix spellings as uses, even without compiler-resolved token-paste
bindings. Improving token/context classification is a narrower opportunity than
building a whole-kernel call graph. Global line/counter protections still need
to be preserved when considering any such change.

The additional **1% mixed C/header example**, sample 33 (`1d89d7fd592e`), makes
`mem_cgroup_ino` and `mem_cgroup_get_from_ino` unconditional. Their only found
external consumers are in `mm/shrinker_debug.c`; `CONFIG_SHRINKER_DEBUG` is off.
The global C definition and its 148 KiB file exceed the current static-function,
64 KiB analysis envelope.

### Renames, movement, and semantic cleanup: 11%

Only **3%** of remaining commits fall into the narrower rename/movement pool:
the `page.index` field rename, an independent helper reorder after dead-code
masking, and movement of trace-printk functions/state between translation units.
The old 8% rename/reorder estimate was a different sample and included cases
whose interfaces or trace strings made automatic pruning uncertain.

The separate **8% small semantic/dataflow group** consists of samples
4, 11, 41, 59, 66, 82, 84, and 92: redundant assignment, stable local alias,
mutex scope guards, temporary-variable elimination, bounded formatting,
equivalent power-of-two rounding, constant-to-macro extraction, and another
local alias elimination. They require use/def, alias, cleanup-macro, value-range,
or helper-invariant reasoning. A rename-tolerant or order-independent AST
comparison alone would not establish those properties.

For example, sample 66's `cdev%d` name uses a nonnegative integer ID and a
20-byte destination. A 32-bit nonnegative integer requires at most ten digits,
so the four-character prefix plus digits and terminator fit. That gives a
specific range-proof route for the `sprintf` to `snprintf` change; arbitrary
formatting-call substitutions should remain significant.

### Hardware and policy: 25%, plus conditional cases

The **10% hardware/resource candidates** cover Scarlett USB audio, Type-C muxes,
DAX memory, QCA Bluetooth, xHCI, a new CPU feature, PHY topology, Qualcomm GENI
UART, Qualcomm PCIe, and SCMI cpufreq. These require an inventory with explicit
hotplug/lifetime assumptions. Their code changes are real when the resource is
present, and denying direct device access to the app is insufficient.

The **15% direct-entry policy candidates** include five io_uring commits, four
BPF verifier commits, and six administrative/socket/debug/control cases.
Runtime BPF/cgroup, Bluetooth receive, shared networking, and filesystem code
were retained where normal app activity or existing privileged state could
reach the changes. The **5% conditional group** covers FunctionFS, ublk,
traffic-action teardown, bridge MAC changes, and eventfs allocation/lifecycle.

Seccomp filters the calling process's syscall entry and arguments. It does not
by itself establish that shared code cannot run through another process or an
existing kernel resource; the policy estimates keep that distinction.
[Kernel seccomp documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html).

## Saved evidence

The [offline report](benchmarks/policy_reachability/2026-11-06/report.html)
provides all 100 decisions, reasons, caveats, and links to patches. The directory
also contains `sample.json`, `reviews.jsonl`, `analysis.json`, `analysis.csv`,
`breakdown.json`, the original/current/legacy patches, the mask ledger,
both-revision source searches, parser/retention-gate observations, and removal
audit results. The snapshot and per-file checksums make the review reproducible.
