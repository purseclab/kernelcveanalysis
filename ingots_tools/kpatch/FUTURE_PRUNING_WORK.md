# Future pruning work

## Implementation status

`filter config --source-pruning` now enables experimental Tree-sitter rename
comparison and a lazy revision-specific reference index. The default pipeline
is unchanged. This implements a subset of the opportunities below: consistent
renames and changes confined to eligible definitions without found active uses.
Reordering, general type/layout dependencies, target hardware detection, and
policy-aware reachability remain future work.

The [masking update](FILTER_MASKING.md) preserves original patch coordinates,
distinguishes ignored edits from excluded code, and runs dead-code pruning
before whitespace cleanup and rename analysis. It also supports bounded
partial pruning of unused functions. Reordering is still unimplemented.

The table records the original manual sample and its then-current pipeline;
its percentages are candidate estimates, not measured automatic pruning rates.
See [the implementation and benchmark report](benchmarks/ast_pruning/2026-10-25/REPORT.md)
for the new rules, measured yield, costs, and source-analysis limitations.

## Scope and estimates

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
