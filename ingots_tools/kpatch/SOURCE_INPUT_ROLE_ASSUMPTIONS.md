# Explicit assumptions about unresolved source consumers

The default source filters retain changes when a recognized input consumer is
unresolved. A C token comparison cannot prove that a generator or assembler does
not also read the original source bytes. This protects real cases such as Linux
`lib/build_OID_registry`, which reads numeric OIDs from header comments.

`--unresolved-inputs-lossy --input-role-report PATH` separately assumes that the
supported inventory's unresolved Make and assembler expressions cannot observe
the affected source changes. **This can remove runtime-relevant commits. There
is no measured bound on its false-removal rate.** It requires its own audit and
is disabled by default.

```sh
uv run kpatch filter --repo linux --db all_commits --dest assumed_inputs config \
  --unresolved-inputs-lossy --input-role-report input-role-decisions.jsonl
```

Use the original commit database. Loading a previously reduced patch without
its mask history does not recreate the original filtering context.

## What remains a barrier

The assumption requires both original historical sides to have an operationally
complete inventory of the recognized consumer patterns. Additions/deletions
check their existing side. It never waives:

- An observed positive raw-consumer match, including conservative basename matches.
- Failed native scans, reads or decoding, missing/nonregular consumer targets,
  unresolved aliases, or incomplete inventories.
- Aggregate file, input-byte, reference, tree, path or revision-delta limits.
- The stage's existing lexer, regular-file, line/column, macro, unused-reference,
  code-address, build-context, caller-scope or BTF requirements.

The mode can waive only the typed local classes `make_operand`, `asm_operand`
and `make_expansion`. Their evidence includes the consumer path, rule/directive start line,
operand and source SHA-256. A bounded Make expansion keeps independently found
literal positives and other rules; reaching that expansion limit does not make
an aggregate reference/input failure waivable. Observed positives are not a
complete list of every consumer that a real Make evaluation could resolve.

The complete recognized inventory is **not** whole-build input closure. Generated,
external, untracked and unmodeled consumers can still exist. The assumption does
not bind a source revision to the challenge 7.1 kernel or supply missing build,
ABI, policy-service or hardware reachability evidence.

## Shared evaluation and publication

`FilterContext.input_role_policy` holds a `SourceInputAssumptionPolicy` with a
required decision callback. The default provider uses full `RawInputIndex.lookup`
when that policy is present. It never clears uncertainty from a retention-only
witness, which can omit other positive consumer facts.

`RawInputObservation` separates inventory state (`full`, `incomplete`,
`retention_witness`), positive consumers, typed local unknowns and hard failures.
`SourceRoleDecision` is blocked, observed-clear or assumed and carries original
side/revision/path evidence. These types replace the previous flat uncertainty
strings; no empty observation is a build-input closure certificate.

All six semantic publishers use a `SourceMaskPlan`. It contains accepted role
decisions and proposed typed edit/code masks. The mandatory assumption audit is
written before any planned mask is applied. An audit failure propagates and
publishes no new masks. Rename and policy decisions collect every file's role
decision before applying any part of the operation. Unused-code analysis uses a
private mask preview so chained unused definitions can be proved without
publishing speculative masks.

Every affected stage audit also has `lossy=true`, the risk
`unresolved_raw_consumers_may_change_build_or_runtime_behavior`, and typed
`input_role_evidence`. Existing risk labels remain additive. The separate input
report uses `unresolved_input_roles_assumed` and contains the planned masks.
The source rename/reorder report preserves its comparison mask context for
independent replay; the dedicated input report records the proposed output masks.

The existing `--source-pruning-lossy` and `--whitespace-line-numbers-lossy`
options remain independent. For example, allowing unresolved input expressions
still does not permit a physical line-number change unless the line-number
option and its separate report are also supplied.

## Generic consumer aliases

Assembly/Make consumer symlinks are resolved within the historical Git tree,
with bounded link traversal and a verified regular target. Their target bytes
are parsed under the consumer alias's context. Every revision update refreshes
these aliases, including when only their target changes. Unknown evidence names
the actual target path whose bytes match its SHA-256. Missing, cyclic, external
or nonregular targets retain the candidate. Alias facts cannot seed the regular
file retention-witness shortcut.

This resolves the nine PowerPC selftest assembly links seen in the representative
kernel inventory without a path-specific exemption or an assumption that those
tests are unbuilt.

## Evidence and limits

Independent compiled controls retain the four original raw-consumer examples
in both modes, and preserve literal generator inputs on either side of an
unrelated 129-name Make expansion. An adverse control puts a generator input in
a separate Make include: default mode retains its comment edit; the explicit
assumption removes it even though GCC and Clang both demonstrate runtime exit
7 changing to 8. This documents the risk; it is not a rate estimate.

The pre-implementation witness-only screen gave optimistic ceilings of 154
strict whole removals and 355 with the separate line-number assumption. Those
were not measured recoveries: witness observations omit hidden positive facts
and the opposite historical side. A full inventory also exposed conservative
basename matches, including an unrelated `device.h` generator. Actual population
measurements and their qualifications are recorded in
[FUTURE_PRUNING_WORK.md](FUTURE_PRUNING_WORK.md).

Local ignored evidence is in `benchmarks/source_role_assumptions/2026-11-07/`,
`benchmarks/input_role_assumption_characterization/2026-11-07/` and
`benchmarks/typed_input_role_preflight/2026-11-07/`. Test and benchmark artifacts
are excluded from milestone commits under the user's commit constraint.
