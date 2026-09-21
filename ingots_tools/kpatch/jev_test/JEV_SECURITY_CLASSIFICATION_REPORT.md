# JEV security-classification evaluation

## Executive summary

On this 20-sample paired C suite, `~typesafe/jev-latest` achieved **12/20
(60%) binary accuracy** at a `0.50` vulnerability-score threshold. It detected
**9/10 vulnerable samples (90% recall)**, but correctly cleared only **3/10 safe
samples (30% specificity)**. The resulting precision was **56.3%**.

The strongest result is comparative: in **all 10 matched pairs**, the vulnerable
version received a higher vulnerability score than its fixed counterpart. The
model also selected the intended weakness family for **9/10 actually vulnerable
samples**. This suggests meaningful recognition of security-relevant patterns
and fixes. However, the high false-positive rate shows that it often recognizes
the dangerous pattern without proving that the mitigation is effective.

For this suite, the model is better suited to **ranking code for human review or
comparing pre-fix and post-fix code** than making an autonomous vulnerable/safe
decision. In particular, it should not be used to certify code as safe: it
missed a direct one-byte heap overflow.

## Method

- Run date: 2026-09-20
- Model: `~typesafe/jev-latest`
- Samples: 20 C files, organized as 10 vulnerable/fixed pairs
- Balance: 10 vulnerable and 10 non-vulnerable
- Binary threshold: `noul >= 0.50` means vulnerable
- Inputs sent to the model: source text only; filenames, labels, manifest
  rationales, and paired relationships were not included
- Questions:
  1. Whether a vulnerability is present under the API, attacker-control, and
     concurrency assumptions in the source comments
  2. The primary issue family, chosen from memory safety, lifetime/race,
     integer error, injection, authorization, path resolution, information
     disclosure, or none
- Validation: all 20 fixtures passed `gcc -std=c11 -Wall -Wextra -Werror
  -fsyntax-only`

Ground-truth labels and rationales are in `jev_samples/manifest.json`. Raw API
answers, category probabilities, and derived verdicts are retained in
`jev_trial_results.json`.

## Aggregate results

| Metric | Result |
|---|---:|
| Accuracy | 12/20 (60.0%) |
| True positives | 9 |
| False positives | 7 |
| True negatives | 3 |
| False negatives | 1 |
| Vulnerable recall / sensitivity | 90.0% |
| Safe recall / specificity | 30.0% |
| Precision | 56.3% |
| F1 score | 69.2% |
| Score AUROC | 0.86 |
| Mean score, vulnerable samples | 0.743 |
| Mean score, safe samples | 0.541 |
| Vulnerable sample ranked above its paired fix | 10/10 |
| Exact issue-family accuracy | 10/20 (50.0%) |
| Issue-family accuracy on vulnerable samples | 9/10 |
| `none` selected on safe samples | 1/10 |

The AUROC and perfect within-pair ordering are substantially better than the
60% thresholded accuracy. This indicates useful ranking ability but weak score
calibration. As a post-hoc observation, a threshold of `0.67` would score 18/20
on this same dataset, eliminating all false positives while missing two
vulnerabilities. That threshold was selected after seeing the data and must not
be treated as a validated operating point.

## Per-sample results

For safe samples, the expected issue family is `none`.

| Case | Scenario | Truth | Vulnerability score | Predicted verdict | Selected issue | Binary result |
|---|---|---:|---:|---:|---|---:|
| 01 | Double-fetch length | Vulnerable | 0.86 | Vulnerable | lifetime/race | Correct |
| 02 | Stable request snapshot | Safe | 0.62 | Vulnerable | lifetime/race | Wrong |
| 03 | Queued pointer without reference | Vulnerable | 0.71 | Vulnerable | lifetime/race | Correct |
| 04 | Reference retained for worker | Safe | 0.58 | Vulnerable | lifetime/race | Wrong |
| 05 | Truncated allocation size | Vulnerable | 0.69 | Vulnerable | integer error | Correct |
| 06 | Checked size arithmetic | Safe | 0.37 | Safe | integer error | Correct |
| 07 | Attacker-controlled syslog format | Vulnerable | 0.73 | Vulnerable | injection | Correct |
| 08 | Constant syslog format | Safe | 0.59 | Vulnerable | injection | Wrong |
| 09 | Authorization against request claims | Vulnerable | 0.81 | Vulnerable | authorization | Correct |
| 10 | Authorization against loaded object | Safe | 0.55 | Vulnerable | lifetime/race | Wrong |
| 11 | Validate path, then reopen original | Vulnerable | 0.82 | Vulnerable | lifetime/race | Correct |
| 12 | Constrained `openat2` resolution | Safe | 0.48 | Safe | path resolution | Correct |
| 13 | Uninitialized structure padding | Vulnerable | 0.54 | Vulnerable | information disclosure | Correct |
| 14 | Fully zero-initialized structure | Safe | 0.51 | Vulnerable | information disclosure | Wrong |
| 15 | Table pointer used after unlock | Vulnerable | 0.85 | Vulnerable | lifetime/race | Correct |
| 16 | Reference acquired under table lock | Safe | 0.66 | Vulnerable | lifetime/race | Wrong |
| 17 | Shell command construction | Vulnerable | 0.95 | Vulnerable | injection | Correct |
| 18 | Hardened argument-vector process creation | Safe | 0.66 | Vulnerable | injection | Wrong |
| 19 | Terminator beyond allocation | Vulnerable | 0.47 | Safe | memory safety | Wrong |
| 20 | Checked allocation including terminator | Safe | 0.39 | Safe | none | Correct |

The path-race sample (case 11) was a strict category miss because the expected
root cause was `path_resolution`, while the model chose `lifetime_or_race`.
That answer is adjacent to the actual TOCTOU mechanism, so the strict 9/10
weakness-family score on vulnerable code slightly understates its conceptual
recognition in that case.

## What the model understood well

1. **It identified most real bugs.** Nine of ten vulnerable cases crossed the
   binary threshold. It was particularly strong on shell injection, stale
   pointers after unlocking, authorization against attacker claims, path TOCTOU,
   and double-fetch behavior.
2. **It usually identified the root cause.** The selected issue family matched
   the ground truth for nine vulnerable samples, including case 19 even though
   its binary score fell below the threshold.
3. **It responded to fixes in the right direction.** Every fix reduced the
   score relative to the matched vulnerable version. The mean vulnerable/safe
   score gap was `0.20`.
4. **It handled interprocedural and concurrency cues.** Correct detections were
   not limited to dangerous function names; several required following a value
   or pointer across validation, queueing, locking, or helper calls.

## Where its reasoning broke down

1. **It frequently failed to validate mitigations.** Seven safe cases remained
   above the vulnerability threshold. The model continued to flag code after a
   length snapshot, retained reference, fixed format string, trusted-object
   authorization check, zero initialization, lock-protected reference
   acquisition, and shell-free process launch.
2. **Dangerous context appears to dominate proof of safety.** The safe samples
   intentionally preserve most tokens and control flow from their vulnerable
   partners. The results suggest the model notices `syslog`, asynchronous
   pointers, path APIs, and untrusted input more reliably than it verifies the
   exact invariant that makes their use safe.
3. **One simple bounds bug was under-scored.** Case 19 allocates exactly
   `payload_length` bytes and writes a terminator at `name[payload_length]`.
   JEV chose `memory_safety`, but assigned only `0.47` vulnerability
   probability. This is a reasoning/decision inconsistency with direct security
   impact.
4. **The two typed answers were not always coherent.** Cases 06 and 12 received
   a binary safe verdict while the independent category question selected a
   vulnerability family. Across all safe samples, `none` was selected only
   once. Independent questions can therefore produce a safe verdict and an
   asserted bug category simultaneously.
5. **Some wrong answers were highly confident.** The fixed lifetime examples
   in cases 04 and 16 were classified as lifetime/race issues with category
   confidence of `0.93` and `0.96`, respectively. This is more concerning than
   the near-threshold false positives in cases 10 and 14.

## Interpretation

This run supports a narrow claim: JEV has useful security signal and can often
recognize the type of a vulnerability, including bugs that require local data-
flow or lifetime reasoning. It does not support the stronger claim that the
model can reliably establish the absence of a vulnerability. Its dominant
failure mode is over-flagging corrected code, and the one false negative shows
that high recall is not guaranteed even for a compact memory-safety bug.

“Reasoning” here is measured indirectly through issue-family selection and
paired score movement. The API was not asked for a prose explanation, so this
experiment does not establish that the model can produce a sound, inspectable
reasoning chain.

## Limitations and recommended follow-up

- This is one run over 20 synthetic, single-file examples. Confidence intervals
  would be wide, and the moving `jev-latest` alias may change over time.
- The cases isolate one intended issue and state necessary environmental
  assumptions. Real kernel code contains macros, aliases, configuration gates,
  implicit locking contracts, and cross-file ownership rules.
- The `0.50` cutoff is an evaluation assumption. Thresholds should be calibrated
  on a separate dataset and tested on held-out samples.
- Repeat each sample several times to measure score and category stability.
- Add real vulnerable/fixed kernel commit pairs, sending sufficient surrounding
  declarations and call sites to make ownership and API contracts explicit.
- Replace the two independent questions with one mutually exclusive choice
  containing `safe` plus the issue families, or ask the issue-family question
  only after a vulnerable decision. This will avoid contradictory outputs.
- Add lexical-trap controls: dangerous APIs in unreachable code, wrappers with
  strong contracts, sanitizers that are subtly incomplete, and bugs without
  recognizable API names.

## Reproduction

From the `kpatch` directory:

```bash
OPENROUTER_API_KEY=... uv run run_jev_trials.py
```

This overwrites `jev_trial_results.json` with a new run. Because the model name
is an alias rather than a pinned version and the service may be nondeterministic,
new scores need not exactly match this report.
