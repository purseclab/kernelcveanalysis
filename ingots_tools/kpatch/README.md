# kpatch

WIP, we want to focus on finding lpe vs just manually looking up a few for ingots.

Everyone of course use llm to find lpe bug, requires hundreds of dollars possibly, not very cheap.
These automatically found commits land in kernel trees, so scanning to find them instead of finding them ourselves may be cheaper.

For ingots, something like looking only at CVEs and filtering is probably enough?
Many but not all lpe bugs are given a CVE, and we don't really care if CVE delayed a few weeks from patch.
More interesting overall is if you can find commit as soon as it hits some kernel tree, which would enable exploitation irl, and be an issue.
Since kernel requires patch before issuing cve.

## Filtering performance

The pipeline parses mutable patches lazily, keeps compact history metadata
instead of cached full parsed patches, streams SQLite and Git index output,
shares bounded caches of fragment-independent Kbuild parses, and indexes
Kbuild rule owners and invalidation dependencies. Complete history
is still traversed; these changes do not add new rejection rules.

Run the non-destructive, one-month benchmark from this directory:

```console
uv run python benchmarks/filter_pipeline.py --start 07-01-2026 --end 08-01-2026
```

It reports loading/filtering time, peak Python-process RSS (MiB, on Linux),
commit counts, and a SHA-256 of ordered commit IDs and reduced patches. It
never saves filtered commits and rejects ranges longer than 93 days.

### Measured comparison

For `[2026-07-01, 2026-08-01)`, using the local Linux repository and
`kernel.config`, single unprofiled runs measured:

| Metric | Before | After |
| --- | ---: | ---: |
| Load + filtering time | 870.7 s | 276.8 s |
| Peak Python RSS | 2,423.8 MiB | 996.9 MiB |
| Input / retained commits | 10,681 / 1,519 | 10,681 / 1,519 |

That is **3.15× faster** with **58.9% less peak Python memory**. Every retained
commit ID and reduced-patch hash matched, including output order. The shared
output SHA-256 was
`105cfdf8b8f3f60725ece7cb0ed9fe8f2f85d2fe6f6df6224ae98a57ec21f1d4`.
RSS excludes Git subprocesses; timings vary with hardware and filesystem cache.
