# kpatch

WIP, we want to focus on finding lpe vs just manually looking up a few for ingots.

Everyone of course use llm to find lpe bug, requires hundreds of dollars possibly, not very cheap.
These automatically found commits land in kernel trees, so scanning to find them instead of finding them ourselves may be cheaper.

For ingots, something like looking only at CVEs and filtering is probably enough?
Many but not all lpe bugs are given a CVE, and we don't really care if CVE delayed a few weeks from patch.
More interesting overall is if you can find commit as soon as it hits some kernel tree, which would enable exploitation irl, and be an issue.
Since kernel requires patch before issuing cve.
