#!/usr/bin/env python3
"""Build a Linux fixing-commit dataset from the generated finding datasets.

Run this after ``generate_dataset.py``.  For every CVE record, this script
queries the NVD CVE API, examines every reference URL, and augments those
references with narrowly scoped source adapters for Android bulletins, Google
kernelCTF metadata, and Linux CVE announcements.  It downloads each recognized
patch and emits one record per unique fixing commit.  Existing non-CVE findings
are processed through the same patch-download path and included in the output.

Only the Python standard library is required.  Set NVD_API_KEY to use an NVD
API key.  Responses are cached so an interrupted run can be resumed without
repeating successful NVD requests.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent
DEFAULT_CVE_INPUT = ROOT / "linux_lpe_rce_cves.json"
DEFAULT_NON_CVE_INPUT = ROOT / "non_cve_lpe_findings.json"
DEFAULT_OUTPUT = ROOT / "linux_lpe_rce_fix_commits.json"
DEFAULT_CACHE = ROOT / ".cache" / "nvd_cves"
DEFAULT_SOURCE_CACHE = ROOT / ".cache" / "fix_sources"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
LINUX_CVE_ARCHIVE = "https://yhbt.net/lore/linux-cve-announce/"
USER_AGENT = "linux-lpe-dataset-fix-commit-enricher/1.0"
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
PATCH_FROM_RE = re.compile(r"\AFrom ([0-9a-fA-F]{40,64}) ")

# These are verified cross-CVE aliases: each announcement explicitly says its
# fix addresses the key CVE.  Keeping the source message here makes the result
# reproducible without relying on fuzzy full-text archive search.
LINUX_CVE_ALIAS_ANNOUNCEMENTS = {
    "CVE-2022-2586": [
        LINUX_CVE_ARCHIVE + "2025061844-CVE-2022-50213-bc19@gregkh/raw",
    ],
    "CVE-2023-0179": [
        LINUX_CVE_ARCHIVE + "2025032721-CVE-2023-53033-9089@gregkh/raw",
    ],
}

# Ubuntu's tracker exposes the two util-linux fixes before NVD publishes the
# corresponding CVE records.  Keep this deliberately small and source-bound:
# the adapter below verifies that each expected full GitHub commit URL is
# present in the named Ubuntu CVE page before emitting it.
SOURCE_BACKED_CVE_ADVISORIES = {
    "CVE-2026-53613": {
        "url": "https://ubuntu.com/security/CVE-2026-53613",
        "commit_urls": (
            "https://github.com/util-linux/util-linux/commit/0d3d55975aa3492c62fd345eac38f41cd166c0b0",
            "https://github.com/util-linux/util-linux/commit/0b010025a0e429bc80355c94db86a843395d49e2",
        ),
    },
    "CVE-2026-53614": {
        "url": "https://ubuntu.com/security/CVE-2026-53614",
        "commit_urls": (
            "https://github.com/util-linux/util-linux/commit/31e37c1c7dcf25b76ccf41391fe934a75644c661",
            "https://github.com/util-linux/util-linux/commit/cc81bbcec598cb91f0eb8456282f33eed820ed5f",
        ),
    },
}


@dataclass(frozen=True)
class CommitLink:
    """A fixing commit, its patch endpoint, and discovery provenance."""

    commit_id: str
    commit_url: str
    patch_url: str
    provider: str = "direct-reference"
    discovery_url: str | None = None
    scope: str = "upstream"
    patch_encoding: str = "text"
    reference_tags: tuple[str, ...] = ()


class FetchError(RuntimeError):
    pass


class RateLimiter:
    def __init__(self, interval: float) -> None:
        self.interval = max(0.0, interval)
        self._last_request: float | None = None

    def wait(self) -> None:
        if self._last_request is not None:
            remaining = self.interval - (time.monotonic() - self._last_request)
            if remaining > 0:
                time.sleep(remaining)
        self._last_request = time.monotonic()


def fetch_bytes(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    limiter: RateLimiter | None = None,
    retries: int = 3,
    timeout: float = 60.0,
    not_found_ok: bool = False,
) -> bytes:
    request_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    request_headers.update(headers or {})
    last_error: Exception | None = None

    for attempt in range(retries + 1):
        if limiter is not None:
            limiter.wait()
        try:
            with urlopen(Request(url, headers=request_headers), timeout=timeout) as response:
                return response.read()
        except HTTPError as exc:
            if exc.code == 404 and not_found_ok:
                return b""
            last_error = exc
            if exc.code not in {429, 500, 502, 503, 504} or attempt == retries:
                break
            retry_after = exc.headers.get("Retry-After")
            try:
                delay = float(retry_after) if retry_after else 2**attempt
            except ValueError:
                delay = 2**attempt
            time.sleep(min(delay, 60.0))
        except (URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt == retries:
                break
            time.sleep(min(2**attempt, 60.0))

    raise FetchError(f"failed to fetch {url}: {last_error}")


def fetch_cached(
    url: str,
    *,
    cache_dir: Path,
    refresh: bool,
    not_found_ok: bool = False,
) -> bytes:
    """Fetch and content-address-cache a non-NVD source URL."""

    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    cache_path = cache_dir / digest
    if cache_path.exists() and not refresh:
        return cache_path.read_bytes()
    raw = fetch_bytes(url, not_found_ok=not_found_ok)
    cache_dir.mkdir(parents=True, exist_ok=True)
    temporary = cache_path.with_name(cache_path.name + ".tmp")
    temporary.write_bytes(raw)
    temporary.replace(cache_path)
    return raw


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"could not read JSON from {path}: {exc}") from exc


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def nvd_record_for_cve(
    cve_id: str,
    *,
    cache_dir: Path,
    api_key: str | None,
    limiter: RateLimiter,
    refresh: bool,
) -> dict[str, Any]:
    cache_path = cache_dir / f"{cve_id}.json"
    if cache_path.exists() and not refresh:
        payload = load_json(cache_path)
    else:
        query = urlencode({"cveId": cve_id})
        headers = {"Accept": "application/json"}
        if api_key:
            headers["apiKey"] = api_key
        raw = fetch_bytes(
            f"{NVD_CVE_API}?{query}", headers=headers, limiter=limiter
        )
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FetchError(f"NVD returned invalid JSON for {cve_id}: {exc}") from exc
        cache_dir.mkdir(parents=True, exist_ok=True)
        write_json_atomic(cache_path, payload)

    vulnerabilities = payload.get("vulnerabilities", [])
    for vulnerability in vulnerabilities:
        cve = vulnerability.get("cve", {})
        if cve.get("id", "").upper() == cve_id.upper():
            return cve
    raise FetchError(f"NVD returned no record for {cve_id}")


def _normalized_https_url(parsed: Any) -> str:
    return urlunparse(("https", parsed.netloc.lower(), parsed.path, "", parsed.query, ""))


def parse_commit_url(
    url: str,
    *,
    provider: str = "direct-reference",
    discovery_url: str | None = None,
    reference_tags: Iterable[str] = (),
) -> CommitLink | None:
    """Recognize verified commit URL forms used by this dataset's sources."""

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    parts = [part for part in parsed.path.split("/") if part]
    tags = tuple(reference_tags)

    if host in {"github.com", "www.github.com"}:
        if len(parts) < 4 or parts[2] != "commit":
            return None
        owner, repository, _, commit_id = parts[:4]
        commit_id = commit_id.removesuffix(".patch")
        if not COMMIT_RE.fullmatch(commit_id):
            return None
        commit_url = f"https://github.com/{owner}/{repository}/commit/{commit_id}"
        scope = "upstream-linux" if repository.lower() in {"linux", "linux-stable"} else "upstream-project"
        return CommitLink(
            commit_id.lower(), commit_url, commit_url + ".patch", provider,
            discovery_url or url, scope, "text", tags,
        )

    if host.startswith("gitlab.") and len(parts) >= 5 and parts[-2] == "commit":
        commit_id = parts[-1].removesuffix(".patch")
        if not COMMIT_RE.fullmatch(commit_id):
            return None
        commit_path = "/" + "/".join(parts)
        commit_url = urlunparse(("https", parsed.netloc, commit_path, "", "", ""))
        return CommitLink(
            commit_id.lower(), commit_url, commit_url + ".patch", provider,
            discovery_url or url, "upstream-project", "text", tags,
        )

    if host == "android.googlesource.com" and "+" in parts:
        plus_index = parts.index("+")
        if plus_index + 1 >= len(parts):
            return None
        commit_id = parts[plus_index + 1].split("^", 1)[0]
        if not COMMIT_RE.fullmatch(commit_id):
            return None
        repo_path = "/" + "/".join(parts[:plus_index])
        commit_url = f"https://android.googlesource.com{repo_path}/+/{commit_id}"
        patch_url = commit_url + "%5E%21/?format=TEXT"
        return CommitLink(
            commit_id.lower(), commit_url, patch_url, provider,
            discovery_url or url, "android-kernel", "base64", tags,
        )

    if host != "git.kernel.org":
        return None

    # NVD's Linux CNA normally emits compact stable links such as
    # https://git.kernel.org/stable/c/<hash>.
    if len(parts) == 3 and parts[:2] == ["stable", "c"]:
        commit_id = parts[2]
        if not COMMIT_RE.fullmatch(commit_id):
            return None
        patch_url = (
            "https://git.kernel.org/pub/scm/linux/kernel/git/stable/"
            f"linux.git/patch/?id={commit_id}"
        )
        return CommitLink(
            commit_id.lower(), _normalized_https_url(parsed), patch_url, provider,
            discovery_url or url, "stable-linux", "text", tags,
        )

    # Short canonical links used by distribution trackers.
    if len(parts) == 2 and parts[0] == "linus" and COMMIT_RE.fullmatch(parts[1]):
        commit_id = parts[1].lower()
        commit_url = f"https://git.kernel.org/linus/{commit_id}"
        patch_url = (
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/"
            f"linux.git/patch/?id={commit_id}"
        )
        return CommitLink(
            commit_id, commit_url, patch_url, provider, discovery_url or url,
            "upstream-linux", "text", tags,
        )

    git_path = parsed.path
    if git_path.startswith("/cgit/linux/kernel/git/"):
        git_path = "/pub/scm" + git_path[len("/cgit"):]
    if "/pub/scm/linux/kernel/git/" not in git_path or ".git/commit" not in git_path:
        return None
    commit_ids = parse_qs(parsed.query).get("id", [])
    if not commit_ids or not COMMIT_RE.fullmatch(commit_ids[0]):
        return None
    commit_id = commit_ids[0].lower()
    patch_path = git_path.replace(".git/commit", ".git/patch", 1)
    patch_url = urlunparse(("https", "git.kernel.org", patch_path, "", urlencode({"id": commit_id}), ""))
    scope = "stable-linux" if "/stable/" in git_path else "upstream-linux"
    return CommitLink(
        commit_id, _normalized_https_url(parsed), patch_url, provider,
        discovery_url or url, scope, "text", tags,
    )


def parse_linux_commit_url(url: str) -> CommitLink | None:
    """Backward-compatible name for callers of the original parser."""

    return parse_commit_url(url)


def unique_commit_links(urls: Iterable[str]) -> list[CommitLink]:
    result: list[CommitLink] = []
    seen: set[tuple[str, str]] = set()
    for url in urls:
        link = parse_commit_url(url)
        if link is None:
            continue
        key = (link.commit_id, link.patch_url)
        if key not in seen:
            seen.add(key)
            result.append(link)
    return result


def deduplicate_links(links: Iterable[CommitLink]) -> list[CommitLink]:
    result: list[CommitLink] = []
    # Different providers can identify the same commit with different tree
    # URL forms and therefore different patch endpoints.  Keep one candidate
    # per finding/commit ID so a stale duplicate URL cannot create a spurious
    # fetch error after another provider supplied the usable patch.
    seen: set[str] = set()
    for link in links:
        key = link.commit_id.lower()
        if key not in seen:
            seen.add(key)
            result.append(link)
    return result


def links_from_nvd_references(references: list[dict[str, Any]]) -> list[CommitLink]:
    """Extract direct commits, requiring Patch evidence for non-kernel repos."""

    links: list[CommitLink] = []
    for reference in references:
        url = reference.get("url", "")
        tags = reference.get("tags", [])
        link = parse_commit_url(
            url,
            provider="nvd-reference",
            discovery_url=url,
            reference_tags=tags,
        )
        if link is None:
            continue
        if link.scope in {"upstream-linux", "stable-linux", "android-kernel"} or "Patch" in tags:
            links.append(link)
    return deduplicate_links(links)


def discover_android_bulletin_links(
    cve_id: str,
    references: list[dict[str, Any]],
    *,
    source_cache_dir: Path,
    refresh: bool,
) -> list[CommitLink]:
    """Read only the named CVE's row from official Android bulletins."""

    links: list[CommitLink] = []
    bulletin_urls = {
        reference["url"]
        for reference in references
        if "source.android.com" in reference.get("url", "")
        and "/bulletin/" in reference.get("url", "")
    }
    for bulletin_url in sorted(bulletin_urls):
        raw = fetch_cached(
            bulletin_url, cache_dir=source_cache_dir, refresh=refresh
        )
        page = html.unescape(raw.decode("utf-8", errors="replace"))
        match = re.search(
            re.escape(cve_id) + r"(?P<row>.*?)</tr>", page,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if match is None:
            continue
        for commit_url in re.findall(
            r'href=["\'](https://android\.googlesource\.com/kernel/common/\+/[0-9a-fA-F]+)',
            match.group("row"),
        ):
            link = parse_commit_url(
                commit_url,
                provider="android-security-bulletin",
                discovery_url=bulletin_url,
                reference_tags=("Patch", "Vendor Advisory"),
            )
            if link:
                links.append(link)
    return deduplicate_links(links)


def _kernelctf_metadata_url(url: str) -> str | None:
    parsed = urlparse(url)
    if (parsed.hostname or "").lower() != "github.com":
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 7 or parts[2] not in {"tree", "blob"}:
        return None
    owner, repository, _, branch, *repository_path = parts
    try:
        kernelctf_index = repository_path.index("kernelctf")
    except ValueError:
        return None
    if kernelctf_index + 1 >= len(repository_path):
        return None
    submission_path = repository_path[: kernelctf_index + 2]
    return (
        f"https://raw.githubusercontent.com/{owner}/{repository}/{branch}/"
        + "/".join(submission_path)
        + "/metadata.json"
    )


def discover_kernelctf_links(
    finding: dict[str, Any],
    *,
    source_cache_dir: Path,
    refresh: bool,
) -> list[CommitLink]:
    candidate_urls = [
        finding.get("source_url", ""),
        *finding.get("additional_source_urls", []),
    ]
    links: list[CommitLink] = []
    for source_url in candidate_urls:
        metadata_url = _kernelctf_metadata_url(source_url)
        if metadata_url is None:
            continue
        raw = fetch_cached(metadata_url, cache_dir=source_cache_dir, refresh=refresh)
        try:
            metadata = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FetchError(f"invalid kernelCTF metadata from {metadata_url}: {exc}") from exc
        vulnerability = metadata.get("vulnerability", {})
        if vulnerability.get("cve", "").upper() != finding["cve"].upper():
            raise FetchError(f"kernelCTF metadata CVE mismatch at {metadata_url}")
        patch_commit = vulnerability.get("patch_commit", "")
        link = parse_commit_url(
            patch_commit,
            provider="kernelctf-metadata",
            discovery_url=metadata_url,
            reference_tags=("Patch",),
        )
        if link:
            links.append(link)
    return deduplicate_links(links)


def discover_linux_cve_alias_links(
    cve_id: str,
    *,
    source_cache_dir: Path,
    refresh: bool,
) -> list[CommitLink]:
    links: list[CommitLink] = []
    for announcement_url in LINUX_CVE_ALIAS_ANNOUNCEMENTS.get(cve_id, []):
        raw = fetch_cached(
            announcement_url, cache_dir=source_cache_dir, refresh=refresh
        )
        message = raw.decode("utf-8", errors="replace")
        relationship = re.search(
            rf"(?:fix(?:es|ed)?|address(?:es|ed)?)\s+{re.escape(cve_id)}\b",
            message,
            flags=re.IGNORECASE,
        )
        if relationship is None:
            raise FetchError(
                f"alias announcement no longer explicitly associates {cve_id}: {announcement_url}"
            )
        for commit_url in re.findall(
            r"https://git\.kernel\.org/stable/c/[0-9a-fA-F]{7,64}", message
        ):
            link = parse_commit_url(
                commit_url,
                provider="linux-cve-announce-alias",
                discovery_url=announcement_url,
                reference_tags=("Patch", "Mailing List"),
            )
            if link:
                links.append(link)
    return deduplicate_links(links)


def discover_advisory_links(
    cve_id: str,
    references: list[dict[str, Any]],
    *,
    source_cache_dir: Path,
    refresh: bool,
) -> list[CommitLink]:
    """Extract commits asserted as fixes by narrowly recognized advisories.

    This deliberately does not scrape every hexadecimal string from arbitrary
    pages.  Each adapter requires both the requested CVE and source-specific
    wording that identifies the hash as a fix rather than an introducing or
    merely related commit.
    """

    links: list[CommitLink] = []
    for reference in references:
        source_url = reference.get("url", "")
        host = (urlparse(source_url).hostname or "").lower()
        is_dirty_pipe = host == "dirtypipe.cm4all.com" and cve_id == "CVE-2022-0847"
        is_ubuntu_patch = (
            host == "lists.ubuntu.com"
            and "/archives/kernel-team/" in urlparse(source_url).path
            and "Patch" in reference.get("tags", [])
        )
        if not (is_dirty_pipe or is_ubuntu_patch):
            continue

        raw = fetch_cached(source_url, cache_dir=source_cache_dir, refresh=refresh)
        page = html.unescape(raw.decode("utf-8", errors="replace"))
        if is_dirty_pipe:
            matches = re.findall(
                r'href=["\'](https://git\.kernel\.org/[^"\']+/commit/\?id=[0-9a-fA-F]{40})["\']>was fixed</a>',
                page,
                flags=re.IGNORECASE,
            )
            provider = "vulnerability-researcher-advisory"
        else:
            plain_text = re.sub(r"<[^>]+>", " ", page)
            if cve_id.lower() not in plain_text.lower():
                continue
            commit_ids = re.findall(
                r"cherry picked from commit\s+([0-9a-fA-F]{40})\b",
                plain_text,
                flags=re.IGNORECASE,
            )
            matches = [
                "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/"
                f"linux.git/commit/?id={commit_id}"
                for commit_id in commit_ids
            ]
            provider = "ubuntu-kernel-mailing-list"

        for commit_url in matches:
            link = parse_commit_url(
                commit_url,
                provider=provider,
                discovery_url=source_url,
                reference_tags=reference.get("tags", ()),
            )
            if link:
                links.append(link)
    return deduplicate_links(links)


def discover_source_backed_cve_links(
    cve_id: str,
    *,
    source_cache_dir: Path,
    refresh: bool,
) -> list[CommitLink]:
    """Read explicitly mapped fixing commits from an authoritative CVE page."""

    entry = SOURCE_BACKED_CVE_ADVISORIES.get(cve_id)
    if entry is None:
        return []
    source_url = entry["url"]
    raw = fetch_cached(source_url, cache_dir=source_cache_dir, refresh=refresh)
    page = html.unescape(raw.decode("utf-8", errors="replace"))
    if cve_id not in page or "Patch details" not in page:
        raise FetchError(f"source-backed CVE page does not identify {cve_id}: {source_url}")

    links: list[CommitLink] = []
    for commit_url in entry["commit_urls"]:
        if commit_url not in page:
            raise FetchError(f"expected fixing commit is absent from {source_url}: {commit_url}")
        link = parse_commit_url(
            commit_url,
            provider="source-backed-cve-advisory",
            discovery_url=source_url,
            reference_tags=("Patch", "Vendor Advisory"),
        )
        if link:
            links.append(link)
    return deduplicate_links(links)


def fetch_patch(
    link: CommitLink,
    *,
    source_cache_dir: Path,
    refresh: bool,
) -> tuple[str, str]:
    raw = fetch_cached(
        link.patch_url,
        cache_dir=source_cache_dir,
        refresh=refresh,
    )
    if link.patch_encoding == "base64":
        try:
            raw = base64.b64decode(raw, validate=True)
        except ValueError as exc:
            raise FetchError(f"invalid Gitiles base64 patch for {link.commit_url}: {exc}") from exc
    try:
        patch_text = raw.decode("utf-8")
    except UnicodeDecodeError:
        patch_text = raw.decode("utf-8", errors="replace")
    if not patch_text.strip():
        raise FetchError(f"empty patch returned for {link.commit_url}")
    match = PATCH_FROM_RE.match(patch_text)
    commit_id = match.group(1).lower() if match else link.commit_id

    # Gitiles diffs do not carry an mbox From line.  Resolve abbreviated IDs
    # through the commit JSON endpoint so output uses a stable full hash.
    if link.patch_encoding == "base64" and len(commit_id) < 40:
        raw_metadata = fetch_cached(
            link.commit_url + "?format=JSON",
            cache_dir=source_cache_dir,
            refresh=refresh,
        )
        if raw_metadata.startswith(b")]}'"):
            raw_metadata = raw_metadata.split(b"\n", 1)[1]
        try:
            metadata = json.loads(raw_metadata.decode("utf-8"))
            resolved = metadata.get("commit", "")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FetchError(f"invalid Gitiles commit metadata for {link.commit_url}: {exc}") from exc
        if COMMIT_RE.fullmatch(resolved) and len(resolved) >= 40:
            commit_id = resolved.lower()
    return commit_id, patch_text


def base_output_record(finding: dict[str, Any], *, source_kind: str) -> dict[str, Any]:
    fields = [
        "cve",
        "identifier",
        "source_url",
        "summary",
        "evidence_group",
        "certainty",
        "type",
        "caveat",
        "checked_on",
    ]
    record = {field: finding[field] for field in fields if field in finding}
    record["source_kind"] = source_kind
    return record


def commit_tree_category(scope: str) -> str:
    """Return the dataset's normalized commit-tree category."""

    return {
        "stable-linux": "stable",
        "upstream-linux": "mainline",
        "android-kernel": "android",
    }.get(scope, "other")


def enrich_link(
    finding: dict[str, Any],
    link: CommitLink,
    *,
    source_kind: str,
    source_cache_dir: Path,
    refresh: bool,
    nvd_reference_urls: list[str] | None = None,
) -> tuple[dict[str, Any], str | None]:
    record = base_output_record(finding, source_kind=source_kind)
    record.update(
        {
            "commit_id": link.commit_id,
            "commit_url": link.commit_url,
            "patch_url": link.patch_url,
            "patch_text": None,
            "commit_provider": link.provider,
            "commit_scope": link.scope,
            "commit_tree": commit_tree_category(link.scope),
            "commit_discovery_url": link.discovery_url or link.commit_url,
        }
    )
    if nvd_reference_urls is not None:
        record["nvd_url"] = f"https://nvd.nist.gov/vuln/detail/{finding['cve']}"
        record["nvd_reference_urls"] = nvd_reference_urls
        if link.provider == "nvd-reference":
            record["nvd_reference_url"] = link.discovery_url or link.commit_url
            record["nvd_reference_tags"] = list(link.reference_tags)

    try:
        commit_id, patch_text = fetch_patch(
            link,
            source_cache_dir=source_cache_dir,
            refresh=refresh,
        )
        record["commit_id"] = commit_id
        record["patch_text"] = patch_text
        return record, None
    except FetchError as exc:
        message = str(exc)
        record["patch_fetch_error"] = message
        return record, message


def build_dataset(args: argparse.Namespace) -> dict[str, Any]:
    cve_dataset = load_json(args.cve_input)
    non_cve_findings = load_json(args.non_cve_input)
    cve_records = cve_dataset.get("records", [])
    if args.limit is not None:
        cve_records = cve_records[: args.limit]

    api_key = os.environ.get(args.api_key_env)
    interval = args.delay if args.delay is not None else (0.6 if api_key else 6.0)
    nvd_limiter = RateLimiter(interval)
    source_cache_dir: Path = args.source_cache_dir
    output_records: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    cves_without_fix_commits: list[str] = []

    for index, finding in enumerate(cve_records, start=1):
        cve_id = finding["cve"]
        print(f"[{index}/{len(cve_records)}] querying {cve_id}", file=sys.stderr)
        source_only = False
        try:
            nvd_cve = nvd_record_for_cve(
                cve_id,
                cache_dir=args.cache_dir,
                api_key=api_key,
                limiter=nvd_limiter,
                refresh=args.refresh,
            )
        except FetchError as exc:
            try:
                links = discover_source_backed_cve_links(
                    cve_id,
                    source_cache_dir=source_cache_dir,
                    refresh=args.refresh,
                )
            except FetchError as source_exc:
                errors.append({"identifier": cve_id, "stage": "nvd", "error": str(exc)})
                errors.append(
                    {
                        "identifier": cve_id,
                        "stage": "source-backed-cve-advisory",
                        "error": str(source_exc),
                    }
                )
                continue
            if not links:
                errors.append({"identifier": cve_id, "stage": "nvd", "error": str(exc)})
                continue
            # Some newly assigned CVEs have an authoritative vendor/CNA page
            # and fixes but no NVD record yet.  Preserve those associations
            # without fabricating NVD metadata.
            references = []
            reference_urls = []
            source_only = True
        else:
            references = nvd_cve.get("references", [])
            reference_urls = [reference["url"] for reference in references if reference.get("url")]
            links = links_from_nvd_references(references)

        providers = [
            (
                "android-security-bulletin",
                lambda: discover_android_bulletin_links(
                    cve_id,
                    references,
                    source_cache_dir=source_cache_dir,
                    refresh=args.refresh,
                ),
            ),
            (
                "kernelctf-metadata",
                lambda: discover_kernelctf_links(
                    finding,
                    source_cache_dir=source_cache_dir,
                    refresh=args.refresh,
                ),
            ),
            (
                "linux-cve-announce-alias",
                lambda: discover_linux_cve_alias_links(
                    cve_id,
                    source_cache_dir=source_cache_dir,
                    refresh=args.refresh,
                ),
            ),
            (
                "source-advisory",
                lambda: discover_advisory_links(
                    cve_id,
                    references,
                    source_cache_dir=source_cache_dir,
                    refresh=args.refresh,
                ),
            ),
            (
                "source-backed-cve-advisory",
                lambda: discover_source_backed_cve_links(
                    cve_id,
                    source_cache_dir=source_cache_dir,
                    refresh=args.refresh,
                ),
            ),
        ]
        for provider_name, discover in providers:
            try:
                links.extend(discover())
            except FetchError as exc:
                errors.append(
                    {"identifier": cve_id, "stage": provider_name, "error": str(exc)}
                )
        links = deduplicate_links(links)
        if not links:
            cves_without_fix_commits.append(cve_id)
            continue
        for link in links:
            record, error = enrich_link(
                finding,
                link,
                source_kind="cve",
                source_cache_dir=source_cache_dir,
                refresh=args.refresh,
                nvd_reference_urls=None if source_only else reference_urls,
            )
            output_records.append(record)
            if error:
                errors.append(
                    {"identifier": cve_id, "stage": "patch", "error": error}
                )

    for finding in non_cve_findings:
        candidate_urls = [
            finding.get("commit_url", ""),
            finding.get("source_url", ""),
            *finding.get("additional_source_urls", []),
        ]
        links = []
        for candidate_url in candidate_urls:
            if not candidate_url:
                continue
            link = parse_commit_url(
                candidate_url,
                provider="non-cve-finding",
                discovery_url=finding.get("source_url"),
                reference_tags=("Patch",),
            )
            if link:
                links.append(link)
        links = deduplicate_links(links)
        if not links and finding.get("commit_hash"):
            commit_id = finding["commit_hash"]
            commit_url = (
                "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/"
                f"linux.git/commit/?id={commit_id}"
            )
            parsed = parse_commit_url(
                commit_url,
                provider="non-cve-finding",
                discovery_url=finding.get("source_url"),
                reference_tags=("Patch",),
            )
            if parsed:
                links = [parsed]
        if not links:
            identifier = finding.get("identifier", "unknown-non-cve")
            errors.append(
                {
                    "identifier": identifier,
                    "stage": "commit-discovery",
                    "error": "no recognized upstream Linux commit URL",
                }
            )
            continue
        for link in links:
            record, error = enrich_link(
                finding,
                link,
                source_kind="non-cve",
                source_cache_dir=source_cache_dir,
                refresh=args.refresh,
            )
            output_records.append(record)
            if error:
                errors.append(
                    {
                        "identifier": finding.get("identifier", link.commit_id),
                        "stage": "patch",
                        "error": error,
                    }
                )

    # A full and a short URL can resolve to the same commit.  Prefer the first
    # successful patch-bearing record while retaining distinct CVE associations.
    deduplicated: list[dict[str, Any]] = []
    positions: dict[tuple[str, str], int] = {}
    for record in output_records:
        association = record.get("cve") or record.get("identifier", "")
        key = (association, record["commit_id"])
        if key not in positions:
            positions[key] = len(deduplicated)
            deduplicated.append(record)
        elif deduplicated[positions[key]].get("patch_text") is None and record.get("patch_text"):
            deduplicated[positions[key]] = record

    return {
        "schema_version": 3,
        "generated_on": date.today().isoformat(),
        "scope": "Fixing commits for the generated Linux LPE/RCE CVEs and non-CVE findings, collected from direct CVE references and verified source-specific providers.",
        "methodology": {
            "cve_source": NVD_CVE_API,
            "selection": "Direct NVD commit references tagged as patches are combined with current and legacy kernel.org links, Android Security Bulletin CVE rows, kernelCTF metadata patch_commit fields, explicitly verified Linux-CVE alias announcements, and narrowly parsed researcher or distribution advisories that explicitly identify a fixing commit.",
            "providers": [
                "nvd-reference",
                "android-security-bulletin",
                "kernelctf-metadata",
                "linux-cve-announce-alias",
                "vulnerability-researcher-advisory",
                "ubuntu-kernel-mailing-list",
                "non-cve-finding",
            ],
            "record_granularity": "One record per finding and resolved fixing commit. A CVE with multiple fixing commits produces multiple records.",
            "commit_tree": "Normalized tree category: stable for Linux stable backports, mainline for upstream Linux commits, android for Android common-kernel commits, and other for user-space or downstream projects.",
            "patch_text": "Downloaded from kernel cgit, GitHub, GitLab, or Android Gitiles. A null value is accompanied by patch_fetch_error.",
            "nvd_rate_limit_delay_seconds": interval,
            "nvd_api_key_used": bool(api_key),
        },
        "summary": {
            "input_cves": len(cve_records),
            "input_non_cve_findings": len(non_cve_findings),
            "records": len(deduplicated),
            "cve_commit_records": sum(record["source_kind"] == "cve" for record in deduplicated),
            "non_cve_commit_records": sum(record["source_kind"] == "non-cve" for record in deduplicated),
            "records_with_patch_text": sum(record.get("patch_text") is not None for record in deduplicated),
            "by_provider": dict(sorted(Counter(record["commit_provider"] for record in deduplicated).items())),
            "by_commit_tree": dict(sorted(Counter(record["commit_tree"] for record in deduplicated).items())),
            "cves_without_fix_commits": len(cves_without_fix_commits),
            "errors": len(errors),
        },
        "cves_without_fix_commits": cves_without_fix_commits,
        "cves_without_linux_commit_urls": cves_without_fix_commits,
        "errors": errors,
        "records": deduplicated,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cve-input", type=Path, default=DEFAULT_CVE_INPUT)
    parser.add_argument("--non-cve-input", type=Path, default=DEFAULT_NON_CVE_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--source-cache-dir", type=Path, default=DEFAULT_SOURCE_CACHE)
    parser.add_argument("--api-key-env", default="NVD_API_KEY")
    parser.add_argument(
        "--delay",
        type=float,
        help="seconds between NVD calls (default: 6 without an API key, 0.6 with one)",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="ignore cached NVD, advisory, metadata, and patch responses",
    )
    parser.add_argument("--limit", type=int, help="process only the first N CVEs (for testing)")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit nonzero if any NVD or patch fetch failed",
    )
    args = parser.parse_args(argv)
    if args.delay is not None and args.delay < 0:
        parser.error("--delay must be non-negative")
    if args.limit is not None and args.limit < 0:
        parser.error("--limit must be non-negative")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    dataset = build_dataset(args)
    write_json_atomic(args.output, dataset)
    summary = dataset["summary"]
    print(
        f"wrote {args.output} ({summary['records']} commit records; "
        f"{summary['records_with_patch_text']} patches; {summary['errors']} errors)"
    )
    return 1 if args.strict and summary["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
