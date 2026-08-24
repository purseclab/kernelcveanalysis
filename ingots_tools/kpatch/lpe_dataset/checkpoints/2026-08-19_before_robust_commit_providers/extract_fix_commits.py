#!/usr/bin/env python3
"""Build a Linux fixing-commit dataset from the generated finding datasets.

Run this after ``generate_dataset.py``.  For every CVE record, this script
queries the NVD CVE API, examines every reference URL, downloads patches for
recognized upstream Linux Git commit links, and emits one record per unique
fixing commit.  Existing non-CVE findings are processed through the same patch
download path and included in the output.

Only the Python standard library is required.  Set NVD_API_KEY to use an NVD
API key.  Responses are cached so an interrupted run can be resumed without
repeating successful NVD requests.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
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
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "linux-lpe-dataset-fix-commit-enricher/1.0"
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
PATCH_FROM_RE = re.compile(r"\AFrom ([0-9a-fA-F]{40,64}) ")


@dataclass(frozen=True)
class CommitLink:
    """A recognized upstream Linux commit URL and its patch endpoint."""

    commit_id: str
    commit_url: str
    patch_url: str


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


def parse_linux_commit_url(url: str) -> CommitLink | None:
    """Recognize GitHub Linux and kernel.org Linux commit links."""

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    parts = [part for part in parsed.path.split("/") if part]

    if host in {"github.com", "www.github.com"}:
        if len(parts) < 4 or parts[2] != "commit":
            return None
        owner, repository, _, commit_id = parts[:4]
        if repository.lower() not in {"linux", "linux-stable"}:
            return None
        commit_id = commit_id.removesuffix(".patch")
        if not COMMIT_RE.fullmatch(commit_id):
            return None
        commit_url = f"https://github.com/{owner}/{repository}/commit/{commit_id}"
        return CommitLink(commit_id.lower(), commit_url, commit_url + ".patch")

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
        return CommitLink(commit_id.lower(), _normalized_https_url(parsed), patch_url)

    if "/pub/scm/linux/kernel/git/" not in parsed.path or ".git/commit" not in parsed.path:
        return None
    commit_ids = parse_qs(parsed.query).get("id", [])
    if not commit_ids or not COMMIT_RE.fullmatch(commit_ids[0]):
        return None
    commit_id = commit_ids[0].lower()
    patch_path = parsed.path.replace(".git/commit", ".git/patch", 1)
    patch_url = urlunparse(("https", "git.kernel.org", patch_path, "", urlencode({"id": commit_id}), ""))
    return CommitLink(commit_id, _normalized_https_url(parsed), patch_url)


def unique_commit_links(urls: Iterable[str]) -> list[CommitLink]:
    result: list[CommitLink] = []
    seen: set[tuple[str, str]] = set()
    for url in urls:
        link = parse_linux_commit_url(url)
        if link is None:
            continue
        key = (link.commit_id, link.patch_url)
        if key not in seen:
            seen.add(key)
            result.append(link)
    return result


def fetch_patch(link: CommitLink) -> tuple[str, str]:
    raw = fetch_bytes(link.patch_url, headers={"Accept": "text/plain"})
    try:
        patch_text = raw.decode("utf-8")
    except UnicodeDecodeError:
        patch_text = raw.decode("utf-8", errors="replace")
    if not patch_text.strip():
        raise FetchError(f"empty patch returned for {link.commit_url}")
    match = PATCH_FROM_RE.match(patch_text)
    commit_id = match.group(1).lower() if match else link.commit_id
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


def enrich_link(
    finding: dict[str, Any],
    link: CommitLink,
    *,
    source_kind: str,
    nvd_reference_urls: list[str] | None = None,
    nvd_reference_tags: list[str] | None = None,
) -> tuple[dict[str, Any], str | None]:
    record = base_output_record(finding, source_kind=source_kind)
    record.update(
        {
            "commit_id": link.commit_id,
            "commit_url": link.commit_url,
            "patch_url": link.patch_url,
            "patch_text": None,
        }
    )
    if nvd_reference_urls is not None:
        record["nvd_url"] = f"https://nvd.nist.gov/vuln/detail/{finding['cve']}"
        record["nvd_reference_url"] = link.commit_url
        record["nvd_reference_tags"] = nvd_reference_tags or []
        record["nvd_reference_urls"] = nvd_reference_urls

    try:
        commit_id, patch_text = fetch_patch(link)
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
    output_records: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    cves_without_linux_commit_urls: list[str] = []

    for index, finding in enumerate(cve_records, start=1):
        cve_id = finding["cve"]
        print(f"[{index}/{len(cve_records)}] querying {cve_id}", file=sys.stderr)
        try:
            nvd_cve = nvd_record_for_cve(
                cve_id,
                cache_dir=args.cache_dir,
                api_key=api_key,
                limiter=nvd_limiter,
                refresh=args.refresh,
            )
        except FetchError as exc:
            errors.append({"identifier": cve_id, "stage": "nvd", "error": str(exc)})
            continue

        references = nvd_cve.get("references", [])
        reference_urls = [reference["url"] for reference in references if reference.get("url")]
        links = unique_commit_links(reference_urls)
        if not links:
            cves_without_linux_commit_urls.append(cve_id)
            continue
        reference_tags = {
            reference["url"]: reference.get("tags", [])
            for reference in references
            if reference.get("url")
        }
        for link in links:
            record, error = enrich_link(
                finding,
                link,
                source_kind="cve",
                nvd_reference_urls=reference_urls,
                nvd_reference_tags=reference_tags.get(link.commit_url, []),
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
        links = unique_commit_links(url for url in candidate_urls if url)
        if not links and finding.get("commit_hash"):
            commit_id = finding["commit_hash"]
            commit_url = (
                "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/"
                f"linux.git/commit/?id={commit_id}"
            )
            parsed = parse_linux_commit_url(commit_url)
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
            record, error = enrich_link(finding, link, source_kind="non-cve")
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
        "schema_version": 1,
        "generated_on": date.today().isoformat(),
        "scope": "Fixing commits referenced by NVD for the generated Linux LPE/RCE CVEs, plus generated non-CVE findings with known upstream Linux commits.",
        "methodology": {
            "cve_source": NVD_CVE_API,
            "selection": "Every NVD reference URL is examined. Recognized git.kernel.org Linux commit links and GitHub repositories named linux or linux-stable are treated as fixing-commit candidates.",
            "record_granularity": "One record per finding and resolved fixing commit. A CVE with multiple fixing commits produces multiple records.",
            "patch_text": "Downloaded from the corresponding upstream cgit or GitHub patch endpoint. A null value is accompanied by patch_fetch_error.",
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
            "cves_without_linux_commit_urls": len(cves_without_linux_commit_urls),
            "errors": len(errors),
        },
        "cves_without_linux_commit_urls": cves_without_linux_commit_urls,
        "errors": errors,
        "records": deduplicated,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cve-input", type=Path, default=DEFAULT_CVE_INPUT)
    parser.add_argument("--non-cve-input", type=Path, default=DEFAULT_NON_CVE_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--api-key-env", default="NVD_API_KEY")
    parser.add_argument(
        "--delay",
        type=float,
        help="seconds between NVD calls (default: 6 without an API key, 0.6 with one)",
    )
    parser.add_argument("--refresh", action="store_true", help="ignore cached NVD responses")
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
