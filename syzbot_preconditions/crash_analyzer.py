#!/usr/bin/env python3
"""
crash_analyzer.py

Parse a kernel crash log (KASAN/BUG) and extract key information.
Optionally, given a source root, pull surrounding source lines for frames.

This is a heuristic tool that combines log parsing and simple static
inspection to produce pre/post-conditions and a primitive classification.
"""
import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from typing import List, Dict, Any, Optional, Tuple


def parse_crash_log(text: str) -> Dict[str, Any]:
    """Parse the crash text and extract structured fields.

    Returns a dict with keys: kind, message_lines, frames (ordered top->bottom),
    access (type,size,addr), allocation_traces (alloc/free), object_info
    """
    out: Dict[str, Any] = {}
    lines = text.splitlines()

    # Kind: look for KASAN or BUG lines
    kind = None
    for l in lines:
        m = re.match(r"BUG: (.+)", l)
        if m:
            kind = m.group(1).strip()
            break
    out["kind"] = kind

    # Extract KASAN access line: "Read of size 4 at addr ..." or "Write of size ..."
    access = {}
    for l in lines:
        m = re.search(r"(Read|Write) of size (\d+) at addr ([0-9a-fA-Fx]+)", l)
        if m:
            access = {"op": m.group(1).lower(), "size": int(m.group(2)), "addr": m.group(3)}
            break
    out["access"] = access or None

    # Parse "The buggy address belongs to the object at ... which belongs to the cache <name> of size <N>"
    object_info = {}
    for i, l in enumerate(lines):
        m = re.search(r"object at ([0-9a-fA-Fx]+)", l)
        if m:
            object_info["obj_addr"] = m.group(1)
        m2 = re.search(r"cache (\S+) of size (\d+)", l)
        if m2:
            object_info["cache"] = m2.group(1)
            object_info["obj_size"] = int(m2.group(2))
        m3 = re.search(r"located (\d+) bytes inside of", l)
        if m3:
            object_info["offset"] = int(m3.group(1))
        m4 = re.search(r"region \[([0-9a-fx]+), ([0-9a-fx]+)\)", l)
        if m4:
            object_info.setdefault("region", {})["start"] = m4.group(1)
            object_info.setdefault("region", {})["end"] = m4.group(2)
    out["object_info"] = object_info or None

    # Extract "Allocated by task" and "Freed by task" stacks. We'll collect blocks.
    allocs = []
    frees = []
    cur = None
    cur_block = []
    cur_type = None
    for l in lines:
        if l.startswith("Allocated by task"):
            if cur_block and cur_type == "alloc":
                allocs.append(cur_block)
            cur_block = [l]
            cur_type = "alloc"
            continue
        if l.startswith("Freed by task"):
            if cur_block and cur_type == "alloc":
                allocs.append(cur_block)
            cur_block = [l]
            cur_type = "free"
            continue
        if cur_type and (l.startswith(" ") or l.startswith('\t') or l.strip().startswith("kasan_") or l.strip().startswith("kmem_") or ":" in l):
            cur_block.append(l)
        else:
            if cur_block:
                if cur_type == "alloc":
                    allocs.append(cur_block)
                elif cur_type == "free":
                    frees.append(cur_block)
            cur_block = []
            cur_type = None
    # flush
    if cur_block:
        if cur_type == "alloc":
            allocs.append(cur_block)
        elif cur_type == "free":
            frees.append(cur_block)

    out["allocated_by"] = ["\n".join(b) for b in allocs]
    out["freed_by"] = ["\n".join(b) for b in frees]

    # Extract stack frames (simple): lines like " func+0x... file:line [inline]" or "func file:line"
    frame_re = re.compile(r"^\s*([\w0-9_@\+\-]+)\+?0x?[0-9a-fA-F]*/?[0-9a-fA-F]*\s+([^:]+):(\d+)(?:\s+\[inline\])?$")
    frames: List[Dict[str, Any]] = []
    for l in lines:
        m = frame_re.match(l)
        if m:
            frames.append({"func": m.group(1), "file": m.group(2).strip(), "line": int(m.group(3)), "raw": l.strip()})

    # A looser fallback: lines like "f2fs_iget+0x43aa/0x4dc0 fs/f2fs/inode.c:514"
    loose_re = re.compile(r"^\s*([\w0-9_@\-]+)(?:\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+)?\s+([^:]+):(\d+)\b")
    if not frames:
        for l in lines:
            m = loose_re.match(l)
            if m:
                frames.append({"func": m.group(1), "file": m.group(2).strip(), "line": int(m.group(3)), "raw": l.strip()})

    # Also extract frames embedded as HTML anchors: <a href='URL'>path/file.c:123</a>
    link_frames: List[Dict[str, Any]] = []
    for m in re.finditer(r"<a\s+[^>]*href=[\'\"]([^\'\"]+)[\'\"][^>]*>([^<:]+:[0-9]+)</a>", text, re.I):
        url = m.group(1)
        target = m.group(2)
        # target like fs/ext4/namei.c:3704
        try:
            filepart, lineno = target.rsplit(':', 1)
            link_frames.append({"url": url, "file": filepart.strip(), "line": int(lineno)})
        except Exception:
            continue
    out["link_frames"] = link_frames

    # Ensure we have frames; also preserve order as in trace (top->bottom is how we collected)
    out["frames"] = frames

    # Keep the original message for reference
    out["raw"] = text

    return out


def extract_source_urls(text: str) -> List[str]:
    """Find http(s) links in a crash log that look like source viewers and return them."""
    urls = []
    for m in re.finditer(r"https?://[\w\-./:?=#%]+", text):
        u = m.group(0)
        # keep links that reference common source viewers
        if "googlesource.com" in u or "github.com" in u or "git.kernel.org" in u:
            urls.append(u)
    return urls


def parse_fragment_for_range(url: str) -> Tuple[Optional[int], Optional[int]]:
    """Parse URL fragment to find a line or range.

    Supports formats:
      - #L245 (GitHub)
      - #L245-L255 (GitHub range)
      - #245 (android.googlesource style)
      - #245-255
    Returns (start_line, end_line) where end_line may be None if single line.
    """
    parsed = urllib.parse.urlparse(url)
    frag = parsed.fragment
    if not frag:
        return None, None

    # GitHub style L245 or L245-L255
    m = re.match(r"L?(\d+)-?L?(\d+)?", frag)
    if m:
        s = int(m.group(1))
        e = int(m.group(2)) if m.group(2) else s
        return s, e
    return None, None


def _is_function_header(line: str, lookahead: List[str]) -> bool:
    """Heuristic: return True if the given line looks like a C function header.

    We try to avoid matching control statements like 'if', 'for', 'while', 'switch'.
    """
    s = line.strip()
    if not s:
        return False
    # exclude common control keywords
    if re.match(r'^(if|for|while|switch|else|case|do)\b', s):
        return False
    # exclude preprocessor or labels
    if s.startswith('#') or s.endswith(':'):
        return False
    # quick check: must contain a '(' and end with ')' or '){' or similar
    if '(' not in s:
        return False
    # avoid simple constructs like 'for (' caught above; now look for an identifier before the '('
    m = re.match(r'^[\w\s\*\(\)]+?([A-Za-z_][A-Za-z0-9_]*)\s*\(', s)
    if not m:
        return False
    # if the line already ends with ') {' it's very likely a function header
    if re.search(r'\)\s*{\s*$', line):
        return True
    # otherwise look ahead a few lines for an opening brace
    for l in lookahead[:6]:
        if l.strip().startswith('{'):
            return True
    return False


def _find_function_start(lines: List[str], ln: int) -> int:
    """Find a reasonable function start line number (1-based) given lines and target line ln (1-based).

    Returns a 1-based start line. Uses conservative heuristics to avoid stopping on control statements.
    """
    # scan backwards from ln-1 to 0
    for i in range(max(0, ln - 1), -1, -1):
        line = lines[i]
        # prepare lookahead slice for checking for opening brace following a prototype
        lookahead = lines[i + 1: i + 7] if i + 1 < len(lines) else []
        try:
            if _is_function_header(line, lookahead):
                return i + 1
        except Exception:
            pass
    # fallback: search for any line that looks like 'identifier ... )' (less strict)
    # for i in range(max(0, ln - 1), max(0, ln - 200) - 1, -1):
    #     if i < 0:
    #         break
    #     if re.match(r"^\s*[A-Za-z_][A-Za-z0-9_].*\)$", lines[i].strip()):
    #         return i + 1
    # final fallback: reasonable context
    return max(1, ln - 100)


def fetch_raw_from_android_googlesource(url: str) -> Tuple[Optional[str], Optional[str]]:
    """Convert a android.googlesource.com commit link (with +/commit/path#L) into a raw file URL
    and fetch the snippet. Returns (snippet_text, error_message)

    Example:
    https://android.googlesource.com/kernel/common/+/1154f779f3f3d196ace7d5084498f5d7f418ba64/mm/page_alloc.c#2456
    Raw file can be fetched via (this site supports +/commit/path -> /+/<commit>/<path>?format=TEXT or use raw URL):
    We'll construct: https://android.googlesource.com/kernel/common/+/COMMIT/PATH?format=TEXT
    and base64-decode if needed; simpler: try to fetch the URL as-is with ?format=TEXT
    """
    # lightweight retry/backoff and in-memory cache
    # cache key is the URL requested (with format param)
    try:
        parsed = urllib.parse.urlparse(url)
        # Expect a path containing '+/' per googlesource commit blob URLs
        if "+/" not in parsed.path:
            return None, "URL not in expected +/commit/path format"

        # Build fetch URL: ensure we add format=TEXT to the query portion (not fragment)
        # Strip fragment before adding query
        base = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ""))
        qdict = dict(urllib.parse.parse_qsl(parsed.query))
        qdict.setdefault("format", "TEXT")
        fetch_url = base + ("?" + urllib.parse.urlencode(qdict) if qdict else "")

        # simple module-level cache
        if not hasattr(fetch_raw_from_android_googlesource, "_cache"):
            fetch_raw_from_android_googlesource._cache = {}
        cache = fetch_raw_from_android_googlesource._cache
        if fetch_url in cache:
            return cache[fetch_url], None

        # prepare a Request with a sensible User-Agent header to avoid blocking
        headers = {"User-Agent": "crash-analyzer/1.0 (+https://example.invalid)"}

        # retry with exponential backoff (short attempts)
        backoff = 1.0
        last_err = None
        for attempt in range(3):
            try:
                req = urllib.request.Request(fetch_url, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as r:
                    data = r.read()
                    try:
                        import base64

                        txt = base64.b64decode(data).decode(errors="ignore")
                    except Exception:
                        txt = data.decode(errors="ignore")
                    # cache the result
                    cache[fetch_url] = txt
                    return txt, None
            except Exception as e:
                last_err = e
                import time

                time.sleep(backoff)
                backoff *= 2
        return None, str(last_err)
    except Exception as e:
        return None, str(e)


def fetch_source_from_url(url: str) -> Dict[str, Any]:
    """Fetch source from known viewers and return a dict with 'text' or 'error'.

    Currently supports android.googlesource.com. Other viewers may be added.
    """
    # Try to convert common viewer URLs to raw file URLs when possible
    raw_url = None
    try:
        raw_url = convert_to_raw(url)
    except Exception:
        raw_url = None

    # android.googlesource needs special handling (format=TEXT which returns base64)
    if "android.googlesource.com" in url:
        txt, err = fetch_raw_from_android_googlesource(url)
        if err:
            return {"error": err}
        return {"text": txt}

    # If we have a raw URL (e.g., raw.githubusercontent.com or git.kernel.org plain), fetch it
    if raw_url:
        # cache raw_url results too
        if not hasattr(fetch_source_from_url, "_cache"):
            fetch_source_from_url._cache = {}
        cache = fetch_source_from_url._cache
        if raw_url in cache:
            return {"text": cache[raw_url]}
        try:
            backoff = 1.0
            last_err = None
            headers = {"User-Agent": "crash-analyzer/1.0 (+https://example.invalid)"}
            for attempt in range(3):
                try:
                    req = urllib.request.Request(raw_url, headers=headers)
                    with urllib.request.urlopen(req, timeout=10) as r:
                        data = r.read().decode(errors="ignore")
                        cache[raw_url] = data
                        return {"text": data}
                except Exception as e:
                    last_err = e
                    import time

                    time.sleep(backoff)
                    backoff *= 2
            return {"error": str(last_err)}
        except Exception as e:
            return {"error": str(e)}

    # fallback: try simple GET on the original URL
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            data = r.read().decode(errors="ignore")
            return {"text": data}
    except Exception as e:
        return {"error": str(e)}

    # DEBUG: report fetched size/lines for link frame urls
    try:
        print(f"[DEBUG] fetched link {u}: {len(text)} bytes, {len(text.splitlines())} lines", file=sys.stderr)
        print(f"[DEBUG] fetched link preview: {text[:200]!r}", file=sys.stderr)
    except Exception:
        pass

def convert_to_raw(url: str) -> Optional[str]:
    """Convert common source viewer URLs to raw file URLs when possible.

    Supported conversions:
    - GitHub blob URL -> raw.githubusercontent.com
      e.g. https://github.com/owner/repo/blob/branch/path -> https://raw.githubusercontent.com/owner/repo/branch/path
    - raw.githubusercontent.com -> returned as-is
    - git.kernel.org cgit tree -> convert /tree/ to /plain/
    Returns None if conversion not known.
    """
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path
    # GitHub blob -> raw.githubusercontent
    if "github.com" in host:
        # path like /owner/repo/blob/branch/path/to/file
        parts = path.lstrip('/').split('/')
        if len(parts) >= 5 and parts[2] == 'blob':
            owner = parts[0]
            repo = parts[1]
            ref = parts[3]
            file_path = '/'.join(parts[4:])
            return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{file_path}"
    # already raw
    if "raw.githubusercontent.com" in host:
        return url

    # git.kernel.org cgit: try to convert /cgit/.../tree/ -> /cgit/.../plain/
    if "git.kernel.org" in host:
        if '/cgit/' in path and '/tree/' in path:
            raw_path = path.replace('/tree/', '/plain/')
            # preserve query (e.g., ?h=commit)
            q = ('?' + parsed.query) if parsed.query else ''
            return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, raw_path, '', parsed.query, ''))
        if '/cgit/' in path and '/plain/' in path:
            return url

    # No conversion known
    return None


def analyze_snippet_for_evidence(snippet: str, access: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Run simple heuristics on source snippet to detect pointer dereferences, array accesses, and alloc/free patterns.

    Returns a small evidence dict.
    """
    evidence = {"dereference": False, "array_access": False, "alloc_calls": [], "free_calls": [], "nearby_lines": []}
    lines = snippet.splitlines()
    for i, l in enumerate(lines):
        if "->" in l or "(*" in l or "*" in l and "." not in l:
            evidence["dereference"] = True
            evidence["nearby_lines"].append((i + 1, l.strip()))
        if "[" in l and "]" in l and "if" not in l:
            evidence["array_access"] = True
            evidence["nearby_lines"].append((i + 1, l.strip()))
        if re.search(r"\b(kmalloc|kmem_cache_alloc|kzalloc|alloc_pages|kmalloc_array)\b", l):
            evidence["alloc_calls"].append((i + 1, l.strip()))
        if re.search(r"\b(kfree|__kasan_slab_free|kmem_cache_free|free_pages)\b", l):
            evidence["free_calls"].append((i + 1, l.strip()))
    # if access provided, note size and op
    if access:
        evidence["access_op"] = access.get("op")
        evidence["access_size"] = access.get("size")
    return evidence


def stronger_heuristics(parsed: Dict[str, Any], snippets: Dict[str, Any], evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Combine parsed data, snippets, and initial evidence to produce a classification,
    primitive guess, confidence score (0-1), pre/post conditions, and supporting notes.
    """
    report: Dict[str, Any] = {
        "primitive": None,
        "vulnerability": None,
        "confidence": 0.0,
        "preconditions": [],
        "postconditions": [],
        "support": [],
    }

    kind = (parsed.get("kind") or "").lower()
    access = parsed.get("access") or {}

    # Heuristic: explicit slab-out-of-bounds messages are strong indicator of OOB access
    if "slab-out-of-bounds" in kind or "out-of-bounds" in kind:
        # prefer mapping to an out-of-bounds read/write depending on access
        if access and access.get("op") == "read":
            report["primitive"] = "out-of-bounds read"
            report["confidence"] += 0.35
            report["support"].append("KASAN reported slab-out-of-bounds (log contains 'slab-out-of-bounds')")
        elif access and access.get("op") == "write":
            report["primitive"] = "out-of-bounds write"
            report["confidence"] += 0.35
            report["support"].append("KASAN reported slab-out-of-bounds (log contains 'slab-out-of-bounds')")

    # Base classification from kind
    if "use-after-free" in kind:
        report["primitive"] = "use-after-free"
        report["confidence"] += 0.3
        report["preconditions"].append("Object freed prior to access (log indicates use-after-free)")

    if "double-free" in kind or "invalid-free" in kind:
        report["primitive"] = "double-free/invalid-free"
        report["confidence"] += 0.3

    # Analyze reported object info offsets
    obj = parsed.get("object_info") or {}
    if obj.get("offset") is not None and obj.get("obj_size") is not None:
        off = obj["offset"]
        sz = obj["obj_size"]
        if off >= sz:
            report["support"].append(f"Access offset {off} >= object size {sz}: OOB evidence")
            report["confidence"] += 0.2
            # prefer to set primitive to an OOB label if not already set
            if not report.get("primitive"):
                report["primitive"] = "out-of-bounds"
        else:
            report["support"].append(f"Access offset {off} inside object size {sz}")

    # Use evidence from snippet analysis to refine primitive
    # evidence keys: dereference, array_access, alloc_calls, free_calls, nearby_lines
    any_evidence = False
    for k, v in evidence.items():
        if not isinstance(v, dict):
            continue
        any_evidence = True
        if v.get("dereference"):
            report["support"].append("Source shows pointer dereference near crash site")
            report["confidence"] += 0.15
        if v.get("array_access"):
            report["support"].append("Source shows array/index access near crash site")
            report["confidence"] += 0.12
        if v.get("free_calls"):
            report["support"].append("Source contains free-like calls near crash site")
            report["confidence"] += 0.12
        if v.get("alloc_calls"):
            report["support"].append("Source contains alloc-like calls near crash site")
            report["confidence"] += 0.05
        if v.get("access_size"):
            sz = v.get("access_size")
            if sz == 1:
                report["primitive"] = report["primitive"] or "controlled write (1 byte)"
                report["confidence"] += 0.08

    # If access is write and size > 8, hint at larger primitive
    if access:
        if access.get("op") == "write":
            s = access.get("size", 0)
            if s == 1:
                if not report.get("primitive"):
                    report["primitive"] = "1-byte write"
                report["confidence"] += 0.05
            elif s > 8:
                if not report.get("primitive"):
                    report["primitive"] = f"write ({s} bytes)"
                report["confidence"] += 0.06
        elif access.get("op") == "read":
            if not report.get("primitive"):
                report["primitive"] = f"read ({access.get('size')} bytes)"
            report["confidence"] += 0.03

    # If no evidence found but we have logs from syzkaller, lower-confidence fuzzer-triggered flag
    if not any_evidence and "syz-executor" in parsed.get("raw", ""):
        report["support"].append("Crash triggered by syzkaller (fuzzer) — input likely controlled")
        report["confidence"] += 0.05

    # Clamp confidence to 0..1
    report["confidence"] = max(0.0, min(1.0, report["confidence"]))

    # Postconditions always include that KASAN caught the issue
    report["postconditions"].append("KASAN or BUG report emitted indicating invalid memory access")
    # Derive a best-effort vulnerability description (what an attacker could do)
    vuln = None
    prim = report.get("primitive", "").lower() if report.get("primitive") else ""
    # look through evidence to find deref/array/write/read hints
    any_deref = False
    any_array = False
    any_free = False
    any_write = False
    any_read = False
    for k, v in (evidence or {}).items():
        if not isinstance(v, dict):
            continue
        if v.get("dereference"):
            any_deref = True
        if v.get("array_access"):
            any_array = True
        if v.get("free_calls"):
            any_free = True
        if v.get("access_op") == "write":
            any_write = True
        if v.get("access_op") == "read":
            any_read = True

    # heuristic mapping
    if "use-after-free" in prim:
        # if evidence indicates a read access and attacker-controlled input can reach the path,
        # prefer calling it an info-leak; if write evidence exists prefer arbitrary write.
        if any_write:
            vuln = "arbitrary write (via use-after-free dereference)"
        elif any_read:
            if any_deref or any_array:
                vuln = "info-leak (use-after-free read of reclaimed memory)"
            else:
                vuln = "use-after-free (may allow read of reclaimed memory)"
        else:
            vuln = "use-after-free (may allow read/write of reclaimed memory)"
    elif "double-free" in prim or "invalid-free" in prim:
        vuln = "memory corruption (double/invalid free may lead to heap corruption)"
    elif "write" in prim:
        vuln = "data corruption / potential arbitrary write"
    elif "read" in prim or prim.startswith("read"):
        vuln = "info-leak (bounded or unbounded read)"
    elif "oob" in prim or "out-of-bounds" in " ".join(report.get("support", [])):
        if any_write:
            vuln = "arbitrary write (oob write)"
        else:
            vuln = "info-leak (oob read)"
    else:
        vuln = "unknown"

    # Swap semantics: make vulnerability the primitive label (what low-level bug it is)
    # and primitive a description of what an attacker can do (capability)
    report["vulnerability"] = report.get("primitive") or "unknown"
    report["primitive"] = vuln or report.get("primitive") or "unknown"

    # Add final best-effort label if still unknown
    if not report["vulnerability"] or report["vulnerability"] == "unknown":
        report["vulnerability"] = "unknown"
    # Improve preconditions: describe what input state is necessary to reach this primitive
    preconds = report.get("preconditions", [])
    # If syzkaller or executor appears in raw, indicate fuzzer/user-controlled input
    raw = parsed.get("raw", "") or ""
    if "syz-executor" in raw or "syzkaller" in raw or "syz" in raw:
        preconds.append("An externally-controlled syscall input (fuzzer/syzkaller) reached the vulnerable syscall path")
    # If evidence indicates dereference in kernel code reachable from syscall/FUSE/ioctl/etc, mark as attacker controlled
    # Heuristic: presence of 'user' or 'copy_from_user' or 'ioctl' in nearby lines or raw log
    user_control_indicators = False
    if re.search(r"copy_from_user|get_user|put_user|ioctl|syscall|fuse|netlink", raw, re.I):
        user_control_indicators = True
    for k, v in (evidence or {}).items():
        if isinstance(v, dict):
            nearby = " ".join([t for (_, t) in v.get("nearby_lines", [])])
            if re.search(r"copy_from_user|get_user|put_user|ioctl|syscall|fuse|netlink", nearby, re.I):
                user_control_indicators = True
    if user_control_indicators:
        preconds.append("Input state: attacker-controlled syscall parameters or user-supplied data must reach the vulnerable code path")

    # ---- New: concrete input-state extraction for filesystem directory parsing errors ----
    # Look for ext4-specific log lines that indicate malformed directory entries
    # Example messages in logs: "bad entry in directory: rec_len % 4 != 0 - offset=24, inode=..., rec_len=29527, size=148"
    m_ext4 = re.search(r"bad entry in directory: .*rec_len=.*offset=(\d+), inode=(\d+), rec_len=(\d+), size=(\d+)", raw)
    if m_ext4:
        off = m_ext4.group(1)
        inode = m_ext4.group(2)
        rec_len = m_ext4.group(3)
        sz = m_ext4.group(4)
        # concrete precondition: the directory entry header contains invalid rec_len/name_len causing ext4 inline dir parsing to overflow
        preconds.insert(0, f"Input state: malformed directory entry data (inode={inode}, rec_len={rec_len}, offset={off}, entry_size_field={sz}) in an inline directory")
        preconds.insert(1, "Attacker-controlled: feed crafted directory metadata or filesystem image with invalid rec_len/name_len to user-visible directory (e.g., via file creation/rename) or via loopback device")
        report["support"].append(f"EXT4 log indicates malformed directory entry: rec_len={rec_len} offset={off} size={sz}")
        report["confidence"] = min(1.0, report["confidence"] + 0.06)

    # Attempt to extract concrete function names and variable identifiers from snippets/frames/link_frames
    funcs = []
    vars_found = []
    # 1) function from parsed.kind (e.g., 'in ext4_rename_dir_prepare')
    kind_fn = None
    mfn = re.search(r"in\s+([A-Za-z_][A-Za-z0-9_]*)", raw)
    if mfn:
        kind_fn = mfn.group(1)
        funcs.append(kind_fn)

    # 2) collect function names from frames
    for f in (parsed.get("frames") or []):
        fn = f.get("func")
        if fn and fn not in funcs:
            funcs.append(fn)

    # 3) collect function/file info from link_frames
    for lf in (parsed.get("link_frames") or []):
        # sometimes link frames include function info in file:line context; use file basename as hint
        fp = lf.get("file")
        if fp:
            bn = os.path.basename(fp)
            # drop extension
            bnname = os.path.splitext(bn)[0]
            if bnname and bnname not in funcs:
                funcs.append(bnname)

    # 4) extract variable names from nearby lines using common deref/index/pointer patterns
    var_patterns = [re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*->"),
                    re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\["),
                    re.compile(r"\*\s*([A-Za-z_][A-Za-z0-9_]*)"),
                    re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*[A-Za-z_]"),]
    for k, v in (evidence or {}).items():
        if isinstance(v, dict):
            for _, line in v.get("nearby_lines", []):
                for pr in var_patterns:
                    for gm in pr.findall(line):
                        tok = gm
                        if tok in ("if", "for", "while", "return", "sizeof", "struct", "case"):
                            continue
                        if tok.isupper():
                            continue
                        if tok not in vars_found and len(tok) > 1:
                            vars_found.append(tok)

    # craft concrete preconditions using the best available symbols
    if funcs:
        preconds.append(f"Code path: execution reaches function '{funcs[0]}' (from crash context)")
    if vars_found:
        preconds.append(f"State: variable(s) like {', '.join(vars_found[:3])} may point into freed/reclaimed memory (observed in nearby source lines)")

    # Concrete object precondition: use object_info when available
    if obj:
        obj_parts = []
        if obj.get("cache"):
            obj_parts.append(f"cache '{obj.get('cache')}'")
        if obj.get("obj_addr"):
            obj_parts.append(f"address {obj.get('obj_addr')}")
        if obj.get("obj_size"):
            obj_parts.append(f"size {obj.get('obj_size')}")
        if obj.get("offset") is not None:
            obj_parts.append(f"offset {obj.get('offset')}")
        if obj_parts:
            preconds.insert(0, f"Object: {', '.join(obj_parts)}")

    # Free-call evidence: list exact free/cleanup calls and their source locations when available
    free_evidence = []
    for k, v in (evidence or {}).items():
        if not isinstance(v, dict):
            continue
        fcs = v.get("free_calls") or []
        if fcs:
            # find source context if available in snippets
            src_info = None
            if k.startswith("link:") and isinstance(snippets.get("links", {}).get(k), dict):
                src = snippets["links"][k]
                src_info = (src.get("file"), src.get("line"), src.get("url"))
            elif isinstance(snippets.get("local", {}).get(k), dict):
                src = snippets["local"][k]
                src_info = (src.get("path"), src.get("line"), None)
            for ln, call_line in fcs:
                desc = call_line
                if src_info:
                    desc = f"{call_line} (near {src_info[0]}:{src_info[1]} url={src_info[2]})"
                free_evidence.append(desc)
    if free_evidence:
        preconds.insert(0, f"Free observed: {free_evidence[0]}")

    # Try to identify the exact object/structure type being freed or accessed.
    obj_type = None
    obj_addr = obj.get("obj_addr") if obj else None
    # prefer object cache name if it looks like a struct name
    if obj and obj.get("cache"):
        obj_type = obj.get("cache")
    # inspect snippets for declarations matching the variable names we found
    if vars_found and not obj_type:
        # search snippets for declarations like 'struct foo *var' or 'struct foo var' near the variable
        for k, s in (snippets.get("links", {}) or {}).items():
            text = s.get("snippet") or ""
            for vname in vars_found:
                m = re.search(rf"struct\s+([A-Za-z_][A-Za-z0-9_]*)[^\n]*\b{re.escape(vname)}\b", text)
                if m:
                    obj_type = m.group(1)
                    break
            if obj_type:
                break
        if not obj_type:
            for k, s in (snippets.get("local", {}) or {}).items():
                text = s.get("snippet") or ""
                for vname in vars_found:
                    m = re.search(rf"struct\s+([A-Za-z_][A-Za-z0-9_]*)[^\n]*\b{re.escape(vname)}\b", text)
                    if m:
                        obj_type = m.group(1)
                        break
                if obj_type:
                    break

    if obj_type or obj_addr:
        parts = []
        if obj_type:
            parts.append(f"type '{obj_type}'")
        if obj_addr:
            parts.append(f"address {obj_addr}")
        if obj.get("obj_size"):
            parts.append(f"size {obj.get('obj_size')}")
        preconds.insert(0, "Object details: " + ", ".join(parts))

    # ---- New: allocation origin and 'how to create' guidance ----
    alloc_blocks = parsed.get('allocated_by') or []
    how_to_create = None
    if alloc_blocks:
        # allocated_by is a list of stack text blocks; pick the most recent (last) or the one that looks like a kernel allocator
        # We parse the text to find the first non-kasan allocator frame (e.g., kmalloc, kzalloc, kmem_cache_alloc_trace, etc.)
        chosen = None
        for block in alloc_blocks:
            # block is a multi-line string; split and inspect lines
            for line in block.splitlines():
                if re.search(r"\b(kmalloc|kzalloc|kmem_cache_alloc|kmalloc_array|__kasan_kmalloc|kasan_kmalloc)\b", line):
                    chosen = line.strip()
                    break
            if chosen:
                break
        if not chosen:
            # fallback: use the top line of the first allocation block
            chosen = alloc_blocks[0].splitlines()[0][:200]
        # try to synthesize a short guidance: map allocator to syscall or kernel action
        # naive mapping: if allocation happened in network stack (ipv6/netlink/socket) suggest network setup; if in fs code, suggest opening/creating files
        guidance = []
        if re.search(r"net/|socket|ipv6|rtnetlink|netlink|sendto|sock_sendmsg", chosen, re.I):
            guidance.append("Trigger via network syscalls (socket/sendto/connect) or netlink operations to exercise the allocation path")
        if re.search(r"fs/|open|openat|do_sys_open|path_openat|vfs_open", chosen, re.I):
            guidance.append("Trigger via filesystem syscalls (open/openat/getdents/getdents64/readdir) or create files/directories to exercise the allocation")
        if re.search(r"mm/|kmalloc|kzalloc|slub|slab", chosen, re.I):
            guidance.append("Allocation from slab/kmalloc: create objects via normal kernel paths (file ops, network ops, or module-specific APIs)")
        if not guidance:
            guidance.append("Allocation observed in kernel stack: reproduce by running the same syscall path observed in the allocation stack (see 'allocated_by' frames for details)")

        how_to_create = {
            'alloc_frame': chosen,
            'guidance': guidance,
        }
        # insert a concise human-friendly precondition/hint
        preconds.insert(0, f"How to create: allocate the object via code path that calls: {chosen}")
        preconds.insert(1, f"How to create hint: {guidance[0]}")
        report['support'].append(f"Allocation origin: {chosen}")
        report['confidence'] = min(1.0, report['confidence'] + 0.04)
        report['how_to_create'] = how_to_create

    # Syscall detection: find syscall entry frames and build a short call chain
    syscall_funcs = []
    frames = parsed.get("frames") or []
    for i, f in enumerate(frames):
        fn = f.get("func") or ""
        if re.match(r"(__x64_sys_|__se_sys_|ksys_|sys_|__x64_sys|__se_sys)", fn):
            # build chain: functions from this frame up to a few above
            chain = []
            for j in range(max(0, i - 3), min(len(frames), i + 3)):
                chain.append(frames[j].get("func"))
            syscall_funcs.append((fn, " -> ".join([c for c in chain if c])))
    if syscall_funcs:
        # prefer first detected syscall
        sf, chain = syscall_funcs[0]
        # normalize syscall function name to known syscall (strip prefixes/suffixes)
        def normalize_syscall(fn: str) -> str:
            # strip offsets like +0x123
            fn = re.sub(r"\+.*$", "", fn)
            # remove common kernel prefixes
            fn = re.sub(r"^(__x64_sys_|__se_sys_|ksys_|sys_)", "", fn)
            return fn

        syscall_name = normalize_syscall(sf)
        preconds.insert(0, f"Triggering syscall: {syscall_name} (entry {sf}) — call chain: {chain}")

    # Also search the raw crash text and link_frames for explicit syscall names, which
    # often appear as __x64_sys_getdents64, __se_sys_getdents64, or plain getdents/getdents64
    raw_text = parsed.get("raw", "") or ""
    raw_sys = []
    for m in re.finditer(r"__x64_sys_([A-Za-z0-9_]+)", raw_text):
        raw_sys.append(m.group(1))
    for m in re.finditer(r"__se_sys_([A-Za-z0-9_]+)", raw_text):
        raw_sys.append(m.group(1))
    for m in re.finditer(r"\b(getdents64|getdents|getdents64)\b", raw_text):
        raw_sys.append(m.group(1))
    # check link_frames (some logs embed plain function names in anchors)
    for lf in (parsed.get("link_frames") or []):
        # sometimes the file/line context contains nearby function names; look at raw anchor url string
        u = lf.get("url") or ""
        for m in re.finditer(r"(__x64_sys_|__se_sys_)([A-Za-z0-9_]+)", u):
            raw_sys.append(m.group(2))

    if raw_sys:
        # normalize and deduplicate
        seen = []
        for s in raw_sys:
            n = re.sub(r"^(__x64_sys_|__se_sys_|sys_)", "", s)
            if n not in seen:
                seen.append(n)
        preconds.insert(0, f"Triggering syscall(s) from crash text: {', '.join(seen)}")
        report["support"].append(f"Syscall(s) detected in crash text: {', '.join(seen)}")
        report["confidence"] = min(1.0, report["confidence"] + 0.08)

    # If available, try to fetch a syz reproducer or syz program embedded in the raw log/links
    # and extract explicit syscall names from it (syzkaller often includes a C-like pseudo-program)
    syz_syscalls = []
    # prefer explicit syz attachments in snippets (page_pre or link content)
    raw = parsed.get("raw", "") or ""
    # try naive detection: a syzkaller prog often contains 'syz_open' or 'open(' or 'syz_'
    if "syz" in raw or "syz-executor" in raw or "syz_prog" in raw:
        # don't block on network; use existing link snippets as candidate attachments
        for k, s in (snippets.get("links") or {}).items():
            text = s.get("snippet") or ""
            if text and ("syz" in text or "MAKE_SYSCALL" in text or "call" in text):
                syz_syscalls.extend(extract_syscalls_from_syzprog(text))
    # as fallback, inspect evidence keys for syz attachments
    for k in (evidence or {}).keys():
        if k.startswith("link:") and k.endswith(".syz"):
            # try to fetch if snippet not already present
            sn = snippets.get("links", {}).get(k)
            if sn and sn.get("snippet"):
                syz_syscalls.extend(extract_syscalls_from_syzprog(sn.get("snippet")))

    if syz_syscalls:
        # prefer first syscall found
        preconds.insert(0, f"Triggering syzkaller syscall(s): {', '.join(syz_syscalls)}")

    # If the vulnerability is an arbitrary write, make pre/post statements explicit
    if report.get("vulnerability") and "arbitrary write" in report.get("vulnerability"):
        preconds.append("Precondition: attacker must trigger the vulnerable path exposing a writable pointer or OOB write")
        report["postconditions"].append("Postcondition: attacker may achieve arbitrary memory write leading to code/data corruption or control-flow hijack")
    if report.get("vulnerability") and "info-leak" in report.get("vulnerability"):
        preconds.append("Precondition: attacker must trigger the vulnerable path that allows reading reclaimed or out-of-bounds memory")
        report["postconditions"].append("Postcondition: attacker may read sensitive kernel memory (info-leak)")

    # Deduplicate preconditions while preserving order
    seen = set()
    new_pre = []
    for p in preconds:
        if p not in seen:
            new_pre.append(p)
            seen.add(p)
    report["preconditions"] = new_pre

    # ---- New: syz repro parsing integration ----
    try:
        syz_candidates = []
        # check link snippets for syz content
        for k, v in (snippets or {}).get("links", {}).items():
            txt = v.get("snippet") or ""
            if txt and ("syz" in txt or "syz_" in txt):
                syz_candidates.extend(parse_syz_repro(txt))
        # if none yet, check raw text for embedded syz programs
        if not syz_candidates and raw:
            if "syz" in raw or "syz_" in raw:
                syz_candidates.extend(parse_syz_repro(raw))
        if syz_candidates:
            seen = []
            for s in syz_candidates:
                if s not in seen:
                    seen.append(s)
            report["preconditions"].insert(0, f"Triggering syzkaller syscall(s): {', '.join(seen)}")
            report["support"].append(f"Syzkaller repro indicates syscalls: {', '.join(seen)}")
            report["confidence"] = min(1.0, report["confidence"] + 0.08)
    except Exception:
        # non-fatal: keep going
        pass

    # ---- New: bounded vs unbounded classification and exploitability scoring ----
    boundedness = None
    if access and obj:
        a_op = access.get('op')
        a_sz = access.get('size') or 0
        obj_sz = obj.get('obj_size')
        obj_off = obj.get('offset')
        if obj_off is not None and obj_sz is not None:
            remaining = obj_sz - obj_off
            if remaining <= 0:
                boundedness = 'oob'
            elif a_sz <= remaining:
                boundedness = 'bounded'
            else:
                boundedness = 'partially_bounded'
        else:
            if obj_sz and a_sz and a_sz <= obj_sz:
                boundedness = 'likely_bounded'
            else:
                boundedness = 'unknown'

    # reflect boundedness in labels where appropriate
    if boundedness:
        # if read
        if (access and access.get('op') == 'read') or ('read' in (report.get('primitive') or '')):
            if boundedness in ('bounded', 'likely_bounded'):
                report.setdefault('primitive', 'info-leak (bounded read)')
                report.setdefault('vulnerability', report.get('vulnerability') or 'bounded info-leak')
            elif boundedness == 'partially_bounded':
                report.setdefault('primitive', 'info-leak (partially bounded read)')
                report.setdefault('vulnerability', report.get('vulnerability') or 'info-leak (partially bounded)')
            elif boundedness == 'oob':
                report.setdefault('primitive', 'info-leak (out-of-bounds read)')
                report.setdefault('vulnerability', report.get('vulnerability') or 'out-of-bounds read')
        # if write
        if (access and access.get('op') == 'write') or ('write' in (report.get('primitive') or '')):
            if boundedness in ('bounded', 'likely_bounded'):
                report.setdefault('primitive', 'bounded write')
                report.setdefault('vulnerability', report.get('vulnerability') or 'bounded write (data corruption)')
            elif boundedness == 'partially_bounded':
                report.setdefault('primitive', 'partially-bounded write')
                report.setdefault('vulnerability', report.get('vulnerability') or 'partial arbitrary write (limited)')
            elif boundedness == 'oob':
                report.setdefault('primitive', 'out-of-bounds write')
                report.setdefault('vulnerability', report.get('vulnerability') or 'out-of-bounds write (arbitrary write)')

    # exploitability scoring: combine attacker control, op type, boundedness, and confidence
    score = 0
    attacker_control = any(re.search(r'fuzzer|syzkaller|attacker|user-controlled|syscall', p, re.I) for p in report.get('preconditions', []))
    if attacker_control:
        score += 2
    if access and access.get('op') == 'write':
        score += 2
    elif access and access.get('op') == 'read':
        score += 1
    if boundedness == 'oob':
        score += 2
    elif boundedness == 'partially_bounded':
        score += 1
    # small boost for confidence
    score += int(report.get('confidence', 0) * 2)

    if score <= 1:
        exp = 'low'
    elif score <= 3:
        exp = 'medium'
    else:
        exp = 'high'
    report['exploitability'] = exp

    return report


def extract_syscalls_from_syzprog(text: str) -> List[str]:
    """Attempt to extract syscall names from a syz pseudo-program or C-like repro.

    Heuristic: look for lines like 'open(fd, path, flags)' or 'syz_open(...)' or 'syscall(...)'
    Returns a list of syscall-like tokens (short names).
    """
    calls = []
    # simple patterns: syz_XXXX, syscall names like open, read, write, renameat2, ioctl, connect
    # match syz_ prefixed helpers
    for m in re.finditer(r"\b(syz_[A-Za-z0-9_]+)\b", text):
        tok = m.group(1)
        if tok not in calls:
            calls.append(tok)
    # match sys_* wrappers or direct syscall names with parentheses
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
        name = m.group(1)
        # ignore C keywords and types
        if name in ("if", "for", "while", "return", "struct", "sizeof", "int", "char", "long", "void"):
            continue
        # common noise: syz executor helpers may include MAKE_* macros; ignore MAKE_*
        if name.startswith("MAKE_"):
            continue
        # accept likely syscall names or syz helpers
        # filter out very short tokens
        if len(name) >= 3 and name not in calls:
            calls.append(name)
    # normalize names: strip 'sys_' or '__x64_sys_' prefixes
    def normalize(n: str) -> str:
        n = re.sub(r"^(__x64_sys_|__se_sys_|ksys_|sys_)", "", n)
        return n

    return [normalize(c) for c in calls]


def parse_syz_repro(text: str) -> List[str]:
    """Parse a syzkaller reproducer or pseudo-program and return likely syscalls.

    This is a small, permissive parser that:
      - prefers explicit syz_* helper tokens (syz_open, syz_read, etc.)
      - maps common syz helpers to canonical syscall names where possible
      - falls back to extracting bare syscall-like tokens
    """
    # mapping for common syz helpers -> syscall
    syz_map = {
        'syz_open': 'openat',
        'syz_openat': 'openat',
        'syz_close': 'close',
        'syz_read': 'read',
        'syz_write': 'write',
        'syz_getdents': 'getdents',
        'syz_getdents64': 'getdents64',
        'syz_sendto': 'sendto',
        'syz_connect': 'connect',
        'syz_socket': 'socket',
    }
    found = []
    # look for syz_ helpers first
    for m in re.finditer(r"\b(syz_[A-Za-z0-9_]+)\b", text):
        name = m.group(1)
        mapped = syz_map.get(name, None)
        if mapped and mapped not in found:
            found.append(mapped)
        elif not mapped and name not in found:
            # strip syz_ prefix as fallback
            found.append(name.replace('syz_', ''))

    # if none found from syz_ helpers, try the more general extractor but de-prioritize common C tokens
    if not found:
        candidates = extract_syscalls_from_syzprog(text)
        for c in candidates:
            if c not in found:
                found.append(c)

    # cleanup: normalize names (strip prefixes) and keep order
    norm = []
    for n in found:
        nn = re.sub(r"^(__x64_sys_|__se_sys_|sys_)", "", n)
        if nn not in norm and len(nn) > 1:
            norm.append(nn)
    return norm


def _call_llm(prompt: str, model_path: Optional[str] = None, max_tokens: int = 512) -> Dict[str, Any]:
    """Try to call a local LLM (llama_cpp) if available.

    Returns a dict: {"ok": True, "answer": str} or {"ok": False, "error": str, "prompt": prompt}
    This avoids adding a hard requirement on llama_cpp: if it's not importable we return the prompt
    and an informative error so callers can run it manually.
    """
    # First try local Llama (llama_cpp) if available
    llama_err = None
    try:
        # lazy import to avoid hard dependency
        from llama_cpp import Llama  # type: ignore
        try:
            kwargs = {"max_tokens": max_tokens, "temperature": 0.0}
            if model_path:
                llm = Llama(model_path=model_path)
            else:
                llm = Llama()
            resp = llm.create(prompt=prompt, **kwargs)
            # llama_cpp returns choices with text; try a few fallbacks
            ans = None
            if isinstance(resp, dict):
                ch = resp.get('choices') or []
                if ch and isinstance(ch, list):
                    ans = ch[0].get('text')
            if ans is None:
                ans = getattr(resp, 'text', None) or str(resp)
            return {"ok": True, "answer": ans}
        except Exception as e:
            # Record the llama-specific error and fall back to other providers
            llama_err = f"llama_cpp invocation failed: {e}"
    except Exception as e:
        llama_err = f"llama_cpp not available: {e}"

    # Fallback: try OpenAI if configured via environment (OPENAI_API_KEY)
    openai_err = None
    try:
        import openai  # type: ignore
        # require an API key in environment or openai package configuration
        api_key = os.environ.get('OPENAI_API_KEY')
        if not api_key and not getattr(openai, 'api_key', None):
            openai_err = "OPENAI_API_KEY not set and openai.api_key not configured"
        else:
            if api_key:
                openai.api_key = api_key
            # Use ChatCompletion where available
            try:
                # prefer chat completion
                msgs = [{"role": "system", "content": "You are a helpful assistant for analyzing kernel crashes."},
                        {"role": "user", "content": prompt}]
                resp = openai.ChatCompletion.create(model=os.environ.get('OPENAI_MODEL', 'gpt-3.5-turbo'), messages=msgs, max_tokens=max_tokens, temperature=0.0)
                # extract text
                ans = None
                if resp and hasattr(resp, 'choices'):
                    ch = resp.choices
                    if isinstance(ch, (list, tuple)) and len(ch) > 0:
                        delta = ch[0]
                        # for chat-style, content may be in delta.message or delta['message'] depending on lib
                        if isinstance(delta, dict):
                            msg = delta.get('message') or delta.get('text')
                            if isinstance(msg, dict):
                                ans = msg.get('content')
                            else:
                                ans = msg
                        else:
                            # fallback to string conversion
                            ans = getattr(delta, 'message', None) or getattr(delta, 'text', None) or str(delta)
                if ans is None:
                    # try alternative structure
                    ans = getattr(resp, 'text', None) or str(resp)
                return {"ok": True, "answer": ans}
            except Exception as e:
                openai_err = f"openai.ChatCompletion failed: {e}"
    except Exception as e:
        openai_err = f"openai not available: {e}"

    # If we reach here, neither llama_cpp nor OpenAI produced a usable result
    errs = []
    if llama_err:
        errs.append(llama_err)
    if openai_err:
        errs.append(openai_err)
    return {"ok": False, "error": " | ".join(errs) or "No LLM available", "prompt": prompt}


def llm_analyze_traces(frames: List[Dict[str, Any]], snippet_map: Dict[str, str], model_path: Optional[str] = None) -> Dict[str, Any]:
    """Use an LLM to analyze a function trace chain and suggest concrete preconditions.

    Inputs:
      - frames: list of frame dicts (as parsed by parse_crash_log)
      - snippet_map: mapping from a frame key or url to the source snippet string
      - model_path: optional local Llama model path for llama_cpp

    Output: dict with keys: prompt, llm_response (if any), summary (heuristic fallback)

    This function constructs a concise prompt that includes the call chain (top->bottom),
    relevant source snippets, and asks the model to return:
      - a short precondition (concrete input ranges or states)
      - the reasoning/evidence lines
      - suggested reproduction steps

    If no LLM is available the function returns the assembled prompt under 'prompt' so
    it can be used manually.
    """
    # Build call chain summary
    chain = []
    for f in frames:
        func = f.get('func') or '<anon>'
        file = f.get('file') or ''
        line = f.get('line') or ''
        chain.append(f"{func} @ {file}:{line}")

    prompt_lines = []
    prompt_lines.append("You are given a kernel crash stack trace and surrounding source snippets. Your task is to produce a concise, developer-friendly description of the PRECONDITION(s) that must hold to reach the crash. Provide concrete input ranges, variable constraints, and reproduction hints.")
    prompt_lines.append("")
    prompt_lines.append("Call chain (top -> bottom):")
    for c in chain:
        prompt_lines.append(" - " + c)
    prompt_lines.append("")
    prompt_lines.append("Available source snippets (filename:line -> snippet):")
    # limit snippet size
    for k, s in snippet_map.items():
        snippet_preview = '\n'.join(s.splitlines()[:20])
        prompt_lines.append(f"-- {k}:\n{snippet_preview}\n---")

    prompt_lines.append("")
    prompt_lines.append("Please output JSON with fields: preconditions (list of short statements), input_constraints (list of variable name -> allowed ranges), reproduction (steps), evidence (lines in the snippets that support each precondition). Keep answers concise and concrete.")
    prompt = "\n".join(prompt_lines)

    llm_out = _call_llm(prompt, model_path=model_path, max_tokens=512)
    out = {"prompt": prompt}
    out.update(llm_out)
    # Heuristic fallback summary in case LLM not available or failed
    if not llm_out.get('ok'):
        # produce a tiny heuristic summary using simple rules
        summary = {"preconditions": [], "input_constraints": [], "reproduction": [], "evidence": []}
        # if any snippet mentions copy_from_user or user pointers, mark user-controlled
        combined = "\n".join(snippet_map.values())
        if re.search(r"copy_from_user|get_user|put_user|ioctl|syscall|fuse|netlink", combined, re.I):
            summary['preconditions'].append("Attacker-controlled user data must reach this code path (copy_from_user or ioctl-like path detected)")
            summary['reproduction'].append("Call the syscall or ioctl which reaches the call chain above with crafted user-controlled buffers")
        # look for alloc/free patterns
        if re.search(r"kmalloc|kzalloc|kmem_cache_alloc|alloc_pages", combined):
            summary['preconditions'].append("A kernel allocation of the relevant object must occur prior to the access")
        # array/deref
        if re.search(r"->|\[|\*", combined):
            summary['input_constraints'].append({"note": "Pointer or index dereference observed near crash; consider off-by-one or size fields controlling ranges"})
        out['summary'] = summary
    return out




def load_source_snippets(frames: List[Dict[str, Any]], source_root: str, context: int = 6) -> Dict[str, Any]:
    """Given parsed frames, try to open the source files under source_root and capture snippets."""
    snippets: Dict[str, Any] = {}
    for f in frames:
        file_path = f["file"]
        # file_path in logs often uses linux tree relative prefixes like fs/f2fs/inode.c
        abs_path = os.path.join(source_root, file_path)
        if os.path.exists(abs_path):
            try:
                with open(abs_path, "r", errors="ignore") as fh:
                    src_lines = fh.readlines()
                ln = f.get("line", 0)
                start = max(1, ln - context)
                end = min(len(src_lines), ln + context)
                snippet = "".join(src_lines[start - 1:end])
                snippets[f"{file_path}:{ln}"] = {"path": abs_path, "line": ln, "snippet": snippet}
            except Exception as e:
                snippets[f"{file_path}:{f.get('line','?')}"] = {"error": str(e)}
        else:
            snippets[f"{file_path}:{f.get('line','?')}"] = {"error": "file not found", "expected_path": abs_path}
    return snippets


def classify(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Heuristic classification of the primitive and pre/post conditions.

    Returns a dict with: classification, preconditions, postconditions, notes
    """
    cls = {
        "classification": None,
        "preconditions": [],
        "postconditions": [],
        "notes": [],
    }

    # Use direct hints from the KASAN/BUG lines and derive a vulnerability description
    kind = parsed.get("kind", "") or ""
    if "use-after-free" in kind.lower():
        cls["classification"] = "use-after-free"
    elif "double-free" in kind.lower() or "invalid-free" in kind.lower():
        cls["classification"] = "double-free/invalid-free"

    access = parsed.get("access") or {}
    if access:
        op = access.get("op")
        size = access.get("size")
        if op == "read":
            cls["notes"].append(f"Detected a read of size {size}")
            # Primitive: limited read vs arbitrary read: if size small -> limited
            if size <= 8:
                prim = f"bounded read ({size} bytes)"
            else:
                prim = f"larger read ({size} bytes)"
            cls["notes"].append(f"Primitive: {prim}")
        elif op == "write":
            cls["notes"].append(f"Detected a write of size {size}")
            if size == 1:
                cls["classification"] = cls["classification"] or "controlled write (1 byte)"
            else:
                cls["classification"] = cls["classification"] or f"write ({size} bytes)"

    # Object info: offset/size can indicate OOB
    obj = parsed.get("object_info") or {}
    if obj:
        if "offset" in obj and "obj_size" in obj:
            if obj["offset"] >= obj["obj_size"]:
                cls["notes"].append("Access is out-of-bounds relative to object size")
            else:
                cls["notes"].append("Access is inside the object's bounds (but could be use-after-free)")
        if "cache" in obj:
            cls["notes"].append(f"Object comes from cache {obj['cache']}")

    # Precondition: freed by earlier task + allocation trace
    if parsed.get("freed_by"):
        cls["preconditions"].append("Object was freed previously (see 'Freed by task' stack)")
    if parsed.get("allocated_by"):
        cls["preconditions"].append("Object was previously allocated (see 'Allocated by task' stack)")

    # Postcondition: KASAN reported invalid access
    cls["postconditions"].append("KASAN reported invalid memory access (see crash report)")

    # Heuristic about attacker control: many syzkaller tasks indicate fuzzer-controlled inputs
    raw = parsed.get("raw", "") or ""
    if re.search(r"syz|syzkaller|syz-executor", raw, re.I):
        cls["notes"].append("Triggering syscall likely came from syzkaller (fuzzer) — input may be controlled")
        cls.setdefault("preconditions", []).append("Input state: attacker-controlled syscall parameters or fuzzer input must reach the syscall path")

    # Look at frames or alloc/free stacks for syscall entry points to infer attacker control
    frames = parsed.get("frames") or []
    frame_text = " ".join([f.get("func","") + " " + str(f.get("file","")) for f in frames])
    if re.search(r"__x64_sys|__se_sys|ksys_|do_syscall|entry_SYSCALL|sys_read|sys_write|ioctl", frame_text, re.I):
        cls.setdefault("preconditions", []).append("Input state: a user-controlled syscall reaches the vulnerable code path")

    # Now derive a best-effort vulnerability label (attacker capability) from primitive hints
    # Prefer to describe what an attacker could do (vulnerability) instead of the low-level primitive
    primitive_hint = cls.get("classification", "") or ""
    vuln = None
    access = parsed.get("access") or {}
    if "use-after-free" in primitive_hint:
        # if read vs write, decide info-leak vs write primitive
        if access.get("op") == "write":
            vuln = "arbitrary write (via use-after-free)"
        elif access.get("op") == "read":
            vuln = "info-leak (use-after-free read of reclaimed memory)"
        else:
            vuln = "use-after-free (may allow read/write of reclaimed memory)"
    elif "double-free" in primitive_hint or "invalid-free" in primitive_hint:
        vuln = "memory corruption (double/invalid free may lead to heap corruption)"
    else:
        # fallback based on detected access
        if access:
            if access.get("op") == "write":
                vuln = f"write ({access.get('size')} bytes) — potential data corruption/arbitrary write"
            elif access.get("op") == "read":
                vuln = f"read ({access.get('size')} bytes) — potential info-leak"
        if not vuln:
            vuln = cls.get("classification") or "unknown"

    # set the vulnerability field (attacker capability) while preserving the primitive classification
    cls["vulnerability"] = vuln

    return cls


def analyze(crash_text: str, source_root: Optional[str] = None) -> Dict[str, Any]:
    parsed = parse_crash_log(crash_text)
    snippets = {}

    # 1) Try URLs found in the log
    urls = extract_source_urls(crash_text)
    url_snippets = {}
    for u in urls:
        fetched = fetch_source_from_url(u)
        if "text" in fetched:
            # Use fragment parsing to extract a focused snippet when the URL contains a fragment
            text = fetched["text"]
            try:
                print(f"[DEBUG] fetched URL {u}: {len(text)} bytes, {len(text.splitlines())} lines", file=sys.stderr)
                print(f"[DEBUG] fetched URL preview: {text[:200]!r}", file=sys.stderr)
            except Exception:
                pass
            sl, el = parse_fragment_for_range(u)
            print(f"[DEBUG] parsed fragment for {u}: start_line={sl}, end_line={el}", file=sys.stderr)
            if sl is not None:
                lines = text.splitlines()
                # single-line fragment -> try to return from function start -> that line
                if el == sl:
                    ln = sl
                    # use helper to find function start conservatively
                    start_fn = _find_function_start(lines, ln)
                    fn_start = start_fn
                    fn_end = min(len(lines), ln)
                    snippet = "\n".join(lines[fn_start - 1:fn_end])
                else:
                    # explicit range -> use exact range bounds
                    start = max(1, sl)
                    end = min(len(lines), el)
                    snippet = "\n".join(lines[start - 1:end])
            else:
                snippet = text
            url_snippets[u] = snippet
        else:
            url_snippets[u] = {"error": fetched.get("error")}

    snippets.update({"urls": url_snippets})

    # 1.b) Try link_frames captured as HTML anchors in the crash report
    link_snippets = {}
    for lf in parsed.get("link_frames", []) or []:
        u = lf.get("url")
        if not u:
            continue
        fetched = fetch_source_from_url(u)
        if "text" in fetched:
            text = fetched["text"]
            try:
                print(f"[DEBUG] fetched link {u}: {len(text)} bytes, {len(text.splitlines())} lines", file=sys.stderr)
                print(f"[DEBUG] fetched link preview: {text[:200]!r}", file=sys.stderr)
            except Exception:
                pass
            sl, el = parse_fragment_for_range(u)
            print(f"[DEBUG] parsed fragment for {u}: start_line={sl}, end_line={el}", file=sys.stderr)
            if sl is not None:
                lines = text.splitlines()
                if el == sl:
                    start = max(1, sl - 6)
                    end = min(len(lines), sl + 6)
                else:
                    start = max(1, sl)
                    end = min(len(lines), el)
                snippet = "\n".join(lines[start - 1:end])
                # When fragment provides a specific line, also try to extract function start -> linked line
                func_snippet = None
                func_snippet_file = None
                try:
                    ln = sl
                    # search backwards for probable function start (same heuristic as below)
                    start_fn = _find_function_start(lines, ln)
                    fn_start = start_fn
                    fn_end = min(len(lines), ln)
                    func_snippet = "\n".join(lines[fn_start - 1:fn_end])
                    try:
                        crash_dir = os.path.join(os.getcwd(), 'crash_analysis')
                        os.makedirs(crash_dir, exist_ok=True)
                        default_name = os.path.splitext(os.path.basename(lf.get('file') or 'link'))[0]
                        bugid = determine_bug_id(parsed, default_name)
                        bn = os.path.basename(urllib.parse.urlparse(u).path) or default_name
                        safe_bn = re.sub(r"[^A-Za-z0-9._-]", "_", bn)
                        out_name = f"{bugid}__{safe_bn}__L{ln}.txt"
                        out_path = os.path.join(crash_dir, out_name)
                        try:
                            print(f"[DEBUG] writing function snippet {out_path}: {len(func_snippet) if func_snippet is not None else 0} chars", file=sys.stderr)
                        except Exception:
                            pass
                        with open(out_path, 'w', encoding='utf-8') as ofh:
                            ofh.write(func_snippet or "")
                        func_snippet_file = out_path
                    except Exception:
                        func_snippet_file = None
                except Exception:
                    func_snippet = None
                    func_snippet_file = None
            else:
                # try to extract around the reported line number in the anchor if present
                if lf.get("line"):
                    lines = text.splitlines()
                    ln = lf.get("line")
                    start = max(1, ln - 6)
                    end = min(len(lines), ln + 6)
                    snippet = "\n".join(lines[start - 1:end])
                    # attempt function-snippet extraction (already implemented below)
                    func_snippet = None
                    func_snippet_file = None
                    try:
                        lines = text.splitlines()
                        ln = int(lf.get("line"))
                        # search backwards for a likely function definition start
                        start_fn = _find_function_start(lines, ln)
                        fn_start = start_fn
                        fn_end = min(len(lines), ln)
                        func_snippet = "\n".join(lines[fn_start - 1:fn_end])
                        try:
                            crash_dir = os.path.join(os.getcwd(), 'crash_analysis')
                            os.makedirs(crash_dir, exist_ok=True)
                            default_name = os.path.splitext(os.path.basename(lf.get('file') or 'link'))[0]
                            bugid = determine_bug_id(parsed, default_name)
                            bn = os.path.basename(urllib.parse.urlparse(u).path) or default_name
                            safe_bn = re.sub(r"[^A-Za-z0-9._-]", "_", bn)
                            out_name = f"{bugid}__{safe_bn}__L{ln}.txt"
                            out_path = os.path.join(crash_dir, out_name)
                            try:
                                print(f"[DEBUG] writing function snippet {out_path}: {len(func_snippet) if func_snippet is not None else 0} chars", file=sys.stderr)
                            except Exception:
                                pass
                            with open(out_path, 'w', encoding='utf-8') as ofh:
                                ofh.write(func_snippet or "")
                            func_snippet_file = out_path
                        except Exception:
                            func_snippet_file = None
                    except Exception:
                        func_snippet = None
                        func_snippet_file = None
                else:
                    snippet = text
            # additional: attempt to capture from function start to the linked line
            func_snippet = None
            func_snippet_file = None
            try:
                if lf.get("line"):
                    lines = text.splitlines()
                    ln = int(lf.get("line"))
                    # search backwards for a likely function definition start
                    start_fn = _find_function_start(lines, ln)
                    # build snippet from function start to the linked line (inclusive)
                    fn_start = start_fn
                    fn_end = min(len(lines), ln)
                    func_snippet = "\n".join(lines[fn_start - 1:fn_end])
                    # save to crash_analysis/<bugid>__<basename>__L<ln>.txt
                    try:
                        crash_dir = os.path.join(os.getcwd(), 'crash_analysis')
                        os.makedirs(crash_dir, exist_ok=True)
                        # determine bug id from parsed (fallback to file basename without extension)
                        default_name = os.path.splitext(os.path.basename(lf.get('file') or 'link'))[0]
                        bugid = determine_bug_id(parsed, default_name)
                        bn = os.path.basename(urllib.parse.urlparse(u).path) or default_name
                        safe_bn = re.sub(r"[^A-Za-z0-9._-]", "_", bn)
                        out_name = f"{bugid}__{safe_bn}__L{ln}.txt"
                        out_path = os.path.join(crash_dir, out_name)
                        try:
                            print(f"[DEBUG] writing function snippet {out_path}: {len(func_snippet) if func_snippet is not None else 0} chars", file=sys.stderr)
                        except Exception:
                            pass
                        with open(out_path, 'w', encoding='utf-8') as ofh:
                            ofh.write(func_snippet or "")
                        func_snippet_file = out_path
                    except Exception:
                        func_snippet_file = None
            except Exception:
                func_snippet = None
                func_snippet_file = None

            # always try to save the context snippet to a file so we have a local copy
            snippet_file = None
            try:
                crash_dir = os.path.join(os.getcwd(), 'crash_analysis')
                os.makedirs(crash_dir, exist_ok=True)
                default_name = os.path.splitext(os.path.basename(lf.get('file') or 'link'))[0]
                # prefer bugid when available, but don't fail on it
                try:
                    bugid = determine_bug_id(parsed, default_name)
                except Exception:
                    bugid = default_name
                bn = os.path.basename(urllib.parse.urlparse(u).path) or default_name
                safe_bn = re.sub(r"[^A-Za-z0-9._-]", "_", bn)
                ln_for_name = str(lf.get('line','?'))
                snippet_name = f"{bugid}__{safe_bn}__L{ln_for_name}__ctx.txt"
                snippet_path = os.path.join(crash_dir, snippet_name)
                try:
                    print(f"[DEBUG] writing context snippet {snippet_path}: {len(snippet) if snippet is not None else 0} chars", file=sys.stderr)
                except Exception:
                    pass
                with open(snippet_path, 'w', encoding='utf-8') as sfh:
                    sfh.write(snippet or "")
                snippet_file = snippet_path
            except Exception:
                snippet_file = None

            key = f"link:{u}#{lf.get('line','?')}"
            link_snippets[key] = {"url": u, "file": lf.get("file"), "line": lf.get("line"), "snippet": snippet}
            if snippet_file:
                link_snippets[key]["snippet_file"] = snippet_file
            if func_snippet is not None:
                link_snippets[key]["function_snippet"] = func_snippet
            if func_snippet_file:
                link_snippets[key]["function_snippet_file"] = func_snippet_file
        else:
            key = f"link:{u}#{lf.get('line','?')}"
            link_snippets[key] = {"url": u, "error": fetched.get("error")}

    if link_snippets:
        snippets.update({"links": link_snippets})

    # 2) Try local source root if available
    if source_root:
        local_snips = load_source_snippets(parsed.get("frames", []), source_root)
        snippets.update({"local": local_snips})

    # 3) Analyze available snippets for evidence
    evidence = {}
    # analyze URL snippets first
    for u, s in url_snippets.items():
        if isinstance(s, str):
            # if URL includes a fragment range, try to parse exact lines (already handled above), analyze snippet
            evidence[u] = analyze_snippet_for_evidence(s, parsed.get("access"))
        else:
            evidence[u] = s

    # analyze link-based snippets
    for k, info in (snippets.get("links") or {}).items():
        if isinstance(info, dict) and info.get("snippet"):
            evidence[k] = analyze_snippet_for_evidence(info.get("snippet"), parsed.get("access"))
            # attach contextual url/file info
            evidence[k]["source_url"] = info.get("url")
            evidence[k]["source_file"] = info.get("file")
            evidence[k]["source_line"] = info.get("line")
        else:
            evidence[k] = {"error": info.get("error")}

    if source_root and isinstance(snippets.get("local"), dict):
        for key, s in snippets.get("local", {}).items():
            if isinstance(s, dict) and "snippet" in s:
                evidence[key] = analyze_snippet_for_evidence(s["snippet"], parsed.get("access"))

    classification = classify(parsed)
    return {"parsed": parsed, "snippets": snippets, "evidence": evidence, "classification": classification}


def determine_bug_id(parsed: Dict[str, Any], default_name: str = "unknown") -> str:
    """Determine a stable bug id/name to use for output filenames.

    Heuristics:
      - If parsed['link_frames'] contains a URL with an obvious id, use its basename
      - If parsed['raw'] contains 'BUG: ' or 'syz' annotations with an id-like token, try to extract
      - Otherwise fall back to default_name (often the input basename or hash)
    Returns a filesystem-safe string.
    """
    try:
        raw = parsed.get('raw', '') or ''
        # try to find patterns like 'syzbot.org/bug?id=12345' or '/bugs/12345' or 'bug 12345'
        m = re.search(r"[bB]ug(?:[: ]|=)(\s*#?)([0-9]{3,})", raw)
        if m:
            return f"bug{m.group(2)}"
        # look for common syz bug anchors
        for lf in (parsed.get('link_frames') or []):
            u = lf.get('url') or ''
            if not u:
                continue
            # try to extract trailing numeric id or filename
            bn = os.path.basename(urllib.parse.urlparse(u).path)
            if bn:
                # sanitize
                bn = re.sub(r"[^A-Za-z0-9._-]", "_", bn)
                return bn
        # fallback: try to extract first word after 'BUG:' in raw
        m2 = re.search(r"BUG:\s*([^\n]+)", raw)
        if m2:
            s = m2.group(1).split()[0]
            s = re.sub(r"[^A-Za-z0-9._-]", "_", s)
            return s
    except Exception:
        pass
    # final fallback
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", default_name)
    return safe


def build_evidence_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    """Produce a richer evidence summary for JSON/HTML output.

    The summary includes per-snippet:
      - dereference, array_access, alloc_calls, free_calls
      - up to 10 nearby lines (content)
    """
    summary = {}
    evidence = result.get("evidence", {})
    snippets = result.get("snippets", {})
    for key, val in evidence.items():
        if not isinstance(val, dict):
            summary[key] = {"error": val}
            continue
        entry = {
            "dereference": bool(val.get("dereference")),
            "array_access": bool(val.get("array_access")),
            "alloc_calls": val.get("alloc_calls", []),
            "free_calls": val.get("free_calls", []),
            "nearby_lines": val.get("nearby_lines", [])[:10],
        }
        # include raw snippet if available in snippets
        if isinstance(snippets.get("urls", {}).get(key), str):
            entry["snippet"] = snippets["urls"][key]
        elif isinstance(snippets.get("local", {}).get(key), dict):
            entry["snippet"] = snippets["local"][key].get("snippet")
        elif isinstance(snippets.get("links", {}).get(key), dict):
            entry["snippet"] = snippets["links"][key].get("snippet")
            entry["source_url"] = snippets["links"][key].get("url")
            entry["source_file"] = snippets["links"][key].get("file")
            entry["source_line"] = snippets["links"][key].get("line")
        summary[key] = entry
    return summary


def generate_html_report(result: Dict[str, Any], out_path: str) -> None:
    """Generate a simple HTML report showing classification, evidence and snippets."""
    strong = result.get("strong_report", {})
    parsed = result.get("parsed", {})
    evidence_summary = build_evidence_summary(result)

    html_parts = []
    html_parts.append("<html><head><meta charset=\"utf-8\"><title>Crash Analysis Report</title>")
    html_parts.append("<style>body{font-family:Arial,Helvetica,sans-serif}pre{background:#f6f8fa;padding:8px;border-radius:6px;overflow:auto} .snippet{border:1px solid #ddd;padding:8px;margin:8px 0}</style>")
    html_parts.append("</head><body>")
    html_parts.append(f"<h1>Crash Analysis Report</h1>")
    html_parts.append(f"<h2>Primitive: {strong.get('primitive')}</h2>")
    html_parts.append(f"<p>Vulnerability: {strong.get('vulnerability')}</p>")
    html_parts.append(f"<p>Confidence: {strong.get('confidence')}</p>")
    html_parts.append("<h3>Preconditions</h3><ul>")
    for p in strong.get("preconditions", []):
        html_parts.append(f"<li>{p}</li>")
    html_parts.append("</ul><h3>Postconditions</h3><ul>")
    for p in strong.get("postconditions", []):
        html_parts.append(f"<li>{p}</li>")
    html_parts.append("</ul>")

    html_parts.append("<h3>Evidence Summary</h3>")
    for key, e in evidence_summary.items():
        html_parts.append(f"<div class=\"snippet\"><h4>{key}</h4>")
        if "error" in e:
            html_parts.append(f"<p>Error fetching snippet: {e['error']}</p>")
            html_parts.append("</div>")
            continue
        html_parts.append("<p>")
        html_parts.append(f"Dereference: {e.get('dereference')} | Array access: {e.get('array_access')}")
        html_parts.append("</p>")
        if e.get("alloc_calls"):
            html_parts.append("<p>Alloc calls:</p><pre>" + "\n".join([l for (_, l) in e.get("alloc_calls")]) + "</pre>")
        if e.get("free_calls"):
            html_parts.append("<p>Free calls:</p><pre>" + "\n".join([l for (_, l) in e.get("free_calls")]) + "</pre>")
        if e.get("nearby_lines"):
            html_parts.append("<p>Nearby lines:</p><pre>")
            for ln, txt in e.get("nearby_lines"):
                html_parts.append(f"{ln}: {txt}\n")
            html_parts.append("</pre>")
        if e.get("snippet"):
            html_parts.append("<p>Snippet:</p><pre>" + e.get("snippet") + "</pre>")
        html_parts.append("</div>")

    html_parts.append("</body></html>")
    html = "\n".join(html_parts)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)


def fetch_syz_bug_page(url: str) -> Optional[str]:
    """Fetch a syzkaller bug page and attempt to extract the crash log text.

    The syzkaller bug page contains structured sections; we'll look for the <pre> or text block
    that contains the BUG: KASAN or Call Trace and return it. This is best-effort HTML parsing.
    """
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            html = r.read().decode(errors='ignore')
    except Exception:
        return None
    # crude extraction: find the first <pre>...</pre> block which usually contains logs
    m = re.search(r"<pre[^>]*>(.*?)</pre>", html, re.S | re.I)
    if m:
        txt = m.group(1)
        # strip HTML entities naive
        txt = re.sub(r"&lt;", "<", txt)
        txt = re.sub(r"&gt;", ">", txt)
        txt = re.sub(r"&amp;", "&", txt)
        return txt
    # fallback: look for 'Call Trace' lines
    if 'Call Trace' in html:
        # remove tags
        txt = re.sub(r"<[^>]+>", "\n", html)
        # compact and return
        return txt
    return None


def download_syz_bug_assets(url: str, out_dir: str) -> bool:
    """Download attachments and embedded logs from a syzkaller bug page into out_dir.

    This is a best-effort HTML parser: it downloads the bug page, finds links to attachments
    (often under /files/ or direct raw links) and saves them using their basename. It also
    extracts the first <pre> block and saves it as `page_pre.txt`.
    """
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            html = r.read().decode(errors='ignore')
    except Exception:
        return False
    os.makedirs(out_dir, exist_ok=True)
    # save first <pre> block if present
    m = re.search(r"<pre[^>]*>(.*?)</pre>", html, re.S | re.I)
    if m:
        txt = m.group(1)
        txt = re.sub(r"&lt;", "<", txt)
        txt = re.sub(r"&gt;", ">", txt)
        txt = re.sub(r"&amp;", "&", txt)
        with open(os.path.join(out_dir, 'page_pre.txt'), 'w', encoding='utf-8') as fh:
            fh.write(txt)

    # find hrefs that look like files or direct links
    links = re.findall(r'href=["\']([^"\']+)["\']', html)
    for l in links:
        # consider links that contain '/files/' or end with common extensions
        if '/files/' in l or l.endswith('.txt') or l.endswith('.log') or l.endswith('.bz2') or l.endswith('.gz'):
            full = urllib.parse.urljoin(url, l)
            try:
                with urllib.request.urlopen(full, timeout=15) as r2:
                    data = r2.read()
                    name = os.path.basename(urllib.parse.urlparse(full).path) or 'attachment'
                    path = os.path.join(out_dir, name)
                    with open(path, 'wb') as fh:
                        fh.write(data)
            except Exception:
                # ignore single failures
                continue
    return True

def save_to_json(result: Dict[str, Any], url: str) -> None:
    """Save the analysis result to a JSON file."""
    # write JSON to crash_analysis/<bugid>.json
    out_dir = os.path.join(os.getcwd(), 'crash_analysis')
    os.makedirs(out_dir, exist_ok=True)
    # attempt to determine a bug id from parsed data; fallback to input basename
    default_name = url.split('=')[-1]
    # bugid = determine_bug_id(result.get('parsed', {}), default_name)
    # Attempt to enrich result with LLM analysis when possible
    try:
        snippets = result.get('snippets', {}) or {}
        def _build_snippet_map(snips: Dict[str, Any]) -> Dict[str, str]:
            out = {}
            # urls
            for k, v in (snips.get('urls') or {}).items():
                if isinstance(v, str):
                    out[k] = v
                elif isinstance(v, dict) and v.get('snippet'):
                    out[k] = v.get('snippet')
            # links
            for k, v in (snips.get('links') or {}).items():
                if isinstance(v, dict) and v.get('snippet'):
                    out[k] = v.get('snippet')
            # local
            for k, v in (snips.get('local') or {}).items():
                if isinstance(v, dict) and v.get('snippet'):
                    out[k] = v.get('snippet')
            return out

        frames = result.get('parsed', {}).get('frames', [])
        snippet_map = _build_snippet_map(snippets)
        try:
            llm_res = llm_analyze_traces(frames, snippet_map)
            result['llm_analysis'] = llm_res
        except Exception as e:
            result['llm_analysis'] = {"ok": False, "error": str(e)}
    except Exception:
        # non-fatal, continue without LLM
        pass

    out_path = os.path.join(out_dir, f"{default_name}.json")
    with open(out_path, 'w', encoding='utf-8') as fh:
        json.dump(result, fh, indent=2)
    print(out_path)


def main():
    p = argparse.ArgumentParser(description="Analyze kernel crash logs and classify primitives")
    p.add_argument("--source-root", help="Path to source root to find referenced files (optional)")
    p.add_argument("--json", action="store_true", help="Emit JSON result")
    p.add_argument("--json-report", action="store_true", help="Emit compact JSON report for triage")
    p.add_argument("--html-report", help="Write an HTML report to the given file path")
    p.add_argument("--bulk-dir", help="Directory containing crash logs to analyze in bulk")
    p.add_argument("--out-dir", help="Output directory for bulk analysis")
    p.add_argument("--fetch-urls", help="Path to a file containing crash report URLs to fetch and analyze")
    p.add_argument("--syz-bug", help="Fetch and analyze a syzkaller bug page URL (single)")
    p.add_argument("--download-syz", help="Download all attachments and logs from a syzkaller bug page into out-dir")
    args = p.parse_args()

    # Bulk operations
    if args.bulk_dir and args.out_dir:
        analyze_directory(args.bulk_dir, args.out_dir, args.source_root)
        return
    if args.fetch_urls and args.out_dir:
        fetch_and_analyze_urls(args.fetch_urls, args.out_dir, args.source_root)
        return
    if args.syz_bug:
        txt = fetch_syz_bug_page(args.syz_bug)
        if not txt:
            print("Failed to fetch or parse syz bug page")
            return
        result = analyze(txt, args.source_root)
        strong = stronger_heuristics(result["parsed"], result.get("snippets", {}), result.get("evidence", {}))
        result["strong_report"] = strong
        if args.json:
            save_to_json(result, args.syz_bug)
            return
        if args.json_report:
            compact = {
                "primitive": strong["primitive"],
                "vulnerability": strong.get("vulnerability"),
                "confidence": strong["confidence"],
                "preconditions": strong["preconditions"],
                "postconditions": strong["postconditions"],
                "support": strong["support"],
                "evidence_summary": {k: {"dereference": v.get("dereference"), "array_access": v.get("array_access")}
                                      for k, v in result.get("evidence", {}).items() if isinstance(v, dict)},
            }
            save_to_json(compact, args.syz_bug)
            return
        # default human summary
        print("Primitive:", strong["primitive"])
        print("Confidence:", strong["confidence"])
        print("Support:")
        for s in strong["support"]:
            print(" -", s)
        if args.html_report:
            generate_html_report(result, args.html_report)
        return
    if args.download_syz and args.out_dir:
        ok = download_syz_bug_assets(args.download_syz, args.out_dir)
        if not ok:
            print("Failed to download syz bug assets")
            return
        # run analysis on downloaded directory
        analyze_directory(args.out_dir, args.out_dir, args.source_root)
        return

    result = analyze(txt, args.source_root)
    # run stronger heuristics and include in output
    strong = stronger_heuristics(result["parsed"], result.get("snippets", {}), result.get("evidence", {}))
    result["strong_report"] = strong

    if args.json:
        save_to_json(result, "input")
        return

    if args.json_report:
        # compact report
        compact = {
            "primitive": strong["primitive"],
            "vulnerability": strong.get("vulnerability"),
            "confidence": strong["confidence"],
            "preconditions": strong["preconditions"],
            "postconditions": strong["postconditions"],
            "support": strong["support"],
            "evidence_summary": {k: {"dereference": v.get("dereference"), "array_access": v.get("array_access")}
                                  for k, v in result.get("evidence", {}).items() if isinstance(v, dict)},
        }
        save_to_json(compact, "input")
        return
    else:
        # human friendly concise summary (show vulnerability prominently)
        print("Vulnerability:", strong.get("vulnerability"))
        print("Primitive:", strong.get("primitive"))
        print("Confidence:", strong.get("confidence"))
        print("Preconditions:")
        for p in strong.get("preconditions", []):
            print(" -", p)
        print("Postconditions:")
        for p in strong.get("postconditions", []):
            print(" -", p)
        print("Support:")
        for s in strong.get("support", []):
            print(" -", s)

    # Optionally generate an HTML report if requested
    if hasattr(args, 'html_report') and args.html_report:
        generate_html_report(result, args.html_report)


if __name__ == "__main__":
    import sys
    main()


def analyze_directory(input_dir: str, out_dir: str, source_root: Optional[str] = None) -> None:
    """Analyze all crash log files in a directory and write per-file JSON+HTML to out_dir.

    Behavior: scans files with .txt or .log extension; for each file runs analyze() and writes
    `{basename}.json` and `{basename}.html` (HTML only if html generation is possible).
    """
    os.makedirs(out_dir, exist_ok=True)
    # central crash_analysis directory for JSON outputs
    crash_dir = os.path.join(os.getcwd(), 'crash_analysis')
    os.makedirs(crash_dir, exist_ok=True)
    for fn in os.listdir(input_dir):
        if not (fn.endswith('.txt') or fn.endswith('.log') or fn.endswith('.crash')):
            continue
        path = os.path.join(input_dir, fn)
        try:
            with open(path, 'r', errors='ignore') as fh:
                txt = fh.read()
        except Exception:
            continue
        result = analyze(txt, source_root)
        base = os.path.splitext(fn)[0]
        # determine bug id and write JSON into crash_analysis (includes LLM enrichment)
        bugid = determine_bug_id(result.get('parsed', {}), base)
        save_to_json(result, bugid)
        # generate HTML report
        html_path = os.path.join(out_dir, base + '.html')
        try:
            strong = stronger_heuristics(result['parsed'], result.get('snippets', {}), result.get('evidence', {}))
            result['strong_report'] = strong
            generate_html_report(result, html_path)
        except Exception:
            # continue even if HTML generation fails
            pass


def fetch_and_analyze_urls(url_list_file: str, out_dir: str, source_root: Optional[str] = None) -> None:
    """Fetch crash logs from a list of URLs (one per line) and analyze them.

    It will attempt to GET each URL and treat the response as the crash log text.
    Results are stored under out_dir, named by a sanitized hash of the URL.
    """
    os.makedirs(out_dir, exist_ok=True)
    # central crash_analysis directory for JSON outputs
    crash_dir = os.path.join(os.getcwd(), 'crash_analysis')
    os.makedirs(crash_dir, exist_ok=True)
    with open(url_list_file, 'r') as fh:
        urls = [l.strip() for l in fh if l.strip()]
    for u in urls:
        try:
            with urllib.request.urlopen(u, timeout=15) as r:
                txt = r.read().decode(errors='ignore')
        except Exception:
            continue
        result = analyze(txt, source_root)
        # try naming by bug id or url basename; fallback to hash
        default_name = os.path.splitext(os.path.basename(urllib.parse.urlparse(u).path))[0] or 'url'
        bugid = determine_bug_id(result.get('parsed', {}), default_name)
        try:
            save_to_json(result, bugid)
        except Exception:
            import hashlib
            h = hashlib.sha1(u.encode()).hexdigest()[:12]
            save_to_json(result, h)
        html_path = os.path.join(out_dir, f'{os.path.splitext(os.path.basename(urllib.parse.urlparse(u).path))[0] or h}.html')
        try:
            strong = stronger_heuristics(result['parsed'], result.get('snippets', {}), result.get('evidence', {}))
            result['strong_report'] = strong
            generate_html_report(result, html_path)
        except Exception:
            pass


def fetch_syz_bug_page(url: str) -> Optional[str]:
    """Fetch a syzkaller bug page and attempt to extract the crash log text.

    The syzkaller bug page contains structured sections; we'll look for the <pre> or text block
    that contains the BUG: KASAN or Call Trace and return it. This is best-effort HTML parsing.
    """
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            html = r.read().decode(errors='ignore')
    except Exception:
        return None
    # crude extraction: find the first <pre>...</pre> block which usually contains logs
    m = re.search(r"<pre[^>]*>(.*?)</pre>", html, re.S | re.I)
    if m:
        txt = m.group(1)
        # strip HTML entities naive
        txt = re.sub(r"&lt;", "<", txt)
        txt = re.sub(r"&gt;", ">", txt)
        txt = re.sub(r"&amp;", "&", txt)
        return txt
    # fallback: look for 'Call Trace' lines
    if 'Call Trace' in html:
        # remove tags
        txt = re.sub(r"<[^>]+>", "\n", html)
        # compact and return
        return txt
    return None


def download_syz_bug_assets(url: str, out_dir: str) -> bool:
    """Download attachments and embedded logs from a syzkaller bug page into out_dir.

    This is a best-effort HTML parser: it downloads the bug page, finds links to attachments
    (often under /files/ or direct raw links) and saves them using their basename. It also
    extracts the first <pre> block and saves it as `page_pre.txt`.
    """
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            html = r.read().decode(errors='ignore')
    except Exception:
        return False
    os.makedirs(out_dir, exist_ok=True)
    # save first <pre> block if present
    m = re.search(r"<pre[^>]*>(.*?)</pre>", html, re.S | re.I)
    if m:
        txt = m.group(1)
        txt = re.sub(r"&lt;", "<", txt)
        txt = re.sub(r"&gt;", ">", txt)
        txt = re.sub(r"&amp;", "&", txt)
        with open(os.path.join(out_dir, 'page_pre.txt'), 'w', encoding='utf-8') as fh:
            fh.write(txt)

    # find hrefs that look like files or direct links
    links = re.findall(r'href=["\']([^"\']+)["\']', html)
    for l in links:
        # consider links that contain '/files/' or end with common extensions
        if '/files/' in l or l.endswith('.txt') or l.endswith('.log') or l.endswith('.bz2') or l.endswith('.gz'):
            full = urllib.parse.urljoin(url, l)
            try:
                with urllib.request.urlopen(full, timeout=15) as r2:
                    data = r2.read()
                    name = os.path.basename(urllib.parse.urlparse(full).path) or 'attachment'
                    path = os.path.join(out_dir, name)
                    with open(path, 'wb') as fh:
                        fh.write(data)
            except Exception:
                # ignore single failures
                continue
    return True
