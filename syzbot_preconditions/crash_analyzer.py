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
from typing import List, Dict, Any, Optional, Tuple, Set
from openai import OpenAI
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
from dotenv import load_dotenv


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
            func_name = m.group(1)
            # skip KASAN/shadow-memory helper frames -- they refer to shadow memory handling, not the actual buggy code
            file_path = (m.group(2) or '').strip()
            if (func_name and 'kasan' in func_name.lower()) or ('kasan' in file_path.lower()):
                # ignore any frames that refer to KASAN/shadow or kernel sanitizers
                continue
            frames.append({"func": func_name, "file": file_path, "line": int(m.group(3)), "raw": l.strip()})

    # A looser fallback: lines like "f2fs_iget+0x43aa/0x4dc0 fs/f2fs/inode.c:514"
    loose_re = re.compile(r"^\s*([\w0-9_@\-]+)(?:\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+)?\s+([^:]+):(\d+)\b")
    if not frames:
        for l in lines:
            m = loose_re.match(l)
            if m:
                func_name = m.group(1)
                file_path = (m.group(2) or '').strip()
                if (func_name and 'kasan' in func_name.lower()) or ('kasan' in file_path.lower()):
                    continue
                frames.append({"func": func_name, "file": file_path, "line": int(m.group(3)), "raw": l.strip()})

    # Also extract frames embedded as HTML anchors: <a href='URL'>path/file.c:123</a>
    link_frames: List[Dict[str, Any]] = []
    for m in re.finditer(r"<a\s+[^>]*href=[\'\"]([^\'\"]+)[\'\"][^>]*>([^<:]+:[0-9]+)</a>", text, re.I):
        url = m.group(1)
        target = m.group(2)
        # target like fs/ext4/namei.c:3704
        try:
            filepart, lineno = target.rsplit(':', 1)
            # filter out KASAN-related anchors as well
            if 'kasan' in (filepart or '').lower() or 'kasan' in (url or '').lower():
                continue
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
    evidence = {"dereference": False, "array_access": False, "alloc_calls": [], "free_calls": [], "nearby_lines": [],
                # counts to help distinguish read vs write uses of dereferences
                "deref_writes": 0, "deref_reads": 0,
                # capture exact dereference expressions like "dentry->d_inode->i_mode"
                "deref_exprs": []}
    lines = snippet.splitlines()
    for i, l in enumerate(lines):
        # detect pointer dereference usages
        if "->" in l or "(*" in l or ("*" in l and "." not in l):
            evidence["dereference"] = True
            evidence["nearby_lines"].append((i + 1, l.strip()))
            # capture full dereference expressions (var->field->...)
            try:
                for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*(?:->[A-Za-z_][A-Za-z0-9_]*)+)\b", l):
                    expr = m.group(1)
                    if expr not in evidence['deref_exprs']:
                        evidence['deref_exprs'].append(expr)
            except Exception:
                pass
            # improved LHS/RHS assignment heuristic: explicitly capture simple assignments
            try:
                assign_m = re.match(r"^\s*(?P<left>.+?)\s*=\s*(?P<right>.+);?\s*$", l)
                if assign_m:
                    left = assign_m.group('left')
                    right = assign_m.group('right')
                    # if LHS contains a deref/pointer/index, count as a write
                    if re.search(r"->|\[|\*", left):
                        evidence['deref_writes'] += 1
                    # if RHS contains a deref, count as a read
                    if re.search(r"->|\[|\*", right):
                        evidence['deref_reads'] += 1
                else:
                    # no simple assignment detected: check for comparison or read-like usage
                    if re.search(r"\bif\b|==|!=|<|>|memcmp|memcmp_from_user|strncmp|strcmp|memcmp", l):
                        evidence['deref_reads'] += 1
                    else:
                        # conservative: leave counts unchanged when undecidable
                        pass
            except Exception:
                pass
        # detect mem* and copy_from_user/copy_to_user patterns which are strongly indicative
        # of reads vs writes depending on argument position
        mem_m = re.search(r"\b(memcpy|memmove|memset)\s*\((.*)\)", l)
        if mem_m:
            evidence['array_access'] = True
            evidence['nearby_lines'].append((i + 1, l.strip()))
            try:
                args = mem_m.group(2)
                # naive split by comma (works for common simple usages)
                parts = [p.strip() for p in args.split(',')]
                if parts:
                    # dest is first arg for memcpy/memmove
                    dest = parts[0]
                    if re.search(r"->|\[|\*", dest):
                        evidence['deref_writes'] += 1
                    if len(parts) > 1:
                        src = parts[1]
                        if re.search(r"->|\[|\*", src):
                            evidence['deref_reads'] += 1
            except Exception:
                pass
        # copy_from_user(dst, src, n): copies from user into kernel (dst is written)
        if re.search(r"\bcopy_from_user\s*\(", l):
            evidence['nearby_lines'].append((i + 1, l.strip()))
            # mark as write to kernel-side pointers
            evidence['deref_writes'] += 1
        # copy_to_user(dst, src, n): copies from kernel to user (src is read)
        if re.search(r"\bcopy_to_user\s*\(", l):
            evidence['nearby_lines'].append((i + 1, l.strip()))
            evidence['deref_reads'] += 1
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


def _analyze_control_flow_path_constraints(parsed: Dict[str, Any], snippets: Dict[str, Any], evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Scan available snippets and stack frames backwards from the crash and extract
    control-flow conditions (if/for/while/switch) and early blockers (returns/gotos).

    Heuristics attempt to classify each condition as either an INPUT constraint
    (checks that gate user-controlled/syscall-provided buffers/lengths/flags) or a
    KERNEL-STATE constraint (NULL checks, capability/feature checks, allocation/ownership checks).

    Returns dict with keys: input_constraints (list), kernel_state_constraints (list)
    Each entry contains: frame,file,line,code,condition,variables,evidence (nearby lines),why_it_blocks
    """
    input_constraints = []
    kernel_constraints = []

    # Build a simple vars_found set from evidence if provided, otherwise attempt a best-effort scan
    vars_found = set()
    try:
        if evidence:
            for k, v in (evidence or {}).items():
                if not isinstance(v, dict):
                    continue
                for (_, ln) in v.get('nearby_lines', []):
                    # extract var-like tokens
                    for tok in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", ln):
                        if len(tok) > 1 and not tok.isupper():
                            vars_found.add(tok)
        # also inspect snippet texts for pointer/field usages
        for section in (snippets.get('links') or {}).values():
            if not isinstance(section, dict):
                continue
            txt = section.get('function_snippet') or ''
            for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*->\s*([A-Za-z_][A-Za-z0-9_]*)", txt):
                vars_found.add(m.group(1))
            for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*\[", txt):
                vars_found.add(m.group(1))
    except Exception:
        pass

    # token lists for heuristics
    input_indicators = set(["copy_from_user", "get_user", "put_user", "ioctl", "syscall", "user", "uid", "gid", "flags", "len", "count", "size", "addr", "offset", "buf", "name", "path", "dname", "name_len", "rec_len"])
    kernel_indicators = set(["== NULL", "!= NULL", "IS_ERR", "IS_ERR_OR_NULL", "unlikely", "mutex", "spin_lock", "test_bit", "capable", "in_interrupt", "return -EINVAL", "return -ENOMEM", "goto", "return 0", "return -EPERM"])

    # First: collect conditional-like lines from all available snippets (links, local, urls)
    conditions = []

    def _collect_from_text(file_hint, base_line, text, key):
        if not text:
            return
        for i, ln in enumerate(text.splitlines(), start=1):
            s = ln.strip()
            if not s:
                continue
            # candidate conditional lines
            if re.search(r"\b(if|for|while|switch)\b\s*\(|\breturn\b|\bgoto\b", s):
                # extract a parenthesized condition when possible
                cond = None
                m = re.search(r"\bif\s*\((.+)\)", s)
                if not m:
                    m = re.search(r"\bfor\s*\((.+)\)", s)
                if not m:
                    m = re.search(r"\bwhile\s*\((.+)\)", s)
                if not m:
                    m = re.search(r"\bswitch\s*\((.+)\)", s)
                if m:
                    cond = m.group(1).strip()
                else:
                    # for returns/goto/other take the full line as condition text
                    cond = s

                vars_in_cond = [tok for tok in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", cond or '') if not re.match(r"^[0-9]+$", tok)]
                conditions.append({'file': file_hint, 'line': (base_line or 0) + i, 'code': s, 'condition': cond, 'variables': vars_in_cond, 'key': key})

    # collect from link snippets
    for k, v in (snippets.get('links') or {}).items():
        if isinstance(v, dict):
            txt = v.get('function_snippet') or v.get('snippet') or ''
            _collect_from_text(v.get('file'), v.get('line'), txt, k)
    # collect from local snippets
    for k, v in (snippets.get('local') or {}).items():
        if isinstance(v, dict):
            txt = v.get('snippet') or ''
            _collect_from_text(os.path.basename(v.get('path') or ''), v.get('line') or 0, txt, k)
    # collect from urls mapping
    for k, v in (snippets.get('urls') or {}).items():
        txt = v if isinstance(v, str) else (v.get('snippet') if isinstance(v, dict) else '')
        _collect_from_text(None, None, txt, k)

    # Heuristics for classification
    input_kw = set(list(input_indicators) + ['name', 'd_name', 'nd', 'last', 'path', 'dentry', 'buf', 'filename', 'dirent', 'count', 'len', 'name_len'])
    kernel_kw = set(list(kernel_indicators) + ['== NULL', '!= NULL', 'IS_ERR', 'WARN_ON', 'BUG_ON', 'unlikely', 'goto', 'return'])

    # Helper: try to detect variable origin (copy_from_user/memcpy/syscall param)
    def _trace_var_origin(var):
        origins = set()
        # scan all snippets for patterns that assign or copy into var
        for k, v in (snippets.get('links') or {}).items():
            if not isinstance(v, dict):
                continue
            txt = v.get('function_snippet') or v.get('snippet') or ''
            for i, ln in enumerate(txt.splitlines(), start=1):
                if re.search(rf"\bcopy_from_user\s*\(.*\b{re.escape(var)}\b|\bmemcpy\s*\(\s*{re.escape(var)}\b", ln):
                    origins.add('copy_from_user')
                if re.search(rf"\bcopy_to_user\s*\(.*\b{re.escape(var)}\b", ln):
                    origins.add('copy_to_user')
                if re.search(rf"\b{re.escape(var)}\b\s*=\s*.*\bcopy_from_user\b", ln):
                    origins.add('copy_from_user')
                # syscall param heuristic: presence of var in function header and function name suggests syscall origin
                if re.search(rf"\b{re.escape(var)}\b\s*[,\)]", ln):
                    # if snippet key suggests syscall wrapper, mark as param
                    if re.search(r"__x64_sys_|__se_sys_|sys_|ksys_", v.get('function_snippet') or '' or '', re.I):
                        origins.add('syscall_param')
        # local snippets
        for k, v in (snippets.get('local') or {}).items():
            if not isinstance(v, dict):
                continue
            txt = v.get('snippet') or ''
            for ln in txt.splitlines():
                if re.search(rf"\bcopy_from_user\s*\(.*\b{re.escape(var)}\b", ln):
                    origins.add('copy_from_user')
        return list(origins)

    # Classify collected conditions and attach to input/kernel lists
    for c in conditions:
        cond_text = (c.get('condition') or '')
        lowc = cond_text.lower() if cond_text else ''
        vars_in_cond = c.get('variables') or []
        classification = 'kernel_state'
        reasons = []

        # direct indicators
        if any(kw in lowc for kw in ('copy_from_user', 'get_user', 'put_user', 'ioctl', 'syscall', 'copy_to_user')):
            classification = 'input'
            reasons.append('contains explicit user-copy/syscall keywords')

        # variable-origin tracing
        for vname in vars_in_cond:
            origins = _trace_var_origin(vname)
            if any(o in ('copy_from_user', 'syscall_param', 'user_buffer') for o in origins):
                classification = 'input'
                reasons.append(f"variable '{vname}' traced to user/syscall source: {', '.join(origins)}")
                break

        # token heuristics
        if classification != 'input':
            if any(tok in lowc for tok in ('== null', '!= null', 'is_err', 'is_err_or_null', 'warn_on', 'bug_on')):
                classification = 'kernel_state'
                reasons.append('null/is_err/warn guard')
            elif any(tok in lowc for tok in ('len', 'size', 'offset', 'addr', 'count', 'name_len')):
                # likely input constraint if comparing sizes/offsets
                classification = 'input'
                reasons.append('size/len/offset token present in condition')

        # if still ambiguous because both kernel and input tokens present
        if any(tok in lowc for tok in ('copy_from_user', 'len')) and any(tok in lowc for tok in ('== null', 'is_err')):
            classification = 'ambiguous'
            reasons.append('both input and kernel-state patterns present')

        entry = {
            'frame': None,
            'file': c.get('file'),
            'line': c.get('line'),
            'code': c.get('code'),
            'condition': c.get('condition'),
            'variables': vars_in_cond,
            'evidence': [],
            'why_it_blocks': '; '.join(reasons) if reasons else 'guard or conditional that may prevent reaching crash site',
        }

        if classification == 'input':
            input_constraints.append(entry)
        elif classification == 'kernel_state':
            kernel_constraints.append(entry)
        else:
            # ambiguous entries go into kernel by default but marked
            entry['why_it_blocks'] = (entry.get('why_it_blocks') + '; marked ambiguous') if entry.get('why_it_blocks') else 'ambiguous'
            kernel_constraints.append(entry)

    # dedupe by (file,line,condition)
    def _dedupe(lst):
        seen = set()
        out = []
        for e in lst:
            key = (e.get('file'), e.get('line'), e.get('condition'))
            if key in seen:
                continue
            seen.add(key)
            out.append(e)
        return out

    # If we found no constraints at all, attempt a weaker, broad scan over all
    # available snippets (link snippets and local/url snippets) and extract any
    # conditional lines we can find. This helps in cases where the original
    # backward walk did not match frames to snippets tightly (common with inlined
    # functions or different naming conventions). The results are lower-confidence
    # but better than empty lists.
    try:
        if not input_constraints and not kernel_constraints:
            fallback_hits = []
            # collect candidate texts
            candidates = []
            for k, v in (snippets.get('links') or {}).items():
                if isinstance(v, dict) and v.get('function_snippet'):
                    candidates.append({'file': v.get('file'), 'line': v.get('line'), 'text': v.get('function_snippet'), 'key': k})
            for k, v in (snippets.get('local') or {}).items():
                if isinstance(v, dict) and v.get('snippet'):
                    candidates.append({'file': os.path.basename(v.get('path') or ''), 'line': v.get('line'), 'text': v.get('snippet'), 'key': k})
            for k, v in (snippets.get('urls') or {}).items():
                txt = v if isinstance(v, str) else (v.get('snippet') if isinstance(v, dict) else '')
                if txt:
                    candidates.append({'file': None, 'line': None, 'text': txt, 'key': k})

            for item in candidates:
                text = item.get('text') or ''
                file = item.get('file')
                base_line = item.get('line') or 0
                for i, ln in enumerate(text.splitlines(), start=1):
                    s = ln.strip()
                    # quick filter for lines likely to be conditionals
                    if not s:
                        continue
                    if re.search(r"\b(if|for|while|switch)\b\s*\(|\breturn\b|\bgoto\b", s):
                        # extract condition text where possible
                        m = re.search(r"\bif\s*\((.+)\)", s)
                        cond = None
                        kind = 'kernel_state'
                        if m:
                            cond = m.group(1).strip()
                        else:
                            # try for for/while/switch
                            m2 = re.search(r"\bfor\s*\((.+)\)", s) or re.search(r"\bwhile\s*\((.+)\)", s) or re.search(r"\bswitch\s*\((.+)\)", s)
                            if m2:
                                cond = m2.group(1).strip()
                            else:
                                # return/goto/other - keep the full line as condition
                                cond = s

                        lowc = (cond or '').lower()
                        # classify heuristically
                        if re.search(r"copy_from_user|get_user|put_user|ioctl|syscall|user|len|size|offset|count|buf|name|path", lowc):
                            kind = 'input'
                        elif re.search(r"==\s*NULL|!=\s*NULL|is_err|is_err_or_null|unlikely|mutex|spin_lock|capable|return\s*-E", lowc):
                            kind = 'kernel_state'
                        else:
                            # fallback: if condition mentions numeric comparisons or size tokens, lean input
                            if re.search(r"[<>]=?|\b(len|size|offset|count|addr)\b", lowc):
                                kind = 'input'
                            else:
                                kind = 'kernel_state'

                        entry = {'frame': None, 'file': file, 'line': base_line + i, 'code': s, 'condition': cond, 'variables': re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", cond or ''), 'evidence': [{'line_no': i, 'text': s}], 'why_it_blocks': 'fallback conditional extracted from snippet'}
                        if kind == 'input':
                            input_constraints.append(entry)
                        else:
                            kernel_constraints.append(entry)
    except Exception:
        pass

    return {'input_constraints': _dedupe(input_constraints), 'kernel_state_constraints': _dedupe(kernel_constraints)}


def _trace_variable_across_frames(parsed: Dict[str, Any], snippets: Dict[str, Any], var_names: List[str]) -> Dict[str, Any]:
    """Attempt a lightweight backward trace for variables across frames/snippets.

    For each variable name, search earlier frames/snippets for:
      - copy_from_user/copy_to_user usages involving the var
      - memcpy/memmove where var appears as a source/dest
      - simple assignments 'var = ...' or '&var ='
      - function parameter names in function headers present in snippets

    Returns a map var -> list of trace records with keys: frame,file,line,code,source (one of copy_from_user,user_buffer,syscall_param,assignment,unknown)
    This is a heuristic helper (best-effort) and not a full dataflow engine.
    """
    # Build a dataflow graph from available snippets and propagate taint from user/syscall seeds
    try:
        graph_result = build_dataflow_graph(parsed, snippets)
        graph = graph_result.get('graph')
        node_occurrences = graph_result.get('occurrences')
        # identify seeds: copy_from_user destinations and syscall parameter nodes
        seeds = {}
        # copy_from_user detected ops
        for node, meta in graph_result.get('meta', {}).get('copy_from_user', {}).items():
            # meta may list occurrences; mark seed with label copy_from_user
            seeds[node] = {'label': 'copy_from_user'}
        # syscall parameter seeds: detect frames with syscall-like names
        for f in (parsed.get('frames') or []):
            fname = f.get('func') or ''
            if re.search(r"^(__x64_sys_|__se_sys_|sys_|ksys_)", fname):
                # add all param nodes for this function if present in graph
                params = graph_result.get('func_params', {}).get(fname) or []
                for p in params:
                    n = f"{p}@{fname}"
                    seeds[n] = {'label': 'syscall_param'}

        # propagate taint forward from seeds
        tainted = propagate_taint_graph(graph, seeds, max_depth=7, max_nodes=500)

        out = {}
        for v in var_names:
            out[v] = []
            # find any occurrences of variable 'v' in node_occurrences
            for node, occs in node_occurrences.items():
                # node format: var@func
                if not node.startswith(v + '@') and not node.split('@')[0] == v:
                    continue
                # if node is tainted, collect traces
                if node in tainted:
                    tag = tainted[node].get('seed_label')
                    dist = tainted[node].get('distance')
                    # include all occurrence contexts for this node
                    for occ in occs:
                        rec = {'file': occ.get('file'), 'line': occ.get('line'), 'code': occ.get('code'), 'source': tag, 'distance': dist}
                        out[v].append(rec)
                else:
                    # include occurrence as non-tainted mention
                    for occ in occs:
                        out[v].append({'file': occ.get('file'), 'line': occ.get('line'), 'code': occ.get('code'), 'source': None, 'distance': None})
        return out
    except Exception:
        # fallback to previous simple heuristic when graphing fails
        out = {}
        frames = parsed.get('frames') or []
        for v in var_names:
            out[v] = []
        try:
            # collect snippet texts keyed by filename for quick search
            texts = []
            for k, s in (snippets.get('links') or {}).items():
                if isinstance(s, dict) and s.get('function_snippet'):
                    texts.append({'key': k, 'file': s.get('file'), 'text': s.get('function_snippet')})
            for k, s in (snippets.get('local') or {}).items():
                if isinstance(s, dict) and s.get('snippet'):
                    texts.append({'key': k, 'file': os.path.basename(s.get('path') or ''), 'text': s.get('snippet')})
            for k, s in (snippets.get('urls') or {}).items():
                txt = s if isinstance(s, str) else (s.get('snippet') if isinstance(s, dict) else '')
                if txt:
                    texts.append({'key': k, 'file': None, 'text': txt})

            # simple heuristics to identify origin
            for item in texts:
                file = item.get('file')
                txt = item.get('text') or ''
                for i, line in enumerate(txt.splitlines(), start=1):
                    for v in var_names:
                        # exact token boundary check
                        if re.search(rf"\b{re.escape(v)}\b", line):
                            rec = {'file': file, 'line': i, 'code': line.strip(), 'key': item.get('key')}
                            if re.search(rf"copy_from_user\s*\(\s*{re.escape(v)}\s*,", line):
                                rec['source'] = 'copy_from_user'
                                out[v].append(rec)
                                continue
                            if re.search(rf"copy_to_user\s*\(.*,{re.escape(v)}\s*\)", line):
                                rec['source'] = 'copy_to_user'
                                out[v].append(rec)
                                continue
                            m_mem = re.search(rf"\b(memcpy|memmove)\s*\(\s*{re.escape(v)}\s*,\s*([^,]+)", line)
                            if m_mem:
                                src = m_mem.group(2).strip()
                                if re.search(r"copy_from_user|user", src, re.I):
                                    rec['source'] = 'user_buffer'
                                else:
                                    rec['source'] = 'memcpy_assignment'
                                out[v].append(rec)
                                continue
                            if re.search(rf"\b{re.escape(v)}\s*=", line) or re.search(rf"\*\s*{re.escape(v)}\s*=" , line):
                                rec['source'] = 'assignment'
                                out[v].append(rec)
                                continue
                            if '(' in line and ')' in line and re.search(rf"\b{re.escape(v)}\b", line):
                                rec['source'] = 'param' if re.search(r'syz_|sys_|__x64_sys_|__se_sys_', txt, re.I) else 'param'
                                out[v].append(rec)
                                continue
                            rec['source'] = 'unknown'
                            out[v].append(rec)
        except Exception:
            pass
        return out


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
    deref_writes = 0
    deref_reads = 0
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
        # aggregate deref read/write heuristics if present
        try:
            dw = int(v.get('deref_writes', 0) or 0)
            dr = int(v.get('deref_reads', 0) or 0)
            deref_writes += dw
            deref_reads += dr
        except Exception:
            pass

    # heuristic mapping
    if "use-after-free" in prim:
        # if evidence indicates a read access and attacker-controlled input can reach the path,
        # prefer calling it an info-leak; if write evidence exists prefer arbitrary write.
        # Prefer evidence-driven decision: if deref_writes exceeds reads, call it an arbitrary write
        if deref_writes > deref_reads or any_write:
            vuln = "arbitrary_write"
        elif deref_reads > 0 or any_read:
            # pointer deref reads or array reads -> info leak
            if any_deref or any_array:
                vuln = "arbitrary_read"
            else:
                vuln = "info-leak (use-after-free read of reclaimed memory)"
        else:
            vuln = "use-after-free (may allow read/write of reclaimed memory)"
    elif "double-free" in prim or "invalid-free" in prim:
        vuln = "memory corruption (double/invalid free may lead to heap corruption)"
    elif "write" in prim:
        vuln = "data corruption / potential arbitrary write"
    elif "read" in prim or prim.startswith("read"):
        vuln = "info-leak (bounded or unbounded read)"
    elif "oob" in prim or "out-of-bounds" in " ".join(report.get("support", [])):
        # for OOB prefer write if evidence shows deref writes or access op write
        if deref_writes > deref_reads or any_write:
            vuln = "arbitrary_write"
        elif deref_reads > 0 or any_read:
            vuln = "arbitrary_read"
        else:
            # fallback to info-leak for reads
            vuln = "info-leak (oob read)"
    else:
        vuln = "unknown"

    # Swap semantics: make vulnerability the primitive label (what attacker can do)
    # and primitive the low-level bug description
    report["vulnerability"] = vuln or report.get("vulnerability") or "unknown"
    report["primitive"] = report.get("primitive") or "unknown"

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

    # Analyze control-flow along the stack to surface path constraints
    try:
        path_constraints = _analyze_control_flow_path_constraints(parsed, snippets, evidence)
        # attach to report for downstream use and LLM context
        report['path_constraints'] = path_constraints
        # convert constraints into human-friendly preconditions
        for ic in path_constraints.get('input_constraints', [])[:5]:
            preconds.append(f"path constraint (input): {ic.get('condition') or ic.get('code')} -- at {ic.get('file')}:{ic.get('line')}")
        for kc in path_constraints.get('kernel_state_constraints', [])[:8]:
            preconds.append(f"path constraint (kernel state): {kc.get('condition') or kc.get('code')} -- at {kc.get('file')}:{kc.get('line')}")
        report['support'].append('Control-flow path constraints extracted from stack snippets (if/for/while/switch, returns)')
        report['confidence'] = min(1.0, report['confidence'] + 0.05)
    except Exception:
        # non-fatal
        pass

    # Special-case: KASAN null-pointer dereference -> likely a crash/DoS rather than arbitrary R/W
    try:
        raw = parsed.get('raw') or ''
        raw_lower = raw.lower()
        if 'kasan' in raw_lower and 'null-ptr-deref' in raw_lower:
            # core classification for KASAN null-pointer derefs: low exploitability, DoS primitive
            report['primitive'] = 'null-pointer-deref'
            report['vulnerability'] = 'denial-of-service (kernel crash)'
            report['exploitability'] = 'low'
            report['confidence'] = min(1.0, report.get('confidence', 0) + 0.2)
            report.setdefault('support', []).append('KASAN reported null-ptr-deref in crash log')

            # Build a short evidence set and rationale including specific snippet lines when available
            found = []
            for k, s in (snippets.get('links') or {}).items():
                if not isinstance(s, dict):
                    continue
                txt = (s.get('function_snippet') or s.get('snippet') or '')
                base = s.get('line') or 0
                for i, ln in enumerate(txt.splitlines(), start=1):
                    low_ln = ln.lower()
                    if 'dentry' in low_ln or 'd_is_negative' in low_ln or 'd_is_miss' in low_ln or 'dcache' in low_ln or 'path_openat' in low_ln:
                        found.append({'file': s.get('file'), 'line': base + i - 1, 'code': ln.strip()})

            # Add concrete precondition & kernel_state constraint if we found namei/dcache-related lines
            if found:
                report.setdefault('preconditions', []).insert(0, "State: dentry pointer may be NULL or invalid leading to null-pointer deref in dcache/namei code paths")
                kc = {
                    'frame': None,
                    'file': found[0]['file'],
                    'line': found[0]['line'],
                    'code': found[0]['code'],
                    'condition': 'dentry pointer may be NULL or invalid',
                    'variables': ['dentry'],
                    'evidence': [ {'file': found[0]['file'], 'line': found[0]['line'], 'code': found[0]['code'], 'note': 'dentry-related line near crash site'} ],
                    'why_it_blocks': 'null/invalid dentry pointer will cause dereference and crash'
                }
                pc = report.setdefault('path_constraints', {'input_constraints': [], 'kernel_state_constraints': []})
                pc['kernel_state_constraints'].insert(0, kc)

            # Compose a concise rationale that includes the KASAN message and any snippet evidence
            rationale_parts = []
            # include the first non-empty KASAN line or the header
            for ln in raw.splitlines():
                if 'kasan' in ln.lower() or 'null-ptr-deref' in ln.lower() or 'general protection fault' in ln.lower():
                    rationale_parts.append(ln.strip())
                    break
            if found:
                # include up to two snippet evidence lines
                for f in found[:2]:
                    rationale_parts.append(f"{os.path.basename(f.get('file') or '')}:{f.get('line')} -> {f.get('code')}")
                    report.setdefault('support', []).append(f"evidence: {f.get('file')}:{f.get('line')} '{f.get('code')}'")

            # capture any explicit dereference expressions found by snippet analysis
            try:
                deref_exprs = []
                for k, ev in (evidence or {}).items():
                    if isinstance(ev, dict):
                        for expr in ev.get('deref_exprs', []) or []:
                            if expr not in deref_exprs:
                                deref_exprs.append(expr)
                if deref_exprs:
                    rationale_parts.append(f"dereference expressions: {', '.join(deref_exprs[:3])}")
                    report.setdefault('support', []).append(f"deref_exprs: {', '.join(deref_exprs[:3])}")
            except Exception:
                pass

            # detect non-canonical fault address or CR2 from raw log and include as evidence
            try:
                m_nc = re.search(r"non-?canonical address\s*([0-9a-fxXA-F]+)", raw, re.I)
                if not m_nc:
                    m_nc = re.search(r"CR2:\s*([0-9a-fxXA-F]+)", raw, re.I)
                if m_nc:
                    addr = m_nc.group(1)
                    report['non_canonical_addr'] = addr
                    report.setdefault('support', []).append(f"faulting address: {addr}")
                    rationale_parts.append(f"faulting address: {addr}")
            except Exception:
                pass

            # fallback: include a short statement about lack of arbitrary R/W evidence
            rationale_parts.append('No clear evidence of arbitrary read/write (KASAN null-pointer derefs commonly indicate DoS)')

            kasan_rationale = '; '.join(rationale_parts)
            report.setdefault('support', []).append(kasan_rationale)

            # Ensure the overview reflects low exploitability and includes this rationale and primitive capability
            # compute a compact confidence breakdown for KASAN case
            try:
                attack_ctrl = any(re.search(r'fuzzer|syzkaller|attacker|user-controlled|syscall|ioctl|copy_from_user', p, re.I) for p in report.get('preconditions', []) + report.get('support', []))
                att_score = 0.4 if attack_ctrl else 0.0
                deref_count = 0
                for k, ev in (evidence or {}).items():
                    if isinstance(ev, dict):
                        deref_count += int(ev.get('deref_reads', 0) or 0) + int(ev.get('deref_writes', 0) or 0)
                evidence_score = min(0.4, 0.02 * deref_count)
                nc_flag = 0.1 if report.get('non_canonical_addr') else 0.0
                breakdown_total = min(1.0, att_score + evidence_score + nc_flag)
            except Exception:
                att_score = evidence_score = nc_flag = breakdown_total = 0.0

            report['overview'] = {
                'exploitability': 'LOW',
                'rationale': kasan_rationale,
                'primitive_capabilities': 'Denial-of-service via kernel null-pointer dereference; no confirmed arbitrary read/write from static evidence.',
                'confidence_breakdown': {
                    'attacker_control': round(att_score, 2),
                    'evidence_strength': round(evidence_score, 2),
                    'non_canonical_address': round(nc_flag, 2),
                    'aggregate_estimate': round(breakdown_total, 2),
                    'reported_confidence': round(report.get('confidence', 0.0) or 0.0, 2)
                }
            }
    except Exception:
        pass

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
    if report.get("vulnerability") and ("arbitrary_write" in report.get("vulnerability") or "arbitrary write" in report.get("vulnerability")):
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

    # ---- New: overview summarizing exploitability, short rationale, and primitive capabilities
    try:
        # Aggregate support evidence into concise, de-duplicated phrases
        supports = []
        for s in report.get('support', []):
            if s not in supports:
                supports.append(s)
        top_support = supports[:5]

        # Reuse signals computed earlier (fallback to conservative defaults)
        vuln = (report.get('vulnerability') or 'unknown')
        prim = (report.get('primitive') or 'unknown')
        conf = float(report.get('confidence', 0.0) or 0.0)

        # summarize low-level evidence counts
        try:
            dw = int(deref_writes or 0)
            dr = int(deref_reads or 0)
        except Exception:
            dw = dr = 0
        any_deref_flag = any_deref
        any_array_flag = any_array
        any_free_flag = any_free

        # attacker control heuristic
        attacker_control = any(re.search(r'fuzzer|syzkaller|attacker|user-controlled|syscall|ioctl|copy_from_user', p, re.I) for p in report.get('preconditions', []) + report.get('support', []))

        # Compose rationale: vulnerability + primitive + key supporting facts
        rationale_items = [f"vuln={vuln}", f"primitive={prim}", f"confidence={conf:.2f}"]
        if any_deref_flag:
            rationale_items.append(f"pointer derefs (reads={dr}, writes={dw})")
        if any_array_flag:
            rationale_items.append("array/index accesses observed")
        if any_free_flag:
            rationale_items.append("free-like calls observed")
        if attacker_control:
            rationale_items.append("attacker-controlled input observed")
        if top_support:
            # include up to two short support phrases
            for s in top_support[:2]:
                rationale_items.append(s if len(s) < 120 else s[:116] + '...')

        rationale = '; '.join(rationale_items)

        # More precise primitive capability description
        prim_caps = 'Unknown or limited primitive; further manual analysis required'
        lowv = vuln.lower()
        if 'arbitrary_write' in lowv or 'arbitrary write' in lowv or ('write' in prim and dw >= dr):
            size_note = ''
            if access and access.get('size'):
                size_note = f" (size={access.get('size')} bytes)"
            prim_caps = f"Potential arbitrary write{size_note} — may permit kernel memory corruption or control/data corruption"
        elif 'arbitrary_read' in lowv or 'info-leak' in lowv or ('read' in prim and dr >= 0):
            size_note = ''
            if access and access.get('size'):
                size_note = f" (size={access.get('size')} bytes)"
            bounded_note = ''
            if boundedness:
                bounded_note = f"; boundedness={boundedness}"
            prim_caps = f"Potential info-leak{size_note}{bounded_note} — may expose kernel memory to attacker"
        elif 'use-after-free' in lowv:
            prim_caps = 'Use-after-free: may allow reading or writing reclaimed memory depending on attacker control of contents (may lead to info-leak or arbitrary write)'
        elif 'double-free' in lowv or 'invalid-free' in lowv:
            prim_caps = 'Double/invalid free: may enable heap corruption primitives (useful for exploitation if allocator behavior is controlled)'

        # Expand exploitability rationale to include 2-3 concise reasons
        reasons = []
        if attacker_control:
            reasons.append('attacker-controlled input reaches vulnerable path')
        if any_deref_flag:
            reasons.append(f'pointer deref evidence (reads={dr}, writes={dw})')
        if any_free_flag:
            reasons.append('free/cleanup observed near site')
        if boundedness:
            reasons.append(f'boundedness={boundedness}')
        # fall back to support phrases if empty
        if not reasons and top_support:
            reasons.append(top_support[0])

        expl_rationale = '; '.join(reasons) if reasons else 'heuristic indicates potential issue based on code evidence'

        # Build a small confidence breakdown to explain the numeric confidence score
        try:
            conf_total = float(report.get('confidence', 0.0) or 0.0)
            attacker_score = 0.4 if attacker_control else 0.0
            evidence_score = min(0.4, 0.02 * float((dr or 0) + (dw or 0)))
            if boundedness in ('oob', 'partially_bounded'):
                bounded_score = 0.1
            elif boundedness == 'likely_bounded':
                bounded_score = 0.05
            else:
                bounded_score = 0.0
            kasen_flag = 0.1 if re.search(r"kasan|null-ptr-deref", raw, re.I) else 0.0
            breakdown_total = min(1.0, attacker_score + evidence_score + bounded_score + kasen_flag)
        except Exception:
            attacker_score = evidence_score = bounded_score = kasen_flag = breakdown_total = 0.0

        report['overview'] = {
            'exploitability': (report.get('exploitability') or 'unknown').upper(),
            'rationale': expl_rationale,
            'primitive_capabilities': prim_caps,
            'confidence_breakdown': {
                'attacker_control': round(attacker_score, 2),
                'evidence_strength': round(evidence_score, 2),
                'boundedness_score': round(bounded_score, 2),
                'kasan_indicator': round(kasen_flag, 2),
                'aggregate_estimate': round(breakdown_total, 2),
                'reported_confidence': round(conf_total, 2)
            }
        }
    except Exception:
        # non-fatal: if overview building fails, still return report
        report['overview'] = {
            'exploitability': (report.get('exploitability') or 'unknown').upper(),
            'rationale': 'overview generation failed',
            'primitive_capabilities': 'unknown'
        }

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

def safe_json_loads(s: str):
    """
    Extracts and repairs JSON from text containing a ```json block,
    even if it's truncated or missing the closing ```
    """
    s = s.strip()

    # Extract JSON block between ```json ... ``` or until end of text
    match = re.search(r"```json\s*(.*?)(?:```|$)", s, re.DOTALL)
    if match:
        s = match.group(1).strip()

    try:
        return json.loads(s)
    except json.JSONDecodeError as e:
        print(f"❌ JSON parsing failed: {e}")
        print("🧩 Attempting structured recovery...")

        s_fixed = auto_fix_json(s)
        try:
            return json.loads(s_fixed)
        except json.JSONDecodeError as e2:
            print(f"⚠️ Second attempt failed: {e2}")
            s_final = force_close_json(s_fixed)
            try:
                return json.loads(s_final)
            except json.JSONDecodeError:
                print("🚫 Could not recover valid JSON.")
                return None


def auto_fix_json(s: str):
    """
    Repair truncated JSON: close dangling quotes, braces, and brackets.
    """
    s = s.strip()

    # Remove any incomplete trailing escape like \"
    s = re.sub(r'\\+$', '', s)

    # Close any unbalanced quotes
    quote_count = s.count('"')
    if quote_count % 2 != 0:
        s += '"'

    # Remove incomplete lines like "foo": "some partial
    s = re.sub(r'\"[^\"]*$','"', s)

    # Remove obvious trailing commas before } or ]
    s = re.sub(r',\s*([\]}])', r'\1', s)

    # Balance braces/brackets
    s = balance_brackets(s)
    return s


def balance_brackets(s: str):
    """
    Ensures that curly and square brackets are balanced.
    """
    open_curly = s.count('{')
    close_curly = s.count('}')
    open_square = s.count('[')
    close_square = s.count(']')

    if open_curly > close_curly:
        s += '}' * (open_curly - close_curly)
    if open_square > close_square:
        s += ']' * (open_square - close_square)

    return s


def force_close_json(s: str):
    """
    Final fallback: close strings, braces, and brackets until JSON parses.
    """
    for _ in range(5):
        s = auto_fix_json(s)
        try:
            json.loads(s)
            return s
        except json.JSONDecodeError:
            s += '}'
    return s

def get_openai_response(prompt: str, api_key: str, model: str = "gpt-5"):
    """
    Sends a prompt to the OpenAI API and returns the model's response text.

    Args:
        prompt (str): The text prompt to send.
        api_key (str): Your OpenAI API key.
        model (str): Model name (default: 'gpt-5').

    Returns:
        str: The model's response content.
    """
    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a precise, structured assistant."},
            {"role": "user", "content": prompt}
        ]
    )

    # Extract text output
    return response.choices[0].message.content.strip()

def _call_llm(prompt: str, model_path: Optional[str] = None, max_tokens: int = 16000) -> Dict[str, Any]:
    """Try to call a local LLM (llama_cpp) if available.

    Returns a dict: {"ok": True, "answer": str} or {"ok": False, "error": str, "prompt": prompt}
    This avoids adding a hard requirement on llama_cpp: if it's not importable we return the prompt
    and an informative error so callers can run it manually.
    """
    # User-requested primary provider: Direct transformers AutoTokenizer + AutoModelForCausalLM
    # The original multiple-provider fallbacks (llama_cpp, gpt4all, openai, pipeline) have been
    # intentionally omitted/commented-out in favor of using the specified model below.
    try:
        # lazy import to avoid hard dependency at module import time
        model_id = os.environ.get('TRANSFORMERS_DIRECT_MODEL', 'meta-llama/CodeLlama-34b-Instruct-hf')
        # Load HuggingFace access token from env or keyfile. Prefer these env vars:
        # HF_ACCESS_TOKEN, HUGGINGFACE_HUB_TOKEN, HF_TOKEN
        hf_token = os.environ.get('HF_ACCESS_TOKEN') or os.environ.get('HUGGINGFACE_HUB_TOKEN') or os.environ.get('HF_TOKEN')
        if not hf_token:
            hf_key_file = os.environ.get('HF_ACCESS_TOKEN_FILE') or os.path.expanduser('~/.config/kernelcveanalysis/hf_token')
            try:
                if hf_key_file and os.path.exists(hf_key_file):
                    with open(hf_key_file, 'r') as _kf:
                        hf_token = _kf.read().strip()
            except Exception:
                hf_token = None

        # try loading from a .env if python-dotenv is available (non-fatal)
        if not hf_token:
            try:
                load_dotenv()
                hf_token = os.environ.get('HF_ACCESS_TOKEN') or os.environ.get('HUGGINGFACE_HUB_TOKEN') or os.environ.get('HF_TOKEN')
            except Exception:
                pass

        # instantiate tokenizer and model (may download/check local cache)
        # If no token is available, call from_pretrained without a token (may still work for public models)
        if hf_token:
            tokenizer = AutoTokenizer.from_pretrained(model_id, token=hf_token)
            model = AutoModelForCausalLM.from_pretrained(model_id, token=hf_token)
        else:
            tokenizer = AutoTokenizer.from_pretrained(model_id)
            model = AutoModelForCausalLM.from_pretrained(model_id)

        # Build chat-style messages and try to use tokenizer.apply_chat_template if present
        messages = [{"role": "user", "content": prompt}]
        try:
            inputs = tokenizer.apply_chat_template(
                messages,
                add_generation_prompt=True,
                tokenize=True,
                return_dict=True,
                return_tensors="pt",
            )
            # move tensors to model device if available
            device = next(model.parameters()).device if any(True for _ in model.parameters()) else torch.device('cpu')
            inputs = {k: v.to(device) for k, v in inputs.items()}
        except Exception:
            # fallback: simple single-text tokenization
            inputs = tokenizer(prompt, return_tensors="pt")
            device = next(model.parameters()).device if any(True for _ in model.parameters()) else torch.device('cpu')
            inputs = {k: v.to(device) for k, v in inputs.items()}

        # generate
        gen = model.generate(**inputs, max_new_tokens=max_tokens)
        # decode: skip prompt tokens when possible
        try:
            skip = inputs.get('input_ids').shape[-1]
        except Exception:
            skip = 0
        decoded = tokenizer.decode(gen[0][skip:], skip_special_tokens=True)
        formated_answer =  safe_json_loads(decoded)
        return {"ok": True, "answer": decoded, "provider": "transformers_direct", "model": model_id, "analysis": formated_answer}
    except Exception as e:
        return {"ok": False, "error": f"transformers_direct failed: {e}", "prompt": prompt}

"""
Task: Given the crash log and the provided source snippets, produce a concise developer-friendly description of the PRECONDITION(s) required to reach the crash. Provide concrete input ranges and variable constraints. Analyze the full call chain from the crash point backwards and inspect all 'if/for/while/switch' conditions, early 'return' and 'goto' statements that restrict reaching the crash. For each such conditional, classify it as either an INPUT constraint (user-controlled) or KERNEL_STATE constraint. Also include short evidence lines from the provided snippets that justify each constraint.

INPUTS I WILL PROVIDE:
- "crash_log": the full kernel oops/trace.
- "snippets": a list of {file, line_start, line_end, code} entries (text blocks) containing the relevant source around frames in the call stack.

OUTPUT FORMAT (strict JSON):
{
  "preconditions": [
    {
      "summary": "<one-sentence developer-friendly precondition>",
      "concrete_constraints": [
         "<variable> => <allowed range or constraint, be concrete>"
      ],
      "why_reaches_crash": "<short reasoning>"
    }
  ],
  "path_constraints": {
    "input": [
      {
        "file": "<file path>",
        "line": <line number>,
        "code": "<exact single-line snippet that is the condition>",
        "condition": "<short human-readable condition>",
        "why_it_blocks": "<why this prevents/restricts reaching crash (user-controlled?)>"
      }, ...
    ],
    "kernel_state": [
      {
        "file": "<file path>",
        "line": <line number>,
        "code": "<exact single-line snippet>",
        "condition": "<short kernel-state condition>",
        "why_it_blocks": "<why this prevents/restricts reaching crash (internal invariant)>"
      }, ...
    ]
  },
  "evidence": [
    { "file": "<file>", "line": <line>, "code": "<line text>", "note":"<one-line justification linking to precondition>" }
  ]
}

REQUIREMENTS:
1. Keep JSON **compact** but include only necessary fields. Do not include extra commentary outside the JSON.
2. For each constraint entry in path_constraints.* produce **the exact single-line code text** from snippet that implements the check (or part of it) and a one-line explanation (why_it_blocks).
3. If the snippets are truncated or missing some callee lines, indicate that clearly with a short note in the JSON (e.g., "note": "caller's guard not present in snippets").
4. If a condition is ambiguous about whether it’s input vs kernel_state, mark as "ambiguous" and explain why in the same entry.
5. If the crash appears to be caused by corrupted metadata (e.g., extent header), give plausible concrete ranges/values that would cause arithmetic overflow or out-of-range lengths (e.g., `ee_len > EXT4_BLOCKS_PER_GROUP(sb)` or `ee_block + ee_len` wraps).
6. Do not propose exploit techniques. If asked about exploitability, respond with a short field `"exploitability": "<HIGH|MEDIUM|LOW>"` plus one-sentence rationale, but do not provide attack steps.

Now analyze the following inputs. Be precise, inspect conditional checks and early returns, and output only JSON that follows the schema above.

<<<INSERT crash_log BELOW>>>

<<<INSERT snippets as a list; for each snippet include a header comment like:
-- fs/ext4/extents.c:2730 -> <code lines>
-- fs/ext4/extents.c:2952 -> <code lines>
... >>>

"""
def llm_analyze_traces(crash: str, snippet_map: Dict[str, str], model_path: Optional[str] = None) -> Dict[str, Any]:
    """Use an LLM to analyze a function trace chain and suggest concrete preconditions.

    Inputs:
      - crash: the crash log
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
    prompt_lines = []
    prompt_lines.append("Task: Given the crash log and the provided source snippets, produce a concise developer-friendly description of the PRECONDITION(s) required to reach the crash. Provide concrete input ranges and variable constraints. Analyze the full call chain from the crash point backwards and inspect all 'if/for/while/switch' conditions, early 'return' and 'goto' statements that restrict reaching the crash. For each such conditional, classify it as either an INPUT constraint (user-controlled) or KERNEL_STATE constraint. Also include short evidence lines from the provided snippets that justify each constraint.")
    prompt_lines.append("")
    prompt_lines.append("INPUTS I WILL PROVIDE:")
    prompt_lines.append("- \"crash_log\": the full kernel oops/trace.")
    prompt_lines.append("- \"snippets\": a list of {file, line_start, line_end, code} entries (text blocks) containing the relevant source around frames in the call stack.")

    prompt_lines.append("OUTPUT FORMAT (strict JSON):")
    prompt_lines.append("{")
    prompt_lines.append("  \"overview\": {")
    prompt_lines.append("    \"exploitability\": \"<HIGH|MEDIUM|LOW>\",")
    prompt_lines.append("    \"rationale\": \"<one-sentence justification with evidence>\"")
    prompt_lines.append("    \"primitive_capabilities\": \"<1-2 sentence description of the capabilities this exploit provides, if any.>\"")
    prompt_lines.append("  },")
    prompt_lines.append("  \"preconditions\": [")
    prompt_lines.append("    {")
    prompt_lines.append("      \"summary\": \"<one-sentence developer-friendly precondition>\",")
    prompt_lines.append("      \"concrete_constraints\": [")
    prompt_lines.append("         \"<variable> => <allowed range or constraint, be concrete>\"")
    prompt_lines.append("      ],")
    prompt_lines.append("      \"why_reaches_crash\": \"<short reasoning>\"")
    prompt_lines.append("    }")
    prompt_lines.append("  ],")
    prompt_lines.append("  \"path_constraints\": {")
    prompt_lines.append("    \"input\": [")
    prompt_lines.append("      {")
    prompt_lines.append("        \"file\": \"<file path>\",")
    prompt_lines.append("        \"line\": <line number>,")
    prompt_lines.append("        \"code\": \"<exact single-line snippet that is the condition>\",")
    prompt_lines.append("        \"condition\": \"<short human-readable condition>\",")
    prompt_lines.append("        \"why_it_blocks\": \"<why this prevents/restricts reaching crash (user-controlled?)>\"")
    prompt_lines.append("      }, ...")
    prompt_lines.append("    ],")
    prompt_lines.append("    \"kernel_state\": [")
    prompt_lines.append("      {")
    prompt_lines.append("        \"file\": \"<file path>\",")
    prompt_lines.append("        \"line\": <line number>,")
    prompt_lines.append("        \"code\": \"<exact single-line snippet>\",")
    prompt_lines.append("        \"condition\": \"<short kernel-state condition>\",")
    prompt_lines.append("        \"why_it_blocks\": \"<why this prevents/restricts reaching crash (internal invariant)>\"")
    prompt_lines.append("      }, ...")
    prompt_lines.append("    ]")
    prompt_lines.append("  },")
    prompt_lines.append("  \"evidence\": [")
    prompt_lines.append("    { \"file\": \"<file>\", \"line\": <line>, \"code\": \"<line text>\", \"note\":\"<one-line justification linking to precondition>\" }")
    prompt_lines.append("  ]")
    prompt_lines.append("}")
    prompt_lines.append("")
    prompt_lines.append("REQUIREMENTS:")
    prompt_lines.append("1. Keep JSON **compact** but include only necessary fields. Do not include extra commentary outside the JSON.")
    prompt_lines.append("2. For each constraint entry in path_constraints.* produce **the exact single-line code text** from snippet that implements the check (or part of it) and a one-line explanation (why_it_blocks).")
    prompt_lines.append("3. If the snippets are truncated or missing some callee lines, indicate that clearly with a short note in the JSON (e.g., \"note\": \"caller's guard not present in snippets\").")
    prompt_lines.append("4. If a condition is ambiguous about whether it’s input vs kernel_state, mark as \"ambiguous\" and explain why in the same entry.")
    prompt_lines.append("5. If the crash appears to be caused by corrupted metadata (e.g., extent header), give plausible concrete ranges/values that would cause arithmetic overflow or out-of-range lengths (e.g., `ee_len > EXT4_BLOCKS_PER_GROUP(sb)` or `ee_block + ee_len` wraps).")
    prompt_lines.append("6. Do not propose exploit techniques. If asked about exploitability, respond with a short field \"exploitability\": \"<HIGH|MEDIUM|LOW>\" plus one-sentence rationale, but do not provide attack steps.")
    prompt_lines.append("")
    prompt_lines.append("Now analyze the following inputs. Be precise, inspect conditional checks and early returns, and output only JSON that follows the schema above.")

    prompt_lines.append(crash)
    count = 0
    for k, s in snippet_map.items():
        if count > 2:
            break
        if "kasan" not in s.get('file', ''):
            count += 1
            prompt_lines.append(f"-- {s.get('file', '')}:{s.get('line', '')} -> {s.get('function_snippet', '')}\n---")
    prompt = "\n".join(prompt_lines)
    # Run local LLM
    # llm_out = _call_llm(prompt, model_path=model_path)
    llm_out = {"ok": False, "error": "Local LLM calls disabled in this version", "prompt": prompt}
    # Run OpenAI LLM
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("OPENAI_KEY")
    if not api_key:
        key_file = os.environ.get("OPENAI_API_KEY_FILE") or os.path.expanduser("~/.config/kernelcveanalysis/openai_api_key")
        try:
            if key_file and os.path.exists(key_file):
                with open(key_file, "r") as _kf:
                    api_key = _kf.read().strip()
        except Exception:
            api_key = None

    # Try loading from a .env if python-dotenv is available (non-fatal)
    if not api_key:
        try:
            
            load_dotenv()
            api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("OPENAI_KEY")
        except Exception:
            pass

    if not api_key:
        raise RuntimeError(
            "OpenAI API key not found. Set the OPENAI_API_KEY environment variable or create '" +
            (os.environ.get("OPENAI_API_KEY_FILE") or os.path.expanduser("~/.config/kernelcveanalysis/openai_api_key")) +
            "' with your key."
        )
    
    result = get_openai_response(prompt, api_key)

    # Base output structure
    out = {
        "prompt": prompt,
        "local_llm": llm_out,
        "openai_llm": {"raw_output": result, "parsed": safe_json_loads(result)},
        "summary": None
    }

    # If local LLM produced structured JSON, try to merge
    # if isinstance(llm_out, dict) and llm_out.get("ok"):
    #     # Merge OpenAI raw output alongside local JSON
    #     out.update({
    #         "combined": {
    #             "local": llm_out,
    #             "openai": result
    #         }
    #     })

    # # Heuristic fallback summary in case both failed or local failed
    # if not llm_out.get("ok"):
    #     summary = {
    #         "preconditions": [],
    #         "input_constraints": [],
    #         "reproduction": [],
    #         "evidence": []
    #     }

    #     # Combine snippet text for heuristic inference
    #     combined = "\n".join(str(v) for v in snippet_map.values())

    #     # Detect user-controlled input patterns
    #     if re.search(r"copy_from_user|get_user|put_user|ioctl|syscall|fuse|netlink", combined, re.I):
    #         summary["preconditions"].append(
    #             "Attacker-controlled user data must reach this code path (copy_from_user or ioctl-like path detected)"
    #         )
    #         summary["reproduction"].append(
    #             "Call the syscall or ioctl that reaches the call chain above with crafted user-controlled buffers"
    #         )

    #     # Detect kernel allocation patterns
    #     if re.search(r"kmalloc|kzalloc|kmem_cache_alloc|alloc_pages", combined):
    #         summary["preconditions"].append(
    #             "A kernel allocation of the relevant object must occur prior to the access"
    #         )

    #     # Detect dereference or indexing behavior
    #     if re.search(r"->|\[|\*", combined):
    #         summary["input_constraints"].append({
    #             "note": "Pointer or index dereference observed near crash; consider off-by-one or size fields controlling ranges"
    #         })

    #     out["summary"] = summary

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
        # refined capability: one of unknown, arbitrary_read, arbitrary_write,
        # partial_overwrite, controlled_read, controlled_write, info_leak
        "vulnerability": "unknown",
    }

    # primitive classification from crash text
    kind = (parsed.get("kind") or "").lower()
    if "use-after-free" in kind:
        cls["classification"] = "use-after-free"
    elif "double-free" in kind or "invalid-free" in kind:
        cls["classification"] = "double-free"
    elif "out-of-bounds" in kind or "oob" in kind:
        cls["classification"] = "out-of-bounds"
    elif "null-deref" in kind or "null pointer" in kind:
        cls["classification"] = "null-deref"
    else:
        cls["classification"] = kind or "unknown"

    access = parsed.get("access") or {}
    obj = parsed.get("object_info") or {}

    # Always include KASAN/report postcondition hint
    cls["postconditions"].append("KASAN reported invalid memory access (see crash report)")

    # Heuristic: is the crash reachable from attacker-controlled entry (syscall/syz)?
    raw = parsed.get("raw", "") or ""
    attacker_control = False
    if re.search(r"syz|syzkaller|syz-executor", raw, re.I):
        attacker_control = True
        cls["notes"].append("Crash generated by syzkaller/fuzzer - likely attacker-controlled input")

    frames = parsed.get("frames") or []
    frame_text = " ".join([str(f.get("func", "")) + " " + str(f.get("file", "")) for f in frames])
    if re.search(r"__x64_sys|__se_sys|ksys_|do_syscall|entry_SYSCALL|sys_read|sys_write|ioctl", frame_text, re.I):
        attacker_control = True
        cls["notes"].append("Call chain contains syscall entry points -> input may be attacker-controlled")

    # detect common user-copy helpers near frames
    if re.search(r"copy_from_user|get_user|strncpy_from_user|copy_to_user", frame_text, re.I):
        attacker_control = True
        cls["notes"].append("User-copy functions observed in call chain")

    # If allocation/free traces exist, note them as preconditions
    if parsed.get("freed_by"):
        cls["preconditions"].append("Object must have been freed earlier on a prior code path (see freed_by stack)")
    if parsed.get("allocated_by"):
        cls["preconditions"].append("An allocation for the object occurred earlier (see allocated_by stack)")

    # Analyze object layout and access to guess attacker capabilities
    access_op = (access.get("op") or "").lower()
    access_size = access.get("size")
    obj_size = obj.get("obj_size")
    obj_offset = obj.get("offset")

    # If we have object size/offset, a write can be an arbitrary write if attacker controls allocation reuse
    capability = "unknown"
    if cls["classification"] == "use-after-free":
        # base on access type
        if access_op == "write":
            # if attacker-controlled path exists and allocation came from slab/kmalloc then likely arbitrary write
            cache = (obj.get("cache") or "")
            if attacker_control and cache:
                capability = "likely_arbitrary_write"
                cls["notes"].append(f"Freed object from cache '{cache}' may be reallocated under attacker control")
            elif attacker_control:
                capability = "possible_arbitrary_write"
            else:
                capability = "write_uaf"
        elif access_op == "read":
            if attacker_control:
                capability = "likely_arbitrary_read"
            else:
                capability = "read_uaf"
        else:
            capability = "use-after-free"

        # if we can see the object size and the access offset, indicate whether full overwrite is possible
        try:
            if obj_size and access_size and obj_offset is not None:
                # if access writes beyond the object's size it's an OOB write not just UAF
                if int(obj_offset) + int(access_size) > int(obj_size):
                    cls["notes"].append("Access appears to write past the original object size -> may allow out-of-bounds/wider overwrite")
                    if capability.startswith("likely") or capability.startswith("possible"):
                        capability = capability.replace("_write", "_partial_overwrite")
        except Exception:
            pass

    elif cls["classification"] in ("out-of-bounds",):
        if access_op == "write":
            capability = "arbitrary_write"
        elif access_op == "read":
            capability = "arbitrary_read"
        else:
            capability = "oob"
    else:
        capability = "unknown"

    # Convert capability to a concise vulnerability string
    # prefer readable short labels
    if capability.startswith("likely_arbitrary_write"):
        vuln_label = "likely_arbitrary_write"
    elif capability.startswith("possible_arbitrary_write"):
        vuln_label = "possible_arbitrary_write"
    elif capability == "likely_arbitrary_read":
        vuln_label = "likely_arbitrary_read"
    elif capability == "arbitrary_write":
        vuln_label = "arbitrary_write"
    elif capability == "arbitrary_read":
        vuln_label = "arbitrary_read"
    elif capability == "read_uaf":
        vuln_label = "controlled_read?"
    elif capability == "write_uaf":
        vuln_label = "controlled_write?"
    elif capability == "partial_overwrite" or "partial_overwrite" in capability:
        vuln_label = "partial_overwrite"
    else:
        vuln_label = capability

    cls["vulnerability"] = vuln_label

    # Add an explicit precondition that the call chain must be reachable with attacker-controlled inputs
    if attacker_control:
        cls["preconditions"].append("Path from syscall/fuzzer entry to crash site must be executed with attacker-controlled inputs")
    else:
        cls["notes"].append("No clear evidence of attacker-controlled entry in call chain; exploitability may be limited")

    # If freed_by/allocated_by are in different tasks/contexts, note the concurrency requirement
    try:
        freed = parsed.get("freed_by") or []
        alloc = parsed.get("allocated_by") or []
        if freed and alloc:
            # cheap heuristic: if the allocation/free stacks differ, note that reallocation timing matters
            if freed != alloc:
                cls["preconditions"].append("A timing/reuse window must exist for the freed object to be reallocated and reused by the vulnerable code path")
    except Exception:
        pass

    # small final hygiene: dedupe lists
    for k in ("preconditions", "postconditions", "notes"):
        seen = set()
        out_list = []
        for v in cls.get(k, []) or []:
            if v not in seen:
                seen.add(v)
                out_list.append(v)
        cls[k] = out_list

    return cls


def analyze(crash_text: str, source_root: Optional[str] = None) -> Dict[str, Any]:
    parsed = parse_crash_log(crash_text)
    snippets = {}

    # 1) Try URLs found in the log
    # Only keep function-level snippets in-memory; do not write files or keep +/-6 line context
    urls = extract_source_urls(crash_text)
    url_snippets = {}
    for u in urls:
        fetched = fetch_source_from_url(u)
        if "text" in fetched:
            text = fetched["text"]
            sl, el = parse_fragment_for_range(u)
            function_snippet = None
            if sl is not None:
                lines = text.splitlines()
                # If fragment is a single line or a range, prefer function start -> fragment/end line
                ln = el if (el is not None) else sl
                try:
                    start_fn = _find_function_start(lines, int(ln))
                    fn_start = start_fn
                    fn_end = min(len(lines), int(ln))
                    function_snippet = "\n".join(lines[fn_start - 1:fn_end])
                except Exception:
                    function_snippet = None
            # If we were able to extract a function-level snippet, keep it as the URL's snippet
            if function_snippet:
                url_snippets[u] = function_snippet
            else:
                # Record that no function snippet was available (no files written)
                url_snippets[u] = {"note": "no function snippet available", "text_len": len(text)}
        else:
            url_snippets[u] = {"error": fetched.get("error")}

    snippets.update({"urls": url_snippets})

    # 1.b) Try link_frames captured as HTML anchors in the crash report
    # Keep only function-level snippets in-memory; do not write files or keep +/-6 context
    link_snippets = {}
    for lf in parsed.get("link_frames", []) or []:
        u = lf.get("url")
        if not u:
            continue
        fetched = fetch_source_from_url(u)
        if "text" in fetched:
            text = fetched["text"]
            sl, el = parse_fragment_for_range(u)
            function_snippet = None
            ln = None
            # prefer explicit fragment; fall back to anchor 'line' if present
            if sl is not None:
                ln = el if (el is not None) else sl
            elif lf.get("line"):
                try:
                    ln = int(lf.get("line"))
                except Exception:
                    ln = None

            if ln is not None:
                try:
                    lines = text.splitlines()
                    start_fn = _find_function_start(lines, int(ln))
                    fn_start = start_fn
                    fn_end = min(len(lines), int(ln))
                    function_snippet = "\n".join(lines[fn_start - 1:fn_end])
                except Exception:
                    function_snippet = None

            key_line = ln if ln is not None else lf.get('line','?')
            key = f"link:{u}#{key_line}"
            entry = {"url": u, "file": lf.get("file"), "line": lf.get("line")}
            if function_snippet:
                entry["function_snippet"] = function_snippet
            else:
                entry["note"] = "no function snippet available"
            link_snippets[key] = entry
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

    # analyze link-based snippets (use function_snippet if available)
    for k, info in (snippets.get("links") or {}).items():
        if isinstance(info, dict) and info.get("function_snippet"):
            evidence[k] = analyze_snippet_for_evidence(info.get("function_snippet"), parsed.get("access"))
            # attach contextual url/file info
            evidence[k]["source_url"] = info.get("url")
            evidence[k]["source_file"] = info.get("file")
            evidence[k]["source_line"] = info.get("line")
        else:
            # preserve any error or note
            err = info.get("error") if isinstance(info, dict) else None
            note = info.get("note") if isinstance(info, dict) else None
            evidence[k] = {"error": err, "note": note}

    if source_root and isinstance(snippets.get("local"), dict):
        for key, s in snippets.get("local", {}).items():
            if isinstance(s, dict) and "snippet" in s:
                evidence[key] = analyze_snippet_for_evidence(s["snippet"], parsed.get("access"))

    # Use stronger heuristics that combine parsed logs, snippets, and evidence
    try:
        classification = stronger_heuristics(parsed, snippets, evidence)
    except Exception:
        # fallback to older classify() if something goes wrong
        classification = classify(parsed)
    # Build a more detailed exploitability summary using parsed frames, snippets and evidence
    exploitability = analyze_exploitability(parsed, snippets, evidence)
    return {"parsed": parsed, "snippets": snippets, "evidence": evidence, "classification": classification, "exploitability": exploitability}


def analyze_exploitability(parsed: Dict[str, Any], snippets: Dict[str, Any], evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Produce a per-bug exploitability summary with concrete sites and structure info.

    Returns a dict with:
      - free_site: {func,file,line,stack}
      - trigger_site: {func,file,line,stack}
      - allocation_site: {func,file,line,stack}
      - object: {obj_addr, cache, obj_size, offset}
      - struct_info: {struct_name, fields_used, struct_def_snippet}
      - usage_examples: list of lines showing deref/index usage supporting preconditions
      - notes: additional heuristics and exploitation-relevant observations
    """
    out: Dict[str, Any] = {"free_site": None, "trigger_site": None, "allocation_site": None, "object": None, "struct_info": {}, "usage_examples": [], "notes": []}

    # Helper to extract file/line/func from stack-like strings or from parsed link_frames
    def _extract_site_from_stack_entry(entry: str) -> Dict[str, Any]:
        site = {"raw": entry}
        try:
            # attempt to extract filename and line like 'file.c:123' or within an anchor
            m = re.search(r"([\w/.-]+\.(c|h))[:](\d{1,6})", entry)
            if m:
                site["file"] = m.group(1)
                site["line"] = int(m.group(3))
            # try to get a function name before any <a href or before the file token
            func_m = re.match(r"\s*([^<\n]+?)\s*(?:<a href|$)", entry)
            if func_m:
                func = func_m.group(1).strip()
                # sanitize: keep first token-like name
                func = func.split()[-1]
                site["func"] = func
        except Exception:
            pass
        return site

    # free site: prefer parsed['freed_by'] first entry
    try:
        freed = parsed.get("freed_by") or []
        if isinstance(freed, list) and freed:
            out["free_site"] = _extract_site_from_stack_entry(freed[0])
        else:
            # try to find an inline 'free' mention in raw
            raw = parsed.get("raw", "") or ""
            if "free(" in raw or "kfree" in raw:
                out["notes"].append("Found 'free' mention in raw crash text; a free site may exist but not parsed into freed_by list")
    except Exception:
        pass

    # allocation site
    try:
        alloc = parsed.get("allocated_by") or []
        if isinstance(alloc, list) and alloc:
            out["allocation_site"] = _extract_site_from_stack_entry(alloc[0])
    except Exception:
        pass

    # trigger site: use parsed.link_frames first (they contain url/file/line)
    try:
        link_frames = parsed.get("link_frames") or []
        if isinstance(link_frames, list) and link_frames:
            lf = link_frames[0]
            out["trigger_site"] = {"file": lf.get("file"), "line": lf.get("line"), "url": lf.get("url"), "func": None}
            # try to extract func from snippets if available
            key = f"link:{lf.get('url')}#{lf.get('line','?')}"
            link_info = (snippets.get("links") or {}).get(key) or {}
            if link_info and link_info.get("function_snippet"):
                # attempt to find the function header line
                header = link_info.get("function_snippet").splitlines()[0] if link_info.get("function_snippet") else None
                if header:
                    out["trigger_site"]["func"] = header.strip().split("(")[0][:120]
    except Exception:
        pass

    # object info
    try:
        obj = parsed.get("object_info") or {}
        if obj:
            out["object"] = {"obj_addr": obj.get("obj_addr"), "cache": obj.get("cache"), "obj_size": obj.get("obj_size"), "offset": obj.get("offset")}
    except Exception:
        pass

    # Struct / field inference: search snippets for struct definitions or '->' usages
    struct_name = None
    fields_used: Set[str] = set()
    struct_def_snippet = None
    try:
        # scan all function snippets in links then urls
        candidate_texts: List[str] = []
        for d in (snippets.get("links") or {}).values():
            if isinstance(d, dict) and d.get("function_snippet"):
                candidate_texts.append(d.get("function_snippet"))
        for t in (snippets.get("urls") or {}).values():
            if isinstance(t, str):
                candidate_texts.append(t)

        for text in candidate_texts:
            # find struct definition
            m = re.search(r"struct\s+([A-Za-z0-9_]+)\s*\{([\s\S]{0,800})\};", text)
            if m and not struct_name:
                struct_name = m.group(1)
                struct_def_snippet = m.group(0)[:2000]
            # find arrow uses like 'ent->parent_de'
            for f in re.findall(r"->\s*([A-Za-z0-9_]+)", text):
                fields_used.add(f)
            # find dot uses (struct.field)
            for f in re.findall(r"\.\s*([A-Za-z0-9_]+)", text):
                fields_used.add(f)
    except Exception:
        pass

    out["struct_info"] = {"struct_name": struct_name, "fields_used": sorted(list(fields_used)), "struct_def_snippet": struct_def_snippet}

    # usage examples: find specific lines in trigger function snippet that dereference fields
    try:
        usage_lines: List[str] = []
        if out.get("trigger_site"):
            ts = out.get("trigger_site")
            lf_url = None
            if parsed.get("link_frames"):
                lf0 = parsed.get("link_frames")[0]
                lf_url = lf0.get("url")
            key = f"link:{lf_url}#{ts.get('line','?')}" if lf_url else None
            link_info = (snippets.get("links") or {}).get(key) if key else None
            if link_info and link_info.get("function_snippet"):
                for i, line in enumerate(link_info.get("function_snippet").splitlines(), start=1):
                    if "->" in line or "[" in line or "*" in line:
                        usage_lines.append({"line_no": i, "text": line.strip()})
        out["usage_examples"] = usage_lines
    except Exception:
        pass

    # Add concrete exploitation-relevant notes
    try:
        if out.get("object"):
            o = out.get("object")
            if o.get("cache"):
                out["notes"].append(f"Object allocated from cache '{o.get('cache')}', reallocation under attacker control increases exploitability")
            if o.get("obj_size") and o.get("offset") is not None:
                out["notes"].append(f"Object size={o.get('obj_size')}, access offset={o.get('offset')}")
    except Exception:
        pass

    # ---- New: synthesize concrete preconditions from usage lines/snippets ----
    try:
        concrete_preconds: List[Dict[str, Any]] = []
        ts = out.get('trigger_site') or {}
        lf_url = ts.get('url') if ts else None
        link_key = f"link:{lf_url}#{ts.get('line','?')}" if lf_url else None
        link_info = (snippets.get('links') or {}).get(link_key) if link_key else None

        # prefer usage_lines collected earlier; otherwise scan the trigger snippet for deref/index patterns
        candidates = []
        if out.get('usage_examples'):
            for u in out.get('usage_examples'):
                candidates.append(u.get('text'))
        elif link_info and link_info.get('function_snippet'):
            for line in link_info.get('function_snippet').splitlines():
                if '->' in line or '[' in line or '*' in line:
                    candidates.append(line.strip())

        var_re = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*->\s*([A-Za-z_][A-Za-z0-9_]*)")
        idx_re = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([^\]]+)\s*\]")
        simple_var_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")

        for c in candidates:
            try:
                vars_found = []
                fields = []
                indices = []
                for m in var_re.finditer(c):
                    vars_found.append(m.group(1))
                    fields.append(m.group(2))
                for m in idx_re.finditer(c):
                    indices.append({'base': m.group(1), 'index_expr': m.group(2)})
                    vars_found.append(m.group(1))
                # fallback: find pointer/deref var names
                if not vars_found:
                    for m in re.finditer(r"\*\s*([A-Za-z_][A-Za-z0-9_]*)", c):
                        vars_found.append(m.group(1))
                # dedupe
                seen = set()
                vars_found = [v for v in vars_found if not (v in seen or seen.add(v))]

                evidence_lines = []
                if link_info and link_info.get('function_snippet'):
                    # include surrounding lines as evidence
                    snippet_lines = link_info.get('function_snippet').splitlines()
                    for i, l in enumerate(snippet_lines, start=1):
                        if any(v in l for v in vars_found) or '->' in l or '[' in l:
                            evidence_lines.append({'line_no': i, 'text': l.strip()})

                # craft constraint/hypothesis
                constraint = None
                if indices:
                    # if index expression is numeric or simple var, produce a range hint
                    idx = indices[0]
                    expr = idx.get('index_expr')
                    # if it's a simple number
                    try:
                        num = int(expr)
                        constraint = f"index {idx['base']} == {num} (literal index access)"
                    except Exception:
                        constraint = f"index expression '{expr}' on {idx['base']} may be attacker-controlled and cause OOB access"
                elif fields:
                    # if field length-like names present (len/len_field), hint at malformed length
                    constraint = f"field(s) {', '.join(fields)} may contain malformed/large values leading to OOB access"
                elif vars_found:
                    constraint = f"variable(s) {', '.join(vars_found)} may point to reclaimed/out-of-bounds memory or contain attacker-controlled indices"
                else:
                    constraint = "A pointer or index dereference in the trigger function must be fed attacker-controlled data to reach the crash"

                pre = {
                    'file': ts.get('file') if ts else None,
                    'line': ts.get('line') if ts else None,
                    'code': c.strip(),
                    'variables': vars_found,
                    'indices': indices,
                    'constraint': constraint,
                    'evidence': evidence_lines,
                }
                concrete_preconds.append(pre)
            except Exception:
                continue

        if concrete_preconds:
            out['concrete_preconditions'] = concrete_preconds
    except Exception:
        # non-fatal
        pass

    return out



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


def parse_function_snippet(snippet_text: str) -> Dict[str, Any]:
    """Parse a function-level snippet (heuristic) and return params, assignments, calls, and memops.

    Returns: {
      'func_name': str or None,
      'params': [param_names],
      'assigns': [{'dest': dest_var, 'rhs': [tokens], 'line': n, 'code': line}],
      'calls': [{'callee': name, 'args': [tokens], 'line': n, 'code': line}],
      'memops': [{'type': 'memcpy'|'memmove'|'copy_from_user'|'copy_to_user', 'args': [tokens], 'line': n, 'code': line}],
    }
    """
    out: Dict[str, Any] = {'func_name': None, 'params': [], 'assigns': [], 'calls': [], 'memops': []}
    if not snippet_text:
        return out
    lines = snippet_text.splitlines()
    # try to find a function header in the first 8 lines
    header = None
    for l in lines[:8]:
        s = l.strip()
        if not s:
            continue
        if '(' in s and ')' in s and not re.match(r'^(if|for|while|switch)\b', s):
            header = s
            break
    func_name = None
    params = []
    if header:
        # extract function name as the token before the first '('
        m = re.match(r".*?([A-Za-z_][A-Za-z0-9_]*)\s*\(", header)
        if m:
            func_name = m.group(1)
        # extract parameter list between first ( and last ) in header
        try:
            pstart = header.index('(')
            pend = header.rindex(')')
            plen = header[pstart + 1:pend]
            parts = [p.strip() for p in plen.split(',') if p.strip()]
            for part in parts:
                # parameter name is often the last token in the part
                toks = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)", part)
                if toks:
                    pname = toks[-1]
                    if pname not in params:
                        params.append(pname)
        except Exception:
            pass
    out['func_name'] = func_name
    out['params'] = params

    # patterns
    assign_re = re.compile(r"^\s*(?P<left>[^=]+?)\s*=\s*(?P<right>[^;]+);?")
    call_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
    mem_re = re.compile(r"\b(memcpy|memmove|copy_from_user|copy_to_user)\s*\(([^)]*)\)")

    for i, l in enumerate(lines, start=1):
        try:
            # assignments
            m = assign_re.match(l)
            if m:
                left = m.group('left').strip()
                right = m.group('right').strip()
                # extract variable base names
                left_vars = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)", left)
                rhs_vars = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)", right)
                if left_vars:
                    dest = left_vars[-1]
                else:
                    dest = None
                out['assigns'].append({'dest': dest, 'rhs': rhs_vars, 'line': i, 'code': l.strip()})
            # mem ops
            for mm in mem_re.finditer(l):
                mtype = mm.group(1)
                args = mm.group(2)
                parts = [p.strip() for p in args.split(',') if p.strip()]
                arg_vars = []
                for p in parts:
                    av = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)", p)
                    if av:
                        arg_vars.append(av[-1])
                out['memops'].append({'type': mtype, 'args': arg_vars, 'line': i, 'code': l.strip()})
            # calls
            for mc in call_re.finditer(l):
                cname = mc.group(1)
                args = mc.group(2)
                # skip control keywords
                if cname in ('if', 'for', 'while', 'switch', 'return', 'sizeof'):
                    continue
                parts = [p.strip() for p in args.split(',') if p.strip()]
                arg_vars = []
                for p in parts:
                    av = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)", p)
                    if av:
                        arg_vars.append(av[-1])
                out['calls'].append({'callee': cname, 'args': arg_vars, 'line': i, 'code': l.strip()})
        except Exception:
            continue

    return out


def build_dataflow_graph(parsed: Dict[str, Any], snippets: Dict[str, Any]) -> Dict[str, Any]:
    """Build a simple dataflow graph from snippets.

    Returns a dict with:
      - graph: {node: set([dest_nodes])} where nodes are 'var@func'
      - occurrences: {node: [{'file','line','code'}...]}
      - meta: auxiliary info like copy_from_user occurrences
      - func_params: {func_name: [param_names]}
    """
    graph: Dict[str, Set[str]] = {}
    occurrences: Dict[str, List[Dict[str, Any]]] = {}
    meta: Dict[str, Any] = {'copy_from_user': {}}
    func_params: Dict[str, List[str]] = {}

    def _add_node(n: str):
        if n not in graph:
            graph[n] = set()

    # helper to register an occurrence
    def _add_occ(node: str, file: Optional[str], line: Optional[int], code: str):
        occurrences.setdefault(node, []).append({'file': file, 'line': line, 'code': code})

    # iterate snippets sources: links, local, urls
    candidates = []
    for k, v in (snippets.get('links') or {}).items():
        if isinstance(v, dict) and v.get('function_snippet'):
            candidates.append((k, v.get('file'), v.get('line'), v.get('function_snippet')))
    for k, v in (snippets.get('local') or {}).items():
        if isinstance(v, dict) and v.get('snippet'):
            candidates.append((k, os.path.basename(v.get('path') or ''), v.get('line'), v.get('snippet')))
    for k, v in (snippets.get('urls') or {}).items():
        txt = v if isinstance(v, str) else (v.get('snippet') if isinstance(v, dict) else None)
        if txt:
            candidates.append((k, None, None, txt))

    # map of function names to parsed snippet content for callee lookup
    func_snip_map: Dict[str, Dict[str, Any]] = {}

    for key, file, start_line, txt in candidates:
        parsed_snip = parse_function_snippet(txt)
        func = parsed_snip.get('func_name') or key
        func_snip_map[func] = parsed_snip
        params = parsed_snip.get('params') or []
        func_params[func] = params

        # register occurrences for param nodes
        for p in params:
            node = f"{p}@{func}"
            _add_node(node)
            _add_occ(node, file, start_line, f"param {p} in {func}")

        # process assigns
        for a in parsed_snip.get('assigns', []):
            dest = a.get('dest')
            rhs = a.get('rhs') or []
            if not dest:
                continue
            dest_node = f"{dest}@{func}"
            _add_node(dest_node)
            _add_occ(dest_node, file, start_line or a.get('line'), a.get('code'))
            for r in rhs:
                src_node = f"{r}@{func}"
                _add_node(src_node)
                # edge src -> dest
                graph.setdefault(src_node, set()).add(dest_node)

        # process memops
        for m in parsed_snip.get('memops', []):
            mtype = m.get('type')
            args = m.get('args') or []
            if mtype in ('memcpy', 'memmove') and len(args) >= 2:
                dst = args[0]
                src = args[1]
                dst_node = f"{dst}@{func}"
                src_node = f"{src}@{func}"
                _add_node(dst_node)
                _add_node(src_node)
                graph.setdefault(src_node, set()).add(dst_node)
                _add_occ(dst_node, file, start_line or m.get('line'), m.get('code'))
            if mtype == 'copy_from_user' and len(args) >= 1:
                dst = args[0]
                dst_node = f"{dst}@{func}"
                _add_node(dst_node)
                _add_occ(dst_node, file, start_line or m.get('line'), m.get('code'))
                meta['copy_from_user'].setdefault(dst_node, []).append({'file': file, 'line': start_line or m.get('line'), 'code': m.get('code')})

        # process calls: create arg->param edges when callee parsed
        for c in parsed_snip.get('calls', []):
            callee = c.get('callee')
            args = c.get('args') or []
            # register occurrences for args
            for idx, aarg in enumerate(args):
                src_node = f"{aarg}@{func}"
                _add_node(src_node)
                _add_occ(src_node, file, start_line or c.get('line'), c.get('code'))
            # if callee has params parsed, connect arg->param
            callee_params = func_params.get(callee) or (func_snip_map.get(callee) or {}).get('params') or []
            for i, arg_name in enumerate(args):
                if i < len(callee_params):
                    param = callee_params[i]
                    src_node = f"{arg_name}@{func}"
                    dst_node = f"{param}@{callee}"
                    _add_node(src_node)
                    _add_node(dst_node)
                    graph.setdefault(src_node, set()).add(dst_node)
                    # no direct occurrence for dst unless we have callee snippet
    return {'graph': graph, 'occurrences': occurrences, 'meta': meta, 'func_params': func_params}


def propagate_taint_graph(graph: Dict[str, Set[str]], seeds: Dict[str, Dict[str, Any]], max_depth: int = 7, max_nodes: int = 500) -> Dict[str, Dict[str, Any]]:
    """Propagate taint forward from seed nodes over the dataflow graph.

    Returns mapping node -> {'seed_label': label, 'distance': dist}
    """
    from collections import deque

    tainted: Dict[str, Dict[str, Any]] = {}
    q = deque()
    # initialize queue
    for node, info in (seeds or {}).items():
        label = info.get('label')
        if node:
            tainted[node] = {'seed_label': label, 'distance': 0}
            q.append((node, label, 0))

    visited_count = len(tainted)
    while q and visited_count < max_nodes:
        node, label, dist = q.popleft()
        if dist >= max_depth:
            continue
        for nb in graph.get(node, set()):
            if nb in tainted:
                # keep the shortest distance/earliest seed
                continue
            tainted[nb] = {'seed_label': label, 'distance': dist + 1}
            q.append((nb, label, dist + 1))
            visited_count += 1
            if visited_count >= max_nodes:
                break
    return tainted

def save_to_json(crash_log: str, result: Dict[str, Any], url: str) -> None:
    """Save the analysis result to a JSON file."""
    # write JSON to crash_analysis/<bugid>.json
    out_dir = os.path.join(os.getcwd(), 'crash_analysis')
    os.makedirs(out_dir, exist_ok=True)
    # attempt to determine a bug id from parsed data; fallback to input basename
    default_name = url.split('=')[-1]
    # bugid = determine_bug_id(result.get('parsed', {}), default_name)
    # Attempt to enrich result with LLM analysis when possible
    try:
        snippet_map = result.get('snippets', {}).get('links', {})
        # output static analysis summary with just the exploitability level, the rationale, and the capabilities the primitive provides
        print("Static Analysis Summary:")
        print(f"  Exploitability Level: {result.get('strong_report', {}).get('overview', {}).get('exploitability', 'unknown')}")
        print(f"  Rationale: {result.get('strong_report', {}).get('overview', {}).get('rationale', 'unknown')}")
        print(f"  Capabilities: {result.get('strong_report', {}).get('overview', {}).get('primitive_capabilities', 'unknown')}")

        # provide a prompt to user output to decide whether to use LLM analysis
        print("Would you like to perform LLM-based analysis of the crash? (y/n): ", end='', flush=True)
        choice = input().strip().lower()
        if choice == 'y':
            try:
                llm_res = llm_analyze_traces(crash_log, snippet_map)
                print("LLM Analysis Summary:")
                print(f"  Exploitability Level: {llm_res.get('openai_llm', {}).get('parsed', {}).get('overview', {}).get('exploitability', 'unknown')}")
                print(f"  Rationale: {llm_res.get('openai_llm', {}).get('parsed', {}).get('overview', {}).get('rationale', 'unknown')}")
                print(f"  Capabilities: {llm_res.get('openai_llm', {}).get('parsed', {}).get('overview', {}).get('primitive_capabilities', 'unknown')}")
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
    # if args.bulk_dir and args.out_dir:
    #     analyze_directory(args.bulk_dir, args.out_dir, args.source_root)
    #     return
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
            save_to_json(txt, result, args.syz_bug)
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
            save_to_json(txt, compact, args.syz_bug)
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
    # if args.download_syz and args.out_dir:
    #     ok = download_syz_bug_assets(args.download_syz, args.out_dir)
    #     if not ok:
    #         print("Failed to download syz bug assets")
    #         return
    #     # run analysis on downloaded directory
    #     analyze_directory(args.out_dir, args.out_dir, args.source_root)
    #     return

    result = analyze(txt, args.source_root)
    # run stronger heuristics and include in output
    strong = stronger_heuristics(result["parsed"], result.get("snippets", {}), result.get("evidence", {}))
    result["strong_report"] = strong

    if args.json:
        save_to_json(txt, result, "input")
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
        save_to_json(txt, compact, "input")
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


# def analyze_directory(input_dir: str, out_dir: str, source_root: Optional[str] = None) -> None:
#     """Analyze all crash log files in a directory and write per-file JSON+HTML to out_dir.

#     Behavior: scans files with .txt or .log extension; for each file runs analyze() and writes
#     `{basename}.json` and `{basename}.html` (HTML only if html generation is possible).
#     """
#     os.makedirs(out_dir, exist_ok=True)
#     # central crash_analysis directory for JSON outputs
#     crash_dir = os.path.join(os.getcwd(), 'crash_analysis')
#     os.makedirs(crash_dir, exist_ok=True)
#     for fn in os.listdir(input_dir):
#         if not (fn.endswith('.txt') or fn.endswith('.log') or fn.endswith('.crash')):
#             continue
#         path = os.path.join(input_dir, fn)
#         try:
#             with open(path, 'r', errors='ignore') as fh:
#                 txt = fh.read()
#         except Exception:
#             continue
#         result = analyze(txt, source_root)
#         base = os.path.splitext(fn)[0]
#         # determine bug id and write JSON into crash_analysis (includes LLM enrichment)
#         bugid = determine_bug_id(result.get('parsed', {}), base)
#         save_to_json(result, bugid)
#         # generate HTML report
#         html_path = os.path.join(out_dir, base + '.html')
#         try:
#             strong = stronger_heuristics(result['parsed'], result.get('snippets', {}), result.get('evidence', {}))
#             result['strong_report'] = strong
#             generate_html_report(result, html_path)
#         except Exception:
#             # continue even if HTML generation fails
#             pass


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
            save_to_json(txt, result, bugid)
        except Exception:
            import hashlib
            h = hashlib.sha1(u.encode()).hexdigest()[:12]
            save_to_json(txt, result, h)
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
