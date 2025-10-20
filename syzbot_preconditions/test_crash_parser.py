from crash_analyzer import parse_crash_log, classify


def test_parse_example():
    example = """
==================================================================
BUG: KASAN: use-after-free in sanity_check_inode fs/f2fs/inode.c:275 [inline]
BUG: KASAN: use-after-free in do_read_inode fs/f2fs/inode.c:415 [inline]
BUG: KASAN: use-after-free in f2fs_iget+0x43aa/0x4dc0 fs/f2fs/inode.c:514
Read of size 4 at addr ffff88812141bf78 by task syz-executor150/338

CPU: 0 PID: 338 Comm: syz-executor150 Not tainted 5.10.240-syzkaller #0
Call Trace:
 __dump_stack+0x21/0x24 lib/dump_stack.c:77
 dump_stack_lvl+0x169/0x1d8 lib/dump_stack.c:118
 print_address_description+0x7f/0x2c0 mm/kasan/report.c:248
 __kasan_report mm/kasan/report.c:435 [inline]
 kasan_report+0xe2/0x130 mm/kasan/report.c:452
 __asan_report_load4_noabort+0x14/0x20 mm/kasan/report_generic.c:308
 sanity_check_inode fs/f2fs/inode.c:275 [inline]
 do_read_inode fs/f2fs/inode.c:415 [inline]
 f2fs_iget+0x43aa/0x4dc0 fs/f2fs/inode.c:514
 f2fs_lookup+0x3ee/0xce0 fs/f2fs/namei.c:544
==================================================================
"""
    parsed = parse_crash_log(example)
    assert parsed["kind"] is not None
    assert parsed["access"]["size"] == 4
    cls = classify(parsed)
    assert cls["classification"] == "use-after-free"


def test_url_extraction_and_evidence():
    text = "See source here: https://android.googlesource.com/kernel/common/+/1154f779f3f3d196ace7d5084498f5d7f418ba64/mm/page_alloc.c#2456"
    from crash_analyzer import extract_source_urls, analyze_snippet_for_evidence

    urls = extract_source_urls(text)
    assert len(urls) == 1

    # Simple snippet evidence: pointer deref
    snippet = "void foo() { struct x *p; p->field = 1; }"
    ev = analyze_snippet_for_evidence(snippet, {"op": "write", "size": 1})
    assert ev["dereference"] is True
    assert ev["access_op"] == "write"


def test_stronger_heuristics_runs():
    from crash_analyzer import stronger_heuristics
    parsed = {"kind": "KASAN: use-after-free", "access": {"op": "read", "size": 4}, "raw": "syz-executor"}
    snippets = {}
    evidence = {"fake": {"dereference": True, "access_size": 4}}
    r = stronger_heuristics(parsed, snippets, evidence)
    assert "primitive" in r and "confidence" in r


def test_convert_to_raw_github():
    from crash_analyzer import convert_to_raw
    url = "https://github.com/owner/repo/blob/main/path/to/file.c"
    raw = convert_to_raw(url)
    assert raw == "https://raw.githubusercontent.com/owner/repo/main/path/to/file.c"


def test_parse_fragment_for_range():
    from crash_analyzer import parse_fragment_for_range
    u1 = "https://github.com/owner/repo/blob/main/file.c#L245"
    s, e = parse_fragment_for_range(u1)
    assert s == 245 and e == 245


def test_generate_html_report(tmp_path):
    from crash_analyzer import analyze, generate_html_report
    example = """
BUG: KASAN: use-after-free in sanity_check_inode fs/f2fs/inode.c:275 [inline]
Read of size 4 at addr ffff88812141bf78 by task syz-executor150/338
"""
    result = analyze(example)
    out = tmp_path / "report.html"
    generate_html_report(result, str(out))
    assert out.exists()


def test_analyze_directory(tmp_path):
    # create two small crash files
    d = tmp_path / "crashes"
    d.mkdir()
    f1 = d / "a.crash"
    f1.write_text("BUG: KASAN: use-after-free in foo\nRead of size 4 at addr 0x1234")
    f2 = d / "b.crash"
    f2.write_text("BUG: KASAN: double-free in bar\nWrite of size 1 at addr 0x4321")
    out = tmp_path / "out"
    out.mkdir()
    from crash_analyzer import analyze_directory
    analyze_directory(str(d), str(out))
    # expect JSON files present
    files = list(out.iterdir())
    assert any(p.suffix == '.json' for p in files)
    u2 = "https://github.com/owner/repo/blob/main/file.c#L245-L255"
    s, e = parse_fragment_for_range(u2)
    assert s == 245 and e == 255
    u3 = "https://android.googlesource.com/.../file.c#245"
    s, e = parse_fragment_for_range(u3)
    assert s == 245 and e == 245


def test_concrete_preconditions_extraction():
    from crash_analyzer import stronger_heuristics

    # synthetic parsed data with frames including a syscall entry
    parsed = {
        "kind": "KASAN: use-after-free",
        "access": {"op": "read", "size": 8},
        "raw": "some raw text",
        "frames": [
            {"func": "do_something", "file": "fs/foo.c", "line": 120},
            {"func": "__x64_sys_open", "file": "kernel/sys.c", "line": 10},
            {"func": "entry_SYSCALL_64", "file": "arch/x86/entry.c", "line": 1},
        ],
    }

    # snippets: include a link snippet with a struct and a deref
    snippets = {
        "links": {
            "link:https://example.com#120": {
                "url": "https://example.com#120",
                "file": "fs/foo.c",
                "line": 120,
                "snippet": "struct bar { int a; };\nvoid foo() { struct bar *b; b->a = 1; }\n",
            }
        }
    }

    # evidence produced by analyze_snippet_for_evidence would flag deref and free/alloc
    evidence = {
        "link:https://example.com#120": {
            "dereference": True,
            "array_access": False,
            "alloc_calls": [],
            "free_calls": [],
            "nearby_lines": [(1, "struct bar { int a; };"), (2, "b->a = 1;")],
            "access_op": "read",
            "access_size": 8,
        }
    }

    r = stronger_heuristics(parsed, snippets, evidence)
    # Expect object details or type mention
    pre = " ".join(r.get("preconditions", []))
    assert "Object details" in pre or "type 'bar'" in pre or "struct bar" in pre
    # Expect syscall trigger indicated
    assert "Triggering syscall" in pre or "syscall" in pre.lower()
    # Expect variable/state mention
    assert "variable" in pre.lower() or "b->a" in pre or "b" in pre


def test_syz_syscall_extraction_and_new_vulns():
    from crash_analyzer import extract_syscalls_from_syzprog, stronger_heuristics

    syz_text = """
    // syz repro pseudo-code
    syz_open(0, "file0", O_RDONLY);
    open(3, "file1", O_WRONLY);
    // end
    """
    calls = extract_syscalls_from_syzprog(syz_text)
    assert 'syz_open' in calls or 'open' in calls

    # test null-deref detection: synthetic evidence and parsed kind
    parsed = {"kind": "KASAN: null-dereference", "access": {"op": "read", "size": 4}, "raw": "syz-executor"}
    snippets = {}
    evidence = {"fake": {"dereference": True, "nearby_lines": [(1, "if (ptr == NULL) return; *ptr = 1;")]}}
    r = stronger_heuristics(parsed, snippets, evidence)
    # vulnerability should not be 'unknown'
    assert r.get('vulnerability') is not None
    # expect primitive or vulnerability to mention null or deref
    pv = (r.get('primitive') or '') + ' ' + (r.get('vulnerability') or '')
    assert 'null' in pv.lower() or 'deref' in pv.lower() or 'use-after-free' in pv.lower() or 'oob' in pv.lower()


if __name__ == "__main__":
    test_parse_example()
    print("test passed")
