Crash Analyzer
================

Small heuristic tool to parse kernel crash logs (KASAN/BUG) and extract frames,
allocation/free traces, object info and attempt a primitive classification.

Usage:

1. Analyze a log and print human readable summary:

   python3 crash_analyzer.py crashlog.txt

2. Emit JSON with optional source lookups:

   python3 crash_analyzer.py crashlog.txt --source-root /path/to/linux

3. Emit full JSON (parsed, snippets, evidence, strong heuristics):

   python3 crash_analyzer.py crashlog.txt --json

4. Emit compact triage JSON report:

   python3 crash_analyzer.py crashlog.txt --json-report

5. Generate a human-friendly HTML report with snippets and evidence:

   python3 crash_analyzer.py crashlog.txt --html-report /tmp/crash_report.html

Notes:
- If the crash log contains web links to source files (for example GitHub or android.googlesource links), the tool will try to fetch the single file and extract the requested lines (via URL fragments) rather than cloning the entire repository.
- If you have a local kernel source tree that matches the build, provide `--source-root` to prefer local file lookups.

Output fields (JSON):
- `parsed`: structured fields extracted from the log (kind, access, frames, object_info, allocated_by, freed_by)
- `snippets`: fetched source snippets (urls/local)
- `evidence`: per-snippet heuristic evidence
- `classification`: initial classification based on log text
- `strong_report`: stronger heuristic report including `primitive`, `confidence`, `preconditions`, `postconditions`, and `support`

Examples:

1) Quick triage (compact JSON):

   python3 crash_analyzer.py crash.txt --json-report > triage.json

2) Full analysis and HTML for human triage:

   python3 crash_analyzer.py crash.txt --source-root ~/linux --html-report /tmp/report.html

Bulk analysis
-------------
You can analyze many syzbot crash logs at once.

1) Analyze all crash log files in a directory and write per-crash JSON+HTML:

   python3 crash_analyzer.py --bulk-dir /path/to/crash_logs --out-dir /tmp/crash_reports --source-root ~/linux

2) Fetch crash report text files from a list of URLs and analyze them:

   python3 crash_analyzer.py --fetch-urls crash_urls.txt --out-dir /tmp/crash_reports

Output
- The bulk commands create `{basename}.json` and `{basename}.html` for each input crash report under the `--out-dir`.

Download and analyze a single syzkaller bug page (attachments + page pre text):

   python3 crash_analyzer.py --download-syz 'https://syzkaller.appspot.com/bug?extid=feecbbf039dd054a80e1' --out-dir /tmp/bug123 --source-root ~/linux

This command will:
 - download attachments and the page <pre> block into `/tmp/bug123`
 - run the analyzer on all downloaded files (producing per-file JSON and HTML in `/tmp/bug123`)




