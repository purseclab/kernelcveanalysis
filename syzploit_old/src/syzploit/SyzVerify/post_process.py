import json
import re
import sys
import os
from collections import Counter
from difflib import SequenceMatcher
from typing import Dict, List, Tuple, Optional


def _load_json(path: str) -> Dict:
	with open(path, 'r') as f:
		return json.load(f)


def _save_json(path: str, obj: Dict) -> None:
	with open(path, 'w') as f:
		json.dump(obj, f, indent=2)


def _parse_int(val) -> Optional[int]:
	if val is None:
		return None
	if isinstance(val, int):
		return val
	if isinstance(val, str):
		val = val.strip()
		try:
			if val.startswith('0x') or val.startswith('0X'):
				return int(val, 16)
			return int(val)
		except Exception:
			return None
	return None


def _alloc_ranges(data: Dict) -> List[Tuple[int, int, Dict]]:
	ranges: List[Tuple[int, int, Dict]] = []
	# Prefer detailed allocations when available
	for k, rec in (data.get('allocations_detailed') or {}).items():
		addr = _parse_int(k)
		size = _parse_int(rec.get('size'))
		if addr is not None and size is not None and size > 0:
			ranges.append((addr, addr + size, {'addr': addr, 'size': size, 'time': rec.get('time'), 'bt': rec.get('bt')}))
	# Fallback to allocations map (size/backtrace only)
	if not ranges:
		for k, v in (data.get('allocations') or {}).items():
			addr = _parse_int(k)
			size = _parse_int((v or {}).get('size')) if isinstance(v, dict) else _parse_int(v)
			if addr is not None and size is not None and size > 0:
				ranges.append((addr, addr + size, {'addr': addr, 'size': size}))
	return ranges


def _freed_ptrs_with_time(data: Dict) -> Dict[int, float]:
	times: Dict[int, float] = {}
	for rec in data.get('frees_detailed', []):
		addr = _parse_int(rec.get('ptr'))
		t = rec.get('time')
		if addr is not None and isinstance(t, (int, float)):
			times[addr] = min(times.get(addr, t), t) if addr in times else t
	# uaf watch hits imply activity on the freed pointer post-free; include for time correlation
	for rec in data.get('uaf_watch_hits', []):
		addr = _parse_int(rec.get('ptr'))
		t = rec.get('time')
		if addr is not None and isinstance(t, (int, float)):
			times[addr] = min(times.get(addr, t), t) if addr in times else t
	return times


def _classify_event(ev: Dict, allocs: List[Tuple[int, int, Dict]], freed_times: Dict[int, float]) -> Optional[Dict]:
	et = ev.get('type')

	# --- Explicit UAF / watch / RIP events (original path) ---
	if et in ('watch', 'uaf_watch', 'rip'):
		ea = _parse_int(ev.get('ea'))
		if ea is None:
			expr = ev.get('expr')
			if isinstance(expr, str) and expr:
				m = re.search(r"0x[0-9a-fA-F]+", expr)
				if m:
					try:
						ea = int(m.group(0), 16)
					except Exception:
						ea = None
		if ea is None:
			return None

		if et == 'uaf_watch':
			return {'class': 'uaf', 'ea': ea}
		free_t = freed_times.get(ea)
		ev_t = ev.get('time')
		if free_t is not None and isinstance(ev_t, (int, float)):
			if ev_t >= free_t:
				return {'class': 'uaf', 'ea': ea}
			else:
				return {'class': 'pre-free-access', 'ea': ea}

		for lo, hi, meta in allocs:
			if lo <= ea < hi:
				return {'class': 'in-bounds', 'ea': ea, 'alloc': {'addr': meta.get('addr', lo), 'size': meta.get('size', hi - lo)}}
		return {'class': 'invalid-access', 'ea': ea}

	# --- Free events ---
	# Accept free events with or without was_allocated. A non-null ptr
	# is useful for ptr-level tracking, but even null-ptr frees serve
	# as temporal evidence that a deallocation occurred.
	if et == 'free':
		ptr = _parse_int(ev.get('ptr'))
		# Classify as uaf-free when ptr is trackable
		if ptr is not None:
			return {'class': 'uaf-free', 'ea': ptr}
		# Even with null ptr, record that a free happened (temporal marker)
		return {'class': 'uaf-free', 'ea': 0}

	# --- Potential UAF evidence from func_hit / stop on crash stack ---
	# If the event happened after at least one free, it may indicate the
	# code path that dereferences the dangling pointer is being exercised.
	if et == 'potential_uaf':
		ea = _parse_int(ev.get('ea') or ev.get('ptr'))
		if ea is not None:
			return {'class': 'uaf', 'ea': ea}
		return None

	return None


def _classify_vulnerability_type(data: Dict, results: Dict, counters: Dict) -> Dict:
	"""Classify the likely vulnerability type from event patterns and crash data.

	Examines:
	- Static crash info (kind field from KASAN report, if available)
	- Dynamic event patterns (alloc/free sequences, crash-stack functions)
	- Heuristics based on function names in events

	Returns a dict with 'type', 'confidence', 'evidence', and 'description'.
	"""
	evidence = []
	scores: Dict[str, float] = {}  # vuln_type -> confidence

	# --- 1. Static crash data (most reliable when available) ---
	crash_kind = data.get("crash_kind", "") or ""
	# Also check embedded parsed_crash or static_analysis
	parsed = data.get("parsed_crash", {}) or {}
	if not crash_kind:
		crash_kind = (parsed.get("kind") or "").lower()

	if crash_kind:
		kind_lower = crash_kind.lower()
		if "use-after-free" in kind_lower:
			scores["use-after-free"] = scores.get("use-after-free", 0) + 0.6
			evidence.append(f"Crash report identifies: use-after-free ({crash_kind})")
		elif "slab-out-of-bounds" in kind_lower or "out-of-bounds" in kind_lower:
			scores["out-of-bounds"] = scores.get("out-of-bounds", 0) + 0.6
			evidence.append(f"Crash report identifies: out-of-bounds ({crash_kind})")
		elif "double-free" in kind_lower or "double free" in kind_lower:
			scores["double-free"] = scores.get("double-free", 0) + 0.6
			evidence.append(f"Crash report identifies: double-free ({crash_kind})")
		elif "null-ptr-deref" in kind_lower or "null pointer" in kind_lower:
			scores["null-ptr-deref"] = scores.get("null-ptr-deref", 0) + 0.6
			evidence.append(f"Crash report identifies: null-pointer dereference ({crash_kind})")
		elif "data-race" in kind_lower or "race" in kind_lower:
			scores["race-condition"] = scores.get("race-condition", 0) + 0.6
			evidence.append(f"Crash report identifies: race condition ({crash_kind})")
		elif "stack-out-of-bounds" in kind_lower:
			scores["stack-buffer-overflow"] = scores.get("stack-buffer-overflow", 0) + 0.6
			evidence.append(f"Crash report identifies: stack overflow ({crash_kind})")
		elif "uninit" in kind_lower or "kmsan" in kind_lower:
			scores["uninitialized-use"] = scores.get("uninitialized-use", 0) + 0.6
			evidence.append(f"Crash report identifies: uninitialized memory use ({crash_kind})")
		else:
			# Store the raw kind
			scores[kind_lower.split(":")[0].strip()] = 0.4
			evidence.append(f"Crash report kind: {crash_kind}")

	# --- 2. Dynamic event patterns ---
	uaf_count = counters.get("uaf", 0) + counters.get("uaf-inferred", 0)
	uaf_free_count = counters.get("uaf-free", 0)
	double_free_count = results.get("summary", {}).get("double_free_count", 0)
	ptr_double_free_count = results.get("summary", {}).get("ptr_double_free_count", 0)
	invalid_free_count = results.get("summary", {}).get("invalid_free_count", 0)
	oob_near = counters.get("oob-near-freelist", 0) + counters.get("oob-near-alloc", 0)
	invalid_access = counters.get("invalid-access", 0)
	lifecycle_reclaim = results.get("summary", {}).get("lifecycle_reclaim_cycles", 0)

	if uaf_count > 0:
		scores["use-after-free"] = scores.get("use-after-free", 0) + 0.3
		evidence.append(f"UAF events detected: {uaf_count}")
	if uaf_free_count > 0:
		scores["use-after-free"] = scores.get("use-after-free", 0) + 0.15
		evidence.append(f"Frees of tracked allocations: {uaf_free_count}")
	if double_free_count > 0 or ptr_double_free_count > 0:
		total_df = max(double_free_count, ptr_double_free_count)
		scores["double-free"] = scores.get("double-free", 0) + 0.4
		evidence.append(f"Double-free detected: {total_df} pointer(s)")
	if lifecycle_reclaim > 0:
		scores["use-after-free"] = scores.get("use-after-free", 0) + 0.15
		evidence.append(f"Alloc-after-free reclaim cycles: {lifecycle_reclaim}")
	if oob_near > 0:
		scores["out-of-bounds"] = scores.get("out-of-bounds", 0) + 0.3
		evidence.append(f"OOB-near events: {oob_near}")
	if invalid_access > 0:
		scores["invalid-access"] = scores.get("invalid-access", 0) + 0.2
		evidence.append(f"Invalid accesses: {invalid_access}")
	if invalid_free_count > 0:
		scores["invalid-free"] = scores.get("invalid-free", 0) + 0.2
		evidence.append(f"Invalid frees: {invalid_free_count}")

	# --- 3. Function-name heuristics from events ---
	func_names = set()
	for ev in data.get("events", []):
		fn = ev.get("func", "")
		if fn:
			func_names.add(fn.lower())
		for frame in ev.get("bt", []):
			fn2 = frame.get("func", "")
			if fn2:
				func_names.add(fn2.lower().split("+")[0])

	# UAF indicators: functions related to free/release + access patterns
	uaf_funcs = {"kfree", "ep_free", "fput", "__fput", "ep_eventpoll_release",
				  "remove_wait_queue", "sk_destruct", "sock_put", "release_sock",
				  "__sock_release", "l2tp_session_free", "pppol2tp_release"}
	if func_names & uaf_funcs:
		scores["use-after-free"] = scores.get("use-after-free", 0) + 0.1
		matched = func_names & uaf_funcs
		evidence.append(f"UAF-related functions in trace: {', '.join(sorted(matched))}")

	# OOB indicators
	oob_funcs = {"__memcpy", "memcpy", "memset", "copy_from_user", "copy_to_user",
				  "skb_put", "skb_push", "nla_put"}
	if func_names & oob_funcs:
		scores["out-of-bounds"] = scores.get("out-of-bounds", 0) + 0.05
		matched = func_names & oob_funcs
		evidence.append(f"Potential OOB functions: {', '.join(sorted(matched))}")

	# Race indicators
	race_funcs = {"__lock_acquire", "_raw_spin_lock", "_raw_spin_lock_irqsave",
				   "mutex_lock", "down_write", "rcu_read_lock"}
	if func_names & race_funcs:
		scores["race-condition"] = scores.get("race-condition", 0) + 0.05
		matched = func_names & race_funcs
		evidence.append(f"Concurrency-related functions: {', '.join(sorted(matched))}")

	# --- 4. Pick winner ---
	if not scores:
		return {
			"type": "unknown",
			"confidence": 0.0,
			"evidence": ["No crash data or distinctive event patterns found"],
			"description": "Could not determine vulnerability type from available data",
		}

	best_type = max(scores, key=scores.get)
	best_score = min(scores[best_type], 1.0)

	# Human-readable descriptions
	descs = {
		"use-after-free": "A heap object is freed and then accessed via a dangling pointer",
		"out-of-bounds": "Memory is read/written beyond the bounds of an allocated object",
		"double-free": "The same heap object is freed more than once",
		"null-ptr-deref": "A null pointer is dereferenced, crashing the kernel",
		"race-condition": "A data race or time-of-check-to-time-of-use vulnerability",
		"stack-buffer-overflow": "A stack buffer is overwritten beyond its bounds",
		"uninitialized-use": "Uninitialized kernel memory is read and leaked",
		"invalid-access": "An invalid memory address is accessed",
		"invalid-free": "A pointer that was not allocated is freed",
	}

	return {
		"type": best_type,
		"confidence": round(best_score, 2),
		"evidence": evidence,
		"description": descs.get(best_type, f"Vulnerability type: {best_type}"),
		"all_scores": {k: round(v, 2) for k, v in sorted(scores.items(), key=lambda x: -x[1])},
	}


# ---------------------------------------------------------------------------
# Lifecycle function sets — used to classify func_hit events
# ---------------------------------------------------------------------------
_FREE_FUNCS = {
	"kmem_cache_free", "kfree", "__sk_free", "sk_free", "sk_prot_free",
	"__sk_destruct", "sk_destruct", "sock_put", "release_sock",
	"__sock_release", "fput", "__fput", "ep_free",
	"ep_eventpoll_release", "remove_wait_queue",
	"l2tp_session_free", "pppol2tp_release", "inet_sock_destruct",
	"__release_sock", "sock_def_destruct", "tcp_close", "udp_destroy_sock",
}
_ALLOC_FUNCS = {
	"kmem_cache_alloc", "kmalloc", "kzalloc", "sk_alloc", "sk_prot_alloc",
	"__sock_create", "sock_create", "inet_create", "__sys_socket",
	"sk_clone_lock",
}
_USE_FUNCS = {
	"process_one_work", "__sys_connect", "__sys_sendto", "__sys_recvfrom",
	"__sys_setsockopt", "__sys_getsockopt", "__sys_bind", "__sys_listen",
	"__sys_accept4", "do_syscall_64", "ret_from_fork", "ret_to_user",
}

MAX_SLAB_SIZE = 1 << 22  # 4 MiB — anything bigger is not a slab alloc


def analyze(input_path: str, output_path: Optional[str] = None, parsed_crash: Optional[Dict] = None) -> Dict:
	data = _load_json(input_path)
	# Embed parsed crash data so the vuln classifier can use the static kind
	if parsed_crash:
		data["parsed_crash"] = parsed_crash
	allocs = _alloc_ranges(data)
	freed_times = _freed_ptrs_with_time(data)

	# --- Build supplemental alloc map from alloc_entry events --------
	for ev in data.get('events', []):
		if ev.get('type') != 'alloc_entry':
			continue
		size = _parse_int(ev.get('size'))
		if size is None or size <= 0 or size > MAX_SLAB_SIZE:
			continue  # bogus value (e.g. misread register)
		pc = _parse_int(ev.get('pc'))
		if pc is None:
			continue
		# We don't know the returned address, but record the event
		allocs.append((pc, pc + size, {'addr': pc, 'size': size, 'time': ev.get('time')}))

	results: Dict = {
		'summary': {
			'alloc_count': len(allocs),
			'freed_count': len(freed_times),
			'uaf_hits': len(data.get('uaf_watch_hits', [])),
		},
		'classifications': [],
		'vulnerabilities_detected': [],
		'confidence': 0,
	}

	for ev in data.get('events', []):
		cls = _classify_event(ev, allocs, freed_times)
		if cls:
			rec = {
				'class': cls['class'],
				'ea': cls['ea'],
				'type': ev.get('type'),
				'time': ev.get('time'),
				'func': ev.get('func', ''),
				'rip': ev.get('rip'),
				'ptid': ev.get('ptid'),
				'insn': ev.get('insn')
			}
			if 'alloc' in cls:
				rec['alloc'] = cls['alloc']
			results['classifications'].append(rec)

	counters: Dict[str, int] = {'uaf': 0, 'invalid-access': 0, 'in-bounds': 0,
								 'pre-free-access': 0, 'uaf-free': 0}
	for c in results['classifications']:
		counters[c['class']] = counters.get(c['class'], 0) + 1
	results['summary'].update(counters)

	# ---------- Temporal & lifecycle-based inference ----------
	# Strategy:
	#  A. Use ALL free events (not just was_allocated) for timeline markers.
	#  B. Classify func_hit events by lifecycle role (alloc / free / use).
	#  C. If free-phase events precede use-phase events → UAF.
	#  D. Same ptr freed >1 time → double-free.
	#  E. Free-related func_hits interleaved with use-related → UAF path.

	# --- Collect timestamps per lifecycle phase -----------------------
	free_times: List[float] = []           # all free-event timestamps
	alloc_times: List[float] = []          # all alloc-event timestamps
	free_func_times: List[float] = []      # func_hits on free-lifecycle funcs
	alloc_func_times: List[float] = []     # func_hits on alloc-lifecycle funcs
	use_func_times: List[Tuple[float, str]] = []  # func_hits on usage funcs
	freed_ptrs: Dict[int, List[float]] = {}  # ptr → list of free times

	# --- Build set of crash-stack functions if available -------------
	crash_stack_funcs: set = set()
	if parsed_crash:
		# Extract function names from crash stack frames
		for frame in parsed_crash.get('crash_stack', []):
			fn = frame.get('func', '').lower()
			if fn:
				crash_stack_funcs.add(fn)
		# Also check 'call_trace' field
		for frame in parsed_crash.get('call_trace', []):
			fn = frame.get('func', '').lower()
			if fn:
				crash_stack_funcs.add(fn)

	for ev in data.get('events', []):
		et = ev.get('type', '')
		t = ev.get('time')
		if not isinstance(t, (int, float)):
			continue

		if et == 'free':
			free_times.append(t)
			ptr = _parse_int(ev.get('ptr'))
			if ptr is not None and ptr != 0:
				freed_ptrs.setdefault(ptr, []).append(t)
		elif et == 'alloc_entry':
			alloc_times.append(t)
		elif et in ('func_hit', 'stop'):
			fn = (ev.get('func') or '').lower()
			if fn in _FREE_FUNCS:
				free_func_times.append(t)
			elif fn in _ALLOC_FUNCS:
				alloc_func_times.append(t)
			elif fn in _USE_FUNCS or fn in crash_stack_funcs:
				# Only count as "use-phase" if it's a known use func or in crash stack
				use_func_times.append((t, fn or ev.get('func', '')))

	# --- A. Basic temporal UAF: frees before use func_hits ----------
	earliest_free = min(free_times) if free_times else None
	earliest_free_func = min(free_func_times) if free_func_times else None
	# The effective "free point" is the earliest evidence of deallocation
	effective_free_time = None
	if earliest_free is not None and earliest_free_func is not None:
		effective_free_time = min(earliest_free, earliest_free_func)
	elif earliest_free is not None:
		effective_free_time = earliest_free
	elif earliest_free_func is not None:
		effective_free_time = earliest_free_func

	inferred_uaf = 0
	inferred_details: List[Dict] = []
	if effective_free_time is not None:
		for (ut, fn) in use_func_times:
			if ut > effective_free_time:
				inferred_uaf += 1
				if len(inferred_details) < 8:
					inferred_details.append({'func': fn, 'time': ut, 'type': 'func_hit'})

	if inferred_uaf > 0:
		counters['uaf-inferred'] = inferred_uaf
		results['summary']['uaf-inferred'] = inferred_uaf
		results['summary']['uaf'] = inferred_uaf
		results['summary']['uaf_inference_note'] = (
			f"{len(free_times)} free events + {len(free_func_times)} free-func hits "
			f"observed, then {inferred_uaf} use-phase func_hits occurred after — "
			f"consistent with UAF path."
		)
		results['vulnerabilities_detected'].append({
			'type': 'use-after-free (inferred)',
			'count': inferred_uaf,
			'free_events': len(free_times),
			'free_func_hits': len(free_func_times),
			'note': 'Inferred from free→use temporal lifecycle pattern',
			'details': inferred_details,
		})

	# --- B. Lifecycle interleaving: free-funcs interleaved with alloc/use ---
	# If we see patterns like: alloc → free → alloc → free ... with use in between
	if len(free_func_times) > 0 and len(alloc_func_times) > 0:
		# Count cycles: how many times does an alloc-func fire AFTER a free-func?
		reclaim_cycles = 0
		sorted_free_ft = sorted(free_func_times)
		for at in alloc_func_times:
			# Binary search: is there a free-func time < at?
			if sorted_free_ft and sorted_free_ft[0] < at:
				reclaim_cycles += 1
		if reclaim_cycles > 0:
			results['summary']['lifecycle_reclaim_cycles'] = reclaim_cycles
			if inferred_uaf == 0:
				# Promote to inferred UAF if we see reclaim-after-free
				counters['uaf-inferred'] = reclaim_cycles
				results['summary']['uaf-inferred'] = reclaim_cycles
				results['summary']['uaf'] = reclaim_cycles
				results['summary']['uaf_inference_note'] = (
					f"{reclaim_cycles} alloc-after-free cycles detected in func_hit "
					f"lifecycle — consistent with slab reclaim after UAF trigger."
				)

	# --- C. Ptr-level double-free from freed_ptrs --------------------
	ptr_double_frees = {ptr: times for ptr, times in freed_ptrs.items()
						 if len(times) > 1}
	if ptr_double_frees:
		results['summary']['ptr_double_free_count'] = len(ptr_double_frees)
		results['summary']['ptr_double_free_total_frees'] = sum(
			len(t) for t in ptr_double_frees.values())
		results['vulnerabilities_detected'].append({
			'type': 'double-free (ptr-tracked)',
			'ptrs': {hex(p): len(t) for p, t in ptr_double_frees.items()},
			'note': f"{len(ptr_double_frees)} pointer(s) freed multiple times",
		})

	# --- D. Func-hit summary for diagnostics -------------------------
	func_hit_counts = Counter(
		ev.get('func', '?') for ev in data.get('events', [])
		if ev.get('type') == 'func_hit'
	)
	if func_hit_counts:
		results['summary']['func_hit_top'] = dict(func_hit_counts.most_common(10))
		# Tag which categories were seen
		seen_fns = set(fn.lower() for fn in func_hit_counts)
		results['summary']['lifecycle_free_funcs_seen'] = sorted(seen_fns & _FREE_FUNCS)
		results['summary']['lifecycle_alloc_funcs_seen'] = sorted(seen_fns & _ALLOC_FUNCS)

	# ---------- OOB windowing heuristics ----------

	def _size_class(sz: int) -> int:
		classes = [8,16,32,64,96,128,192,256,512,1024,2048,4096,8192,16384,32768]
		for c in classes:
			if sz <= c:
				return c
		return classes[-1]

	# Map alloc addr -> size for quick lookup
	alloc_map: Dict[int, int] = {a: (meta.get('size') or (b - a)) for a, b, meta in allocs}
	# Reclassify invalid accesses if near freed pointers or alloc edges
	oob_near_freelist = 0
	oob_near_alloc = 0
	for rec in results['classifications']:
		if rec['class'] != 'invalid-access':
			continue
		ea = rec['ea']
		# Near freed pointer
		closest_free = None
		min_dist = None
		for fp in freed_times.keys():
			d = abs(ea - fp)
			if min_dist is None or d < min_dist:
				min_dist = d
				closest_free = fp
		if closest_free is not None:
			# Window based on size class of original alloc if known, else default
			sz = alloc_map.get(closest_free, 64)
			window = min(256, _size_class(int(sz)) * 2)
			if min_dist is not None and min_dist <= window:
				rec['class'] = 'oob-near-freelist'
				rec['near_ptr'] = hex(closest_free)
				rec['distance'] = int(min_dist)
				rec['cache_size'] = _size_class(int(sz))
				oob_near_freelist += 1
				continue
		# Near allocation edges
		closest_edge = None
		min_edge_dist = None
		edge_cache = None
		for lo, hi, meta in allocs:
			if ea < lo:
				d = lo - ea
				edge = lo
			elif ea >= hi:
				d = ea - hi
				edge = hi
			else:
				continue
			if min_edge_dist is None or d < min_edge_dist:
				min_edge_dist = d
				closest_edge = edge
				edge_cache = _size_class(int(meta.get('size', hi - lo)))
		if closest_edge is not None:
			margin = min(128, edge_cache // 2)
			if min_edge_dist is not None and min_edge_dist <= margin:
				rec['class'] = 'oob-near-alloc'
				rec['near_edge'] = hex(closest_edge)
				rec['distance'] = int(min_edge_dist)
				rec['cache_size'] = edge_cache
				oob_near_alloc += 1

	counters['oob-near-freelist'] = oob_near_freelist
	counters['oob-near-alloc'] = oob_near_alloc
	results['summary'].update({'oob-near-freelist': oob_near_freelist, 'oob-near-alloc': oob_near_alloc})
	if oob_near_freelist:
		results['vulnerabilities_detected'].append({'type': 'oob-near-freelist', 'count': oob_near_freelist})
	if oob_near_alloc:
		results['vulnerabilities_detected'].append({'type': 'oob-near-alloc', 'count': oob_near_alloc})

	# Double-free detection (merge ptr-tracked double-frees with frees_detailed)
	free_hist: Dict[int, List[float]] = {}
	for rec in data.get('frees_detailed', []):
		addr = _parse_int(rec.get('ptr'))
		t = rec.get('time')
		if addr is None or addr == 0 or not isinstance(t, (int, float)):
			continue
		free_hist.setdefault(addr, []).append(t)
	double_frees = [hex(ptr) for ptr, times in free_hist.items() if len(times) > 1]
	# Also include ptr_double_frees already found in lifecycle analysis
	all_double_free_ptrs = set(double_frees)
	all_double_free_ptrs.update(hex(p) for p in ptr_double_frees)
	results['summary']['double_free_count'] = len(all_double_free_ptrs)
	if all_double_free_ptrs:
		results['vulnerabilities_detected'].append({
			'type': 'double-free',
			'count': len(all_double_free_ptrs),
			'ptrs': sorted(all_double_free_ptrs),
		})

	# Invalid free detection
	allocated_ptrs = set(a for a, _, _ in allocs)
	invalid_frees = [hex(ptr) for ptr in freed_times.keys() if ptr not in allocated_ptrs]
	results['summary']['invalid_free_count'] = len(invalid_frees)
	if invalid_frees:
		results['vulnerabilities_detected'].append({'type': 'invalid-free', 'ptrs': invalid_frees})

	# Confidence scoring
	score = 0
	uaf_count = counters.get('uaf', 0) + counters.get('uaf-inferred', 0)
	uaf_free_count = counters.get('uaf-free', 0)
	score += 40 if uaf_count > 0 else 0
	score += 15 if uaf_free_count > 0 else 0     # frees of tracked allocations
	score += 20 if results['summary']['double_free_count'] > 0 else 0
	score += 10 if results['summary']['invalid_free_count'] > 0 else 0
	score += 10 if counters.get('invalid-access', 0) > 0 else 0
	# Lifecycle evidence
	score += 10 if results['summary'].get('lifecycle_reclaim_cycles', 0) > 0 else 0
	score += 5 if results['summary'].get('lifecycle_free_funcs_seen') else 0
	score += 5 if results['summary'].get('lifecycle_alloc_funcs_seen') else 0
	score += min(20, results['summary']['alloc_count']) // 5
	results['confidence'] = min(100, score)

	if uaf_count > 0:
		results['vulnerabilities_detected'].append({'type': 'use-after-free', 'count': uaf_count})
	if counters.get('invalid-access', 0) > 0:
		results['vulnerabilities_detected'].append({'type': 'invalid-access', 'count': counters['invalid-access']})

	if output_path is None:
		base = os.path.splitext(os.path.basename(input_path))[0]
		output_path = os.path.join(os.path.dirname(input_path), f"{base}_analysis.json")

	# ---------- Vulnerability type classification ----------
	# Guess the vulnerability type from the combination of event patterns,
	# static crash data (if embedded), and dynamic observations.
	results['vulnerability_classification'] = _classify_vulnerability_type(data, results, counters)

	_save_json(output_path, results)
	return results


# ============================================================================
# Stack Trace Fuzzy Matching
# ============================================================================

# Symbols commonly inlined/merged by the compiler that can safely be skipped
# when comparing crash stacks across builds.
_INLINE_NOISE = frozenset({
    "__might_fault", "__might_sleep", "might_fault", "might_sleep",
    "lock_acquire", "lock_release", "lockdep_rcu_suspicious",
    "__sanitizer_cov_trace_pc", "__asan_load", "__asan_store",
    "__kasan_check_read", "__kasan_check_write",
    "rcu_read_lock", "rcu_read_unlock",
    "preempt_count_add", "preempt_count_sub",
    "check_preemption_disabled", "trace_hardirqs_on",
    "trace_hardirqs_off", "__raw_spin_lock", "__raw_spin_unlock",
})

# Strip these common prefixes/suffixes when fuzzy-comparing names
_ARCH_PREFIXES = re.compile(
    r"^(__arm64_sys_|__x64_sys_|__ia32_sys_|__se_sys_|__do_sys_)"
)


def _normalize_func_name(name: str) -> str:
    """Normalise a kernel function name for fuzzy comparison.

    Strips arch-specific syscall wrappers so that, e.g.,
    ``__arm64_sys_read`` and ``__x64_sys_read`` both become ``sys_read``.
    Also strips ``+0x…/0x…`` offset suffixes from syzbot crash lines.
    """
    # Strip offset suffix (e.g. "kfree+0x28/0x120")
    name = name.split("+")[0].strip()
    # Normalise arch wrappers
    name = _ARCH_PREFIXES.sub("sys_", name)
    return name


def match_stack_similarity(
    crash_stack: List[str],
    dynamic_stack: List[str],
    *,
    skip_inline_noise: bool = True,
    min_name_ratio: float = 0.80,
) -> Dict:
    """Compare a syzbot crash stack against a GDB dynamic trace stack.

    Both inputs are **ordered lists of function names** (deepest frame
    first, or shallowest—order just needs to be consistent between the
    two).  The function returns a similarity report.

    Algorithm:
    1. Normalise names (strip offsets, arch prefixes).
    2. Optionally filter out compiler-inlined noise symbols.
    3. Compute longest common sub-sequence (LCS) of normalised names.
    4. For each LCS pair, record exact or fuzzy match quality.
    5. Report overall similarity score and per-frame alignment.

    Args:
        crash_stack:  Function names from the syzbot/KASAN report.
        dynamic_stack: Function names captured by GDB tracing.
        skip_inline_noise: Remove known inline/sanitizer helpers before
            comparison.
        min_name_ratio: Minimum SequenceMatcher ratio to accept as a
            fuzzy match (0–1).

    Returns:
        Dict with keys:
          - similarity  (float 0–1): overall match score
          - matched_pairs: list of {crash_func, dynamic_func, quality}
          - unmatched_crash: crash funcs with no dynamic counterpart
          - unmatched_dynamic: dynamic funcs with no crash counterpart
          - lcs_length: length of longest common subsequence
    """

    def _filter(stack):
        out = []
        for f in stack:
            n = _normalize_func_name(f)
            if skip_inline_noise and n in _INLINE_NOISE:
                continue
            out.append(n)
        return out

    c_norm = _filter(crash_stack)
    d_norm = _filter(dynamic_stack)

    if not c_norm or not d_norm:
        return {
            "similarity": 0.0,
            "matched_pairs": [],
            "unmatched_crash": list(crash_stack),
            "unmatched_dynamic": list(dynamic_stack),
            "lcs_length": 0,
        }

    # --- LCS via dynamic programming ---
    m, n = len(c_norm), len(d_norm)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if c_norm[i - 1] == d_norm[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                # Allow fuzzy match to count as partial
                ratio = SequenceMatcher(None, c_norm[i - 1], d_norm[j - 1]).ratio()
                if ratio >= min_name_ratio:
                    dp[i][j] = max(dp[i - 1][j - 1] + 1, dp[i - 1][j], dp[i][j - 1])
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

    # Back-trace to recover matched pairs
    matched_pairs = []
    c_matched = set()
    d_matched = set()
    i, j = m, n
    while i > 0 and j > 0:
        if c_norm[i - 1] == d_norm[j - 1]:
            matched_pairs.append({
                "crash_func": crash_stack[i - 1] if i - 1 < len(crash_stack) else c_norm[i - 1],
                "dynamic_func": dynamic_stack[j - 1] if j - 1 < len(dynamic_stack) else d_norm[j - 1],
                "quality": "exact",
            })
            c_matched.add(i - 1)
            d_matched.add(j - 1)
            i -= 1
            j -= 1
        else:
            ratio = SequenceMatcher(None, c_norm[i - 1], d_norm[j - 1]).ratio()
            if ratio >= min_name_ratio and dp[i][j] == dp[i - 1][j - 1] + 1:
                matched_pairs.append({
                    "crash_func": crash_stack[i - 1] if i - 1 < len(crash_stack) else c_norm[i - 1],
                    "dynamic_func": dynamic_stack[j - 1] if j - 1 < len(dynamic_stack) else d_norm[j - 1],
                    "quality": f"fuzzy ({ratio:.0%})",
                })
                c_matched.add(i - 1)
                d_matched.add(j - 1)
                i -= 1
                j -= 1
            elif dp[i - 1][j] >= dp[i][j - 1]:
                i -= 1
            else:
                j -= 1

    matched_pairs.reverse()
    lcs_len = len(matched_pairs)

    # Similarity: fraction of the *shorter* stack that matched
    shorter = min(len(c_norm), len(d_norm))
    similarity = lcs_len / shorter if shorter else 0.0

    unmatched_crash = [crash_stack[i] for i in range(len(crash_stack))
                       if i not in c_matched]
    unmatched_dynamic = [dynamic_stack[j] for j in range(len(dynamic_stack))
                         if j not in d_matched]

    return {
        "similarity": round(similarity, 4),
        "matched_pairs": matched_pairs,
        "unmatched_crash": unmatched_crash,
        "unmatched_dynamic": unmatched_dynamic,
        "lcs_length": lcs_len,
    }


def extract_stack_from_crash_report(crash_text: str) -> List[str]:
    """Extract function names from a kernel crash/KASAN report.

    Parses lines like:
        ``kfree+0x28/0x120``
        ``[<ffff800080a1b2c4>] kfree+0x28/0x120``
        `` schedule+0x5c/0xd0``

    Returns an ordered list of function names (first = deepest shown).
    """
    funcs: List[str] = []
    # Matches typical kernel stack trace function entries
    pat = re.compile(
        r"(?:\[<[0-9a-fA-F]+>\]\s*)?"     # optional [<addr>]
        r"([a-zA-Z_][a-zA-Z0-9_.]+)"      # function name
        r"(?:\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+)?"  # optional +offset/size
    )
    for line in crash_text.splitlines():
        line = line.strip()
        # Must look like a stack frame (starts with space, [, or function name)
        if not line:
            continue
        m = pat.search(line)
        if m:
            func = m.group(1)
            # Skip generic frame markers
            if func in ("Call", "Trace", "Stack", "Code", "RIP", "RSP",
                         "RAX", "RBX", "RCX", "RDX"):
                continue
            funcs.append(m.group(0))  # Keep full "name+offset" for context
    return funcs


def extract_stack_from_dynamic_trace(events: List[Dict]) -> List[str]:
    """Build a function-name stack from GDB dynamic trace events.

    Expects events as exported by gdb.py: each event has a ``bt`` key with
    a list of ``{func, pc}`` dicts.  Returns the *most recent* backtrace
    for ``func_hit`` events, falling back to the last event with a ``bt``.
    """
    best_bt = None
    for ev in reversed(events):
        if ev.get("type") == "func_hit" and ev.get("bt"):
            best_bt = ev["bt"]
            break
    if best_bt is None:
        for ev in reversed(events):
            if ev.get("bt"):
                best_bt = ev["bt"]
                break
    if not best_bt:
        return []
    return [frame.get("func", "??") for frame in best_bt]


def main():
	if len(sys.argv) < 2:
		print("Usage: post_process.py <kernel_results.json> [output.json]")
		sys.exit(1)
	inp = sys.argv[1]
	outp = sys.argv[2] if len(sys.argv) > 2 else None
	res = analyze(inp, outp)
	print(json.dumps(res['summary'], indent=2))


if __name__ == '__main__':
	main()
