import json
import sys
import os
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
	if et not in ('watch', 'uaf_watch', 'rip'):
		return None

	# Determine effective address
	ea = _parse_int(ev.get('ea'))
	if ea is None:
		expr = ev.get('expr')
		if isinstance(expr, str) and expr:
			import re
			m = re.search(r"0x[0-9a-fA-F]+", expr)
			if m:
				try:
					ea = int(m.group(0), 16)
				except Exception:
					ea = None
	if ea is None:
		return None

	# UAF detection
	if et == 'uaf_watch':
		return {'class': 'uaf', 'ea': ea}
	free_t = freed_times.get(ea)
	ev_t = ev.get('time')
	if free_t is not None and isinstance(ev_t, (int, float)):
		if ev_t >= free_t:
			return {'class': 'uaf', 'ea': ea}
		else:
			return {'class': 'pre-free-access', 'ea': ea}

	# Bounds classification
	for lo, hi, meta in allocs:
		if lo <= ea < hi:
			return {'class': 'in-bounds', 'ea': ea, 'alloc': {'addr': meta.get('addr', lo), 'size': meta.get('size', hi - lo)}}
	return {'class': 'invalid-access', 'ea': ea}


def analyze(input_path: str, output_path: Optional[str] = None) -> Dict:
	data = _load_json(input_path)
	allocs = _alloc_ranges(data)
	freed_times = _freed_ptrs_with_time(data)
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
				'rip': ev.get('rip'),
				'ptid': ev.get('ptid'),
				'insn': ev.get('insn')
			}
			if 'alloc' in cls:
				rec['alloc'] = cls['alloc']
			results['classifications'].append(rec)

	counters = {'uaf': 0, 'invalid-access': 0, 'in-bounds': 0, 'pre-free-access': 0}
	for c in results['classifications']:
		counters[c['class']] = counters.get(c['class'], 0) + 1
	results['summary'].update(counters)

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

	# Double-free detection
	free_hist: Dict[int, List[float]] = {}
	for rec in data.get('frees_detailed', []):
		addr = _parse_int(rec.get('ptr'))
		t = rec.get('time')
		if addr is None or not isinstance(t, (int, float)):
			continue
		free_hist.setdefault(addr, []).append(t)
	double_frees = [hex(ptr) for ptr, times in free_hist.items() if len(times) > 1]
	results['summary']['double_free_count'] = len(double_frees)
	if double_frees:
		results['vulnerabilities_detected'].append({'type': 'double-free', 'ptrs': double_frees})

	# Invalid free detection
	allocated_ptrs = set(a for a, _, _ in allocs)
	invalid_frees = [hex(ptr) for ptr in freed_times.keys() if ptr not in allocated_ptrs]
	results['summary']['invalid_free_count'] = len(invalid_frees)
	if invalid_frees:
		results['vulnerabilities_detected'].append({'type': 'invalid-free', 'ptrs': invalid_frees})

	# Confidence scoring
	score = 0
	score += 40 if counters.get('uaf', 0) > 0 else 0
	score += 20 if results['summary']['double_free_count'] > 0 else 0
	score += 10 if results['summary']['invalid_free_count'] > 0 else 0
	score += 10 if counters.get('invalid-access', 0) > 0 else 0
	score += min(20, results['summary']['alloc_count']) // 5
	results['confidence'] = min(100, score)

	if counters.get('uaf', 0) > 0:
		results['vulnerabilities_detected'].append({'type': 'use-after-free', 'count': counters['uaf']})
	if counters.get('invalid-access', 0) > 0:
		results['vulnerabilities_detected'].append({'type': 'invalid-access', 'count': counters['invalid-access']})

	if output_path is None:
		base = os.path.splitext(os.path.basename(input_path))[0]
		output_path = os.path.join(os.path.dirname(input_path), f"{base}_analysis.json")
	_save_json(output_path, results)
	return results


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
