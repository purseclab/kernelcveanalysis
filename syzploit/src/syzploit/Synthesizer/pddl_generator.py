from pathlib import Path
from typing import List, Dict, Any, Optional
from .core import Primitive

class PDDLGenerator:
    """Generate ChainReactor problem PDDL from primitives and target info.
    This keeps domain static (chainreactor/domain.pddl) and emits a problem with
    objects + init predicates derived from adapter-provided grammar facts.
    """

    def __init__(self, chainreactor_root: str, analysis_dir: Optional[str] = None) -> None:
        self.chainreactor_root = Path(chainreactor_root) if chainreactor_root else None
        self.analysis_dir = Path(analysis_dir) if analysis_dir else None

    def _default_objects(self) -> Dict[str, List[str]]:
        return {
            'user': ['attacker', 'root'],
            'group': ['g_attacker', 'g_root'],
            'executable': ['writer', 'target_exec'],
            'file': ['writer', 'target_exec', 'target_file'],
            'directory': ['target_dir'],
            'process': ['proc'],
            'data': ['SHELL', 'data'],
            'local': ['local'],
            'remote': ['remote'],
            'permission': ['FS_READ', 'FS_WRITE', 'FS_EXEC'],
            'purpose': ['SYSFILE_PASSWD'],
        }

    def _header(self, problem_name: str) -> List[str]:
        return [f"(define (problem {problem_name})", "  (:domain micronix)"]

    def _objects(self, objs: Dict[str, List[str]]) -> List[str]:
        lines = ["  (:objects"]
        # group similar types into one line when possible
        lines.append("    " + " ".join(objs['user']) + " - user")
        lines.append("    " + " ".join(objs['group']) + " - group")
        lines.append("    " + " ".join(objs['executable']) + " - executable")
        lines.append("    " + " ".join(objs['file']) + " - file")
        lines.append("    " + " ".join(objs['directory']) + " - directory")
        lines.append("    " + " ".join(objs['process']) + " - process")
        lines.append("    " + " ".join(objs['data']) + " - data")
        lines.append("    " + " ".join(objs['local']) + " - local")
        lines.append("    " + " ".join(objs['remote']) + " - remote")
        lines.append("    " + " ".join(objs['permission']) + " - permission")
        lines.append("    " + " ".join(objs['purpose']) + " - purpose")
        lines.append("  )")
        return lines

    def _init_base(self, objs: Dict[str, List[str]]) -> List[str]:
        lines = ["  (:init"]
        # base relationships: attacker group, root group
        lines.append("    (user_group attacker g_attacker)")
        lines.append("    (user_group root g_root)")
        lines.append("    (controlled_user attacker)")
        # writer executable owned by attacker; attacker can execute writer
        lines.append("    (file_owner writer attacker g_attacker)")
        lines.append("    (user_file_permission attacker writer FS_EXEC)")
        lines.append("    (system_executable writer)")
        # target exec/file owned by root
        lines.append("    (file_owner target_exec root g_root)")
        lines.append("    (file_present_at_location target_exec local)")
        lines.append("    (file_owner target_file root g_root)")
        lines.append("    (file_present_at_location target_file local)")
        # passwd purpose example
        lines.append("    (file_purpose target_file SYSFILE_PASSWD)")
        return lines

    def _goal(self, goal: str) -> List[str]:
        if 'root' in goal or 'priv' in goal:
            return ["  (:goal (controlled_user root))", ")"]
        return ["  (:goal (controlled_user attacker))", ")"]

    def _cap_facts_from_primitives(self, primitives: List[Primitive]) -> List[str]:
        caps_facts: List[str] = []
        # Gather caps from primitive provides
        for p in primitives:
            prov = p.provides or {}
            # single cap
            cap = prov.get('cap')
            if isinstance(cap, str) and cap:
                caps_facts.append(f"    ({cap} writer)")
            # multiple caps
            caps = prov.get('caps') or []
            for c in caps:
                if isinstance(c, str) and c:
                    caps_facts.append(f"    ({c} writer)")
        # Heuristics (still keep simple fallbacks)
        names = {p.name for p in primitives}
        if any(n.startswith('xdk_') for n in names):
            caps_facts.append("    (CAP_command writer)")
        return caps_facts

    def _facts_from_static(self) -> List[str]:
        facts: List[str] = []
        if not self.analysis_dir:
            return facts
        static_path = self.analysis_dir / 'static_analysis.json'
        if not static_path.exists():
            return facts
        try:
            import json, re
            data = json.loads(static_path.read_text())
            # Syscalls observed
            raw = (data.get('parsed', {}) or {}).get('raw', '')
            # Look for explicit syscall list lines
            # e.g., "Syscall(s) detected in crash text: close, creat, open"
            support = (data.get('classification', {}) or {}).get('support', [])
            line = None
            for s in support or []:
                if isinstance(s, str) and 'Syscall(s) detected' in s:
                    line = s
                    break
            syscalls: List[str] = []
            if line:
                m = re.search(r':\s*([A-Za-z_,\s]+)$', line)
                if m:
                    syscalls = [x.strip().lower() for x in m.group(1).split(',') if x.strip()]
            else:
                # Fallback: scan raw text
                for m in re.finditer(r"__x64_sys_([a-z0-9_]+)", raw):
                    syscalls.append(m.group(1).lower())
            # Map to capabilities
            for sc in set(syscalls):
                if sc in {'open', 'stat', 'read'}:
                    facts.append("    (CAP_read_file writer)")
                if sc in {'creat', 'write', 'chmod', 'chown', 'truncate', 'close'}:
                    facts.append("    (CAP_write_file writer)")
            return facts
        except Exception:
            return facts

    def generate_problem(self, problem_name: str, primitives: List[Primitive], out_path: str, goal: str) -> str:
        objs = self._default_objects()
        lines: List[str] = []
        lines += self._header(problem_name)
        lines += self._objects(objs)
        init = self._init_base(objs)
        init += self._cap_facts_from_primitives(primitives)
        init += self._facts_from_static()
        init.append("  )")
        lines += init
        lines += self._goal(goal)
        content = "\n".join(lines) + "\n"
        out_file = Path(out_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(content)
        return str(out_file)

    def domain_path(self) -> str:
        if not self.chainreactor_root:
            raise RuntimeError("ChainReactor root unset")
        d = self.chainreactor_root / 'domain.pddl'
        if not d.exists():
            raise FileNotFoundError(f"Domain not found at {d}")
        return str(d)
