import json
import os
from typing import Dict, Any, List
from ..core import Primitive, PrimitiveRegistry


def load_from_analysis(analysis_dir: str, registry: PrimitiveRegistry) -> List[Primitive]:
    """Load primitives inferred by SyzAnalyze from analysis outputs.
    Expects files like static_analysis.json and dynamic_analysis.json in analysis_dir.
    Produces primitives with provides.caps to drive PDDL generation.
    """
    prims: List[Primitive] = []
    static_path = os.path.join(analysis_dir, 'static_analysis.json')
    dynamic_path = os.path.join(analysis_dir, 'dynamic_analysis.json')

    def _caps_for_vuln(vuln: str) -> List[str]:
        v = (vuln or '').lower()
        caps: List[str] = []
        if 'use-after-free' in v or 'uaf' in v:
            caps += ['CAP_CVE_write_any_file', 'CAP_CVE_read_any_file']
        if 'shell' in v and 'inject' in v:
            caps += ['CAP_cve_shell_command_injection']
        return caps

    for path in (static_path, dynamic_path):
        if not os.path.exists(path):
            continue
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            # Prefer detailed classification from parsed section
            vuln = None
            try:
                vuln = data.get('parsed', {}).get('classification', {}).get('vulnerability')
            except Exception:
                pass
            # Fallbacks
            crash_type = data.get('crash_type') or data.get('type') or vuln
            if crash_type and isinstance(crash_type, str):
                name = crash_type.lower().strip().replace(' ', '_')
                caps = _caps_for_vuln(crash_type)
                prim = Primitive(
                    name=f"syz_{name}",
                    description=f"Primitive derived from SyzAnalyze: {crash_type}",
                    requirements={},
                    provides={"bug_type": crash_type, "caps": caps}
                )
                registry.add(prim)
                prims.append(prim)
        except Exception:
            continue
    return prims
