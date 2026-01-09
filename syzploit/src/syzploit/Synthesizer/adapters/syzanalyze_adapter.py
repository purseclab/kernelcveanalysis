import json
import os
from typing import Dict, Any, List
from ..core import Primitive, PrimitiveRegistry


def load_from_analysis(analysis_dir: str, registry: PrimitiveRegistry) -> List[Primitive]:
    """Load primitives inferred by SyzAnalyze from analysis outputs.
    Expects files like static_analysis.json and dynamic_analysis.json in analysis_dir.
    """
    prims: List[Primitive] = []
    static_path = os.path.join(analysis_dir, 'static_analysis.json')
    dynamic_path = os.path.join(analysis_dir, 'dynamic_analysis.json')

    for path in (static_path, dynamic_path):
        if not os.path.exists(path):
            continue
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            # Heuristics: map findings to generic primitives
            # Example: use-after-free -> primitive 'uaf_arbitrary_write' or 'uaf_kref'
            crash_type = data.get('crash_type') or data.get('type')
            if crash_type and isinstance(crash_type, str):
                name = crash_type.lower().replace(' ', '_')
                prim = Primitive(
                    name=f"syz_{name}",
                    description=f"Primitive derived from SyzAnalyze: {crash_type}",
                    requirements={},
                    provides={"bug_type": crash_type}
                )
                registry.add(prim)
                prims.append(prim)
        except Exception:
            continue
    return prims
