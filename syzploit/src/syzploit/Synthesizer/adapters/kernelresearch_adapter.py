import os
import subprocess
from typing import List, Dict, Any, Optional
from ..core import Primitive, PrimitiveRegistry

class KernelResearchAdapter:
    def __init__(self, repo_path: Optional[str] = None) -> None:
        self.repo_path = repo_path

    def available(self) -> bool:
        return bool(self.repo_path and os.path.isdir(self.repo_path))

    def list_primitives(self, registry: PrimitiveRegistry) -> List[Primitive]:
        prims: List[Primitive] = []
        # Heuristic: expose common ROP actions as primitives
        actions = [
            "commit_creds_prepare_kernel_cred",
            "switch_task_namespaces",
            "write_what_where_64",
            "fork",
            "telefork",
            "ret_to_user",
        ]
        for a in actions:
            p = Primitive(name=f"xdk_{a}", description=f"kernelXDK action {a}")
            registry.add(p)
            prims.append(p)
        return prims

    def generate_rop_chain(self, vmlinux: str, vmlinuz: Optional[str] = None) -> Optional[str]:
        """If rop_generator is present, generate a ROP chain and return path to output JSON/text."""
        if not self.available():
            return None
        script = os.path.join(self.repo_path, 'rop_generator', 'angrop_rop_generator.py')
        if not os.path.exists(script):
            return None
        try:
            with subprocess.Popen(['python3', script, vmlinux] + ([vmlinuz] if vmlinuz else []),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
                out, err = proc.communicate(timeout=120)
                # Write output to tmp file
                out_path = os.path.join(os.getcwd(), 'outdir', 'generated_rop.txt')
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, 'w') as f:
                    f.write(out)
                return out_path
        except Exception:
            return None
