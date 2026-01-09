import os
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

class ChainReactor:
    def __init__(self, repo_path: Optional[str] = None) -> None:
        self.repo_path = repo_path

    def available(self) -> bool:
        return bool(self.repo_path and os.path.isdir(self.repo_path))

    def synthesize(self, spec_path: str, goal: str, outdir: str) -> Dict[str, Any]:
        """Call ChainReactor with a given spec (JSON/YAML) to produce exploit artifacts.
        This is a placeholder; expects chainreactor CLI to support a synth command.
        """
        if not self.available():
            return {"success": False, "error": "ChainReactor repo not available"}
        try:
            # Prefer invoking the submodule's solve_problem.py if present
            solve_py = Path(self.repo_path) / 'solve_problem.py'
            if solve_py.exists():
                cmd = ['python3', str(solve_py), '--goal', goal, '--spec', spec_path, '--out', outdir]
            else:
                # Fallback to module invocation if package is importable
                cmd = ['python3', '-m', 'chainreactor', '--goal', goal, '--spec', spec_path, '--out', outdir]
            env = os.environ.copy()
            # Ensure the submodule is importable when using -m
            env['PYTHONPATH'] = os.pathsep.join([self.repo_path, env.get('PYTHONPATH', '')])
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
            return {
                "success": proc.returncode == 0,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "outdir": outdir,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
