import os
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

class ChainReactor:
    def __init__(self, repo_path: Optional[str] = None) -> None:
        self.repo_path = repo_path

    def available(self) -> bool:
        return bool(self.repo_path and os.path.isdir(self.repo_path))

    def solve_with_pddl(self, domain_path: str, problem_path: str, outdir: str) -> Dict[str, Any]:
        """Run ChainReactor's planner with domain/problem PDDL using solve_problem.py.
        Requires the external planner `powerlifted` to be available on PATH.
        """
        if not self.available():
            return {"success": False, "error": "ChainReactor repo not available"}
        try:
            solve_py = Path(self.repo_path) / 'solve_problem.py'
            if not solve_py.exists():
                return {"success": False, "error": "solve_problem.py not found in ChainReactor repo"}
            cmd = ['python3', str(solve_py.resolve()), '-d', domain_path, '-p', problem_path]
            env = os.environ.copy()
            # Proactively detect missing external planner
            try:
                import shutil
                if shutil.which('powerlifted') is None:
                    return {
                        "success": False,
                        "error": "External planner 'powerlifted' not found on PATH",
                        "hint": "Install powerlifted or add it to PATH. See chainreactor README or IPC2023 docs.",
                        "command": "powerlifted --iteration alt-bfws1,rff,yannakakis,476 ...",
                        "domain": domain_path,
                        "problem": problem_path,
                    }
            except Exception:
                pass
            # Run without changing cwd to avoid path duplication bugs
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
            # collect generated plan files in repo_path (plan.*)
            plans = []
            try:
                for p in Path(self.repo_path).glob('plan*'):
                    plans.append(str(p))
                    # copy plan into outdir for convenient re-run
                    try:
                        import shutil
                        shutil.copy2(str(p), outdir)
                    except Exception:
                        pass
            except Exception:
                pass
            return {
                "success": proc.returncode == 0,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "outdir": outdir,
                "plans": plans,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
