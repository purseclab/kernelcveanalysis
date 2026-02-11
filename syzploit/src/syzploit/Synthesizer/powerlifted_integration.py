"""
chainreactor_integration.py

Direct integration with powerlifted planner, borrowing patterns from chainreactor.
This module provides the PowerliftedSolver class that directly invokes the powerlifted
planner without relying on external wrapper scripts.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List

from ..utils.debug import debug_print


def plpl_debug(msg: str, debug: bool = True):
    """Print debug message if debug is enabled."""
    debug_print("PowerliftedSolver", msg, debug)


class PowerliftedSolver:
    """
    Direct interface to the powerlifted PDDL planner.
    
    This solver can use either:
    1. A standalone 'powerlifted' binary on PATH
    2. The powerlifted Python driver in src/powerlifted
    """
    
    # Default search configuration from chainreactor (IPC2023 satisficing track)
    DEFAULT_ITERATION = "alt-bfws1,rff,yannakakis,476"
    DEFAULT_TIME_LIMIT = 1800  # 30 minutes
    
    def __init__(self, powerlifted_path: Optional[str] = None, debug: bool = False) -> None:
        """
        Initialize the solver.
        
        Args:
            powerlifted_path: Path to powerlifted installation. If None, tries to
                              find powerlifted on PATH or in src/powerlifted.
            debug: Enable debug output
        """
        self.powerlifted_path = powerlifted_path
        self.debug = debug
        self._powerlifted_binary: Optional[str] = None
        self._powerlifted_driver: Optional[Path] = None
        self._detect_powerlifted()
    
    def _detect_powerlifted(self) -> None:
        """Detect available powerlifted installation."""
        pl_debug("Detecting powerlifted...", self.debug)
        
        # Try standalone binary first
        binary = shutil.which('powerlifted')
        if binary:
            pl_debug(f"Found powerlifted binary on PATH: {binary}", self.debug)
            self._powerlifted_binary = binary
            return
        pl_debug("powerlifted not found on PATH", self.debug)
        
        # Try provided path
        if self.powerlifted_path:
            path = Path(self.powerlifted_path)
            pl_debug(f"Checking provided path: {path}", self.debug)
            if path.is_file() and path.name == 'powerlifted.py':
                pl_debug(f"Found powerlifted.py at provided path", self.debug)
                self._powerlifted_driver = path
                return
            driver = path / 'powerlifted.py'
            if driver.exists():
                pl_debug(f"Found powerlifted.py in provided directory: {driver}", self.debug)
                self._powerlifted_driver = driver
                return
        
        # Try to find in src/powerlifted relative to this file
        try:
            src_root = Path(__file__).resolve().parents[2]  # src/syzploit/Synthesizer -> src
            driver = src_root / 'powerlifted' / 'powerlifted.py'
            pl_debug(f"Checking relative path: {driver}", self.debug)
            if driver.exists():
                pl_debug(f"Found powerlifted.py at: {driver}", self.debug)
                self._powerlifted_driver = driver
                return
        except Exception as e:
            pl_debug(f"Error checking relative path: {e}", self.debug)
        
        pl_debug("powerlifted not found anywhere", self.debug)
    
    def available(self) -> bool:
        """Check if powerlifted is available."""
        return self._powerlifted_binary is not None or self._powerlifted_driver is not None
    
    def _build_command(self, domain: str, problem: str, 
                       plan_file: str = "plan",
                       iteration: Optional[str] = None,
                       time_limit: Optional[int] = None,
                       unit_cost: bool = True,
                       preprocess_task: bool = True,
                       only_effects_novelty_check: bool = True,
                       stop_after_first: bool = False) -> List[str]:
        """
        Build the powerlifted command line.
        
        Args:
            domain: Path to domain PDDL file
            problem: Path to problem PDDL file
            plan_file: Output plan file name
            iteration: Search iteration spec (search,evaluator,generator,time_pct)
            time_limit: Time limit in seconds
            unit_cost: Treat actions as unit cost
            preprocess_task: Preprocess PDDL to STRIPS-like
            only_effects_novelty_check: Novelty check only on effect atoms
            stop_after_first: Stop after finding first plan (False = find all plans)
        """
        iteration = iteration or self.DEFAULT_ITERATION
        time_limit = time_limit or self.DEFAULT_TIME_LIMIT
        
        if self._powerlifted_binary:
            cmd = [self._powerlifted_binary]
        else:
            cmd = ['python3', str(self._powerlifted_driver)]
        
        cmd.extend([
            '--iteration', iteration,
            '--time-limit', str(time_limit),
            '-d', domain,
            '-i', problem,
            '--plan-file', plan_file,
        ])
        
        if unit_cost:
            cmd.append('--unit-cost')
        if preprocess_task:
            cmd.append('--preprocess-task')
        if only_effects_novelty_check:
            cmd.append('--only-effects-novelty-check')
        if stop_after_first:
            cmd.append('--stop-after-first-plan')
        
        return cmd
    
    def solve(self, domain_path: str, problem_path: str, 
              output_dir: str,
              iteration: Optional[str] = None,
              time_limit: Optional[int] = None,
              verbose: bool = False,
              debug: bool = None,
              stop_after_first: bool = False) -> Dict[str, Any]:
        """
        Solve a PDDL planning problem.
        
        Args:
            domain_path: Path to domain PDDL file
            problem_path: Path to problem PDDL file
            output_dir: Directory to store plan files
            iteration: Search iteration spec
            time_limit: Time limit in seconds
            verbose: Print solver output in real-time
            debug: Enable debug output (defaults to self.debug)
            stop_after_first: Stop after first plan (False = find all plans)
            
        Returns:
            Dictionary with success status, plan files, and output
        """
        if debug is None:
            debug = self.debug
            
        pl_debug(f"solve() called", debug)
        pl_debug(f"  domain_path: {domain_path}", debug)
        pl_debug(f"  problem_path: {problem_path}", debug)
        pl_debug(f"  output_dir: {output_dir}", debug)
        pl_debug(f"  time_limit: {time_limit}", debug)
        pl_debug(f"  stop_after_first: {stop_after_first}", debug)
        
        if not self.available():
            pl_debug("Powerlifted not available!", debug)
            return {
                "success": False,
                "error": "Powerlifted planner not available",
                "hint": "Install powerlifted or add src/powerlifted to your workspace"
            }
        
        # Validate inputs - convert to absolute paths since cwd changes
        domain_path = os.path.abspath(domain_path)
        problem_path = os.path.abspath(problem_path)
        output_dir = os.path.abspath(output_dir)
        
        if not os.path.isfile(domain_path):
            pl_debug(f"Domain file not found: {domain_path}", debug)
            return {"success": False, "error": f"Domain file not found: {domain_path}"}
        if not os.path.isfile(problem_path):
            pl_debug(f"Problem file not found: {problem_path}", debug)
            return {"success": False, "error": f"Problem file not found: {problem_path}"}
        
        pl_debug(f"Input files validated", debug)
        os.makedirs(output_dir, exist_ok=True)
        
        # Build command (stop_after_first=False by default to find ALL plans)
        plan_file = os.path.join(output_dir, "plan")
        cmd = self._build_command(
            domain=domain_path,
            problem=problem_path,
            plan_file=plan_file,
            iteration=iteration,
            time_limit=time_limit,
            stop_after_first=stop_after_first
        )
        pl_debug(f"Command: {' '.join(cmd)}", debug)
        
        # Run solver
        all_output = []
        try:
            pl_debug("Starting solver subprocess...", debug)
            if verbose:
                # Stream output in real-time
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    cwd=output_dir,
                    universal_newlines=True
                )
                
                while True:
                    line = process.stdout.readline()
                    if line == '' and process.poll() is not None:
                        break
                    if line:
                        line = line.rstrip()
                        all_output.append(line)
                        print(line, flush=True)
                
                returncode = process.returncode
            else:
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    cwd=output_dir,
                    text=True
                )
                all_output = result.stdout.split('\n') if result.stdout else []
                returncode = result.returncode
            
            pl_debug(f"Solver finished with returncode: {returncode}", debug)
            output_text = '\n'.join(all_output)
            
            # Check for solution
            solution_found = "solution found" in output_text.lower()
            pl_debug(f"Solution found: {solution_found}", debug)
            
            # Collect generated plan files
            # Plan files are named: plan, plan.1, plan.2, etc.
            # The suffix .1 is treated as a suffix by Path, so we check the stem instead
            plans = []
            for f in Path(output_dir).glob('plan*'):
                if f.is_file():
                    # Accept files like 'plan', 'plan.1', 'plan.2', etc.
                    # Exclude 'plan.txt', 'plan.pddl', etc.
                    name = f.name
                    if name == 'plan' or (name.startswith('plan.') and name[5:].isdigit()):
                        plans.append(str(f))
            # Sort plans by number (plan, plan.1, plan.2, etc.)
            plans.sort(key=lambda x: (0 if x.endswith('/plan') or x.endswith('\\plan') else int(Path(x).suffix[1:])))
            pl_debug(f"Plan files found: {plans}", debug)
            
            # Success if solution found (returncode may be non-zero but that's ok if solution found)
            return {
                "success": solution_found and len(plans) > 0,
                "returncode": returncode,
                "plans": plans,
                "stdout": output_text,
                "output_dir": output_dir,
                "domain": domain_path,
                "problem": problem_path,
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "domain": domain_path,
                "problem": problem_path,
            }
    
    def parse_plan(self, plan_path: str) -> List[Dict[str, Any]]:
        """
        Parse a plan file into structured actions.
        
        Args:
            plan_path: Path to plan file
            
        Returns:
            List of action dictionaries with name and parameters
        """
        import re
        
        actions = []
        if not os.path.isfile(plan_path):
            return actions
        
        with open(plan_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(';'):
                    continue
                
                # Parse powerlifted plan format: "N: (action-name param1 param2 ) ;[created objects: ]"
                # Also handles standard PDDL format: "(action-name param1 param2)"
                
                # Remove step number prefix like "1: " if present
                if re.match(r'^\d+:\s*', line):
                    line = re.sub(r'^\d+:\s*', '', line)
                
                # Remove trailing comments like ";[created objects: ]" or "; cost = N"
                if ';' in line:
                    line = line.split(';')[0].strip()
                
                # Now parse the action: (action-name param1 param2 ...)
                if line.startswith('('):
                    # Find the matching closing paren
                    if ')' in line:
                        action_str = line[:line.index(')')+1]
                        parts = action_str[1:-1].split()
                        if parts:
                            actions.append({
                                "action": parts[0],
                                "parameters": parts[1:] if len(parts) > 1 else []
                            })
        
        return actions
