"""
app_decision — LLM-driven decision making for app security analysis.

Decides which tool to run next based on current findings:
    - What areas need deeper analysis?
    - Which vulnerabilities are most exploitable?
    - Should we fuzz, hook, or capture traffic?
    - When to stop and generate the final report?
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


# ── Decision Prompt ──────────────────────────────────────────────────

APP_DECISION_PROMPT = """You are an Android app security analyst agent.

Based on the current analysis state, decide which action to take next.

Available actions:
{actions}

Current state:
{state}

Previous actions taken:
{history}

Findings so far:
{findings}

Rules:
1. ALWAYS analyze the APK first if not done yet
2. Test exported components early — they're the primary attack surface
3. Generate exploits for HIGH/CRITICAL vulnerabilities
4. Fuzz components that accept user input
5. Capture traffic if the app has INTERNET permission
6. Verify exploits before marking them successful
7. Stop when all HIGH/CRITICAL vulns have been tested
8. If a component crashes during fuzzing, that's a potential vulnerability — investigate further

Respond with ONLY a JSON object:
{{"action": "<action_name>", "reason": "<brief reason>", "params": {{}}}}
"""


# ── Available Actions ────────────────────────────────────────────────

AVAILABLE_ACTIONS = {
    "analyze_apk": "Parse APK manifest, permissions, components, and run initial vulnerability checks",
    "scan_source": "Scan decompiled source code for vulnerability patterns (static analysis)",
    "test_intents": "Test all exported components by sending crafted intents",
    "generate_exploits": "Generate exploit scripts for discovered vulnerabilities",
    "fuzz_components": "Fuzz exported components with malformed inputs",
    "capture_traffic": "Monitor app's network traffic for cleartext/API keys",
    "verify_exploits": "Run and verify generated exploit scripts on device",
    "hook_crypto": "Use Frida to hook crypto operations and extract keys",
    "hook_ssl": "Use Frida to bypass SSL pinning for traffic interception",
    "inspect_webview": "Use Frida to inspect WebView security (JS interfaces, URLs)",
    "analyze_hybrid": "Identify hybrid app→kernel exploit chains",
    "generate_report": "Stop analysis and generate the final security report",
}


def format_actions() -> str:
    """Format available actions for the prompt."""
    return "\n".join(f"- {name}: {desc}" for name, desc in AVAILABLE_ACTIONS.items())


def format_state(state: Dict[str, Any]) -> str:
    """Format current analysis state for the prompt."""
    lines = []
    if state.get("package_name"):
        lines.append(f"Package: {state['package_name']}")
    if state.get("apk_analyzed"):
        lines.append("APK: analyzed ✓")
    else:
        lines.append("APK: not analyzed yet")
    lines.append(f"Vulnerabilities found: {state.get('vuln_count', 0)}")
    lines.append(f"  Critical: {state.get('critical_count', 0)}")
    lines.append(f"  High: {state.get('high_count', 0)}")
    lines.append(f"Exported components: {state.get('exported_count', 0)}")
    lines.append(f"Intents tested: {state.get('intents_tested', False)}")
    lines.append(f"Exploits generated: {state.get('exploits_generated', 0)}")
    lines.append(f"Exploits verified: {state.get('exploits_verified', 0)}")
    lines.append(f"Fuzzing done: {state.get('fuzzing_done', False)}")
    lines.append(f"Traffic captured: {state.get('traffic_done', False)}")
    if state.get("kernel_cve"):
        lines.append(f"Kernel CVE available: {state['kernel_cve']}")
        lines.append(f"Hybrid chains identified: {state.get('hybrid_chains', 0)}")
    return "\n".join(lines)


def decide_next_action(
    state: Dict[str, Any],
    history: List[str],
    findings: str = "",
    cfg: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Use LLM to decide the next action, or use rule-based fallback.

    Returns: {"action": str, "reason": str, "params": dict}
    """
    # Try LLM decision
    if cfg:
        try:
            return _llm_decide(state, history, findings, cfg)
        except Exception:
            pass

    # Rule-based fallback (no LLM needed)
    return _rule_based_decide(state, history)


def _llm_decide(
    state: Dict[str, Any],
    history: List[str],
    findings: str,
    cfg: Any,
) -> Dict[str, Any]:
    """LLM-powered decision making."""
    from ..core.llm import LLMClient

    prompt = APP_DECISION_PROMPT.format(
        actions=format_actions(),
        state=format_state(state),
        history="\n".join(f"  {i+1}. {h}" for i, h in enumerate(history[-10:])),
        findings=findings[:2000] if findings else "None yet",
    )

    client = LLMClient(cfg)
    response = client.query(prompt)

    # Parse JSON response
    text = response.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
    if text.startswith("json"):
        text = text[4:]

    return json.loads(text.strip())


def _rule_based_decide(
    state: Dict[str, Any],
    history: List[str],
) -> Dict[str, Any]:
    """Deterministic rule-based decision making (zero LLM cost)."""
    done_actions = set(history)

    # Priority 1: Must analyze APK first
    if not state.get("apk_analyzed"):
        return {"action": "analyze_apk", "reason": "APK not yet analyzed", "params": {}}

    # Priority 2: Test exported components
    if not state.get("intents_tested") and state.get("exported_count", 0) > 0:
        return {"action": "test_intents", "reason": "Exported components not tested", "params": {}}

    # Priority 3: Generate exploits for found vulns
    if (state.get("vuln_count", 0) > 0 and
            state.get("exploits_generated", 0) == 0):
        return {"action": "generate_exploits",
                "reason": f"{state['vuln_count']} vulns need exploit scripts", "params": {}}

    # Priority 4: Fuzz if not done and components available
    if not state.get("fuzzing_done") and state.get("exported_count", 0) > 0:
        return {"action": "fuzz_components", "reason": "IPC interfaces not fuzzed", "params": {}}

    # Priority 5: Capture traffic
    if not state.get("traffic_done"):
        return {"action": "capture_traffic", "reason": "Network traffic not analyzed", "params": {}}

    # Priority 6: Verify exploits
    if (state.get("exploits_generated", 0) > 0 and
            state.get("exploits_verified", 0) == 0):
        return {"action": "verify_exploits", "reason": "Exploits generated but not verified",
                "params": {}}

    # Priority 7: Hybrid analysis if kernel CVE available
    if state.get("kernel_cve") and not state.get("hybrid_done"):
        return {"action": "analyze_hybrid",
                "reason": f"Kernel CVE {state['kernel_cve']} available for hybrid chain",
                "params": {}}

    # Priority 8: Done
    return {"action": "generate_report", "reason": "All analysis steps complete", "params": {}}
