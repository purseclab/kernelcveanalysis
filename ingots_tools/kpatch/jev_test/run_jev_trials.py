# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "requests",
# ]
# ///

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from test_jev import DecisionQuestion, JevAnswer, jev_request


SAMPLES_DIRECTORY = Path("jev_samples")
DEFAULT_MANIFEST = SAMPLES_DIRECTORY / "manifest.json"
DEFAULT_OUTPUT = Path("jev_trial_results.json")

QUESTIONS: dict[str, DecisionQuestion] = {
    "is_vuln": {
        "type": "noul",
        "instructions": (
            "Does this code contain a security vulnerability under the API, "
            "attacker-control, and concurrency assumptions stated in its comments?"
        ),
        "criteria": {
            "true": "A plausibly exploitable security bug is present",
            "false": "No security-relevant bug is present",
        },
    },
    "primary_issue": {
        "type": "choice",
        "instructions": (
            "What is the primary root-cause category of the security assessment?"
        ),
        "criteria": {
            "memory_safety": "A bounds error directly violates memory safety",
            "lifetime_or_race": (
                "A concurrency, object lifetime, double-fetch, or general "
                "time-of-check/time-of-use flaw exists"
            ),
            "integer_error": (
                "Integer conversion or arithmetic creates a security issue"
            ),
            "injection": (
                "Untrusted data alters command, shell, or format interpretation"
            ),
            "authorization": (
                "Authorization is checked against the wrong principal or object"
            ),
            "path_resolution": (
                "Path traversal, symlink handling, or path-resolution timing "
                "creates a security issue"
            ),
            "information_disclosure": (
                "Uninitialized or unintended data can be disclosed"
            ),
            "none": "No security-relevant bug is present",
        },
    },
}


@dataclass(frozen=True)
class TrialDefinition:
    id: str
    file: str
    expected_vulnerable: bool
    expected_issue: str
    pair: str
    rationale: str


@dataclass(frozen=True)
class TrialResult:
    id: str
    file: str
    pair: str
    expected_vulnerable: bool
    expected_issue: str
    rationale: str
    vulnerability_score: float
    predicted_vulnerable: bool
    predicted_issue: str
    issue_confidence: float
    binary_correct: bool
    issue_correct: bool
    raw_answers: dict[str, JevAnswer]


def load_manifest(path: Path) -> list[TrialDefinition]:
    manifest_data = json.loads(path.read_text(encoding="utf-8"))
    return [TrialDefinition(**entry) for entry in manifest_data]


def run_trial(definition: TrialDefinition, samples_directory: Path) -> TrialResult:
    source = (samples_directory / definition.file).read_text(encoding="utf-8")
    answers = jev_request(source, QUESTIONS)
    vulnerability_answer = answers["is_vuln"]
    issue_answer = answers["primary_issue"]
    vulnerability_score = float(vulnerability_answer["noul"])
    predicted_vulnerable = vulnerability_score >= 0.5
    predicted_issue = str(issue_answer["choice"])
    issue_confidence = float(issue_answer["confidence"])

    return TrialResult(
        id=definition.id,
        file=definition.file,
        pair=definition.pair,
        expected_vulnerable=definition.expected_vulnerable,
        expected_issue=definition.expected_issue,
        rationale=definition.rationale,
        vulnerability_score=vulnerability_score,
        predicted_vulnerable=predicted_vulnerable,
        predicted_issue=predicted_issue,
        issue_confidence=issue_confidence,
        binary_correct=predicted_vulnerable == definition.expected_vulnerable,
        issue_correct=predicted_issue == definition.expected_issue,
        raw_answers=answers,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run JEV over paired C samples")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    definitions = load_manifest(args.manifest)
    results: list[TrialResult] = []

    for definition in definitions:
        result = run_trial(definition, args.manifest.parent)
        results.append(result)
        verdict = "PASS" if result.binary_correct else "FAIL"
        print(
            f"{result.id}: score={result.vulnerability_score:.2f} "
            f"issue={result.predicted_issue} {verdict}",
            flush=True,
        )

    payload = {
        "model": "~typesafe/jev-latest",
        "threshold": 0.5,
        "questions": QUESTIONS,
        "results": [asdict(result) for result in results],
    }
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    binary_correct = sum(result.binary_correct for result in results)
    issue_correct = sum(result.issue_correct for result in results)
    print(f"binary: {binary_correct}/{len(results)}")
    print(f"issue:  {issue_correct}/{len(results)}")


if __name__ == "__main__":
    main()
