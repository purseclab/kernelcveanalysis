import os
from dataclasses import dataclass
from typing import Any, Literal, Mapping, Sequence, TypeAlias

import requests  # type: ignore[import-untyped]


# ---------------------------------------------------------------------------
# Questions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NoulQuestion:
    name: str
    instructions: str
    true_criteria: str | None = None
    false_criteria: str | None = None
    type: Literal["noul"] = "noul"


@dataclass(frozen=True)
class ChoiceQuestion:
    name: str
    instructions: str
    criteria: Mapping[str, str]
    type: Literal["choice"] = "choice"


@dataclass(frozen=True)
class ScoreQuestion:
    name: str
    instructions: str
    criteria: Sequence[str]
    type: Literal["score"] = "score"


Question: TypeAlias = NoulQuestion | ChoiceQuestion | ScoreQuestion


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NoulResult:
    type: Literal["noul"]
    noul: float


@dataclass(frozen=True)
class ChoiceResult:
    type: Literal["choice"]
    choice: str
    probabilities: dict[str, float]
    confidence: float


@dataclass(frozen=True)
class ScoreResult:
    type: Literal["score"]
    score: float
    legend: dict[str, str]
    probabilities: dict[str, float]
    confidence: float


Result: TypeAlias = NoulResult | ChoiceResult | ScoreResult


# ---------------------------------------------------------------------------
# API wrapper
# ---------------------------------------------------------------------------

def jev(
    state: Any,
    questions: Sequence[Question],
    *,
    api_key: str | None = None,
    model: str = "~typesafe/jev-latest",
    site_url: str | None = None,
    site_name: str | None = None,
    timeout: float = 30.0,
) -> dict[str, Result]:
    """
    Ask Jev a batch of typed questions about `state`.

    `state` can be any JSON-serializable object.
    """

    api_key = api_key or os.environ["OPENROUTER_API_KEY"]

    # Convert our convenient list-of-named-questions API into
    # OpenRouter's name -> question mapping.
    wire_questions: dict[str, dict[str, Any]] = {}

    for q in questions:
        if q.name in wire_questions:
            raise ValueError(f"Duplicate question name: {q.name!r}")

        wire: dict[str, Any] = {
            "type": q.type,
            "instructions": q.instructions,
        }

        if isinstance(q, NoulQuestion):
            criteria = {}

            if q.true_criteria is not None:
                criteria["true"] = q.true_criteria
            if q.false_criteria is not None:
                criteria["false"] = q.false_criteria

            wire["criteria"] = criteria
        else:
            wire["criteria"] = q.criteria

        wire_questions[q.name] = wire

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    if site_url is not None:
        headers["HTTP-Referer"] = site_url

    if site_name is not None:
        headers["X-OpenRouter-Title"] = site_name

    response = requests.post(
        "https://openrouter.ai/api/alpha/decisions",
        headers=headers,
        json={
            "model": model,
            "state": state,
            "questions": wire_questions,
        },
        timeout=timeout,
    )
    response.raise_for_status()

    raw_answers = response.json()["answers"]

    results: dict[str, Result] = {}

    for name, raw in raw_answers.items():
        match raw["type"]:
            case "noul":
                results[name] = NoulResult(
                    type="noul",
                    noul=float(raw["noul"]),
                )

            case "choice":
                results[name] = ChoiceResult(
                    type="choice",
                    choice=raw["choice"],
                    probabilities={
                        k: float(v)
                        for k, v in raw["probabilities"].items()
                    },
                    confidence=float(raw["confidence"]),
                )

            case "score":
                results[name] = ScoreResult(
                    type="score",
                    score=float(raw["score"]),
                    legend=dict(raw["legend"]),
                    probabilities={
                        k: float(v)
                        for k, v in raw["probabilities"].items()
                    },
                    confidence=float(raw["confidence"]),
                )

            case unknown:
                raise ValueError(f"Unknown Jev answer type: {unknown!r}")

    return results
