import json
from dataclasses import dataclass
from pathlib import Path

from scopegraph.domain.enums import CandidateRootStatus, OwnershipStatus


@dataclass(frozen=True, slots=True)
class OwnershipRules:
    version: int
    weights: dict[str, float]
    thresholds: dict[str, float]

    @classmethod
    def load(cls, path: Path | None = None) -> "OwnershipRules":
        rules_path = path or Path("configs/ownership_rules/v2.json")
        payload = json.loads(rules_path.read_text(encoding="utf-8"))
        return cls(
            version=int(payload["version"]),
            weights={str(key): float(value) for key, value in payload["weights"].items()},
            thresholds={str(key): float(value) for key, value in payload["thresholds"].items()},
        )


@dataclass(frozen=True, slots=True)
class ScoreResult:
    raw_score: float
    score: float
    status: CandidateRootStatus
    ownership_status: OwnershipStatus
    applied: tuple[tuple[str, float], ...]


def score_signals(signals: list[str], rules: OwnershipRules) -> ScoreResult:
    applied = tuple(
        (signal, rules.weights[signal])
        for signal in dict.fromkeys(signals)
        if signal in rules.weights
    )
    raw = sum(weight for _, weight in applied)
    score = max(0.0, min(100.0, raw))
    if raw >= rules.thresholds["confirmed"]:
        return ScoreResult(
            raw,
            score,
            CandidateRootStatus.SUGGESTED_CONFIRM,
            OwnershipStatus.HIGH_CONFIDENCE,
            applied,
        )
    if raw >= rules.thresholds["high_confidence"]:
        return ScoreResult(
            raw,
            score,
            CandidateRootStatus.HIGH_PROBABILITY,
            OwnershipStatus.HIGH_CONFIDENCE,
            applied,
        )
    if raw >= rules.thresholds["pending_review"]:
        return ScoreResult(
            raw, score, CandidateRootStatus.PENDING_REVIEW, OwnershipStatus.PENDING_REVIEW, applied
        )
    if raw >= rules.thresholds["weak_relation"]:
        return ScoreResult(
            raw, score, CandidateRootStatus.PENDING_REVIEW, OwnershipStatus.WEAK_RELATION, applied
        )
    return ScoreResult(
        raw, score, CandidateRootStatus.THIRD_PARTY, OwnershipStatus.THIRD_PARTY, applied
    )
