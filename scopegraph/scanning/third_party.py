import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from scopegraph.normalizers.assets import NormalizationError, normalize_domain


class CnameRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str = Field(min_length=1, max_length=200)
    category: Literal["CDN", "SAAS"]
    suffixes: tuple[str, ...] = Field(min_length=1, max_length=50)

    @field_validator("suffixes")
    @classmethod
    def normalize_suffixes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(normalize_domain(value) for value in values))


class CnameRuleSet(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(ge=1)
    rules: tuple[CnameRule, ...] = Field(min_length=1, max_length=1_000)


@dataclass(frozen=True, slots=True)
class CnameClassification:
    provider: str
    category: Literal["CDN", "SAAS"]
    matched_suffix: str
    rules_version: int


def _default_path() -> Path:
    return Path(__file__).resolve().parents[2] / "configs" / "third_party_rules" / "cname.json"


@lru_cache(maxsize=1)
def load_cname_rules(path: Path | None = None) -> CnameRuleSet:
    source = path or _default_path()
    return CnameRuleSet.model_validate(json.loads(source.read_text(encoding="utf-8")))


def classify_cname(value: str, rules: CnameRuleSet | None = None) -> CnameClassification | None:
    try:
        domain = normalize_domain(value)
    except NormalizationError:
        return None
    active_rules = rules or load_cname_rules()
    for rule in active_rules.rules:
        for suffix in rule.suffixes:
            if domain == suffix or domain.endswith(f".{suffix}"):
                return CnameClassification(
                    provider=rule.provider,
                    category=rule.category,
                    matched_suffix=suffix,
                    rules_version=active_rules.version,
                )
    return None
