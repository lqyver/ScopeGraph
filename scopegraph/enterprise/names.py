import re
from dataclasses import dataclass

from scopegraph.normalizers import normalize_company_name

_bracket_content = re.compile(r"[（(]([^）)]*)[）)]")
_split_aliases = re.compile(r"[/、,，;；|]")
_suffixes = (
    "股份有限公司",
    "有限责任公司",
    "集团有限公司",
    "有限公司",
    "集团",
    "incorporated",
    "corporation",
    "company limited",
    "limited",
    "inc",
    "corp",
    "ltd",
    "co",
)
_word = re.compile(r"[\w\u3400-\u9fff-]+", re.UNICODE)


@dataclass(frozen=True, slots=True)
class CompanyProfile:
    normalized_name: str
    aliases: tuple[str, ...]
    search_keywords: tuple[str, ...]


def _strip_suffix(value: str) -> str:
    candidate = value.strip(" .,-_()（）").casefold()
    for suffix in _suffixes:
        if candidate.endswith(suffix) and len(candidate) > len(suffix):
            return candidate[: -len(suffix)].strip(" .,-_")
    return candidate


def build_company_profile(company_name: str, aliases: list[str] | None = None) -> CompanyProfile:
    normalized = normalize_company_name(company_name)
    candidates = [normalized, _strip_suffix(normalized)]
    for group in _bracket_content.findall(company_name):
        candidates.extend(_split_aliases.split(group))
    candidates.extend(aliases or [])
    cleaned = tuple(dict.fromkeys(item for raw in candidates if (item := _strip_suffix(raw))))
    keywords: list[str] = list(cleaned)
    for alias in cleaned:
        keywords.extend(token.casefold() for token in _word.findall(alias) if len(token) >= 2)
    return CompanyProfile(normalized, cleaned, tuple(dict.fromkeys(keywords)))
