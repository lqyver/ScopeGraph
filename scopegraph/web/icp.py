import html
import re
from dataclasses import dataclass
from html.parser import HTMLParser

from scopegraph.domain.enums import ICPRecordKind

MAX_HTML_BYTES = 2 * 1024 * 1024
_whitespace = re.compile(r"\s+")
_icp = re.compile(
    r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼]"
    r"\s*ICP\s*(?:备|证)\s*\d{6,12}\s*号(?:\s*[-－]\s*\d+)?",
    re.IGNORECASE,
)
_public_security = re.compile(
    r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼]"
    r"\s*公网\s*安备\s*\d{12,18}\s*号?",
)
_copyright_subject = re.compile(
    r"(?:版权所有|版权归属|copyright\s*(?:©|\(c\))?\s*(?:\d{4}(?:\s*[-–]\s*\d{4})?)?\s*[:：]?)"
    r"\s*([^|·•<>]{2,100}?(?:有限(?:责任)?公司|集团|研究院|大学|政府|中心))",
    re.IGNORECASE,
)


class _VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript", "template"}:
            self._ignored_depth += 1
        if tag == "meta" and not self._ignored_depth:
            values = dict(attrs)
            content = values.get("content")
            if content:
                self.parts.append(content)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "template"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth:
            self.parts.append(data)


@dataclass(frozen=True, slots=True)
class ExtractedICPRecord:
    kind: ICPRecordKind
    normalized_number: str
    display_number: str
    excerpt: str


@dataclass(frozen=True, slots=True)
class PageIdentity:
    records: tuple[ExtractedICPRecord, ...]
    copyright_subjects: tuple[str, ...]


def _visible_text(document: str) -> str:
    parser = _VisibleTextParser()
    parser.feed(document)
    parser.close()
    return _whitespace.sub(" ", html.unescape(" ".join(parser.parts))).strip()


def _excerpt(text: str, start: int, end: int, radius: int = 80) -> str:
    return text[max(0, start - radius) : min(len(text), end + radius)].strip()


def _normalize_number(value: str) -> str:
    collapsed = _whitespace.sub("", value).replace("－", "-")
    if "公网安备" in collapsed and not collapsed.endswith("号"):
        collapsed += "号"
    return collapsed


def extract_page_identity(document: str | bytes) -> PageIdentity:
    if isinstance(document, bytes):
        if len(document) > MAX_HTML_BYTES:
            raise ValueError("HTML document exceeds extraction limit")
        decoded = document.decode("utf-8", errors="replace")
    else:
        if len(document.encode("utf-8")) > MAX_HTML_BYTES:
            raise ValueError("HTML document exceeds extraction limit")
        decoded = document
    text = _visible_text(decoded)
    records: list[ExtractedICPRecord] = []
    seen: set[tuple[ICPRecordKind, str]] = set()
    for kind, pattern in (
        (ICPRecordKind.ICP, _icp),
        (ICPRecordKind.PUBLIC_SECURITY, _public_security),
    ):
        for match in pattern.finditer(text):
            normalized = _normalize_number(match.group(0))
            identity = (kind, normalized.casefold())
            if identity in seen:
                continue
            seen.add(identity)
            records.append(
                ExtractedICPRecord(
                    kind=kind,
                    normalized_number=normalized,
                    display_number=_whitespace.sub(" ", match.group(0)).strip(),
                    excerpt=_excerpt(text, match.start(), match.end()),
                )
            )
    subjects = tuple(
        dict.fromkeys(
            _whitespace.sub(" ", match.group(1)).strip(" ：:|·•")
            for match in _copyright_subject.finditer(text)
        )
    )
    return PageIdentity(tuple(records), subjects)
