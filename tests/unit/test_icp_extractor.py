import pytest

from scopegraph.domain.enums import ICPRecordKind
from scopegraph.web.icp import MAX_HTML_BYTES, extract_page_identity


def test_extracts_and_normalizes_icp_public_security_and_subject() -> None:
    result = extract_page_identity(
        """
        <html><head><meta name="description" content="官方站点"></head>
        <body><footer>
        <a href="https://beian.miit.gov.cn">京 ICP 备 12345678 号 - 2</a>
        <span>京公网安备 11010502030143</span>
        <span>版权所有：示例科技有限责任公司</span>
        </footer><script>沪ICP备99999999号</script></body></html>
        """
    )
    assert [(item.kind, item.normalized_number) for item in result.records] == [
        (ICPRecordKind.ICP, "京ICP备12345678号-2"),
        (ICPRecordKind.PUBLIC_SECURITY, "京公网安备11010502030143号"),
    ]
    assert result.copyright_subjects == ("示例科技有限责任公司",)
    assert all("官方" not in item.normalized_number for item in result.records)


def test_deduplicates_records_and_ignores_script_content() -> None:
    result = extract_page_identity(
        "<footer>沪ICP备12345678号 沪ICP备12345678号</footer><script>京ICP备87654321号</script>"
    )
    assert len(result.records) == 1
    assert result.records[0].normalized_number == "沪ICP备12345678号"


def test_rejects_oversized_html() -> None:
    with pytest.raises(ValueError, match="limit"):
        extract_page_identity(b"x" * (MAX_HTML_BYTES + 1))
