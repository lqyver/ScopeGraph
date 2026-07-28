"""Small dependency-free OOXML writer for auditable tabular ScopeGraph exports."""

# ruff: noqa: E501

from collections.abc import Mapping, Sequence
from datetime import date, datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape
from zipfile import ZIP_DEFLATED, ZipFile


def _column_name(index: int) -> str:
    value = index + 1
    result = ""
    while value:
        value, remainder = divmod(value - 1, 26)
        result = chr(65 + remainder) + result
    return result


def _cell(reference: str, value: Any, *, header: bool = False) -> str:
    style = ' s="1"' if header else ""
    if value is None:
        return f'<c r="{reference}"{style}/>'
    if isinstance(value, bool):
        return f'<c r="{reference}" t="b"{style}><v>{int(value)}</v></c>'
    if isinstance(value, int | float):
        return f'<c r="{reference}"{style}><v>{value}</v></c>'
    if isinstance(value, datetime | date):
        value = value.isoformat()
    text = escape(str(value))
    preserve = ' xml:space="preserve"' if str(value).strip() != str(value) else ""
    return f'<c r="{reference}" t="inlineStr"{style}><is><t{preserve}>{text}</t></is></c>'


def _worksheet(headers: Sequence[str], rows: Sequence[Mapping[str, Any]]) -> str:
    matrix: list[list[Any]] = [
        list(headers),
        *[[row.get(header) for header in headers] for row in rows],
    ]
    row_xml = []
    for row_index, values in enumerate(matrix, start=1):
        cells = "".join(
            _cell(f"{_column_name(column_index)}{row_index}", value, header=row_index == 1)
            for column_index, value in enumerate(values)
        )
        row_xml.append(f'<row r="{row_index}">{cells}</row>')
    final_column = _column_name(max(len(headers) - 1, 0))
    widths = "".join(
        f'<col min="{index + 1}" max="{index + 1}" width="{min(48, max(12, len(header) + 4))}" customWidth="1"/>'
        for index, header in enumerate(headers)
    )
    dimension = f"A1:{final_column}{max(len(matrix), 1)}"
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<dimension ref="{dimension}"/><sheetViews><sheetView workbookViewId="0" showGridLines="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        '</sheetView></sheetViews><sheetFormatPr defaultRowHeight="18"/>'
        f"<cols>{widths}</cols><sheetData>{''.join(row_xml)}</sheetData>"
        f'<autoFilter ref="A1:{final_column}{max(len(matrix), 1)}"/></worksheet>'
    )


def write_xlsx(
    path: Path,
    sheets: Mapping[str, tuple[Sequence[str], Sequence[Mapping[str, Any]]]],
) -> None:
    if not sheets:
        raise ValueError("Workbook requires at least one worksheet")
    names = list(sheets)
    if len(names) != len(set(names)) or any(not name or len(name) > 31 for name in names):
        raise ValueError("Worksheet names must be unique and between 1 and 31 characters")
    workbook_sheets = "".join(
        f'<sheet name="{escape(name)}" sheetId="{index}" r:id="rId{index}"/>'
        for index, name in enumerate(names, start=1)
    )
    relationships = "".join(
        f'<Relationship Id="rId{index}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{index}.xml"/>'
        for index in range(1, len(names) + 1)
    )
    relationships += f'<Relationship Id="rId{len(names) + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{index}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for index in range(1, len(names) + 1)
    )
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
            f"{overrides}</Types>",
        )
        archive.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            "</Relationships>",
        )
        archive.writestr(
            "xl/workbook.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            f'<sheets>{workbook_sheets}</sheets><calcPr calcId="0" fullCalcOnLoad="1"/></workbook>',
        )
        archive.writestr(
            "xl/_rels/workbook.xml.rels",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f"{relationships}</Relationships>",
        )
        archive.writestr(
            "xl/styles.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<fonts count="2"><font><sz val="10"/><name val="Aptos"/></font>'
            '<font><b/><color rgb="FFFFFFFF"/><sz val="10"/><name val="Aptos Display"/></font></fonts>'
            '<fills count="3"><fill><patternFill patternType="none"/></fill>'
            '<fill><patternFill patternType="gray125"/></fill>'
            '<fill><patternFill patternType="solid"><fgColor rgb="FF0F766E"/><bgColor indexed="64"/></patternFill></fill></fills>'
            '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
            '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
            '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
            '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs>'
            '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
            "</styleSheet>",
        )
        for index, (_, (headers, rows)) in enumerate(sheets.items(), start=1):
            archive.writestr(f"xl/worksheets/sheet{index}.xml", _worksheet(headers, rows))
