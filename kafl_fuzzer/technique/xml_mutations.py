from __future__ import annotations

"""XML-specific seed analysis and mutation helpers for kAFL."""

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
import copy
import json
import logging
import re
import os
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

from kafl_fuzzer.common.rand import rand
from kafl_fuzzer.common.util import atomic_write

_LOGGER = logging.getLogger(__name__)

# Token collection is unbounded; text length remains capped per entry
_MAX_TOKEN_COUNT = sys.maxsize
_MAX_TEXT_LENGTH = 256
_DEFAULT_TEXT_TOKENS = ["", "0", "1", "true", "false", "null", "NaN", "INF"]
_DEFAULT_TAG_TOKENS = ["data", "item", "node", "value"]

_SCHEMA_PATH = Path(__file__).with_name('xml_schema_tokens.json')
_GLOBAL_SCHEMA = {
    'tags': set(),
    'attributes': set(),
    'attribute_values': set(),
    'texts': set(),
}


def _load_schema_tokens():
    if not _SCHEMA_PATH.exists():
        return
    try:
        data = json.loads(_SCHEMA_PATH.read_text(encoding='utf-8-sig'))
    except (json.JSONDecodeError, OSError):
        return
    for key in _GLOBAL_SCHEMA:
        values = data.get(key, [])
        if not isinstance(values, list):
            continue
        for value in values:
            if value is None:
                continue
            truncated = str(value)[:_MAX_TEXT_LENGTH]
            if truncated:
                _GLOBAL_SCHEMA[key].add(truncated)


def _save_schema_tokens():
    data = {key: sorted(list(values))[:_MAX_TOKEN_COUNT] for key, values in _GLOBAL_SCHEMA.items()}
    try:
        _SCHEMA_PATH.write_text(json.dumps(data, indent=2), encoding='utf-8')
        _LOGGER.info('Persisted XML schema tokens -> %s', ', '.join(f"{k}:{len(v)}" for k, v in data.items()))
    except OSError as exc:
        _LOGGER.warning('Failed to persist XML schema tokens: %s', exc)


_load_schema_tokens()


def _update_schema_store(updates: Dict[str, Iterable[str]]):
    dirty = False
    added_tokens = {key: [] for key in _GLOBAL_SCHEMA}
    for key, values in updates.items():
        if key not in _GLOBAL_SCHEMA:
            continue
        for value in values:
            if value is None:
                continue
            truncated = str(value)[:_MAX_TEXT_LENGTH]
            if truncated and truncated not in _GLOBAL_SCHEMA[key]:
                _GLOBAL_SCHEMA[key].add(truncated)
                added_tokens[key].append(truncated)
                dirty = True
    if dirty:
        summary = []
        for key, vals in added_tokens.items():
            if vals:
                sample = ', '.join(sorted(vals)[:5])
                summary.append(f"{key}: {sample}")
        if summary:
            _LOGGER.info("Updated XML schema tokens -> %s", '; '.join(summary))
        _save_schema_tokens()


_OOXML_TAG_CANDIDATES = {
    'w:document', 'w:body', 'w:p', 'w:r', 'w:t', 'w:tbl', 'w:tr', 'w:tc',
    'w:hyperlink', 'w:drawing', 'wp:anchor', 'wp:inline', 'a:graphic', 'v:shape'
}

_OOXML_ATTR_VALUE_MAP = {
    'w:val': ['single', 'double', 'underline', 'none', 'default'],
    'w:type': ['paragraph', 'character', 'table', 'numbering'],
    'w:styleId': ['Normal', 'Heading1', 'Heading2', 'Title'],
    'w:color': ['000000', 'FFFFFF', 'FF0000', '00FF00', '0000FF'],
    'w:themeColor': ['accent1', 'accent2', 'accent3', 'accent4', 'accent5', 'hyperlink'],
    'w:valCs': ['single', 'double', 'underline'],
}

_EXCEL_CELL_LENGTHS = (4096, 8192, 16384, 32768, 65536)
_EXCEL_PATTERN_SEEDS = ("AB", "1234567890", "XYZ!", "DEADBEEF")
_EXCEL_UNICODE_CODEPOINTS = (
    0x0000,
    0x0001,
    0x0002,
    0xD7FF,
    0xE000,
    0xFFFD,
    0xFEFF,
)
_EXCEL_DATETIME_TEMPLATES = (
    "9999999999999999999-12-31T23:59:59Z",
    "999999-99-99T99:99:99.999999999Z",
    "1970-01-01T25:61:61.999999999Z",
    "2024-01-01T00:00:00+99:99",
    "2024-01-01T00:00:00-99:99",
    "0000-00-00T00:00:00Z",
)
_EXCEL_ALT_DATETIME_FRAGMENTS = (
    "9999999999999999999",
    "999999",
    "99:99:99",
    "+99:99",
    "-99:99",
)
_EXCEL_CELL_REFERENCE_MUTATIONS = (
    "IV65536",
    "XFD1048576",
    "R1048576C16384",
    "",
    "A0",
    "A1048577",
    "XFE1",
    "B0",
    "C-1",
    "D999999999",
    "I2147483647",
)
_EXCEL_CELL_TYPE_MUTATIONS = (
    ("n", "TEXT_MISMATCH"),
    ("n", "NaN"),
    ("str", "123.456"),
    ("str", "-INF"),
    ("b", "maybe"),
    ("b", "2"),
    ("e", "#VALUE!"),
    ("d", "9999-12-31T23:59:59.999999999Z"),
    ("datetime", "9999-12-31T99:99:99Z"),
    ("N", "0"),
    ("STR", "invalid"),
    ("", ""),
)
_EXCEL_CELL_STYLE_MUTATIONS = ("", "0", "1", "64", "99", "4096", "16384", "4294967295", "-1", "2147483647")
_EXCEL_ROW_REFERENCE_MUTATIONS = ("0", "1", "1048576", "1048577", "999999", "-1", "2147483647")
_EXCEL_ROW_SPAN_MUTATIONS = ("1:16384", "0:0", "-1:-1", "1:1048576", "16384:16384", "1048576:1048576", "2:16385", "9:2")
_EXCEL_LARGE_COUNTS = ("2147483647", "4294967295", "1099511627776")
_EXCEL_JSON_PAYLOAD = '{"type":"PowerQuery","data":"' + ('A' * 1024) + '"}'
_EXCEL_MASHUP_PAYLOAD = '{"Mashup":{"Queries":[' + ','.join('"Q{}"'.format(i) for i in range(10)) + '],"Binary":"' + ('B' * 512) + '"}}'
_EXCEL_CONNECTION_STRINGS = (
    "Provider=SQLOLEDB;Data Source=\\\\\\evil\\share;Initial Catalog=Finance;Integrated Security=SSPI;",
    "Driver={SQL Server};Server=localhost;Trusted_Connection=yes;Packet Size=32768;Application Intent=READONLY;",
    "OLEDB;Data Source=|DataDirectory|\\payload.db;Persist Security Info=True;Password=secret;",
)
_EXCEL_TABLE_REF_MUTATIONS = (
    "A1:XFD1048576",
    "A0:A0",
    "IV65536:XFD1048576",
    "A1048576:B1048577",
    "A1:A1048576",
)
_EXCEL_TABLE_STYLE_FLAGS = ("showFirstColumn", "showLastColumn", "showRowStripes", "showColumnStripes", "showAutoFilter")
_EXCEL_CF_TYPES = (
    ("dataBar", {"priority": _EXCEL_LARGE_COUNTS[0], "id": "-1"}),
    ("colorScale", {"priority": "1", "id": "0"}),
    ("iconSet", {"priority": "2", "id": "1"}),
)
_EXCEL_HYPERLINK_TARGETS = (
    "http://127.0.0.1:31337/" + "A" * 128,
    "file:///C:/Windows/System32/calc.exe",
    "file://\\\\\\\\corpserver\\\\share\\\\payload.xlsm",
    "mailto:\"attacker\"@example.com?subject=ExcelTest",
)
_EXCEL_HYPERLINK_LOCATIONS = (
    "Sheet999!A1048576",
    "HiddenSheet!IV65536",
    "ExternalWorkbook.xlsx!Sheet1!A1",
)
_EXCEL_HYPERLINK_UIDS = (
    "{00000000-0000-0000-0000-000000000000}",
    "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}",
    "{12345678-1234-5678-1234-567812345678}",
)
_EXCEL_FORMULA_TYPES = ("normal", "shared", "array", "dataTable", "reference", "", "invalid")
_EXCEL_FORMULA_TEXT_MUTATIONS = (
    "SUM(A1:A1048576)",
    "OFFSET($A$1,1048575,16383)",
    "IF(1,REPT(\"A\",32768),0)",
    "_xlfn.LET(x,1E308,x)",
    "GETPIVOTDATA(\"Value\",Sheet1!$A$1)",
) + _EXCEL_THEMEVAL_FORMULAS
_EXCEL_FORMULA_REF_MUTATIONS = ("A1", "A1:XFD1048576", "Sheet1!A1", "R1C1", "A0", "XFD1048576")
_EXCEL_SHARED_INDEX_MUTATIONS = ("0", "1", "1048575", "2147483647", "-1")
_EXCEL_COLUMN_MIN_MUTATIONS = ("1", "16384", "0", "-1", "2147483647")
_EXCEL_COLUMN_MAX_MUTATIONS = ("1", "16384", "0", "-1", "2147483647", "4294967295")
_EXCEL_COLUMN_WIDTH_MUTATIONS = ("0", "0.1", "255", "1024", "-1", "1.7976931348623157E+308")
_EXCEL_COLUMN_STYLE_MUTATIONS = ("0", "1", "999999", "4294967295", "-1")
_EXCEL_MERGE_REFS = (
    "A1:B1048576",
    "IV1:XFD1048576",
    "A0:B0",
    "A1048576:A1048576",
    "A1:XFD1",
    "A1:A1048576",
)
_EXCEL_HIGH_RISK_TAGS = (
    'controls', 'control', 'controlPr', 'dataValidations', 'dataValidation',
    'formula', 'formula1', 'connections', 'connection', 'HyperlinkBase',
    'AlternateContent', 'Choice', 'Fallback'
)
_EXCEL_HIGH_RISK_ATTRS = (
    'F', 'progId', 'odcFile', 'name', 'id', 'type', 'sqref', 'allowBlank', 'HyperlinkBase'
)
_EXCEL_THEMEVAL_FORMULAS = (
    "=THEMEVAL()",
    '=THEMEVAL()+INDIRECT("A1")',
    '=THEMEVAL()+HYPERLINK("file://C:/")',
    '=THEMEVAL()+WEBSERVICE("http://attacker")',
    '=THEMEVAL()+INFO("system")',
    '=THEMEVAL()+CELL("address")',
)
_EXCEL_CONTROL_IDS = (
    "{00000000-0000-0000-0000-000000000000}",
    "{F0000000-0000-0000-0000-000000000045}",
    "{12345678-9ABC-DEF0-1234-56789ABCDEF0}",
)
_EXCEL_CONTROL_PROGIDS = (
    "Forms.CommandButton.1",
    "Forms.ListBox.1",
    "Forms.TextBox.1",
)
_EXCEL_CONNECTION_IDS = ("1", "2147483647", "4294967295")
_EXCEL_CONNECTION_NAMES = ("BypassConnection", "PowerQueryImport", "ExternalOLEDB")
_EXCEL_COMMENT_TEXTS = (
    "Exploit payload " + "X" * 256,
    "Nested comment " + "<tag>" * 32,
    "A" * 512,
)
_EXCEL_AUTHOR_NAMES = (
    "MegaResearcher",
    "ThreadedActor",
    "PowerHyperMorph",
)
_EXCEL_THREAD_IDS = (
    "{00000000-0000-0000-0000-000000000001}",
    "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}",
    "{12345678-90AB-CDEF-1234-567890ABCDEF}",
)
_EXCEL_SPARKLINE_RANGES = (
    "Sheet1!A1:XFD1",
    "Sheet2!A1:A1048576",
    "Hidden!IV1:IV1048576",
)
_EXCEL_DRAWING_REL_IDS = (
    "rId999999",
    "rId2147483647",
    "rId4294967295",
)
_BYPASS_HYPERLINK_REPEAT = 64
_BYPASS_MEMORY_ROWS = 64
_BYPASS_EXT_URI = "{BYPASS_EXT}"
_BYPASS_EXT_PAYLOAD = "X" * 2048
_EXCEL_HYPERLINK_LOCATIONS = (
    "Sheet999!A1048576",
    "HiddenSheet!IV65536",
    "ExternalWorkbook.xlsx!Sheet1!A1",
)
_EXCEL_COMMENT_TEXTS = (
    "Exploit payload " + "X" * 256,
    "Nested comment " + "<tag>" * 32,
    "A" * 512,
)
_EXCEL_AUTHOR_NAMES = (
    "MegaResearcher",
    "ThreadedActor",
    "PowerHyperMorph",
)
_EXCEL_THREAD_IDS = (
    "{00000000-0000-0000-0000-000000000001}",
    "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}",
    "{12345678-90AB-CDEF-1234-567890ABCDEF}",
)
_EXCEL_SPARKLINE_RANGES = (
    "Sheet1!A1:XFD1",
    "Sheet2!A1:A1048576",
    "Hidden!IV1:IV1048576",
)
_EXCEL_DRAWING_REL_IDS = (
    "rId999999",
    "rId2147483647",
    "rId4294967295",
)


@dataclass
class XMLSeedInfo:
    """Container for XML features extracted from a seed payload."""

    tags: Set[str] = field(default_factory=set)
    attributes: Set[str] = field(default_factory=set)
    attribute_values: Set[str] = field(default_factory=set)
    texts: List[str] = field(default_factory=list)

    @staticmethod
    def from_metadata(data: Optional[Dict[str, Iterable[str]]]) -> Optional["XMLSeedInfo"]:
        if not data:
            return None
        return XMLSeedInfo(
            tags=set(data.get("tags", [])),
            attributes=set(data.get("attributes", [])),
            attribute_values=set(data.get("attribute_values", [])),
            texts=list(data.get("texts", [])),
        )

    def to_metadata(self) -> Dict[str, Sequence[str]]:
        return {
            "tags": sorted(self.tags)[:_MAX_TOKEN_COUNT],
            "attributes": sorted(self.attributes)[:_MAX_TOKEN_COUNT],
            "attribute_values": list(self._truncate_iter(self.attribute_values)),
            "texts": list(self._truncate_iter(self.texts)),
        }

    def _truncate_iter(self, iterable: Iterable[str]) -> Iterable[str]:
        count = 0
        for item in iterable:
            if item is None:
                continue
            if isinstance(item, str):
                trimmed = item[:_MAX_TEXT_LENGTH]
            else:
                trimmed = str(item)[:_MAX_TEXT_LENGTH]
            yield trimmed
            count += 1
            if count >= _MAX_TOKEN_COUNT:
                break

    def diff(self, other: Optional["XMLSeedInfo"]) -> Dict[str, Set[str]]:
        if other is None:
            return {
                "tags": set(self.tags),
                "attributes": set(self.attributes),
                "attribute_values": set(self.attribute_values),
                "texts": set(self.texts),
            }
        return {
            "tags": self.tags - other.tags,
            "attributes": self.attributes - other.attributes,
            "attribute_values": self.attribute_values - other.attribute_values,
            "texts": set(self.texts) - set(other.texts),
        }

    def merge(self, other: Optional["XMLSeedInfo"]):
        if other is None:
            return
        self.tags.update(other.tags)
        self.attributes.update(other.attributes)
        self.attribute_values.update(other.attribute_values)
        for text in other.texts:
            if text not in self.texts:
                self.texts.append(text)


def _iter_elements(root: ET.Element) -> List[ET.Element]:
    return list(root.iter())


def _try_parse_xml(payload: bytes) -> Optional[ET.Element]:
    try:
        return ET.fromstring(payload)
    except (ET.ParseError, ValueError, TypeError):
        return None


def extract_xml_features(payload: bytes) -> Optional[XMLSeedInfo]:
    """Extract tag, attribute, and text data from an XML payload."""

    root = _try_parse_xml(payload)
    if root is None:
        return _extract_tokens_lenient(payload)

    tags: Set[str] = set()
    attributes: Set[str] = set()
    attribute_values: Set[str] = set()
    texts: List[str] = []

    for element in root.iter():
        tags.add(element.tag)
        for key, value in element.attrib.items():
            attributes.add(key)
            attribute_values.add(value)
        if element.text and element.text.strip():
            texts.append(element.text.strip())
        if element.tail and element.tail.strip():
            texts.append(element.tail.strip())

    if not tags and not attributes and not texts:
        return None

    limited_texts = []
    seen = set()
    for text in texts:
        trimmed = text[:_MAX_TEXT_LENGTH]
        if trimmed in seen:
            continue
        limited_texts.append(trimmed)
        seen.add(trimmed)
        if len(limited_texts) >= _MAX_TOKEN_COUNT:
            break

    info = XMLSeedInfo(
        tags=set(list(tags)[:_MAX_TOKEN_COUNT]),
        attributes=set(list(attributes)[:_MAX_TOKEN_COUNT]),
        attribute_values=set(list(attribute_values)[:_MAX_TOKEN_COUNT]),
        texts=limited_texts,
    )
    _update_schema_store({
        'tags': info.tags,
        'attributes': info.attributes,
        'attribute_values': info.attribute_values,
        'texts': info.texts
    })
    return info


def _clone_tree(root: ET.Element) -> ET.Element:
    return copy.deepcopy(root)


def _element_to_bytes(root: ET.Element) -> bytes:
    return ET.tostring(root, encoding="utf-8")


def _local_name(tag: str) -> str:
    if '}' in tag:
        return tag.rsplit('}', 1)[-1]
    return tag


def _excel_ns(reference_tag: str, local_name: str) -> str:
    if reference_tag.startswith('{'):
        namespace = reference_tag.split('}', 1)[0][1:]
        return f'{{{namespace}}}{local_name}'
    return local_name


def _get_or_create_child_by_suffix(element: ET.Element, suffix: str) -> ET.Element:
    existing = _find_child_by_suffix(element, suffix)
    if existing is not None:
        return existing
    return _ensure_child_by_suffix(element, suffix)


def _clear_children(element: ET.Element):
    for child in list(element):
        element.remove(child)


def _create_cell(cell_tag: str, value_tag: str, ref: str, style: Optional[str] = None,
                 cell_type: Optional[str] = None, value: Optional[str] = None) -> ET.Element:
    attrib = {'r': ref}
    if style is not None:
        attrib['s'] = style
    if cell_type is not None:
        attrib['t'] = cell_type
    cell = ET.Element(cell_tag, attrib=attrib)
    if value is not None:
        value_elem = ET.Element(value_tag)
        value_elem.text = value
        cell.append(value_elem)
    return cell


def _create_formula_cell(cell_tag: str, value_tag: str, formula_tag: str, ref: str,
                         formula_text: str, attrib: Optional[Dict[str, str]] = None) -> ET.Element:
    cell = ET.Element(cell_tag, attrib={'r': ref})
    if attrib:
        cell.attrib.update(attrib)
    formula_elem = ET.Element(formula_tag)
    formula_elem.text = formula_text
    cell.append(formula_elem)
    return cell


def _repeat_to_length(seed: str, length: int) -> str:
    if not seed:
        return seed
    repetitions = (length // len(seed)) + 1
    return (seed * repetitions)[:length]


def _excel_unicode_payload(length: int) -> str:
    # Mix control chars, BMP edge cases, and printable ASCII to stress different decoders.
    base_sequence = ''.join(chr(code_point) for code_point in _EXCEL_UNICODE_CODEPOINTS)
    ascii_mix = ''.join(chr(65 + (idx % 26)) for idx in range(len(base_sequence)))
    seed = base_sequence + ascii_mix
    return _repeat_to_length(seed, length)


def _excel_utf16le_payload(length: int) -> str:
    # Simulate UTF-16LE like data inside XML text nodes.
    base = ''.join('A\u0000B\u0000' for _ in range(max(1, length // 4)))
    return base[:length]


def _excel_cell_value_payloads() -> List[Tuple[str, str]]:
    payloads: List[Tuple[str, str]] = []
    lengths = list(_EXCEL_CELL_LENGTHS)
    # Add one random length within the desired boundary to diversify coverage.
    random_length = 4096 + rand.int(65536 - 4096 + 1)
    if random_length not in lengths:
        lengths.append(random_length)

    for length in lengths:
        payloads.append(("cell_value_overflow", "A" * length))
        pattern_seed = ''.join(_EXCEL_PATTERN_SEEDS)
        payloads.append(("cell_value_pattern", _repeat_to_length(pattern_seed, length)))
        alternator = ''.join(chr((32 + (i % 95))) for i in range(length))
        payloads.append(("cell_value_boundary", alternator[:length]))
        payloads.append(("cell_value_unicode", _excel_unicode_payload(length)))
        payloads.append(("cell_value_utf16", _excel_utf16le_payload(length)))

    return payloads


def _excel_datetime_payloads(original: Optional[str] = None) -> List[str]:
    payloads = list(_EXCEL_DATETIME_TEMPLATES)
    # Combine fragments to craft hybrid ISO8601 strings.
    payloads.append(f"{'9' * 20}-{'9' * 2}-{'9' * 2}T{'9' * 2}:{'9' * 2}:{'9' * 2}Z")
    payloads.append("0001-01-01T00:00:00.000000000Z")
    payloads.append("1970-01-01T00:00:00+00:00")
    payloads.append("999999999-12-31T23:59:59.999999999-99:99")

    if original and original.strip():
        stripped = original.strip()
        payloads.append(stripped + "+99:99")
        payloads.append(stripped + "-99:99")

    dynamic_frag = f"{_EXCEL_ALT_DATETIME_FRAGMENTS[0]}-12-31T{_EXCEL_ALT_DATETIME_FRAGMENTS[2]}Z"
    payloads.append(dynamic_frag)
    return payloads


def _excel_collect_nodes(root: ET.Element, suffix: str) -> List[ET.Element]:
    return [node for node in root.iter() if node.tag.endswith(suffix)]


def _excel_collect_nodes_by_suffixes(root: ET.Element, suffixes: Sequence[str]) -> List[ET.Element]:
    suffix_tuple = tuple(suffixes)
    return [node for node in root.iter() if node.tag.endswith(suffix_tuple)]


def _excel_column_name(index: int) -> str:
    if index < 0:
        return "A"
    result = ""
    while True:
        index, remainder = divmod(index, 26)
        result = chr(65 + remainder) + result
        if index == 0:
            break
        index -= 1
    return result


def _excel_reference_mutations(root: ET.Element) -> List[Tuple[str, ET.Element]]:
    mutations: List[Tuple[str, ET.Element]] = []
    sheet_datas = _excel_collect_nodes(root, 'sheetData')
    if not sheet_datas:
        return mutations

    sheet_data_samples = sheet_datas[:3]

    # Duplicate reference mutation: clone cells preserving the same reference id.
    for sheet_idx, sheet_data in enumerate(sheet_data_samples):
        rows = list(sheet_data)
        if not rows:
            continue
        for row_idx, row in enumerate(rows[:3]):
            cells = list(row)
            if not cells:
                continue
            for cell_idx, cell in enumerate(cells[:2]):
                mutated = _clone_tree(root)
                mutated_sheet_data = _excel_collect_nodes(mutated, 'sheetData')[sheet_idx]
                mutated_row = list(mutated_sheet_data)[row_idx]
                mutated_cell = list(mutated_row)[cell_idx]
                duplicated = _clone_tree(mutated_cell)
                mutated_row.insert(cell_idx + 1, duplicated)
                mutations.append(("excel_duplicate_refs", mutated))
                break
            if mutations:
                break
        if mutations:
            break

    sheet_data = sheet_datas[0]
    row_tag = _excel_ns(sheet_data.tag, 'row')
    cell_tag = _excel_ns(sheet_data.tag, 'c')
    formula_tag = _excel_ns(sheet_data.tag, 'f')
    value_tag = _excel_ns(sheet_data.tag, 'v')

    # Circular reference mutation: inject formula cells that reference each other.
    mutated = _clone_tree(root)
    mutated_sheet = _excel_collect_nodes(mutated, 'sheetData')[0]
    circular_row = ET.Element(row_tag, attrib={'r': '1048576'})
    formula_a = ET.Element(cell_tag, attrib={'r': 'A1048576'})
    formula_b = ET.Element(cell_tag, attrib={'r': 'B1048576'})
    f_a = ET.Element(formula_tag)
    f_a.text = "Sheet1!B1048576"
    f_b = ET.Element(formula_tag)
    f_b.text = "Sheet1!A1048576"
    v_a = ET.Element(value_tag)
    v_a.text = "0"
    v_b = ET.Element(value_tag)
    v_b.text = "0"
    formula_a.extend([f_a, v_a])
    formula_b.extend([f_b, v_b])
    circular_row.extend([formula_a, formula_b])
    mutated_sheet.append(circular_row)
    mutations.append(("excel_circular_refs", mutated))

    # Null reference mutation: create cells with empty references and dangling values.
    mutated = _clone_tree(root)
    mutated_sheet = _excel_collect_nodes(mutated, 'sheetData')[0]
    null_row = ET.Element(row_tag, attrib={'r': '2'})
    null_cell = ET.Element(cell_tag, attrib={'r': ''})
    null_value = ET.Element(value_tag)
    null_value.text = ''
    null_cell.append(null_value)
    mutated_sheet.append(null_row)
    null_row.append(null_cell)
    mutations.append(("excel_null_refs", mutated))

    # Race condition style mutation: reorder rows and duplicate high index entries.
    mutated = _clone_tree(root)
    mutated_sheet = _excel_collect_nodes(mutated, 'sheetData')[0]
    rows = list(mutated_sheet)
    if rows:
        duplicated_row = _clone_tree(rows[-1])
        mutated_sheet.insert(0, duplicated_row)
        mutated_sheet.append(_clone_tree(rows[0]))
        mutations.append(("excel_race_refs", mutated))

    # Dense row mutation: add maximal row with many cells.
    mutated = _clone_tree(root)
    mutated_sheet = _excel_collect_nodes(mutated, 'sheetData')[0]
    dense_row = ET.Element(row_tag, attrib={'r': '1048576'})
    for col_idx in range(0, 64):
        cell_ref = f"{_excel_column_name(col_idx)}1048576"
        dense_cell = ET.Element(cell_tag, attrib={'r': cell_ref, 't': 'str'})
        dense_value = ET.Element(value_tag)
        dense_value.text = _repeat_to_length("DENSE", 256)
        dense_cell.append(dense_value)
        dense_row.append(dense_cell)
    mutated_sheet.append(dense_row)
    mutations.append(("excel_dense_row", mutated))

    # Sparse/invalid references row mutation.
    mutated = _clone_tree(root)
    mutated_sheet = _excel_collect_nodes(mutated, 'sheetData')[0]
    sparse_row = ET.Element(row_tag, attrib={'r': '0'})
    for ref in _EXCEL_CELL_REFERENCE_MUTATIONS:
        sparse_cell = ET.Element(cell_tag, attrib={'r': ref, 't': 'n'})
        sparse_value = ET.Element(value_tag)
        sparse_value.text = "0"
        sparse_cell.append(sparse_value)
        sparse_row.append(sparse_cell)
    mutated_sheet.append(sparse_row)
    mutations.append(("excel_sparse_row", mutated))

    return mutations


def _excel_structure_mutations(root: ET.Element) -> List[Tuple[str, ET.Element]]:
    mutations: List[Tuple[str, ET.Element]] = []

    # Shared string table mutations.
    sst_nodes = _excel_collect_nodes(root, 'sst')
    if sst_nodes:
        mutated = _clone_tree(root)
        mutated_sst = _excel_collect_nodes(mutated, 'sst')[0]
        mutated_sst.set('count', _EXCEL_LARGE_COUNTS[0])
        mutated_sst.set('uniqueCount', _EXCEL_LARGE_COUNTS[-1])
        mutations.append(("excel_sst_count", mutated))

        mutated = _clone_tree(root)
        mutated_sst = _excel_collect_nodes(mutated, 'sst')[0]
        new_si = ET.Element(_excel_ns(mutated_sst.tag, 'si'))
        new_text = ET.Element(_excel_ns(mutated_sst.tag, 't'))
        new_text.text = _EXCEL_JSON_PAYLOAD
        new_si.append(new_text)
        mutated_sst.append(new_si)
        mutations.append(("excel_sst_inflate", mutated))

        mutated = _clone_tree(root)
        mutated_sst = _excel_collect_nodes(mutated, 'sst')[0]
        mutated_sst.clear()
        mutated_sst.set('count', '0')
        mutated_sst.set('uniqueCount', _EXCEL_LARGE_COUNTS[1])
        mutations.append(("excel_sst_truncate", mutated))

    # Styles/styleSheet mutations.
    styles_nodes = _excel_collect_nodes_by_suffixes(root, ('styleSheet', 'styles'))
    if styles_nodes:
        mutated = _clone_tree(root)
        mutated_styles = _excel_collect_nodes_by_suffixes(mutated, ('styleSheet', 'styles'))[0]
        for child in mutated_styles:
            if 'count' in child.attrib:
                child.attrib['count'] = _EXCEL_LARGE_COUNTS[0]
        cell_xfs = ET.Element(_excel_ns(mutated_styles.tag, 'cellXfs'), attrib={'count': _EXCEL_LARGE_COUNTS[1]})
        for _ in range(3):
            xf = ET.Element(_excel_ns(mutated_styles.tag, 'xf'), attrib={
                'numFmtId': '0',
                'fontId': '0',
                'fillId': '0',
                'borderId': '0',
                'xfId': '0',
                'applyAlignment': '1',
                'applyProtection': '1',
            })
            cell_xfs.append(xf)
        mutated_styles.append(cell_xfs)
        mutations.append(("excel_styles_expand", mutated))

        mutated = _clone_tree(root)
        mutated_styles = _excel_collect_nodes_by_suffixes(mutated, ('styleSheet', 'styles'))[0]
        to_remove = [child for child in mutated_styles if child.tag.endswith(('cellStyleXfs', 'cellXfs', 'dxfs'))]
        for child in to_remove:
            mutated_styles.remove(child)
        mutations.append(("excel_styles_prune", mutated))

    # Pivot cache definition mutation.
    pivot_nodes = _excel_collect_nodes(root, 'pivotCacheDefinition')
    if pivot_nodes:
        mutated = _clone_tree(root)
        mutated_pivot = _excel_collect_nodes(mutated, 'pivotCacheDefinition')[0]
        mutated_pivot.set('recordCount', _EXCEL_LARGE_COUNTS[0])
        mutated_pivot.set('refreshOnLoad', '1')
        mutated_pivot.set('enableRefresh', '1')
        cache_field = ET.Element(_excel_ns(mutated_pivot.tag, 'cacheField'), attrib={'name': '__MUT_PIVOT__', 'numFmtId': '0'})
        shared_items = ET.Element(_excel_ns(mutated_pivot.tag, 'sharedItems'), attrib={'count': _EXCEL_LARGE_COUNTS[1]})
        for idx in range(8):
            s_item = ET.Element(_excel_ns(mutated_pivot.tag, 's'))
            s_item.text = f"Pivot_{idx:04d}_{'X' * 64}"
            shared_items.append(s_item)
        cache_field.append(shared_items)
        mutated_pivot.append(cache_field)
        mutations.append(("excel_pivot_expand", mutated))

    # Extension list mutation.
    extlst_nodes = _excel_collect_nodes(root, 'extLst')
    if extlst_nodes:
        mutated = _clone_tree(root)
        mutated_ext = _excel_collect_nodes(mutated, 'extLst')[0]
        ext = ET.Element(_excel_ns(mutated_ext.tag, 'ext'), attrib={'uri': 'urn:schemas-microsoft-com:office:excel:calcChain#' + 'A' * 32})
        ext.text = _EXCEL_MASHUP_PAYLOAD
        mutated_ext.append(ext)
        mutations.append(("excel_extlst_payload", mutated))

        mutated = _clone_tree(root)
        mutated_ext = _excel_collect_nodes(mutated, 'extLst')[0]
        for child in list(mutated_ext):
            mutated_ext.remove(child)
        mutations.append(("excel_extlst_remove", mutated))

    # Connections mutation.
    connections_nodes = _excel_collect_nodes(root, 'connections')
    if connections_nodes:
        mutated = _clone_tree(root)
        mutated_conn = _excel_collect_nodes(mutated, 'connections')[0]
        connection = ET.Element(_excel_ns(mutated_conn.tag, 'connection'), attrib={
            'id': _EXCEL_LARGE_COUNTS[0],
            'odcFile': 'file://../../../../etc/passwd',
            'keepAlive': '1',
            'type': '10',
        })
        db_pr = ET.Element(_excel_ns(mutated_conn.tag, 'dbPr'), attrib={'connection': _EXCEL_CONNECTION_STRINGS[0]})
        oledb_pr = ET.Element(_excel_ns(mutated_conn.tag, 'oledbPr'), attrib={'commandType': 'Table', 'command': 'SELECT * FROM Sheet1'})
        connection.extend([db_pr, oledb_pr])
        mutated_conn.append(connection)
        mutations.append(("excel_connections_inject", mutated))

    # Revisions mutation.
    revisions_nodes = _excel_collect_nodes(root, 'revisions')
    if revisions_nodes:
        mutated = _clone_tree(root)
        mutated_rev = _excel_collect_nodes(mutated, 'revisions')[0]
        rrc = ET.Element(_excel_ns(mutated_rev.tag, 'rrc'), attrib={'rId': '-1', 'sheetId': _EXCEL_LARGE_COUNTS[0]})
        action = ET.Element(_excel_ns(mutated_rev.tag, 'action'), attrib={'type': 'unknown'})
        action.text = "corrupt"
        rrc.append(action)
        mutated_rev.append(rrc)
        mutations.append(("excel_revisions_inject", mutated))

    # Table structures mutation.
    table_nodes = _excel_collect_nodes(root, 'table')
    if table_nodes:
        mutated = _clone_tree(root)
        mutated_table = _excel_collect_nodes(mutated, 'table')[0]
        mutated_table.set('ref', _EXCEL_TABLE_REF_MUTATIONS[0])
        mutated_table.set('headerRowCount', _EXCEL_LARGE_COUNTS[0])
        mutated_table.set('totalsRowCount', _EXCEL_LARGE_COUNTS[0])
        mutated_table.set('tableType', 'worksheet')
        table_columns = _ensure_child_by_suffix(mutated_table, 'tableColumns')
        table_columns.attrib['count'] = _EXCEL_LARGE_COUNTS[1]
        for idx in range(32):
            column = ET.Element(_excel_ns(mutated_table.tag, 'tableColumn'), attrib={
                'id': str(1000 + idx),
                'name': f"Column_{idx:04d}_{'X' * 8}"
            })
            table_columns.append(column)
        style_info = _ensure_child_by_suffix(mutated_table, 'tableStyleInfo')
        style_info.attrib['name'] = 'TableStyleMedium2'
        for flag in _EXCEL_TABLE_STYLE_FLAGS:
            style_info.attrib[flag] = '1'
        mutations.append(("excel_table_expand", mutated))

        mutated = _clone_tree(root)
        mutated_table = _excel_collect_nodes(mutated, 'table')[0]
        style_info = _find_child_by_suffix(mutated_table, 'tableStyleInfo')
        if style_info is not None:
            mutated_table.remove(style_info)
        table_columns = _find_child_by_suffix(mutated_table, 'tableColumns')
        if table_columns is not None:
            for child in list(table_columns)[3:]:
                table_columns.remove(child)
            table_columns.attrib['count'] = '3'
        mutations.append(("excel_table_prune", mutated))

    table_parts_nodes = _excel_collect_nodes(root, 'tableParts')
    if table_parts_nodes:
        mutated = _clone_tree(root)
        mutated_parts = _excel_collect_nodes(mutated, 'tableParts')[0]
        mutated_parts.set('count', _EXCEL_LARGE_COUNTS[0])
        new_part = ET.Element(_excel_ns(mutated_parts.tag, 'tablePart'), attrib={'r:id': f"rId{_EXCEL_LARGE_COUNTS[1]}"})
        mutated_parts.append(new_part)
        mutations.append(("excel_tableparts_expand", mutated))

        mutated = _clone_tree(root)
        mutated_parts = _excel_collect_nodes(mutated, 'tableParts')[0]
        for child in list(mutated_parts)[1:]:
            mutated_parts.remove(child)
        if 'count' in mutated_parts.attrib:
            mutated_parts.attrib['count'] = '0'
        mutations.append(("excel_tableparts_prune", mutated))

    # Conditional formatting mutation.
    cf_nodes = _excel_collect_nodes(root, 'conditionalFormatting')
    if cf_nodes:
        mutated = _clone_tree(root)
        mutated_cf = _excel_collect_nodes(mutated, 'conditionalFormatting')[0]
        mutated_cf.set('sqref', 'A1:XFD1048576')
        mutated_cf.set('pivot', '1')
        for cf_type, extra_attrs in _EXCEL_CF_TYPES:
            cf_rule = ET.Element(_excel_ns(mutated_cf.tag, 'cfRule'), attrib={'type': cf_type, **extra_attrs})
            if cf_type == 'dataBar':
                data_bar = ET.Element(_excel_ns(mutated_cf.tag, 'dataBar'))
                data_bar.append(ET.Element(_excel_ns(mutated_cf.tag, 'cfvo'), attrib={'type': 'num', 'val': '-999999999'}))
                data_bar.append(ET.Element(_excel_ns(mutated_cf.tag, 'cfvo'), attrib={'type': 'num', 'val': '999999999'}))
                data_bar.append(ET.Element(_excel_ns(mutated_cf.tag, 'color'), attrib={'rgb': 'FFFF0000'}))
                cf_rule.append(data_bar)
            elif cf_type == 'colorScale':
                color_scale = ET.Element(_excel_ns(mutated_cf.tag, 'colorScale'))
                for val in ('-1', '0', '1'):
                    color_scale.append(ET.Element(_excel_ns(mutated_cf.tag, 'cfvo'), attrib={'type': 'num', 'val': val}))
                for rgb in ('FF00FF00', 'FFFFFF00', 'FFFF0000'):
                    color_scale.append(ET.Element(_excel_ns(mutated_cf.tag, 'color'), attrib={'rgb': rgb}))
                cf_rule.append(color_scale)
            else:
                icon_set = ET.Element(_excel_ns(mutated_cf.tag, 'iconSet'), attrib={'iconSet': '4TrafficLights', 'showValue': '0'})
                cf_rule.append(icon_set)
            mutated_cf.append(cf_rule)
        mutations.append(("excel_conditional_expand", mutated))

        mutated = _clone_tree(root)
        mutated_cf = _excel_collect_nodes(mutated, 'conditionalFormatting')[0]
        for child in list(mutated_cf):
            mutated_cf.remove(child)
        if 'sqref' in mutated_cf.attrib:
            mutated_cf.attrib['sqref'] = ''
        mutations.append(("excel_conditional_prune", mutated))

    # AutoFilter mutation.
    autofilter_nodes = _excel_collect_nodes(root, 'autoFilter')
    if autofilter_nodes:
        mutated = _clone_tree(root)
        mutated_filter = _excel_collect_nodes(mutated, 'autoFilter')[0]
        mutated_filter.set('ref', 'A1:XFD1048576')
        filter_column = ET.Element(_excel_ns(mutated_filter.tag, 'filterColumn'), attrib={'colId': '0'})
        filters = ET.Element(_excel_ns(mutated_filter.tag, 'filters'))
        filters.append(ET.Element(_excel_ns(mutated_filter.tag, 'filter'), attrib={'val': '999999999999'}))
        filters.append(ET.Element(_excel_ns(mutated_filter.tag, 'filter'), attrib={'val': '-999999999999'}))
        filter_column.append(filters)
        mutated_filter.append(filter_column)
        mutations.append(("excel_autofilter_expand", mutated))

        mutated = _clone_tree(root)
        mutated_filter = _excel_collect_nodes(mutated, 'autoFilter')[0]
        for child in list(mutated_filter):
            mutated_filter.remove(child)
        if 'ref' in mutated_filter.attrib:
            mutated_filter.attrib['ref'] = ''
        mutations.append(("excel_autofilter_prune", mutated))

    # Data validation mutation.
    data_validation_containers = _excel_collect_nodes(root, 'dataValidations')
    mutated = _clone_tree(root)
    if data_validation_containers:
        mutated_container = _excel_collect_nodes(mutated, 'dataValidations')[0]
    else:
        mutated_container = ET.Element(_excel_ns(mutated.tag, 'dataValidations'), attrib={'count': '0'})
        mutated.append(mutated_container)
    _clear_children(mutated_container)
    mutated_container.set('count', _EXCEL_LARGE_COUNTS[0])
    dv_tag = _excel_ns(mutated_container.tag, 'dataValidation')
    formula1_tag = _excel_ns(mutated_container.tag, 'formula1')
    data_validation = ET.Element(dv_tag, attrib={
        'type': 'list',
        'allowBlank': '1',
        'showErrorMessage': '1',
        'sqref': 'A1:XFD1048576',
        'errorStyle': 'stop',
    })
    formula1 = ET.Element(formula1_tag)
    formula1.text = '"THEMEVAL()+INDIRECT("A1")"'
    data_validation.append(formula1)
    mutated_container.append(data_validation)
    mutations.append(("excel_datavalidation_expand", mutated))

    mutated = _clone_tree(root)
    mutated_container = _excel_collect_nodes(mutated, 'dataValidations')
    if mutated_container:
        container = mutated_container[0]
        _clear_children(container)
        container.set('count', '0')
        mutations.append(("excel_datavalidation_clear", mutated))

    # AlternateContent mutation.
    alt_nodes = _excel_collect_nodes(root, 'AlternateContent')
    mc_ns = "http://schemas.openxmlformats.org/markup-compatibility/2006"
    mutated = _clone_tree(root)
    if alt_nodes:
        mutated_alt = _excel_collect_nodes(mutated, 'AlternateContent')[0]
    else:
        alt_tag = f"{{{mc_ns}}}AlternateContent"
        mutated_alt = ET.Element(alt_tag)
        mutated.append(mutated_alt)
    _clear_children(mutated_alt)
    choice = ET.Element(f"{{{mc_ns}}}Choice", attrib={'Requires': 'x14ac'})
    fallback = ET.Element(f"{{{mc_ns}}}Fallback")
    choice.append(ET.Element(_excel_ns(mutated.tag, 'controls')))
    fallback.append(ET.Element(_excel_ns(mutated.tag, 'extLst')))
    mutated_alt.append(choice)
    mutated_alt.append(fallback)
    mutations.append(("excel_alternatecontent_inject", mutated))

    mutated = _clone_tree(root)
    mutated_alt_nodes = _excel_collect_nodes(mutated, 'AlternateContent')
    if mutated_alt_nodes:
        _clear_children(mutated_alt_nodes[0])
        mutations.append(("excel_alternatecontent_clear", mutated))

    # HyperlinkBase attribute mutation.
    mutated = _clone_tree(root)
    mutated.attrib['HyperlinkBase'] = 'http://bypass.attacker.local/'
    mutations.append(("excel_hyperlink_base", mutated))

    # Hyperlinks mutation.
    hyperlink_nodes = _excel_collect_nodes(root, 'hyperlinks')
    if hyperlink_nodes:
        mutated = _clone_tree(root)
        mutated_hyper = _excel_collect_nodes(mutated, 'hyperlinks')[0]
        mutated_hyper.set('xmlns:xr', 'http://schemas.microsoft.com/office/spreadsheetml/2019/extlst')
        hyperlink = ET.Element(_excel_ns(mutated_hyper.tag, 'hyperlink'), attrib={
            'ref': 'A1:XFD1048576',
            'location': _EXCEL_HYPERLINK_LOCATIONS[0],
            'display': 'HYPERLINK_' + 'Z' * 32,
            'r:id': _EXCEL_DRAWING_REL_IDS[0],
        })
        hyperlink.attrib['tooltip'] = 'MegaHyperLink'
        hyperlink.attrib['target'] = _EXCEL_HYPERLINK_TARGETS[0]
        hyperlink.attrib['xr:uid'] = _EXCEL_HYPERLINK_UIDS[0]
        mutated_hyper.append(hyperlink)
        mutations.append(("excel_hyperlink_inject", mutated))

        mutated = _clone_tree(root)
        mutated_hyper = _excel_collect_nodes(mutated, 'hyperlinks')[0]
        for child in list(mutated_hyper):
            mutated_hyper.remove(child)
        mutations.append(("excel_hyperlink_clear", mutated))

    # Comments mutation.
    comments_nodes = _excel_collect_nodes(root, 'comments')
    if comments_nodes:
        mutated = _clone_tree(root)
        mutated_comments = _excel_collect_nodes(mutated, 'comments')[0]
        authors = _ensure_child_by_suffix(mutated_comments, 'authors')
        author = ET.Element(_excel_ns(authors.tag, 'author'))
        author.text = _EXCEL_AUTHOR_NAMES[0]
        authors.append(author)
        comment_list = _ensure_child_by_suffix(mutated_comments, 'commentList')
        new_comment = ET.Element(_excel_ns(comment_list.tag, 'comment'), attrib={
            'ref': 'XFD1048576',
            'authorId': str(max(0, len(list(authors)) - 1)),
        })
        text = ET.Element(_excel_ns(comment_list.tag, 'text'))
        run = ET.Element(_excel_ns(comment_list.tag, 'r'))
        run_props = ET.Element(_excel_ns(comment_list.tag, 'rPr'))
        run_props.append(ET.Element(_excel_ns(comment_list.tag, 'b')))  # bold flag
        run.append(run_props)
        run_text = ET.Element(_excel_ns(comment_list.tag, 't'))
        run_text.text = _EXCEL_COMMENT_TEXTS[0]
        run.append(run_text)
        text.append(run)
        new_comment.append(text)
        comment_list.append(new_comment)
        mutations.append(("excel_comment_inject", mutated))

        mutated = _clone_tree(root)
        mutated_comments = _excel_collect_nodes(mutated, 'comments')[0]
        for child in list(mutated_comments):
            mutated_comments.remove(child)
        mutations.append(("excel_comment_clear", mutated))

    # Threaded comments mutation.
    threaded_nodes = _excel_collect_nodes(root, 'threadedComments')
    if threaded_nodes:
        mutated = _clone_tree(root)
        mutated_threaded = _excel_collect_nodes(mutated, 'threadedComments')[0]
        tc = ET.Element(_excel_ns(mutated_threaded.tag, 'threadedComment'), attrib={
            'ref': 'A1',
            'dT': '2025-01-01T00:00:00Z',
            'personId': _EXCEL_AUTHOR_NAMES[0],
            'id': _EXCEL_THREAD_IDS[0],
        })
        body = ET.Element(_excel_ns(mutated_threaded.tag, 'text'))
        body.text = "Threaded -> " + _EXCEL_COMMENT_TEXTS[1]
        tc.append(body)
        mutated_threaded.append(tc)
        mutations.append(("excel_thread_comment_inject", mutated))

        mutated = _clone_tree(root)
        mutated_threaded = _excel_collect_nodes(mutated, 'threadedComments')[0]
        for child in list(mutated_threaded):
            mutated_threaded.remove(child)
        mutations.append(("excel_thread_comment_clear", mutated))

    # Sparkline mutation.
    spark_nodes = _excel_collect_nodes(root, 'sparklineGroups')
    if spark_nodes:
        mutated = _clone_tree(root)
        mutated_spark = _excel_collect_nodes(mutated, 'sparklineGroups')[0]
        spark_group = ET.Element(_excel_ns(mutated_spark.tag, 'sparklineGroup'), attrib={
            'type': 'column',
            'displayEmptyCellsAs': 'span',
            'manualMax': '999999',
            'manualMin': '-999999',
            'dateAxis': '1',
        })
        sparklines = ET.Element(_excel_ns(mutated_spark.tag, 'sparklines'))
        for idx in range(4):
            sparkline = ET.Element(_excel_ns(mutated_spark.tag, 'sparkline'))
            loc = ET.Element(_excel_ns(mutated_spark.tag, 'f'))
            loc.text = _EXCEL_SPARKLINE_RANGES[min(idx, len(_EXCEL_SPARKLINE_RANGES) - 1)]
            cell = ET.Element(_excel_ns(mutated_spark.tag, 'sqref'))
            cell.text = f"A{idx + 1}"
            sparkline.append(loc)
            sparkline.append(cell)
            sparklines.append(sparkline)
        spark_group.append(sparklines)
        mutated_spark.append(spark_group)
        mutations.append(("excel_sparkline_expand", mutated))

        mutated = _clone_tree(root)
        mutated_spark = _excel_collect_nodes(mutated, 'sparklineGroups')[0]
        for child in list(mutated_spark):
            mutated_spark.remove(child)
        mutations.append(("excel_sparkline_clear", mutated))

    # Drawing reference mutation.
    drawing_nodes = _excel_collect_nodes(root, 'drawing')
    if drawing_nodes:
        mutated = _clone_tree(root)
        mutated_drawing = _excel_collect_nodes(mutated, 'drawing')[0]
        mutated_drawing.attrib['r:id'] = _EXCEL_DRAWING_REL_IDS[0]
        mutated_drawing.attrib['xmlns:r'] = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
        mutated_drawing.text = (mutated_drawing.text or '') + "\n"
        mutations.append(("excel_drawing_retarget", mutated))

    legacy_nodes = _excel_collect_nodes(root, 'legacyDrawing')
    if legacy_nodes:
        mutated = _clone_tree(root)
        mutated_legacy = _excel_collect_nodes(mutated, 'legacyDrawing')[0]
        mutated_legacy.attrib['r:id'] = _EXCEL_DRAWING_REL_IDS[1]
        mutations.append(("excel_legacy_drawing_retarget", mutated))

    return mutations


def _is_excel_cell(element: ET.Element) -> bool:
    return element.tag.endswith('c')


def _is_excel_row(element: ET.Element) -> bool:
    return element.tag.endswith('row')


def _find_child_by_suffix(element: ET.Element, suffix: str) -> Optional[ET.Element]:
    for child in element:
        if child.tag.endswith(suffix):
            return child
    return None


def _ensure_child_by_suffix(element: ET.Element, suffix: str) -> ET.Element:
    child = _find_child_by_suffix(element, suffix)
    if child is not None:
        return child
    new_child = ET.Element(_excel_ns(element.tag, suffix))
    element.append(new_child)
    return new_child


def _remove_children_by_suffix(element: ET.Element, suffix: str):
    for child in list(element):
        if child.tag.endswith(suffix):
            element.remove(child)


def _apply_excel_cell_attribute_mutations(root: ET.Element, elements: List[ET.Element], maybe_emit) -> bool:
    for idx, element in enumerate(elements):
        if not _is_excel_cell(element):
            continue

        current_ref = element.attrib.get('r')
        for candidate_ref in _EXCEL_CELL_REFERENCE_MUTATIONS:
            if candidate_ref == current_ref:
                continue
            mutated_root = _clone_tree(root)
            mutated_cell = _iter_elements(mutated_root)[idx]
            mutated_cell.attrib['r'] = candidate_ref
            if maybe_emit(mutated_root, "excel_attr_ref"):
                return True

        for style in _EXCEL_CELL_STYLE_MUTATIONS:
            if element.attrib.get('s') == style:
                continue
            mutated_root = _clone_tree(root)
            mutated_cell = _iter_elements(mutated_root)[idx]
            if style:
                mutated_cell.attrib['s'] = style
            elif 's' in mutated_cell.attrib:
                del mutated_cell.attrib['s']
            if maybe_emit(mutated_root, "excel_attr_style"):
                return True

        for new_type, new_value in _EXCEL_CELL_TYPE_MUTATIONS:
            mutated_root = _clone_tree(root)
            mutated_cell = _iter_elements(mutated_root)[idx]
            mutated_cell.attrib['t'] = new_type
            if new_type == "inlineStr":
                _remove_children_by_suffix(mutated_cell, 'v')
                inline_container = _ensure_child_by_suffix(mutated_cell, 'is')
                text_child = _ensure_child_by_suffix(inline_container, 't')
                text_child.text = new_value
            else:
                inline_container = _find_child_by_suffix(mutated_cell, 'is')
                if inline_container is not None:
                    mutated_cell.remove(inline_container)
                value_child = _ensure_child_by_suffix(mutated_cell, 'v')
                value_child.text = new_value
            if maybe_emit(mutated_root, "excel_attr_type"):
                return True
        original_formula_attr = element.attrib.get('F')
        for theme_formula in _EXCEL_THEMEVAL_FORMULAS:
            if theme_formula == original_formula_attr:
                continue
            mutated_root = _clone_tree(root)
            mutated_cell = _iter_elements(mutated_root)[idx]
            mutated_cell.attrib['F'] = theme_formula
            if maybe_emit(mutated_root, "excel_attr_themeval"):
                return True
        if original_formula_attr is not None:
            mutated_root = _clone_tree(root)
            mutated_cell = _iter_elements(mutated_root)[idx]
            mutated_cell.attrib.pop('F', None)
            if maybe_emit(mutated_root, "excel_attr_themeval_clear"):
                return True
    return False


def _apply_excel_row_attribute_mutations(root: ET.Element, elements: List[ET.Element], maybe_emit) -> bool:
    for idx, element in enumerate(elements):
        if not _is_excel_row(element):
            continue
        current_ref = element.attrib.get('r')
        for candidate_ref in _EXCEL_ROW_REFERENCE_MUTATIONS:
            if candidate_ref == current_ref:
                continue
            mutated_root = _clone_tree(root)
            mutated_row = _iter_elements(mutated_root)[idx]
            mutated_row.attrib['r'] = candidate_ref
            if maybe_emit(mutated_root, "excel_row_ref"):
                return True
        current_spans = element.attrib.get('spans')
        for candidate_span in _EXCEL_ROW_SPAN_MUTATIONS:
            if candidate_span == current_spans:
                continue
            mutated_root = _clone_tree(root)
            mutated_row = _iter_elements(mutated_root)[idx]
            mutated_row.attrib['spans'] = candidate_span
            if maybe_emit(mutated_root, "excel_row_spans"):
                return True
    return False


def _apply_excel_cell_value_mutations(root: ET.Element, elements: List[ET.Element], maybe_emit) -> bool:
    payloads = _excel_cell_value_payloads()
    for idx, element in enumerate(elements):
        if not _is_excel_cell(element):
            continue
        value_child = _find_child_by_suffix(element, 'v')
        if value_child is None:
            continue
        for label_suffix, new_text in payloads:
            mutated_root = _clone_tree(root)
            target_cell = _iter_elements(mutated_root)[idx]
            mutated_value = _find_child_by_suffix(target_cell, 'v')
            if mutated_value is None:
                continue
            mutated_value.text = new_text
            if maybe_emit(mutated_root, f"excel_{label_suffix}"):
                return True
    return False


def _apply_excel_datetime_mutations(root: ET.Element, elements: List[ET.Element], maybe_emit) -> bool:
    for idx, element in enumerate(elements):
        if not _is_excel_cell(element):
            continue
        cell_type = element.attrib.get('t', '')
        value_child = _find_child_by_suffix(element, 'v')
        if value_child is None:
            continue
        original_text = value_child.text or ''
        is_datetime_cell = cell_type in ('d', 'date') or _ISO8601_REGEX.match(original_text or '')
        if not is_datetime_cell:
            continue
        for variant_idx, new_text in enumerate(_excel_datetime_payloads(original_text)):
            mutated_root = _clone_tree(root)
            target_cell = _iter_elements(mutated_root)[idx]
            mutated_value = _find_child_by_suffix(target_cell, 'v')
            if mutated_value is None:
                continue
            mutated_value.text = new_text
            if maybe_emit(mutated_root, f"excel_datetime_{variant_idx}"):
                return True
    return False


def _excel_bypass_mutations(root: ET.Element) -> List[Tuple[str, ET.Element]]:
    mutations: List[Tuple[str, ET.Element]] = []

    def prepare_basic(mut_root: ET.Element):
        if 'xmlns:xr' not in mut_root.attrib:
            mut_root.set('xmlns:xr', 'http://schemas.microsoft.com/office/spreadsheetml/2014/revision')
        dimension = _get_or_create_child_by_suffix(mut_root, 'dimension')
        sheet_views = _get_or_create_child_by_suffix(mut_root, 'sheetViews')
        sheet_view = _get_or_create_child_by_suffix(sheet_views, 'sheetView')
        sheet_view.set('workbookViewId', '0')
        sheet_format = _get_or_create_child_by_suffix(mut_root, 'sheetFormatPr')
        sheet_format.set('defaultRowHeight', '15')
        sheet_data = _get_or_create_child_by_suffix(mut_root, 'sheetData')
        return dimension, sheet_data

    def build_safe_sheet(mut_root: ET.Element, dimension: ET.Element, sheet_data: ET.Element):
        dimension.set('ref', 'A1:C3')
        _clear_children(sheet_data)
        row_tag = _excel_ns(sheet_data.tag, 'row')
        cell_tag = _excel_ns(sheet_data.tag, 'c')
        value_tag = _excel_ns(sheet_data.tag, 'v')
        row = ET.Element(row_tag, attrib={'r': '1', 'spans': '1:3'})
        for idx, text in enumerate(("safe", "data", "test"), start=1):
            ref = chr(ord('A') + idx - 1) + "1"
            cell = _create_cell(cell_tag, value_tag, ref, style='0', cell_type='str', value=text)
            row.append(cell)
        sheet_data.append(row)
        return row_tag, cell_tag, value_tag

    def ensure_merge(mut_root: ET.Element, ranges: Sequence[str]):
        merge_cells = _get_or_create_child_by_suffix(mut_root, 'mergeCells')
        _clear_children(merge_cells)
        merge_cells.set('count', str(len(ranges)))
        merge_tag = _excel_ns(merge_cells.tag, 'mergeCell')
        for ref in ranges:
            merge_cells.append(ET.Element(merge_tag, attrib={'ref': ref}))
        return merge_cells

    # Stage 1: safe baseline
    stage1 = _clone_tree(root)
    dimension, sheet_data = prepare_basic(stage1)
    row_tag, cell_tag, value_tag = build_safe_sheet(stage1, dimension, sheet_data)
    mutations.append(("excel_bypass_stage1", stage1))

    # Stage 2: FirePendingEvents pathway with heavy merges and conditional formatting
    stage2 = _clone_tree(stage1)
    merges = [
        "A1:XFD1048576",
        "A1:A1048576",
        "A1:XFD1",
    ]
    merge_cells = ensure_merge(stage2, merges)
    merge_cells.set('count', "999999")
    cf = _get_or_create_child_by_suffix(stage2, 'conditionalFormatting')
    cf.set('sqref', 'A1:XFD1048576')
    cf_rule = _get_or_create_child_by_suffix(cf, 'cfRule')
    cf_rule.attrib.update({'type': 'expression', 'priority': '1'})
    formula_tag = _excel_ns(cf_rule.tag, 'formula')
    _clear_children(cf_rule)
    formula_elem = ET.Element(formula_tag)
    formula_elem.text = "=TRUE"
    cf_rule.append(formula_elem)
    mutations.append(("excel_bypass_stage2", stage2))

    # Stage 3: Formula and hyperlink stress
    stage3 = _clone_tree(stage2)
    sheet_data3 = _get_or_create_child_by_suffix(stage3, 'sheetData')
    row_formula = ET.Element(row_tag, attrib={'r': '2', 'spans': '1:5'})
    formula_tag_cell = _excel_ns(sheet_data3.tag, 'f')
    array_formula = _create_formula_cell(
        cell_tag, value_tag, formula_tag_cell, 'A2',
        "=SUM(IF(ISERROR(LARGE(ROW(1:1000000),ROW(1:1000))),0,LARGE(ROW(1:1000000),ROW(1:1000))))",
        {'t': 'array', 'ref': 'A2:Z1000', 'si': '0'}
    )
    shared_formula = _create_formula_cell(
        cell_tag, value_tag, formula_tag_cell, 'B2',
        '=CONCATENATE(REPT("A",65535),REPT("B",65535))',
        {'t': 'shared', 'ref': 'B2:XFD1048576', 'si': '999999'}
    )
    simple_formula = _create_formula_cell(
        cell_tag, value_tag, formula_tag_cell, 'C2',
        '=A2+B2',
        None
    )
    row_formula.extend([array_formula, shared_formula, simple_formula])
    sheet_data3.append(row_formula)
    hyperlinks = _get_or_create_child_by_suffix(stage3, 'hyperlinks')
    hyperlinks.set('xmlns:xr', 'http://schemas.microsoft.com/office/spreadsheetml/2014/revision')
    _clear_children(hyperlinks)
    hyperlink_tag = _excel_ns(hyperlinks.tag, 'hyperlink')
    tooltip = "A" * 1024
    display = "B" * 512
    for idx in range(_BYPASS_HYPERLINK_REPEAT):
        hyperlink = ET.Element(hyperlink_tag, attrib={
            'ref': 'A1',
            'r:id': f"rId{idx + 1}",
            'tooltip': tooltip,
            'display': display,
            'xr:uid': _EXCEL_HYPERLINK_UIDS[idx % len(_EXCEL_HYPERLINK_UIDS)],
        })
        hyperlinks.append(hyperlink)
    mutations.append(("excel_bypass_stage3", stage3))

    # Stage 4: Memory exhaustion and integer overflow patterns
    stage4 = _clone_tree(stage3)
    if 'xmlns:x14ac' not in stage4.attrib:
        stage4.set('xmlns:x14ac', 'http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac')
    sheet_data4 = _get_or_create_child_by_suffix(stage4, 'sheetData')
    unicode_row = ET.Element(row_tag, attrib={'r': '3', 'spans': '1:3', 'x14ac:dyDescent': '999999'})
    unicode_row.append(_create_cell(cell_tag, value_tag, 'A3', '0', 'str', '\ufeffUTF8_BOM'))
    unicode_row.append(_create_cell(cell_tag, value_tag, 'B3', '0', 'str', '\u2066CTRL\u2069'))
    unicode_row.append(_create_cell(cell_tag, value_tag, 'C3', '0', 'str', '\u202ERTL\u202CTest\u202C'))
    sheet_data4.append(unicode_row)

    overflow_row = ET.Element(row_tag, attrib={'r': '2147483647', 'spans': '1:2147483647'})
    overflow_row.append(_create_cell(cell_tag, value_tag, 'A2147483647', '4294967295', 'str', 'overflow_test'))
    sheet_data4.append(overflow_row)

    for idx in range(_BYPASS_MEMORY_ROWS):
        r_index = 10 + idx
        row = ET.Element(row_tag, attrib={'r': str(r_index), 'spans': '1:1'})
        value = f"payload_{r_index}_{'X' * 32}"
        row.append(_create_cell(cell_tag, value_tag, f"A{r_index}", '0', 'str', value))
        sheet_data4.append(row)

    merge_cells4 = _get_or_create_child_by_suffix(stage4, 'mergeCells')
    merge_cells4.set('count', _EXCEL_LARGE_COUNTS[1])
    if not list(merge_cells4):
        merge_cells4.append(ET.Element(_excel_ns(merge_cells4.tag, 'mergeCell'), attrib={'ref': 'A1:A2'}))

    ext_list = _get_or_create_child_by_suffix(stage4, 'extLst')
    _clear_children(ext_list)
    ext_tag = _excel_ns(ext_list.tag, 'ext')
    custom_ext = ET.Element(ext_tag, attrib={'uri': _BYPASS_EXT_URI})
    custom_data = ET.Element('customData')
    custom_data.text = _BYPASS_EXT_PAYLOAD
    custom_ext.append(custom_data)
    ext_list.append(custom_ext)

    mutations.append(("excel_bypass_stage4", stage4))
    return mutations


def _apply_excel_bypass_mutations(root: ET.Element, maybe_emit) -> bool:
    mutations = _excel_bypass_mutations(root)
    for label, mutated_root in mutations:
        if maybe_emit(mutated_root, label):
            return True
    return False


def _apply_excel_formula_mutations(root: ET.Element, elements: List[ET.Element], maybe_emit) -> bool:
    for idx, element in enumerate(elements):
        if _local_name(element.tag) != 'f':
            continue
        original_type = element.attrib.get('t')
        for candidate in _EXCEL_FORMULA_TYPES:
            if candidate == original_type:
                continue
            mutated_root = _clone_tree(root)
            target_formula = _iter_elements(mutated_root)[idx]
            if candidate:
                target_formula.set('t', candidate)
            else:
                target_formula.attrib.pop('t', None)
            if maybe_emit(mutated_root, "excel_formula_type"):
                return True
        original_si = element.attrib.get('si')
        for candidate in _EXCEL_SHARED_INDEX_MUTATIONS:
            if candidate == original_si:
                continue
            mutated_root = _clone_tree(root)
            target_formula = _iter_elements(mutated_root)[idx]
            target_formula.set('si', candidate)
            if maybe_emit(mutated_root, "excel_formula_shared"):
                return True
        original_ref = element.attrib.get('ref')
        for candidate in _EXCEL_FORMULA_REF_MUTATIONS:
            if candidate == original_ref:
                continue
            mutated_root = _clone_tree(root)
            target_formula = _iter_elements(mutated_root)[idx]
            target_formula.set('ref', candidate)
            target_formula.set('ca', '1')
            if maybe_emit(mutated_root, "excel_formula_ref"):
                return True
        original_text = element.text or ''
        for candidate in _EXCEL_FORMULA_TEXT_MUTATIONS:
            if candidate == original_text:
                continue
            mutated_root = _clone_tree(root)
            target_formula = _iter_elements(mutated_root)[idx]
            target_formula.text = candidate
            if maybe_emit(mutated_root, "excel_formula_text"):
                return True
    return False


def _apply_excel_column_mutations(root: ET.Element, elements: List[ET.Element], maybe_emit) -> bool:
    for idx, element in enumerate(elements):
        if _local_name(element.tag) != 'col':
            continue
        original_min = element.attrib.get('min')
        for candidate in _EXCEL_COLUMN_MIN_MUTATIONS:
            if candidate == original_min:
                continue
            mutated_root = _clone_tree(root)
            target_col = _iter_elements(mutated_root)[idx]
            target_col.set('min', candidate)
            if maybe_emit(mutated_root, "excel_col_min"):
                return True
        original_max = element.attrib.get('max')
        for candidate in _EXCEL_COLUMN_MAX_MUTATIONS:
            if candidate == original_max:
                continue
            mutated_root = _clone_tree(root)
            target_col = _iter_elements(mutated_root)[idx]
            target_col.set('max', candidate)
            if maybe_emit(mutated_root, "excel_col_max"):
                return True
        original_width = element.attrib.get('width')
        for candidate in _EXCEL_COLUMN_WIDTH_MUTATIONS:
            if candidate == original_width:
                continue
            mutated_root = _clone_tree(root)
            target_col = _iter_elements(mutated_root)[idx]
            target_col.set('width', candidate)
            target_col.set('customWidth', '1')
            if maybe_emit(mutated_root, "excel_col_width"):
                return True
        original_style = element.attrib.get('style')
        for candidate in _EXCEL_COLUMN_STYLE_MUTATIONS:
            if candidate == original_style:
                continue
            mutated_root = _clone_tree(root)
            target_col = _iter_elements(mutated_root)[idx]
            target_col.set('style', candidate)
            if maybe_emit(mutated_root, "excel_col_style"):
                return True
        mutated_root = _clone_tree(root)
        target_col = _iter_elements(mutated_root)[idx]
        target_col.set('hidden', '1')
        target_col.set('outlineLevel', '7')
        if maybe_emit(mutated_root, "excel_col_hidden"):
            return True
    return False


def _apply_excel_merge_mutations(root: ET.Element, maybe_emit) -> bool:
    merge_nodes = _excel_collect_nodes(root, 'mergeCells')
    if not merge_nodes:
        return False
    for merge_idx, merge_node in enumerate(merge_nodes[:3]):
        mutated_root = _clone_tree(root)
        mutated_merge = _excel_collect_nodes(mutated_root, 'mergeCells')[merge_idx]
        mutated_merge.set('count', _EXCEL_LARGE_COUNTS[0])
        mutated_merge.append(ET.Element(_excel_ns(mutated_merge.tag, 'mergeCell'), attrib={'ref': _EXCEL_MERGE_REFS[0]}))
        if maybe_emit(mutated_root, "excel_merge_expand"):
            return True
        for ref in _EXCEL_MERGE_REFS:
            existing_refs = [child.attrib.get('ref') for child in merge_node]
            if ref in existing_refs:
                continue
            mutated_root = _clone_tree(root)
            mutated_merge = _excel_collect_nodes(mutated_root, 'mergeCells')[merge_idx]
            for child in mutated_merge:
                child.set('ref', ref)
            if maybe_emit(mutated_root, "excel_merge_ref"):
                return True
        mutated_root = _clone_tree(root)
        mutated_merge = _excel_collect_nodes(mutated_root, 'mergeCells')[merge_idx]
        for child in list(mutated_merge):
            mutated_merge.remove(child)
        mutated_merge.set('count', '0')
        if maybe_emit(mutated_root, "excel_merge_clear"):
            return True
    return False


def _apply_excel_control_mutations(root: ET.Element, maybe_emit) -> bool:
    controls_nodes = _excel_collect_nodes(root, 'controls')
    mutated_root = _clone_tree(root)
    if controls_nodes:
        mutated_controls = _excel_collect_nodes(mutated_root, 'controls')[0]
    else:
        controls_tag = _excel_ns(mutated_root.tag, 'controls')
        mutated_controls = ET.Element(controls_tag)
        mutated_root.append(mutated_controls)
    control_tag = _excel_ns(mutated_controls.tag, 'control')
    control_pr_tag = _excel_ns(mutated_controls.tag, 'controlPr')
    control = ET.Element(control_tag, attrib={
        'shapeId': '1024',
        'r:id': _EXCEL_DRAWING_REL_IDS[2],
        'progId': _EXCEL_CONTROL_PROGIDS[0],
        'id': _EXCEL_CONTROL_IDS[0],
    })
    control_pr = ET.Element(control_pr_tag, attrib={
        'autoFill': 'false',
        'autoLine': 'false',
        'lockedText': 'false',
    })
    control.append(control_pr)
    mutated_controls.append(control)
    if maybe_emit(mutated_root, "excel_controls_inject"):
        return True

    mutated_root = _clone_tree(root)
    mutated_controls = _excel_collect_nodes(mutated_root, 'controls')
    if mutated_controls:
        parent = mutated_controls[0]
        _clear_children(parent)
        if maybe_emit(mutated_root, "excel_controls_clear"):
            return True
    return False


def _apply_excel_connection_mutations(root: ET.Element, maybe_emit) -> bool:
    connections_nodes = _excel_collect_nodes(root, 'connections')
    mutated_root = _clone_tree(root)
    if connections_nodes:
        mutated_connections = _excel_collect_nodes(mutated_root, 'connections')[0]
    else:
        mutated_connections = ET.Element(_excel_ns(mutated_root.tag, 'connections'))
        mutated_root.append(mutated_connections)
    connection_tag = _excel_ns(mutated_connections.tag, 'connection')
    db_tag = _excel_ns(mutated_connections.tag, 'dbPr')
    connection = ET.Element(connection_tag, attrib={
        'id': _EXCEL_CONNECTION_IDS[0],
        'name': _EXCEL_CONNECTION_NAMES[0],
        'type': '1',
        'odcFile': 'file://C:/Users/Public/Documents/bypass.odc',
        'keepAlive': '1',
        'interval': '0',
    })
    db_pr = ET.Element(db_tag, attrib={
        'connection': _EXCEL_CONNECTION_STRINGS[0],
        'command': 'SELECT * FROM BypassTable',
        'commandType': 'Table',
    })
    connection.append(db_pr)
    mutated_connections.append(connection)
    mutated_connections.attrib['count'] = str(len(list(mutated_connections)))
    if maybe_emit(mutated_root, "excel_connections_bypass"):
        return True

    mutated_root = _clone_tree(root)
    mutated_connections = _excel_collect_nodes(mutated_root, 'connections')
    if mutated_connections:
        parent = mutated_connections[0]
        _clear_children(parent)
        parent.attrib['count'] = '0'
        if maybe_emit(mutated_root, "excel_connections_clear"):
            return True
    return False


def _apply_excel_reference_structure_mutations(root: ET.Element, maybe_emit) -> bool:
    for label_suffix, mutated_root in _excel_reference_mutations(root):
        if maybe_emit(mutated_root, label_suffix):
            return True
    return False


def _apply_excel_structure_mutations(root: ET.Element, maybe_emit) -> bool:
    for label_suffix, mutated_root in _excel_structure_mutations(root):
        if maybe_emit(mutated_root, label_suffix):
            return True
    return False


def _random_excel_cell_mutation(root: ET.Element, elements: List[ET.Element]) -> Optional[Tuple[ET.Element, str]]:
    candidate_indices = []
    for idx, element in enumerate(elements):
        if _is_excel_cell(element) and _find_child_by_suffix(element, 'v') is not None:
            candidate_indices.append(idx)
    if not candidate_indices:
        return None

    target_idx = rand.select(candidate_indices)
    payload_label, new_text = rand.select(_excel_cell_value_payloads())
    mutated_root = _clone_tree(root)
    mutated_cell = _iter_elements(mutated_root)[target_idx]
    mutated_value = _find_child_by_suffix(mutated_cell, 'v')
    if mutated_value is None:
        return None
    mutated_value.text = new_text
    return mutated_root, f"excel_havoc_{payload_label}"


def _random_excel_datetime_mutation(root: ET.Element, elements: List[ET.Element]) -> Optional[Tuple[ET.Element, str]]:
    candidate_indices = []
    for idx, element in enumerate(elements):
        if not _is_excel_cell(element):
            continue
        value_child = _find_child_by_suffix(element, 'v')
        if value_child is None:
            continue
        text = value_child.text or ''
        cell_type = element.attrib.get('t', '')
        if cell_type in ('d', 'date') or _ISO8601_REGEX.match(text):
            candidate_indices.append((idx, text))
    if not candidate_indices:
        return None

    target_idx, original_text = rand.select(candidate_indices)
    mutated_root = _clone_tree(root)
    mutated_cell = _iter_elements(mutated_root)[target_idx]
    mutated_value = _find_child_by_suffix(mutated_cell, 'v')
    if mutated_value is None:
        return None
    mutated_value.text = rand.select(_excel_datetime_payloads(original_text))
    return mutated_root, "excel_havoc_datetime"


def _random_excel_bypass_mutation(root: ET.Element) -> Optional[Tuple[ET.Element, str]]:
    mutations = _excel_bypass_mutations(root)
    if not mutations:
        return None
    label, mutated_root = rand.select(mutations)
    return mutated_root, f"{label}_havoc"


def _random_excel_formula_mutation(root: ET.Element, elements: List[ET.Element]) -> Optional[Tuple[ET.Element, str]]:
    candidates = [idx for idx, element in enumerate(elements) if _local_name(element.tag) == 'f']
    if not candidates:
        return None
    target_idx = rand.select(candidates)
    mutated_root = _clone_tree(root)
    mutated_formula = _iter_elements(mutated_root)[target_idx]
    choice = rand.int(3)
    if choice == 0:
        formula_type = rand.select(_EXCEL_FORMULA_TYPES)
        if formula_type:
            mutated_formula.set('t', formula_type)
        else:
            mutated_formula.attrib.pop('t', None)
        label = "excel_havoc_formula_type"
    elif choice == 1:
        mutated_formula.text = rand.select(_EXCEL_FORMULA_TEXT_MUTATIONS)
        label = "excel_havoc_formula_text"
    else:
        mutated_formula.set('si', rand.select(_EXCEL_SHARED_INDEX_MUTATIONS))
        mutated_formula.set('ref', rand.select(_EXCEL_FORMULA_REF_MUTATIONS))
        label = "excel_havoc_formula_attr"
    return mutated_root, label


def _random_excel_reference_mutation(root: ET.Element) -> Optional[Tuple[ET.Element, str]]:
    mutations = _excel_reference_mutations(root)
    if not mutations:
        return None
    label, mutated_root = rand.select(mutations)
    return mutated_root, f"{label}_havoc"


def _random_excel_structure_mutation(root: ET.Element) -> Optional[Tuple[ET.Element, str]]:
    mutations = _excel_structure_mutations(root)
    if not mutations:
        return None
    label, mutated_root = rand.select(mutations)
    return mutated_root, f"{label}_havoc"


def _random_excel_column_mutation(root: ET.Element, elements: List[ET.Element]) -> Optional[Tuple[ET.Element, str]]:
    candidates = [idx for idx, element in enumerate(elements) if _local_name(element.tag) == 'col']
    if not candidates:
        return None
    target_idx = rand.select(candidates)
    mutated_root = _clone_tree(root)
    mutated_col = _iter_elements(mutated_root)[target_idx]
    choice = rand.int(3)
    if choice == 0:
        mutated_col.set('min', rand.select(_EXCEL_COLUMN_MIN_MUTATIONS))
        mutated_col.set('max', rand.select(_EXCEL_COLUMN_MAX_MUTATIONS))
        label = "excel_havoc_col_range"
    elif choice == 1:
        mutated_col.set('width', rand.select(_EXCEL_COLUMN_WIDTH_MUTATIONS))
        mutated_col.set('customWidth', '1')
        label = "excel_havoc_col_width"
    else:
        mutated_col.set('style', rand.select(_EXCEL_COLUMN_STYLE_MUTATIONS))
        mutated_col.set('hidden', rand.select(('0', '1')))
        label = "excel_havoc_col_style"
    return mutated_root, label


def _random_excel_merge_mutation(root: ET.Element) -> Optional[Tuple[ET.Element, str]]:
    merge_nodes = _excel_collect_nodes(root, 'mergeCells')
    if not merge_nodes:
        return None
    mutated_root = _clone_tree(root)
    mutated_merge = rand.select(_excel_collect_nodes(mutated_root, 'mergeCells'))
    choice = rand.int(3)
    if choice == 0:
        mutated_merge.set('count', rand.select(_EXCEL_LARGE_COUNTS))
        mutated_merge.append(ET.Element(_excel_ns(mutated_merge.tag, 'mergeCell'), attrib={'ref': rand.select(_EXCEL_MERGE_REFS)}))
        label = "excel_havoc_merge_expand"
    elif choice == 1:
        for child in mutated_merge:
            child.set('ref', rand.select(_EXCEL_MERGE_REFS))
        label = "excel_havoc_merge_ref"
    else:
        for child in list(mutated_merge):
            mutated_merge.remove(child)
        mutated_merge.set('count', '0')
        label = "excel_havoc_merge_clear"
    return mutated_root, label


def _random_excel_control_mutation(root: ET.Element) -> Optional[Tuple[ET.Element, str]]:
    controls_nodes = _excel_collect_nodes(root, 'controls')
    mutated_root = _clone_tree(root)
    if controls_nodes:
        mutated_controls = _excel_collect_nodes(mutated_root, 'controls')[0]
    else:
        controls_tag = _excel_ns(mutated_root.tag, 'controls')
        mutated_controls = ET.Element(controls_tag)
        mutated_root.append(mutated_controls)
    control_tag = _excel_ns(mutated_controls.tag, 'control')
    control_pr_tag = _excel_ns(mutated_controls.tag, 'controlPr')
    control = ET.Element(control_tag, attrib={
        'shapeId': str(1024 + rand.int(1024)),
        'r:id': rand.select(_EXCEL_DRAWING_REL_IDS),
        'progId': rand.select(_EXCEL_CONTROL_PROGIDS),
        'id': rand.select(_EXCEL_CONTROL_IDS),
    })
    control_pr = ET.Element(control_pr_tag, attrib={
        'autoFill': rand.select(('true', 'false')),
        'autoLine': rand.select(('true', 'false')),
        'locked': rand.select(('0', '1')),
    })
    control.append(control_pr)
    mutated_controls.append(control)
    return mutated_root, "excel_havoc_controls"


def _random_excel_connection_mutation(root: ET.Element) -> Optional[Tuple[ET.Element, str]]:
    connections_nodes = _excel_collect_nodes(root, 'connections')
    mutated_root = _clone_tree(root)
    if connections_nodes:
        mutated_connections = _excel_collect_nodes(mutated_root, 'connections')[0]
    else:
        mutated_connections = ET.Element(_excel_ns(mutated_root.tag, 'connections'))
        mutated_root.append(mutated_connections)
    connection_tag = _excel_ns(mutated_connections.tag, 'connection')
    db_tag = _excel_ns(mutated_connections.tag, 'dbPr')
    connection = ET.Element(connection_tag, attrib={
        'id': rand.select(_EXCEL_CONNECTION_IDS),
        'name': rand.select(_EXCEL_CONNECTION_NAMES),
        'type': rand.select(('1', '2', '5')),
        'odcFile': 'file://C:/Bypass/connection.odc',
    })
    db_pr = ET.Element(db_tag, attrib={
        'connection': rand.select(_EXCEL_CONNECTION_STRINGS),
        'command': 'SELECT * FROM Sheet1',
        'commandType': rand.select(('Cube', 'Table', 'Default')),
    })
    connection.append(db_pr)
    mutated_connections.append(connection)
    return mutated_root, "excel_havoc_connections"


def _random_excel_cell_attribute_mutation(root: ET.Element, elements: List[ET.Element]) -> Optional[Tuple[ET.Element, str]]:
    candidates = [idx for idx, element in enumerate(elements) if _is_excel_cell(element)]
    if not candidates:
        return None
    target_idx = rand.select(candidates)
    mutated_root = _clone_tree(root)
    mutated_cell = _iter_elements(mutated_root)[target_idx]

    choice = rand.int(4)
    if choice == 0:
        new_ref = rand.select(_EXCEL_CELL_REFERENCE_MUTATIONS)
        mutated_cell.attrib['r'] = new_ref
        label = "excel_havoc_attr_ref"
    elif choice == 1:
        new_style = rand.select(_EXCEL_CELL_STYLE_MUTATIONS)
        if new_style:
            mutated_cell.attrib['s'] = new_style
        elif 's' in mutated_cell.attrib:
            del mutated_cell.attrib['s']
        label = "excel_havoc_attr_style"
    elif choice == 2:
        new_type, new_value = rand.select(_EXCEL_CELL_TYPE_MUTATIONS)
        mutated_cell.attrib['t'] = new_type
        if new_type == "inlineStr":
            _remove_children_by_suffix(mutated_cell, 'v')
            inline_container = _ensure_child_by_suffix(mutated_cell, 'is')
            text_child = _ensure_child_by_suffix(inline_container, 't')
            text_child.text = new_value
        else:
            inline_container = _find_child_by_suffix(mutated_cell, 'is')
            if inline_container is not None:
                mutated_cell.remove(inline_container)
            value_child = _ensure_child_by_suffix(mutated_cell, 'v')
            value_child.text = new_value
        label = "excel_havoc_attr_type"
    else:
        mutated_cell.attrib['F'] = rand.select(_EXCEL_THEMEVAL_FORMULAS)
        label = "excel_havoc_attr_themeval"
    return mutated_root, label


def _random_excel_row_attribute_mutation(root: ET.Element, elements: List[ET.Element]) -> Optional[Tuple[ET.Element, str]]:
    candidates = [idx for idx, element in enumerate(elements) if _is_excel_row(element)]
    if not candidates:
        return None
    target_idx = rand.select(candidates)
    mutated_root = _clone_tree(root)
    mutated_row = _iter_elements(mutated_root)[target_idx]
    if rand.int(2) == 0:
        mutated_row.attrib['r'] = rand.select(_EXCEL_ROW_REFERENCE_MUTATIONS)
        label = "excel_havoc_row_ref"
    else:
        mutated_row.attrib['spans'] = rand.select(_EXCEL_ROW_SPAN_MUTATIONS)
        label = "excel_havoc_row_spans"
    return mutated_root, label


_LOCAL_DICT_CACHE: Set[bytes] = set()


_TAG_REGEX = re.compile(r'<\s*/?\s*([A-Za-z_:][\w:.-]*)')
_ATTR_REGEX = re.compile(r'([A-Za-z_:][\w:.-]*)\s*=')
_ATTR_VALUE_REGEX = re.compile(r'=\s*(?:"([^"]*)"|\'([^\']*)\')')
_SIMPLE_NAME_REGEX = re.compile(r'^[A-Za-z_:][\w:.-]*$')
_ISO8601_REGEX = re.compile(r'^\s*\d{4,}-\d{2}-\d{2}T')


def _decode_token_bytes(data: bytes) -> str:
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return data.decode('latin1', 'ignore')


def _scan_xml_tokens_from_text(text: str):
    tags = set(_TAG_REGEX.findall(text))
    attrs = set(match.group(1) for match in _ATTR_REGEX.finditer(text))
    attr_values = set()
    text_tokens = set()

    for match in _ATTR_VALUE_REGEX.finditer(text):
        value = match.group(1) or match.group(2)
        if value:
            trimmed = value[:_MAX_TEXT_LENGTH]
            attr_values.add(trimmed)
            text_tokens.add(trimmed)

    stripped = text.strip()
    if _SIMPLE_NAME_REGEX.match(stripped):
        tags.add(stripped)
        attrs.add(stripped)

    return tags, attrs, attr_values, text_tokens


def _extract_tokens_lenient(payload: bytes) -> Optional[XMLSeedInfo]:
    if not payload:
        return None
    try:
        text = payload.decode('utf-8', 'ignore')
    except Exception:
        text = payload.decode('latin1', 'ignore')

    tags, attrs, attr_values, text_tokens = _scan_xml_tokens_from_text(text)
    if not (tags or attrs or text_tokens):
        return None

    fragments = []
    for fragment in re.split(r'<[^>]+>', text):
        frag = fragment.strip()
        if frag:
            fragments.append(frag[:_MAX_TEXT_LENGTH])
    text_tokens.update(fragments)

    info = XMLSeedInfo(
        tags=set(list(tags)[:_MAX_TOKEN_COUNT]),
        attributes=set(list(attrs)[:_MAX_TOKEN_COUNT]),
        attribute_values=set(list(attr_values)[:_MAX_TOKEN_COUNT]),
        texts=list(text_tokens)[:_MAX_TOKEN_COUNT],
    )
    _update_schema_store({
        'tags': info.tags,
        'attributes': info.attributes,
        'attribute_values': info.attribute_values,
        'texts': info.texts
    })
    return info


def _gather_external_xml_tokens():
    from kafl_fuzzer.technique import havoc_handler

    tags: Set[str] = set()
    attrs: Set[str] = set()
    attr_values: Set[str] = set()
    text_tokens: Set[str] = set()

    token_sources = list(getattr(havoc_handler, 'dict_import', []))
    redqueen_dict = havoc_handler.get_redqueen_dict()
    for entries in redqueen_dict.values():
        token_sources.extend(entries)

    for entry in token_sources:
        if not entry:
            continue
        decoded = _decode_token_bytes(entry)
        extra_tags, extra_attrs, extra_attr_values, extra_texts = _scan_xml_tokens_from_text(decoded)
        tags.update(extra_tags)
        attrs.update(extra_attrs)
        attr_values.update(extra_attr_values)
        text_tokens.update(extra_texts)

    return tags, attrs, attr_values, text_tokens


def _build_candidate_lists(xml_info: XMLSeedInfo):
    tags = set(xml_info.tags)
    attrs = set(xml_info.attributes)
    attr_values = set(xml_info.attribute_values)
    text_tokens: List[str] = list(xml_info.texts)

    extra_tags, extra_attrs, extra_attr_values, extra_texts = _gather_external_xml_tokens()
    tags.update(extra_tags)
    attrs.update(extra_attrs)
    attr_values.update(extra_attr_values)

    for token in extra_texts:
        trimmed = token[:_MAX_TEXT_LENGTH]
        if trimmed:
            text_tokens.append(trimmed)

    tags.update(_GLOBAL_SCHEMA['tags'])
    attrs.update(_GLOBAL_SCHEMA['attributes'])
    attr_values.update(_GLOBAL_SCHEMA['attribute_values'])
    text_tokens.extend(list(_GLOBAL_SCHEMA['texts']))
    tags.update(_EXCEL_HIGH_RISK_TAGS)
    attrs.update(_EXCEL_HIGH_RISK_ATTRS)

    if any(tag.startswith(('w:', 'wp:', 'a:', 'v:')) for tag in tags):
        tags.update(_OOXML_TAG_CANDIDATES)
        for attr_key, values in _OOXML_ATTR_VALUE_MAP.items():
            attrs.add(attr_key)
            attr_values.update(values)
            text_tokens.extend(values)

    # De-duplicate while preserving order for text tokens
    text_tokens = list(dict.fromkeys(text_tokens))

    tag_candidates = list(tags)[:_MAX_TOKEN_COUNT] or list(_DEFAULT_TAG_TOKENS)
    attr_candidates = list(attrs)[:_MAX_TOKEN_COUNT]
    if not attr_candidates:
        attr_candidates = tag_candidates
    attr_value_candidates = list(attr_values)[:_MAX_TOKEN_COUNT] or list(_DEFAULT_TEXT_TOKENS)
    text_candidates = text_tokens[:_MAX_TOKEN_COUNT]
    if not text_candidates:
        text_candidates = attr_value_candidates
    if not text_candidates:
        text_candidates = list(_DEFAULT_TEXT_TOKENS)

    return tag_candidates, attr_candidates, attr_value_candidates, text_candidates



def _maybe_add_dict_token(token: str) -> bool:
    token = token.strip()
    if not token:
        return False
    token_bytes = token.encode('utf-8', 'ignore')[:_MAX_TEXT_LENGTH]
    if not token_bytes:
        return False
    if token_bytes in _LOCAL_DICT_CACHE:
        return False
    try:
        from kafl_fuzzer.technique import havoc_handler
    except ImportError:
        return False
    dict_import = getattr(havoc_handler, 'dict_import', None)
    if dict_import is None:
        return False
    if token_bytes in dict_import:
        _LOCAL_DICT_CACHE.add(token_bytes)
        return False
    dict_import.append(token_bytes)
    _LOCAL_DICT_CACHE.add(token_bytes)
    return True



def _register_discovered_tokens(base_info: Optional[XMLSeedInfo], mutated_info: XMLSeedInfo) -> bool:
    base = base_info if base_info is not None else XMLSeedInfo()
    diff = mutated_info.diff(base)
    added = False
    updates = {
        'tags': diff["tags"],
        'attributes': diff["attributes"],
        'attribute_values': diff["attribute_values"],
        'texts': diff["texts"]
    }
    for bucket in updates.values():
        for token in bucket:
            added |= _maybe_add_dict_token(token)
    _update_schema_store(updates)
    if added:
        summaries = []
        for key, values in updates.items():
            if values:
                sample = ', '.join(sorted(list(values))[:5])
                summaries.append(f"{key}: {sample}")
        if summaries:
            _LOGGER.info("Discovered XML tokens -> %s", '; '.join(summaries))
    return added



def _mutate_xml_textual(payload: bytes, func, xml_info: Optional[XMLSeedInfo], max_operations: int, label_prefix: str = "xml_txt"):
    if max_operations <= 0:
        return
    try:
        text = payload.decode('utf-8')
    except UnicodeDecodeError:
        text = payload.decode('latin1', 'ignore')

    info = xml_info if xml_info is not None else XMLSeedInfo()
    tag_candidates, attr_candidates, attr_values, text_candidates = _build_candidate_lists(info)
    operations = 0

    def emit(mutated_text: str, label: str):
        nonlocal operations
        func(mutated_text.encode('utf-8', 'ignore'), label=label)
        operations += 1

    for match in _TAG_REGEX.finditer(text):
        original = match.group(1)
        for candidate in tag_candidates:
            if candidate == original:
                continue
            mutated = text[:match.start(1)] + candidate + text[match.end(1):]
            emit(mutated, f"{label_prefix}_tag")
            if operations >= max_operations:
                return

    for attr_key in attr_candidates:
        pattern = re.compile(r'(' + re.escape(attr_key) + r'\s*=\s*")([^"]*)(")')
        matches = list(pattern.finditer(text))
        if not matches:
            continue
        for match in matches:
            original = match.group(2)
            for candidate in attr_values:
                if candidate == original:
                    continue
                mutated = text[:match.start(2)] + candidate + text[match.end(2):]
                emit(mutated, f"{label_prefix}_attr")
                if operations >= max_operations:
                    return
    for match in re.finditer(r'>([^<]+)<', text):
        original = match.group(1)
        for candidate in text_candidates:
            if candidate == original:
                continue
            mutated = text[:match.start(1)] + candidate + text[match.end(1):]
            emit(mutated, f"{label_prefix}_text")
            if operations >= max_operations:
                return


def _emit_xml_mutation(original_payload: bytes, mutated_root: ET.Element, xml_info: Optional[XMLSeedInfo], func, label: str) -> bool:
    mutated_bytes = _element_to_bytes(mutated_root)
    if mutated_bytes == original_payload:
        return False
    mutated_info = extract_xml_features(mutated_bytes)
    if mutated_info is None:
        return False

    base = xml_info if xml_info is not None else XMLSeedInfo()
    diff = mutated_info.diff(base)
    has_new_tokens = any(diff[bucket] for bucket in ("texts", "attribute_values", "tags", "attributes"))

    if not has_new_tokens:
        diff_len = abs(len(mutated_bytes) - len(original_payload))
        differing = sum(1 for a, b in zip(mutated_bytes, original_payload) if a != b) + diff_len
        if differing <= 2 and diff_len <= 2:
            return False

    result = func(mutated_bytes, label=label)
    is_new = False
    if isinstance(result, tuple):
        if len(result) >= 2:
            is_new = bool(result[1])
        elif result:
            is_new = bool(result[0])
    else:
        is_new = bool(result)

    if not is_new:
        return False

    _register_discovered_tokens(xml_info, mutated_info)
    if xml_info is not None:
        xml_info.merge(mutated_info)

    return True


def mutate_seq_xml_structured(payload: bytes, func, xml_info: XMLSeedInfo, max_operations: int = 256):
    """Deterministic XML mutations that preserve well-formed structure."""

    root = _try_parse_xml(payload)
    if root is None:
        _mutate_xml_textual(payload, func, xml_info, max_operations, label_prefix="xml_txt")
        return

    operations = 0
    elements = _iter_elements(root)

    info = xml_info if xml_info is not None else XMLSeedInfo()
    tag_candidates, attr_candidates, attr_values, text_candidates = _build_candidate_lists(info)

    def maybe_emit(mutated_root: ET.Element, label: str) -> bool:
        nonlocal operations
        if _emit_xml_mutation(payload, mutated_root, xml_info, func, label):
            operations += 1
        return operations >= max_operations

    if _apply_excel_cell_attribute_mutations(root, elements, maybe_emit):
        return
    if _apply_excel_cell_value_mutations(root, elements, maybe_emit):
        return
    if _apply_excel_bypass_mutations(root, maybe_emit):
        return
    if _apply_excel_control_mutations(root, maybe_emit):
        return
    if _apply_excel_connection_mutations(root, maybe_emit):
        return
    if _apply_excel_formula_mutations(root, elements, maybe_emit):
        return
    if _apply_excel_row_attribute_mutations(root, elements, maybe_emit):
        return
    if _apply_excel_column_mutations(root, elements, maybe_emit):
        return
    if _apply_excel_merge_mutations(root, maybe_emit):
        return
    if _apply_excel_datetime_mutations(root, elements, maybe_emit):
        return
    if _apply_excel_reference_structure_mutations(root, maybe_emit):
        return
    if _apply_excel_structure_mutations(root, maybe_emit):
        return

    # Tag renaming
    for idx, element in enumerate(elements):
        for candidate in tag_candidates:
            if candidate == element.tag:
                continue
            mutated_root = _clone_tree(root)
            _iter_elements(mutated_root)[idx].tag = candidate
            if maybe_emit(mutated_root, "xml_tag"):
                return

    # Attribute value swaps
    for idx, element in enumerate(elements):
        if not element.attrib:
            continue
        for attr_key in element.attrib:
            original_value = element.attrib[attr_key]
            for candidate in attr_values:
                if candidate == original_value:
                    continue
                mutated_root = _clone_tree(root)
                target = _iter_elements(mutated_root)[idx]
                target.set(attr_key, candidate)
                if maybe_emit(mutated_root, "xml_attr"):
                    return

    # Attribute insertion
    for idx, element in enumerate(elements):
        for attr_key in attr_candidates:
            if attr_key in element.attrib:
                continue
            candidate_value = rand.select(attr_values or _DEFAULT_TEXT_TOKENS)
            mutated_root = _clone_tree(root)
            target = _iter_elements(mutated_root)[idx]
            target.set(attr_key, candidate_value)
            if maybe_emit(mutated_root, "xml_attr_ins"):
                return

    # Text mutations
    for idx, element in enumerate(elements):
        if element.text is None:
            continue
        original_value = element.text
        for candidate in text_candidates:
            if candidate == original_value:
                continue
            mutated_root = _clone_tree(root)
            target = _iter_elements(mutated_root)[idx]
            target.text = candidate
            if maybe_emit(mutated_root, "xml_text"):
                return





def mutate_seq_xml_havoc(payload: bytes, func, xml_info: XMLSeedInfo, max_iterations: int):
    """Randomized XML mutations to be used during havoc-style stages."""

    if max_iterations <= 0:
        return

    info = xml_info if xml_info is not None else XMLSeedInfo()
    tag_candidates, attr_candidates, attr_values, text_candidates = _build_candidate_lists(info)

    for _ in range(max_iterations):
        root = _try_parse_xml(payload)
        if root is None:
            _mutate_xml_textual(payload, func, xml_info, 1, label_prefix="xml_havoc_txt")
            return
        elements = _iter_elements(root)
        if not elements:
            _mutate_xml_textual(payload, func, xml_info, 1, label_prefix="xml_havoc_txt")
            return

        choice = rand.int(17)
        mutated_root: Optional[ET.Element] = None
        label: Optional[str] = None

        if choice < 5:
            target_idx = rand.int(len(elements))
            target = elements[target_idx]
            mutated_root = _clone_tree(root)
            mutated_elements = _iter_elements(mutated_root)
            mutated_target = mutated_elements[target_idx]

            if choice == 0 and mutated_target.text is not None:
                mutated_target.text = rand.select(text_candidates or _DEFAULT_TEXT_TOKENS)
                label = "xml_havoc_text"
            elif choice == 1 and mutated_target.attrib:
                attr_key = rand.select(list(mutated_target.attrib.keys()))
                mutated_target.set(attr_key, rand.select(attr_values or _DEFAULT_TEXT_TOKENS))
                label = "xml_havoc_attr"
            elif choice == 2:
                mutated_target.tag = rand.select(tag_candidates or _DEFAULT_TAG_TOKENS)
                label = "xml_havoc_tag"
            elif choice == 3:
                # Duplicate a subtree
                parent_map = {c: p for p in mutated_root.iter() for c in p}
                parent = parent_map.get(mutated_target)
                if parent is not None:
                    parent.append(_clone_tree(mutated_target))
                label = "xml_havoc_dup"
            else:
                # Remove node if possible
                parent_map = {c: p for p in mutated_root.iter() for c in p}
                parent = parent_map.get(mutated_target)
                if parent is not None:
                    parent.remove(mutated_target)
                label = "xml_havoc_del"
        elif choice == 5:
            result = _random_excel_cell_attribute_mutation(root, elements)
            if result is None:
                continue
            mutated_root, label = result
        elif choice == 6:
            result = _random_excel_cell_mutation(root, elements)
            if result is None:
                continue
            mutated_root, label = result
        elif choice == 7:
            result = _random_excel_formula_mutation(root, elements)
            if result is None:
                continue
            mutated_root, label = result
        elif choice == 8:
            result = _random_excel_row_attribute_mutation(root, elements)
            if result is None:
                continue
            mutated_root, label = result
        elif choice == 9:
            result = _random_excel_datetime_mutation(root, elements)
            if result is None:
                continue
            mutated_root, label = result
        elif choice == 10:
            result = _random_excel_reference_mutation(root)
            if result is None:
                continue
            mutated_root, label = result
        elif choice == 11:
            result = _random_excel_column_mutation(root, elements)
            if result is None:
                continue
            mutated_root, label = result
        elif choice == 12:
            result = _random_excel_merge_mutation(root)
            if result is None:
                continue
            mutated_root, label = result
        elif choice == 13:
            result = _random_excel_bypass_mutation(root)
            if result is None:
                continue
            mutated_root, label = result
        elif choice == 14:
            result = _random_excel_control_mutation(root)
            if result is None:
                continue
            mutated_root, label = result
        elif choice == 15:
            result = _random_excel_connection_mutation(root)
            if result is None:
                continue
            mutated_root, label = result
        else:
            result = _random_excel_structure_mutation(root)
            if result is None:
                continue
            mutated_root, label = result

        if mutated_root is not None and label is not None:
            _emit_xml_mutation(payload, mutated_root, xml_info, func, label)
