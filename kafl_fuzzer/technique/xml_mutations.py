from __future__ import annotations

"""XML-specific seed analysis and mutation helpers for kAFL."""

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
import copy
import json
import re
import os
from pathlib import Path
import xml.etree.ElementTree as ET

from kafl_fuzzer.common.rand import rand
from kafl_fuzzer.common.util import atomic_write

# Limits to keep metadata compact and mutation workloads bounded
_MAX_TOKEN_COUNT = 64
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
        data = json.loads(_SCHEMA_PATH.read_text(encoding='utf-8'))
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
        atomic_write(str(_SCHEMA_PATH), json.dumps(data, indent=2).encode('utf-8'))
    except OSError:
        pass


_load_schema_tokens()


def _update_schema_store(updates: Dict[str, Iterable[str]]):
    dirty = False
    for key, values in updates.items():
        if key not in _GLOBAL_SCHEMA:
            continue
        for value in values:
            if value is None:
                continue
            truncated = str(value)[:_MAX_TEXT_LENGTH]
            if truncated and truncated not in _GLOBAL_SCHEMA[key]:
                _GLOBAL_SCHEMA[key].add(truncated)
                dirty = True
    if dirty:
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
    return info


def _clone_tree(root: ET.Element) -> ET.Element:
    return copy.deepcopy(root)


def _element_to_bytes(root: ET.Element) -> bytes:
    return ET.tostring(root, encoding="utf-8")


_LOCAL_DICT_CACHE: Set[bytes] = set()


_TAG_REGEX = re.compile(r'<\s*/?\s*([A-Za-z_:][\w:.-]*)')
_ATTR_REGEX = re.compile(r'([A-Za-z_:][\w:.-]*)\s*=')
_ATTR_VALUE_REGEX = re.compile(r'=\s*(?:"([^"]*)"|\'([^\']*)\')')
_SIMPLE_NAME_REGEX = re.compile(r'^[A-Za-z_:][\w:.-]*$')


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
        'texts': diff["texts"],
        'attribute_values': diff["attribute_values"],
        'tags': diff["tags"],
        'attributes': diff["attributes"]
    }
    for bucket in updates.values():
        for token in bucket:
            added |= _maybe_add_dict_token(token)
    _update_schema_store(updates)
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
        match = pattern.search(text)
        if not match:
            continue
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

    _register_discovered_tokens(xml_info, mutated_info)
    if xml_info is not None:
        xml_info.merge(mutated_info)

    func(mutated_bytes, label=label)
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

        choice = rand.int(5)
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

        _emit_xml_mutation(payload, mutated_root, xml_info, func, label)
