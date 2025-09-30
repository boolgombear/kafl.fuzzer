from __future__ import annotations

"""Lightweight Nautilus-inspired grammar mutations used within the Python mutator pipeline."""

import logging
import re
import string
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Set

from kafl_fuzzer.common.rand import rand

_LOGGER = logging.getLogger(__name__)

_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z0-9_]+)\}")


class _SimpleGrammarContext:
    """Minimal subset of the Nautilus grammar context used by Python grammars."""

    def __init__(self, max_depth: int = 6, max_repeat: int = 8, max_output: int = 16384):
        self.rules: Dict[str, List[Tuple[str, object]]] = {}
        self.max_depth = max_depth
        self.max_repeat = max_repeat
        self.max_output = max_output

    def rule(self, name: str, rhs: object) -> None:
        self.rules.setdefault(name, []).append(("template", rhs))

    def regex(self, name: str, pattern: str) -> None:
        self.rules.setdefault(name, []).append(("regex", pattern))

    def script(self, name: str, deps: Sequence[str], func: Callable[..., object]) -> None:
        self.rules.setdefault(name, []).append(("script", list(deps), func))

    def has_symbol(self, name: str) -> bool:
        return name in self.rules

    def generate(self, symbol: str, depth: int = 0) -> bytes:
        if depth > self.max_depth * 2:
            return b""
        entries = self.rules.get(symbol)
        if not entries:
            return symbol.encode("utf-8", "ignore")[: self.max_output]

        candidates = entries
        if depth >= self.max_depth:
            terminal_entries = [entry for entry in entries if self._is_terminal(entry)]
            if terminal_entries:
                candidates = terminal_entries

        entry = rand.select(candidates)
        return self._apply_entry(entry, depth + 1)

    def _is_terminal(self, entry: Tuple[str, object]) -> bool:
        kind = entry[0]
        if kind == "template":
            template = entry[1]
            if isinstance(template, bytes):
                return True
            return _PLACEHOLDER_RE.search(str(template)) is None
        if kind == "regex":
            return True
        return False

    def _apply_entry(self, entry: Tuple[str, object], depth: int) -> bytes:
        kind = entry[0]
        if kind == "template":
            template = entry[1]
            if isinstance(template, bytes):
                return template[: self.max_output]
            return self._expand_template(str(template), depth)
        if kind == "regex":
            return self._generate_regex(str(entry[1]))
        if kind == "script":
            deps: List[str] = entry[1]  # type: ignore[assignment]
            func: Callable[..., object] = entry[2]  # type: ignore[assignment]
            args: List[bytes] = [self.generate(dep, depth + 1) for dep in deps]
            try:
                result = func(*args)
            except TypeError:
                # Some grammars expect strings.
                decoded = [arg.decode("utf-8", "ignore") for arg in args]
                result = func(*decoded)
            if isinstance(result, bytes):
                return result[: self.max_output]
            return str(result).encode("utf-8", "ignore")[: self.max_output]
        return b""

    def _expand_template(self, template: str, depth: int) -> bytes:
        cursor = 0
        chunks: List[bytes] = []
        for match in _PLACEHOLDER_RE.finditer(template):
            if match.start() > cursor:
                literal = template[cursor:match.start()].encode("utf-8", "ignore")
                if literal:
                    chunks.append(literal)
            symbol = match.group(1)
            replacement = self.generate(symbol, depth + 1)
            if replacement:
                chunks.append(replacement)
            cursor = match.end()
        if cursor < len(template):
            tail = template[cursor:].encode("utf-8", "ignore")
            if tail:
                chunks.append(tail)
        if not chunks:
            return template.encode("utf-8", "ignore")[: self.max_output]
        combined = b"".join(chunks)
        return combined[: self.max_output]

    def _generate_regex(self, pattern: str) -> bytes:
        try:
            text = self._emit_regex(pattern)
        except Exception:
            _LOGGER.debug("Falling back for unsupported regex pattern: %s", pattern, exc_info=True)
            text = re.sub(r"[^A-Za-z0-9]", "", pattern) or "nautilus"
        return text.encode("utf-8", "ignore")[: self.max_output]

    def _emit_regex(self, pattern: str) -> str:
        tokens: List[str] = []
        index = 0
        while index < len(pattern):
            char = pattern[index]
            if char == "[":
                end = pattern.find("]", index)
                if end == -1:
                    break
                charset = self._expand_char_class(pattern[index + 1 : end])
                index = end + 1
                quantifier, index = self._consume_quantifier(pattern, index)
                tokens.append(self._emit_charset(charset, quantifier))
                continue
            if char == "\\":
                index += 1
                if index >= len(pattern):
                    break
                charset = self._expand_escape(pattern[index])
                index += 1
                quantifier, index = self._consume_quantifier(pattern, index)
                tokens.append(self._emit_charset(charset, quantifier))
                continue
            if char in "().^$":
                index += 1
                continue
            charset = [char]
            index += 1
            quantifier, index = self._consume_quantifier(pattern, index)
            tokens.append(self._emit_charset(charset, quantifier))
        if not tokens:
            return re.sub(r"[^A-Za-z0-9]", "", pattern) or "nautilus"
        return "".join(tokens)

    def _expand_char_class(self, body: str) -> List[str]:
        result: List[str] = []
        index = 0
        while index < len(body):
            char = body[index]
            if char == "\\" and index + 1 < len(body):
                result.extend(self._expand_escape(body[index + 1]))
                index += 2
                continue
            if index + 2 < len(body) and body[index + 1] == "-":
                start = ord(body[index])
                end = ord(body[index + 2])
                if start <= end:
                    for code in range(start, end + 1):
                        result.append(chr(code))
                else:
                    for code in range(end, start + 1):
                        result.append(chr(code))
                index += 3
                continue
            result.append(char)
            index += 1
        return result or list(string.ascii_letters)

    def _expand_escape(self, esc: str) -> List[str]:
        mapping = {
            "d": list(string.digits),
            "D": [c for c in string.printable if c not in string.digits],
            "w": list(string.ascii_letters + string.digits + "_"),
            "W": [c for c in string.printable if c not in (string.ascii_letters + string.digits + "_")],
            "s": list(" \t\r\n"),
        }
        return mapping.get(esc, [esc])

    def _consume_quantifier(self, pattern: str, index: int) -> Tuple[str, int]:
        if index >= len(pattern):
            return "", index
        char = pattern[index]
        if char in "*+?":
            return char, index + 1
        if char == "{":
            end = pattern.find("}", index)
            if end != -1:
                return pattern[index : end + 1], end + 1
        return "", index

    def _emit_charset(self, charset: Iterable[str], quantifier: str) -> str:
        chars = list(charset) or list(string.ascii_letters)
        count = 1
        if quantifier == "?":
            count = rand.int(2)
        elif quantifier == "*":
            count = rand.int(self.max_repeat + 1)
        elif quantifier == "+":
            count = 1 + rand.int(self.max_repeat)
        elif quantifier.startswith("{") and quantifier.endswith("}"):
            parts = quantifier[1:-1].split(",")
            try:
                if len(parts) == 1:
                    count = int(parts[0])
                elif len(parts) == 2:
                    lower = int(parts[0] or 0)
                    upper = int(parts[1] or lower + self.max_repeat)
                    if upper < lower:
                        lower, upper = upper, lower
                    span = max(upper - lower + 1, 1)
                    count = lower + rand.int(span)
            except ValueError:
                count = 1
        count = max(0, min(count, self.max_output))
        return "".join(chars[rand.int(len(chars))] for _ in range(count))


class NautilusGrammarMutator:
    """Loads Nautilus Python grammars and emits grammar-driven byte mutations."""

    DEFAULT_GRAMMAR = Path(__file__).resolve().parents[2] / "nautilus" / "grammars" / "grammar_py_example.py"

    def __init__(
        self,
        grammar_path: Optional[str] = None,
        start_symbol: str = "START",
        max_depth: int = 6,
        max_regex_repeat: int = 8,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.logger = logger or _LOGGER
        self.start_symbol = start_symbol
        self.context = _SimpleGrammarContext(max_depth=max_depth, max_repeat=max_regex_repeat)
        self.grammar_path = self._resolve_grammar(grammar_path)
        self._load_grammar(self.grammar_path)

    def _resolve_grammar(self, grammar_path: Optional[str]) -> Path:
        if grammar_path:
            path = Path(grammar_path).expanduser()
            if not path.is_file():
                raise FileNotFoundError(f"Grammar file not found: {path}")
            return path
        if not self.DEFAULT_GRAMMAR.is_file():
            raise FileNotFoundError("Default Nautilus grammar is missing")
        return self.DEFAULT_GRAMMAR

    def _load_grammar(self, path: Path) -> None:
        namespace = {"ctx": self.context}
        code = path.read_text(encoding="utf-8")
        exec(compile(code, str(path), "exec"), namespace)
        self.logger.debug(
            "Loaded Nautilus grammar from %s with %d nonterminals", path, len(self.context.rules)
        )

    def mutate(
        self,
        base_payload: Optional[bytes],
        func: Callable[[bytes], object],
        max_iterations: int = 64,
        label_prefix: str = "nautilus",
    ) -> int:
        if not self.context.has_symbol(self.start_symbol):
            self.logger.debug("Grammar has no start symbol %s", self.start_symbol)
            return 0

        unique: Set[bytes] = set()
        base = base_payload or b""
        emitted = 0
        iterations = max(0, max_iterations)
        for _ in range(iterations):
            candidate = self.context.generate(self.start_symbol)
            if not candidate:
                continue
            if candidate == base or candidate in unique:
                continue
            unique.add(candidate)
            try:
                func(candidate, label=label_prefix)
            except Exception:
                self.logger.debug("Failed to emit Nautilus mutation", exc_info=True)
                continue
            emitted += 1
        return emitted


def mutate_seq_nautilus(
    payload: Optional[bytes],
    func: Callable[[bytes], object],
    mutator: NautilusGrammarMutator,
    max_iterations: int,
    label_prefix: str = "nautilus_struct",
) -> int:
    """Convenience wrapper mirroring the XML mutation helpers."""

    if mutator is None:
        return 0
    return mutator.mutate(payload, func, max_iterations=max_iterations, label_prefix=label_prefix)
