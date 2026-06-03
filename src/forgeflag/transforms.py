from __future__ import annotations

import base64
import codecs
from dataclasses import dataclass
import html
import re
from urllib.parse import unquote_plus

from forgeflag.flags import extract_flags


TOKEN_PATTERN = re.compile(r"[A-Za-z0-9+/=_&%#;{}:.,!@-]{4,}")
BINARY_ASCII_PATTERN = re.compile(r"(?:[01]{8}\s+){3,}[01]{8}")
NUMBER_ASCII_PATTERN = re.compile(r"(?:\b[0-9]{2,3}\b[\s,;:-]+){3,}\b[0-9]{2,3}\b")
MORSE_PATTERN = re.compile(r"(?:[.\-/]{1,6}\s*){4,}")
MORSE_TABLE = {
    ".-": "a",
    "-...": "b",
    "-.-.": "c",
    "-..": "d",
    ".": "e",
    "..-.": "f",
    "--.": "g",
    "....": "h",
    "..": "i",
    ".---": "j",
    "-.-": "k",
    ".-..": "l",
    "--": "m",
    "-.": "n",
    "---": "o",
    ".--.": "p",
    "--.-": "q",
    ".-.": "r",
    "...": "s",
    "-": "t",
    "..-": "u",
    "...-": "v",
    ".--": "w",
    "-..-": "x",
    "-.--": "y",
    "--..": "z",
    "-----": "0",
    ".----": "1",
    "..---": "2",
    "...--": "3",
    "....-": "4",
    ".....": "5",
    "-....": "6",
    "--...": "7",
    "---..": "8",
    "----.": "9",
}


@dataclass(frozen=True)
class TransformCandidate:
    value: str
    recipe: tuple[str, ...]
    source: str


def transform_candidates(text: str, max_depth: int = 3, max_candidates: int = 100) -> tuple[TransformCandidate, ...]:
    seeds = _seed_values(text)
    queue: list[tuple[str, tuple[str, ...], str]] = [(seed, (), seed) for seed in seeds]
    seen_states = {(seed, ()) for seed in seeds}
    emitted: list[TransformCandidate] = []
    seen_candidates: set[tuple[str, tuple[str, ...]]] = set()

    while queue and len(emitted) < max_candidates:
        value, recipe, source = queue.pop(0)
        _emit_flag_candidates(value, recipe, source, emitted, seen_candidates, max_candidates)
        if recipe:
            _emit_candidate(value, recipe, source, emitted, seen_candidates, max_candidates)
        if len(recipe) >= max_depth:
            continue
        for transform_name, transformed in _apply_transforms(value):
            normalized = _compact_printable(transformed)
            if not normalized or normalized == value:
                continue
            next_recipe = (*recipe, transform_name)
            state = (normalized, next_recipe)
            if state in seen_states:
                continue
            seen_states.add(state)
            queue.append((normalized, next_recipe, source))

    return tuple(emitted)


def candidates_to_payload(candidates: tuple[TransformCandidate, ...], limit: int = 20) -> list[dict[str, object]]:
    return [
        {"value": candidate.value, "recipe": list(candidate.recipe), "source": candidate.source[:160]}
        for candidate in candidates[:limit]
    ]


def _seed_values(text: str) -> list[str]:
    seeds: list[str] = []
    morse_values = _morse_seed_values(text)
    for value in [
        text,
        *BINARY_ASCII_PATTERN.findall(text),
        *NUMBER_ASCII_PATTERN.findall(text),
        *morse_values,
        *TOKEN_PATTERN.findall(text),
    ]:
        normalized = value.strip()
        if len(normalized) < 4:
            continue
        if normalized not in seeds:
            seeds.append(normalized)
    return seeds[:60]


def _morse_seed_values(text: str) -> list[str]:
    values: list[str] = []
    for line in text.splitlines():
        for value in MORSE_PATTERN.findall(line):
            normalized = value.strip()
            if normalized and normalized not in values:
                values.append(normalized)
    return values


def _apply_transforms(value: str) -> list[tuple[str, str]]:
    transformed: list[tuple[str, str]] = []
    transformed.extend(_hex_decode(value))
    transformed.extend(_binary_ascii_decode(value))
    transformed.extend(_base32_decode(value))
    transformed.extend(_base64_decode(value))
    transformed.extend(_rot13_decode(value))
    transformed.extend(_morse_decode(value))
    transformed.extend(_number_ascii_decode(value))
    html_decoded = html.unescape(value)
    if html_decoded != value:
        transformed.append(("html_unescape", html_decoded))
    url_decoded = unquote_plus(value)
    if url_decoded != value:
        transformed.append(("url_decode", url_decoded))
    transformed.extend(_caesar_decode(value))
    return transformed


def _hex_decode(value: str) -> list[tuple[str, str]]:
    cleaned = value.strip()
    if len(cleaned) < 8 or len(cleaned) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        return []
    try:
        decoded = bytes.fromhex(cleaned).decode("utf-8", errors="replace")
    except ValueError:
        return []
    if not _mostly_printable(decoded):
        return []
    return [("hex_decode", decoded)]


def _base64_decode(value: str) -> list[tuple[str, str]]:
    cleaned = value.strip()
    if len(cleaned) < 8 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", cleaned):
        return []
    padded = cleaned + "=" * (-len(cleaned) % 4)
    try:
        decoded_bytes = base64.b64decode(padded, altchars=b"-_", validate=True)
    except Exception:
        return []
    if not decoded_bytes:
        return []
    decoded = decoded_bytes.decode("utf-8", errors="replace")
    if not _mostly_printable(decoded):
        return []
    return [("base64_decode", decoded)]


def _base32_decode(value: str) -> list[tuple[str, str]]:
    cleaned = value.strip().replace(" ", "")
    if len(cleaned) < 8 or not re.fullmatch(r"[A-Z2-7=]+", cleaned, flags=re.IGNORECASE):
        return []
    padded = cleaned + "=" * (-len(cleaned) % 8)
    try:
        decoded_bytes = base64.b32decode(padded, casefold=True)
    except Exception:
        return []
    if not decoded_bytes:
        return []
    decoded = decoded_bytes.decode("utf-8", errors="replace")
    if not _mostly_printable(decoded):
        return []
    return [("base32_decode", decoded)]


def _binary_ascii_decode(value: str) -> list[tuple[str, str]]:
    cleaned = " ".join(value.strip().split())
    if len(cleaned) < 8 or not re.fullmatch(r"[01\s]+", cleaned):
        return []
    bits = cleaned.replace(" ", "")
    if len(bits) < 32 or len(bits) % 8:
        return []
    try:
        decoded = bytes(int(bits[index : index + 8], 2) for index in range(0, len(bits), 8)).decode(
            "utf-8",
            errors="replace",
        )
    except ValueError:
        return []
    if not _mostly_printable(decoded):
        return []
    return [("binary_ascii_decode", decoded)]


def _rot13_decode(value: str) -> list[tuple[str, str]]:
    if len(value) < 4 or "{" not in value or "}" not in value or not re.search(r"[A-Za-z]", value):
        return []
    decoded = codecs.decode(value, "rot_13")
    if decoded == value or not _mostly_printable(decoded):
        return []
    return [("rot13_decode", decoded)]


def _caesar_decode(value: str) -> list[tuple[str, str]]:
    if len(value) < 4 or "{" not in value or "}" not in value or not re.search(r"[A-Za-z]", value):
        return []
    # CTF Caesar puzzles usually preserve punctuation such as braces, so only rotate alphabetic bytes.
    decoded: list[tuple[str, str]] = []
    for shift in range(1, 26):
        candidate_chars: list[str] = []
        for char in value:
            if "a" <= char <= "z":
                candidate_chars.append(chr((ord(char) - ord("a") - shift) % 26 + ord("a")))
            elif "A" <= char <= "Z":
                candidate_chars.append(chr((ord(char) - ord("A") - shift) % 26 + ord("A")))
            else:
                candidate_chars.append(char)
        candidate = "".join(candidate_chars)
        if candidate != value and _mostly_printable(candidate):
            decoded.append((f"caesar_shift_{shift}", candidate))
    return decoded


def _morse_decode(value: str) -> list[tuple[str, str]]:
    cleaned = value.strip()
    if len(cleaned) < 7 or not re.fullmatch(r"[.\-/\s]+", cleaned):
        return []
    words: list[str] = []
    for word in re.split(r"\s*/\s*", cleaned):
        letters: list[str] = []
        for token in word.split():
            decoded = MORSE_TABLE.get(token)
            if decoded is None:
                return []
            letters.append(decoded)
        if letters:
            words.append("".join(letters))
    if not words:
        return []
    decoded_text = " ".join(words)
    results = [("morse_decode", decoded_text)]
    if decoded_text.startswith("flag "):
        body = "_".join(decoded_text[5:].split())
        if body:
            results.append(("morse_decode_flag_braces", f"flag{{{body}}}"))
    return results


def _number_ascii_decode(value: str) -> list[tuple[str, str]]:
    normalized = re.sub(r"[,;:-]+", " ", value.strip())
    if not re.fullmatch(r"[0-9\s]+", normalized):
        return []
    tokens = normalized.split()
    numbers = [int(item) for item in tokens]
    if len(numbers) < 4:
        return []
    decoded: list[tuple[str, str]] = []
    if all(32 <= number <= 126 for number in numbers):
        text = "".join(chr(number) for number in numbers)
        if _mostly_printable(text):
            decoded.append(("decimal_ascii_decode", text))
    if all(re.fullmatch(r"[0-7]+", token) and 0 <= int(token, 8) <= 255 for token in tokens):
        text = "".join(chr(int(token, 8)) for token in tokens)
        if _mostly_printable(text):
            decoded.append(("octal_ascii_decode", text))
    return decoded


def _emit_flag_candidates(
    value: str,
    recipe: tuple[str, ...],
    source: str,
    emitted: list[TransformCandidate],
    seen: set[tuple[str, tuple[str, ...]]],
    max_candidates: int,
) -> None:
    for flag in extract_flags(value):
        _emit_candidate(flag, recipe, source, emitted, seen, max_candidates)


def _emit_candidate(
    value: str,
    recipe: tuple[str, ...],
    source: str,
    emitted: list[TransformCandidate],
    seen: set[tuple[str, tuple[str, ...]]],
    max_candidates: int,
) -> None:
    if len(emitted) >= max_candidates:
        return
    normalized = _compact_printable(value)
    if not normalized:
        return
    key = (normalized, recipe)
    if key in seen:
        return
    seen.add(key)
    emitted.append(TransformCandidate(value=normalized, recipe=recipe, source=source))


def _compact_printable(value: str, limit: int = 500) -> str:
    text = " ".join(value.replace("\x00", " ").split())
    return text[:limit]


def _mostly_printable(value: str) -> bool:
    if not value:
        return False
    if "\ufffd" in value:
        return False
    printable = sum(1 for char in value if char.isprintable() or char.isspace())
    return printable / len(value) >= 0.85
