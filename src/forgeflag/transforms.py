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
CCIR476_BITS_PATTERN = re.compile(r"(?:[01]{7}\s*){4,}")
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
BRAILLE_ASCII_TABLE = {
    "000000": " ",
    "011101": "!",
    "000010": '"',
    "001111": "#",
    "110101": "$",
    "100101": "%",
    "111101": "&",
    "001000": "'",
    "111011": "(",
    "011111": ")",
    "100001": "*",
    "001101": "+",
    "000001": ",",
    "001001": "-",
    "000101": ".",
    "001100": "/",
    "001011": "0",
    "010000": "1",
    "011000": "2",
    "010010": "3",
    "010011": "4",
    "010001": "5",
    "011010": "6",
    "011011": "7",
    "011001": "8",
    "001010": "9",
    "100011": ":",
    "000011": ";",
    "110001": "<",
    "111111": "=",
    "001110": ">",
    "100111": "?",
    "000100": "@",
    "100000": "A",
    "110000": "B",
    "100100": "C",
    "100110": "D",
    "100010": "E",
    "110100": "F",
    "110110": "G",
    "110010": "H",
    "010100": "I",
    "010110": "J",
    "101000": "K",
    "111000": "L",
    "101100": "M",
    "101110": "N",
    "101010": "O",
    "111100": "P",
    "111110": "Q",
    "111010": "R",
    "011100": "S",
    "011110": "T",
    "101001": "U",
    "111001": "V",
    "010111": "W",
    "101101": "X",
    "101111": "Y",
    "101011": "Z",
    "010101": "[",
    "110011": "\\",
    "110111": "]",
    "000110": "^",
    "000111": "_",
}
BRAILLE_DIGITS = {
    "A": "1",
    "B": "2",
    "C": "3",
    "D": "4",
    "E": "5",
    "F": "6",
    "G": "7",
    "H": "8",
    "I": "9",
    "J": "0",
}
CCIR476_LETTERS = {
    0x47: "A",
    0x72: "B",
    0x1D: "C",
    0x53: "D",
    0x56: "E",
    0x1B: "F",
    0x35: "G",
    0x69: "H",
    0x4D: "I",
    0x17: "J",
    0x1E: "K",
    0x65: "L",
    0x39: "M",
    0x59: "N",
    0x71: "O",
    0x2D: "P",
    0x2E: "Q",
    0x55: "R",
    0x4B: "S",
    0x74: "T",
    0x4E: "U",
    0x3C: "V",
    0x27: "W",
    0x3A: "X",
    0x2B: "Y",
    0x63: "Z",
    0x78: "\r",
    0x6C: "\n",
    0x5C: " ",
}
CCIR476_FIGURES = {
    0x2D: "0",
    0x2E: "1",
    0x27: "2",
    0x56: "3",
    0x55: "4",
    0x74: "5",
    0x2B: "6",
    0x4E: "7",
    0x4D: "8",
    0x71: "9",
    0x17: "'",
    0x1B: "!",
    0x1D: ":",
    0x1E: "(",
    0x35: "&",
    0x39: ".",
    0x3A: "/",
    0x3C: "=",
    0x47: "-",
    0x53: "$",
    0x59: ",",
    0x63: "+",
    0x65: ")",
    0x69: "#",
    0x72: "?",
    0x78: "\r",
    0x6C: "\n",
    0x5C: " ",
}
CCIR476_LTRS = 0x5A
CCIR476_FIGS = 0x36
CCIR476_CONTROL = {0x0F, 0x33, 0x66}


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
        *CCIR476_BITS_PATTERN.findall(text),
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
    transformed.extend(_hex_braille_ascii_decode(value))
    transformed.extend(_hex_decode(value))
    transformed.extend(_binary_ascii_decode(value))
    transformed.extend(_ccir476_decode(value))
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


def _hex_braille_ascii_decode(value: str) -> list[tuple[str, str]]:
    cleaned = value.strip()
    if len(cleaned) < 8 or not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        return []
    try:
        bits = bin(int(cleaned, 16))[2:]
    except ValueError:
        return []
    if len(bits) < 24 or len(bits) % 6:
        return []
    groups = [bits[index : index + 6] for index in range(0, len(bits), 6)]
    if any(group not in BRAILLE_ASCII_TABLE for group in groups):
        return []
    braille_ascii = "".join(BRAILLE_ASCII_TABLE[group] for group in groups)
    normalized = _normalize_braille_ascii(braille_ascii)
    results = [("hex_braille_ascii_decode", braille_ascii)]
    if normalized != braille_ascii and _mostly_printable(normalized):
        results.append(("hex_braille_ascii_normalize", normalized))
    return results


def _normalize_braille_ascii(value: str) -> str:
    normalized: list[str] = []
    index = 0
    while index < len(value):
        if value.startswith("_<", index):
            normalized.append("{")
            index += 2
            continue
        if value.startswith(".)", index):
            normalized.append("}")
            index += 2
            continue
        if value[index] == "#" and index + 1 < len(value):
            next_char = value[index + 1]
            normalized.append(BRAILLE_DIGITS.get(next_char, "#" + next_char))
            index += 2
            continue
        normalized.append(value[index])
        index += 1
    return "".join(normalized).lower()


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


def _ccir476_decode(value: str) -> list[tuple[str, str]]:
    bits = "".join(value.strip().split())
    if len(bits) < 28 or len(bits) % 7 or not re.fullmatch(r"[01]+", bits):
        return []
    decoded = _decode_ccir476_bits(bits)
    if not decoded:
        return []
    results: list[tuple[str, str]] = []
    for recipe, text in decoded:
        if _mostly_printable(text):
            results.append((recipe, text))
            if "{" not in text and "}" not in text and text.startswith("##") and len(text) <= 140:
                results.append((f"{recipe}_ductf_wrap", f"DUCTF{{{text}}}"))
    return results


def _decode_ccir476_bits(bits: str) -> list[tuple[str, str]]:
    variants: list[tuple[str, str]] = []
    strict_chars: list[str] = []
    fallback_chars: list[str] = []
    mode = "letters"
    unknown_count = 0
    fallback_used = False
    for index in range(0, len(bits), 7):
        code = int(bits[index : index + 7], 2)
        if code == CCIR476_LTRS:
            mode = "letters"
            continue
        if code == CCIR476_FIGS:
            mode = "figures"
            continue
        if code in CCIR476_CONTROL:
            continue
        table = CCIR476_LETTERS if mode == "letters" else CCIR476_FIGURES
        char = table.get(code)
        if char is None:
            unknown_count += 1
            strict_chars.append("?")
            fallback = CCIR476_LETTERS.get(code) or CCIR476_FIGURES.get(code)
            if fallback:
                fallback_used = True
                fallback_chars.append(fallback)
            else:
                fallback_chars.append("?")
            continue
        strict_chars.append(char)
        fallback_chars.append(char)
    if unknown_count > 3:
        return []
    strict = _compact_printable("".join(strict_chars))
    if strict and "?" not in strict:
        variants.append(("ccir476_decode", strict))
    elif strict:
        variants.append(("ccir476_decode_lossy", strict))
    fallback = _compact_printable("".join(fallback_chars))
    if fallback_used and fallback and fallback != strict:
        variants.append(("ccir476_decode_letter_fallback", fallback))
        possessive = re.sub(
            r"\b([A-Z0-9]*[0-9][A-Z0-9]*?)SS(\s+AR3\b)",
            r"\1'S\2",
            fallback,
            count=1,
        )
        if possessive == fallback:
            possessive = re.sub(r"\b([A-Z0-9]*[0-9][A-Z0-9]*)S(\s+AR3\b)", r"\1'S\2", fallback, count=1)
        if possessive != fallback:
            variants.append(("ccir476_decode_possessive_repair", possessive))
    return list(dict.fromkeys(variants))


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
