from __future__ import annotations

from itertools import product
from pathlib import Path
import re
from typing import TypeAlias

from forgeflag.archive_analysis import analyze_archive, archive_source_markers, preview_archive_text
from forgeflag.ctf_scope import ctf_scope_evidence
from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
from forgeflag.hash_analysis import hash_summary_from_text
from forgeflag.image import analyze_image_stego_hints, analyze_magic_extension_mismatch, analyze_png_ihdr
from forgeflag.solvers.base import SolverContext
from forgeflag.tools import ctf
from forgeflag.transforms import candidates_to_payload, transform_candidates


class MiscSolver:
    name = "MiscSolver"
    supported_categories = {ChallengeCategory.MISC}

    def solve(self, context: SolverContext) -> SolverResult:
        flag_candidates: list[str] = []
        image_findings = self._analyze_image_attachments(context, flag_candidates)
        if image_findings:
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate" if flag_candidates else "ok",
                tuple(image_findings),
                tuple(dict.fromkeys(flag_candidates)),
            )

        archive_findings = self._analyze_archive_attachments(context, flag_candidates)
        if archive_findings:
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate" if flag_candidates else "ok",
                tuple(archive_findings),
                tuple(dict.fromkeys(flag_candidates)),
            )

        text = "\n".join(_text_inputs(context))
        sandbox_finding = _sandbox_serialization_finding(context, text)
        if sandbox_finding:
            context.notebook.add_finding(sandbox_finding)
            return SolverResult(self.name, context.challenge.challenge_id, "ok", (sandbox_finding,))

        chef_finding, chef_flags = _chef_recipe_finding(context, text)
        if chef_finding:
            context.notebook.add_finding(chef_finding)
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate" if chef_flags else "ok",
                (chef_finding,),
                chef_flags,
            )

        doublehelix_finding, doublehelix_flags = _doublehelix_decay_finding(context, text)
        if doublehelix_finding:
            context.notebook.add_finding(doublehelix_finding)
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate" if doublehelix_flags else "ok",
                (doublehelix_finding,),
                doublehelix_flags,
            )

        hash_summary = hash_summary_from_text(text)
        if hash_summary["candidates"]:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Analyzed misc hash candidates",
                evidence={"hashes": hash_summary, "ctf_scope": ctf_scope_evidence(ChallengeCategory.MISC)},
                hypothesis="Misc text or attachment content contains hash-like values that should be triaged before generic transforms.",
                confidence=0.64,
                next_action="Choose a likely mode, prepare a challenge-scoped wordlist, then run hashcat or John only when requested.",
            )
            context.notebook.add_finding(finding)
            return SolverResult(self.name, context.challenge.challenge_id, "ok", (finding,))

        candidates = transform_candidates(text)
        flags = extract_flags("\n".join(candidate.value for candidate in candidates))
        if candidates:
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Decoded misc transform candidates",
                evidence={
                    "transform_candidates": candidates_to_payload(candidates),
                    "flag_candidates": list(flags),
                    "ctf_scope": ctf_scope_evidence(ChallengeCategory.MISC),
                },
                hypothesis=_transform_hypothesis(flags),
                confidence=0.8 if flags else 0.54,
                next_action=_transform_next_action(flags),
            )
            context.notebook.add_finding(finding)
            return SolverResult(
                self.name,
                context.challenge.challenge_id,
                "flag_candidate" if flags else "ok",
                (finding,),
                flags,
            )

        finding = Finding(
            challenge_id=context.challenge.challenge_id,
            solver=self.name,
            finding="Misc solver placeholder registered",
            evidence={
                "planned_adapters": ["archive triage", "encoding detection", "osint-style CTF artifact parsing"],
                "ctf_scope": ctf_scope_evidence(ChallengeCategory.MISC),
            },
            hypothesis="Future implementation should route unusual artifacts into the closest specialist workflow.",
            confidence=0.35,
            next_action="Implement archive, encoding, and puzzle triage.",
        )
        context.notebook.add_finding(finding)
        return SolverResult(self.name, context.challenge.challenge_id, "placeholder", (finding,))

    def _analyze_image_attachments(self, context: SolverContext, flag_candidates: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for attachment_path in context.challenge.attachment_paths:
            try:
                resolved = Path(ctf.ensure_existing_file(attachment_path))
            except FileNotFoundError:
                continue
            magic_mismatch = analyze_magic_extension_mismatch(resolved)
            png_ihdr = analyze_png_ihdr(resolved)
            image_stego = analyze_image_stego_hints(resolved)
            jpeg_tools, jpeg_flags = _analyze_jpeg_stego_tools(context, resolved, image_stego)
            image_text = _image_text(image_stego)
            decoded_image_candidates = tuple(transform_candidates(image_text)) if image_text else ()
            decoded_image_flags = extract_flags("\n".join(candidate.value for candidate in decoded_image_candidates))
            flags = tuple(dict.fromkeys((*extract_flags(image_text), *decoded_image_flags, *jpeg_flags)))
            if not png_ihdr and not image_stego:
                continue
            flag_candidates.extend(flags)
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Analyzed misc image artifact",
                evidence={
                    "artifact": {"name": resolved.name, "path": str(resolved)},
                    "flag_candidates": list(flags),
                    "ctf_scope": ctf_scope_evidence(ChallengeCategory.MISC),
                    **({"magic_extension_mismatch": magic_mismatch} if magic_mismatch else {}),
                    **({"png_ihdr": png_ihdr} if png_ihdr else {}),
                    **({"image_stego": image_stego} if image_stego else {}),
                    **(
                        {"decoded_image_text_candidates": candidates_to_payload(decoded_image_candidates)}
                        if decoded_image_candidates
                        else {}
                    ),
                    **({"jpeg_stego_tools": jpeg_tools} if jpeg_tools else {}),
                },
                hypothesis=_image_hypothesis(flags, magic_mismatch, png_ihdr, image_stego, jpeg_tools),
                confidence=0.78 if flags else 0.68,
                next_action=_image_next_action(flags, magic_mismatch, png_ihdr, image_stego, jpeg_tools),
            )
            context.notebook.add_finding(finding)
            findings.append(finding)
        return findings

    def _analyze_archive_attachments(self, context: SolverContext, flag_candidates: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for attachment_path in context.challenge.attachment_paths:
            try:
                resolved = Path(ctf.ensure_existing_file(attachment_path))
            except FileNotFoundError:
                continue
            archive = analyze_archive(resolved)
            if not archive:
                continue
            previews = preview_archive_text(resolved)
            flags = extract_flags("\n".join(str(item.get("text_preview", "")) for item in previews))
            flag_candidates.extend(flags)
            source_markers = archive_source_markers(previews)
            finding = Finding(
                challenge_id=context.challenge.challenge_id,
                solver=self.name,
                finding="Analyzed misc archive artifact",
                evidence={
                    "artifact": {"name": resolved.name, "path": str(resolved)},
                    "archive": archive,
                    "archive_text_previews": previews,
                    "source_markers": source_markers,
                    "flag_candidates": list(flags),
                    "ctf_scope": ctf_scope_evidence(ChallengeCategory.MISC),
                },
                hypothesis=_archive_hypothesis(flags, source_markers),
                confidence=0.8 if flags else (0.72 if source_markers else 0.66),
                next_action=_archive_next_action(archive, flags, source_markers),
            )
            context.notebook.add_finding(finding)
            findings.append(finding)
        return findings


def _text_inputs(context: SolverContext) -> list[str]:
    challenge = context.challenge
    values = [
        challenge.title or "",
        challenge.description or "",
        " ".join(challenge.tags),
    ]
    for attachment_path in challenge.attachment_paths:
        try:
            resolved = ctf.ensure_existing_file(attachment_path)
        except FileNotFoundError:
            continue
        try:
            raw = Path(resolved).read_bytes()[:64_000]
        except OSError:
            continue
        values.append(raw.decode("utf-8", errors="ignore"))
    return [value for value in values if value.strip()]


def _sandbox_serialization_finding(context: SolverContext, text: str) -> Finding | None:
    lowered = text.lower()
    if "pickle.loads" not in lowered and "pickle.load" not in lowered:
        return None
    if "blacklist" not in lowered and "sandbox" not in lowered:
        return None
    return Finding(
        challenge_id=context.challenge.challenge_id,
        solver=MiscSolver.name,
        finding="Identified misc sandbox serialization pattern",
        evidence={
            "pattern": "pickle blacklist sandbox",
            "evidence_terms": _matched_terms(lowered, ("pickle", "blacklist", "sandbox", "loads")),
            "source_lines": _matching_lines(text, ("pickle", "blacklist", "sandbox", "loads")),
            "ctf_scope": ctf_scope_evidence(ChallengeCategory.MISC),
        },
        hypothesis="The attachment uses pickle deserialization inside a blacklist-style sandbox, a common CTF object-chain escape pattern.",
        confidence=0.72,
        next_action="Treat the blacklist as bypassable evidence: inspect allowed globals/opcodes, then build a safe local pickle payload reproduction path.",
    )


def _matched_terms(lowered: str, terms: tuple[str, ...]) -> list[str]:
    return [term for term in terms if term.lower() in lowered]


def _matching_lines(text: str, terms: tuple[str, ...], limit: int = 8) -> list[str]:
    lowered_terms = tuple(term.lower() for term in terms)
    lines: list[str] = []
    for line in text.splitlines():
        if any(term in line.lower() for term in lowered_terms):
            lines.append(line.strip()[:220])
        if len(lines) >= limit:
            break
    return lines


Expr: TypeAlias = tuple[int, int, int]


def _chef_recipe_finding(context: SolverContext, text: str) -> tuple[Finding | None, tuple[str, ...]]:
    if not _looks_like_chef_recipe(text):
        return None, ()
    analysis = _solve_chef_recipe(text)
    if not analysis:
        return None, ()
    flags = extract_flags(str(analysis.get("decoded_text", "")))
    finding = Finding(
        challenge_id=context.challenge.challenge_id,
        solver=MiscSolver.name,
        finding="Solved Chef-style misc recipe",
        evidence={
            "decoded_text": analysis["decoded_text"],
            "recipe_name": analysis["recipe_name"],
            "recipe_preamble": analysis["recipe_preamble"],
            "unknown_values": analysis["unknown_values"],
            "unknown_ingredients": analysis["unknown_ingredients"],
            "expression_count": analysis["expression_count"],
            "flag_candidates": list(flags),
            "ctf_scope": ctf_scope_evidence(ChallengeCategory.MISC),
        },
        hypothesis=_chef_hypothesis(flags),
        confidence=0.84 if flags else 0.62,
        next_action=_chef_next_action(flags),
    )
    return finding, flags


def _looks_like_chef_recipe(text: str) -> bool:
    lowered = text.lower()
    return (
        "ingredients." in lowered
        and "method." in lowered
        and "mixing bowl" in lowered
        and ("liquefy contents" in lowered or "liquify contents" in lowered)
    )


def _solve_chef_recipe(text: str, max_unknown: int = 100) -> dict[str, object] | None:
    ingredients, unknowns = _chef_ingredients(text)
    if not ingredients or len(unknowns) > 2:
        return None
    expressions = _chef_output_expressions(text, ingredients, unknowns)
    if not expressions:
        return None
    for values in _chef_unknown_value_space(len(unknowns), max_unknown):
        decoded = _chef_decode_expressions(expressions, values)
        if not decoded:
            continue
        if extract_flags(decoded):
            return {
                "decoded_text": decoded,
                "unknown_values": dict(zip(unknowns, values, strict=False)),
                "unknown_ingredients": unknowns,
                "expression_count": len(expressions),
                "recipe_name": _chef_recipe_name(text),
                "recipe_preamble": _chef_recipe_preamble(text),
            }
    return None


def _chef_recipe_preamble(text: str) -> str:
    before_ingredients = re.split(r"(?i)\bIngredients\.", text, maxsplit=1)[0]
    return " ".join(before_ingredients.split())[-500:]


def _chef_recipe_name(text: str) -> str:
    before_ingredients = re.split(r"(?i)\bIngredients\.", text, maxsplit=1)[0]
    for line in reversed(before_ingredients.splitlines()):
        normalized = line.strip().rstrip(".")
        if normalized:
            return normalized[:120]
    return "Chef recipe"


def _chef_ingredients(text: str) -> tuple[dict[str, Expr], tuple[str, ...]]:
    match = re.search(r"(?is)\bIngredients\.\s*(.*?)\bMethod\.", text)
    if not match:
        return {}, ()
    ingredients: dict[str, Expr] = {}
    unknowns: list[str] = []
    for raw_line in match.group(1).splitlines():
        line = raw_line.strip().rstrip(".")
        if not line:
            continue
        item = re.match(r"(?i)^(?P<amount>\?\?|\d+)\s+\S+\s+(?P<name>.+)$", line)
        if not item:
            continue
        name = item.group("name").strip().lower()
        amount = item.group("amount")
        if amount == "??":
            if name not in unknowns:
                unknowns.append(name)
            ingredients[name] = (1 if len(unknowns) == 1 and unknowns[0] == name else 0, 1 if len(unknowns) == 2 and unknowns[1] == name else 0, 0)
        else:
            ingredients[name] = (0, 0, int(amount))
    return ingredients, tuple(unknowns)


def _chef_output_expressions(text: str, ingredients: dict[str, Expr], unknowns: tuple[str, ...]) -> list[Expr]:
    method_match = re.search(r"(?is)\bMethod\.\s*(.*)", text)
    if not method_match:
        return []
    stack: list[Expr] = []
    for raw_line in method_match.group(1).splitlines():
        line = raw_line.strip()
        action = re.match(r"(?i)^(Put|Add|Remove|Combine)\s+(.+?)\s+(?:into|to|from)\s+1st mixing bowl\.", line)
        if not action:
            continue
        operation = action.group(1).lower()
        ingredient_name = action.group(2).strip().lower()
        ingredient = ingredients.get(ingredient_name)
        if ingredient is None:
            return []
        if operation == "put":
            stack.append(ingredient)
        elif not stack:
            return []
        elif operation == "add":
            stack[-1] = _expr_add(stack[-1], ingredient)
        elif operation == "remove":
            stack[-1] = _expr_sub(stack[-1], ingredient)
        elif operation == "combine":
            multiplied = _expr_mul(stack[-1], ingredient, unknowns)
            if multiplied is None:
                return []
            stack[-1] = multiplied
    return list(reversed(stack))


def _chef_unknown_value_space(count: int, max_unknown: int) -> list[tuple[int, ...]]:
    if count == 0:
        return [()]
    if count == 1:
        return [(value,) for value in range(max_unknown + 1)]
    return [(first, second) for first in range(max_unknown + 1) for second in range(max_unknown + 1)]


def _chef_decode_expressions(expressions: list[Expr], values: tuple[int, ...]) -> str | None:
    chars: list[str] = []
    for pain_coef, effort_coef, constant in expressions:
        first = values[0] if len(values) >= 1 else 0
        second = values[1] if len(values) >= 2 else 0
        codepoint = pain_coef * first + effort_coef * second + constant
        if codepoint < 32 or codepoint > 126:
            return None
        chars.append(chr(codepoint))
    return "".join(chars)


def _expr_add(left: Expr, right: Expr) -> Expr:
    return (left[0] + right[0], left[1] + right[1], left[2] + right[2])


def _expr_sub(left: Expr, right: Expr) -> Expr:
    return (left[0] - right[0], left[1] - right[1], left[2] - right[2])


def _expr_mul(left: Expr, right: Expr, unknowns: tuple[str, ...]) -> Expr | None:
    if _expr_is_constant(left):
        scale = left[2]
        return (right[0] * scale, right[1] * scale, right[2] * scale)
    if _expr_is_constant(right):
        scale = right[2]
        return (left[0] * scale, left[1] * scale, left[2] * scale)
    return None


def _expr_is_constant(expr: Expr) -> bool:
    return expr[0] == 0 and expr[1] == 0


def _chef_hypothesis(flags: tuple[str, ...]) -> str:
    if flags:
        return "A Chef-style recipe program with unknown ingredients produced a flag-like output."
    return "A Chef-style recipe program was symbolically evaluated, but no flag-like output was produced."


def _chef_next_action(flags: tuple[str, ...]) -> str:
    if flags:
        return "Send the recovered recipe output to Verifier and preserve the unknown ingredient assignments."
    return "Review the recovered Chef output and expand the unknown search range if the flag format is unusual."


DOUBLEHELIX_FORMAT: tuple[tuple[int, int], ...] = (
    (1, 0),
    (0, 2),
    (0, 3),
    (0, 4),
    (1, 4),
    (2, 4),
    (3, 3),
    (4, 2),
    (5, 0),
    (5, 0),
    (4, 2),
    (3, 3),
    (2, 4),
    (1, 4),
    (0, 4),
    (0, 3),
    (0, 2),
    (1, 0),
)
DOUBLEHELIX_BITS = {"AT": "00", "CG": "01", "GC": "10", "TA": "11"}
DOUBLEHELIX_PAIRS = tuple(DOUBLEHELIX_BITS)


def _doublehelix_decay_finding(context: SolverContext, text: str) -> tuple[Finding | None, tuple[str, ...]]:
    analysis = _recover_doublehelix_decay(text)
    if not analysis:
        return None, ()
    flags = tuple(analysis.get("flag_candidates", ()))
    finding = Finding(
        challenge_id=context.challenge.challenge_id,
        solver=MiscSolver.name,
        finding="Recovered decayed DoubleHelix Ruby source",
        evidence={
            "doublehelix_decay": analysis,
            "flag_candidates": list(flags),
            "ctf_scope": ctf_scope_evidence(ChallengeCategory.MISC),
        },
        hypothesis=_doublehelix_hypothesis(flags),
        confidence=0.86 if flags else 0.58,
        next_action=_doublehelix_next_action(flags),
    )
    return finding, flags


def _recover_doublehelix_decay(
    text: str,
    max_combinations: int = 100_000,
    preview_limit: int = 8,
    flag_limit: int = 8,
) -> dict[str, object] | None:
    lines = _doublehelix_body_lines(text)
    if len(lines) < 12:
        return None
    candidates_by_line = [_compatible_doublehelix_pairs(line, index) for index, line in enumerate(lines)]
    if any(not candidates for candidates in candidates_by_line):
        return None
    ambiguous_positions = [index for index, candidates in enumerate(candidates_by_line) if len(candidates) > 1]
    combination_count = 1
    for candidates in candidates_by_line:
        combination_count *= len(candidates)
        if combination_count > max_combinations:
            return {
                "pattern": "decayed mame/doublehelix Ruby source",
                "line_count": len(lines),
                "ambiguous_positions": ambiguous_positions,
                "combination_count": combination_count,
                "truncated": True,
                "decoded_candidates": [],
                "flag_candidates": [],
            }
    decoded_by_flag: dict[str, tuple[int, str]] = {}
    decoded_candidates: list[dict[str, object]] = []
    flag_scores: dict[str, int] = {}
    for pair_choice in product(*candidates_by_line):
        decoded = _doublehelix_decode_pairs(pair_choice)
        if not decoded or not _looks_like_recovered_ruby(decoded):
            continue
        flags = extract_flags(decoded)
        score = _doublehelix_candidate_score(decoded, flags)
        if not flags and len(decoded_candidates) >= preview_limit:
            continue
        if flags:
            for flag in flags:
                flag_score = score + _doublehelix_flag_score(decoded, flag)
                if flag_score > flag_scores.get(flag, -10_000):
                    flag_scores[flag] = flag_score
                    decoded_by_flag[flag] = (flag_score, decoded)
        if not flags and len(decoded_candidates) < preview_limit:
            decoded_candidates.append({"score": score, "preview": _single_line_preview(decoded), "flags": []})
    if not decoded_candidates and not flag_scores:
        return None
    flag_candidates = tuple(
        flag for flag, _score in sorted(flag_scores.items(), key=lambda item: (-item[1], item[0]))[:flag_limit]
    )
    for flag in flag_candidates:
        score, decoded = decoded_by_flag[flag]
        decoded_candidates.append({"score": score, "preview": _single_line_preview(decoded), "flags": [flag]})
    decoded_candidates.sort(key=lambda item: (-int(item["score"]), str(item["preview"])))
    return {
        "pattern": "decayed mame/doublehelix Ruby source",
        "line_count": len(lines),
        "ambiguous_positions": ambiguous_positions,
        "combination_count": combination_count,
        "truncated": False,
        "decoded_candidates": decoded_candidates[:preview_limit],
        "flag_candidates": list(flag_candidates),
    }


def _doublehelix_body_lines(text: str) -> list[str]:
    if "doublehelix" not in text.lower():
        return []
    body: list[str] = []
    saw_require = False
    body_started = False
    for line in text.splitlines():
        stripped = line.strip()
        if not saw_require:
            if "doublehelix" in stripped.lower():
                saw_require = True
            continue
        if not stripped and not body_started:
            continue
        if set(line) <= {" ", "\t", "-", "A", "T", "C", "G"}:
            body_started = True
            body.append(line.expandtabs(1).rstrip("\r\n"))
    return body


def _compatible_doublehelix_pairs(line: str, index: int) -> tuple[str, ...]:
    return tuple(pair for pair in DOUBLEHELIX_PAIRS if _doublehelix_line_compatible(line, pair, index))


def _doublehelix_line_compatible(line: str, pair: str, index: int) -> bool:
    expected = _render_doublehelix_pair(pair, index)
    for position, char in enumerate(line.rstrip("\r\n")):
        if char == " ":
            continue
        if position >= len(expected) or expected[position] != char:
            return False
    return True


def _render_doublehelix_pair(pair: str, index: int) -> str:
    offset, distance = DOUBLEHELIX_FORMAT[index % len(DOUBLEHELIX_FORMAT)]
    return (" " * offset) + pair[0] + ("-" * distance) + pair[1]


def _doublehelix_decode_pairs(pairs: tuple[str, ...]) -> str:
    bits = "".join(DOUBLEHELIX_BITS[pair] for pair in pairs)
    decoded = bytearray()
    for position in range(0, len(bits) - 7, 8):
        byte = 0
        for bit_index, bit in enumerate(bits[position : position + 8]):
            if bit == "1":
                byte |= 1 << bit_index
        decoded.append(byte)
    return decoded.decode("utf-8", errors="ignore")


def _looks_like_recovered_ruby(decoded: str) -> bool:
    if extract_flags(decoded):
        return True
    printable = sum(1 for char in decoded if char in "\n\r\t" or 32 <= ord(char) <= 126)
    return bool(decoded) and printable / len(decoded) > 0.9 and any(token in decoded for token in ("puts", "print", "flag", "CTF{"))


def _doublehelix_candidate_score(decoded: str, flags: tuple[str, ...]) -> int:
    score = 0
    if flags:
        score += 200
    if re.search(r'(?i)\bputs\s*["\']?[A-Za-z0-9_]{0,20}(?:ctf|flag)\{', decoded):
        score += 80
    if re.search(r'(?i)\bprint(?:s|f)?\s*["\']?[A-Za-z0-9_]{0,20}(?:ctf|flag)\{', decoded):
        score += 40
    if "DUCTF{" in decoded:
        score += 30
    if re.search(r"[A-Za-z]{4,}", decoded):
        score += 10
    score += sum(1 for char in decoded if char.isalnum() or char in "{}_-'\"() ") // 8
    return score


LEET_WORDS = {
    "a",
    "and",
    "cell",
    "ctf",
    "da",
    "flag",
    "for",
    "from",
    "house",
    "is",
    "key",
    "mitochondria",
    "of",
    "power",
    "secret",
    "the",
    "to",
    "with",
}


def _doublehelix_flag_score(decoded: str, flag: str) -> int:
    score = 0
    if all(32 <= ord(char) <= 126 for char in flag):
        score += 500
    else:
        score -= 1_000
    body = flag[flag.find("{") + 1 : -1]
    if re.fullmatch(r"[A-Za-z0-9_]+", body):
        score += 300
    else:
        score -= 120
    if decoded.strip() == f'puts"{flag}"' or decoded.strip() == f"puts'{flag}'":
        score += 300
    score += _leet_phrase_score(body)
    return score


def _leet_phrase_score(body: str) -> int:
    normalized = body.lower().translate(str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"}))
    score = 0
    for token in re.split(r"[_\W]+", normalized):
        if not token:
            continue
        if token in LEET_WORDS:
            score += 60 + len(token)
        elif len(token) >= 5 and token[:-1] in LEET_WORDS:
            score += 25
        elif len(token) >= 4 and token.isalpha():
            score += 4
    return score


def _single_line_preview(text: str, limit: int = 220) -> str:
    return " ".join(text.split())[:limit]


def _doublehelix_hypothesis(flags: tuple[str, ...]) -> str:
    if flags:
        return "A decayed mame/doublehelix Ruby source was structurally reconstructed and decoded to flag-like output."
    return "A decayed mame/doublehelix Ruby source was detected, but the bounded reconstruction did not yield a flag-like token."


def _doublehelix_next_action(flags: tuple[str, ...]) -> str:
    if flags:
        return "Send the highest-ranked decoded flag candidate to Verifier and preserve the ambiguous-line evidence."
    return "Review decoded previews, then raise the bounded combination limit only if the ambiguity count remains small."


def _transform_hypothesis(flags: tuple[str, ...]) -> str:
    if flags:
        return "A reversible transform chain produced a flag-like token."
    return "Misc challenge text contains encoded data that should guide the next puzzle step."


def _transform_next_action(flags: tuple[str, ...]) -> str:
    if flags:
        return "Send decoded candidates to Verifier and preserve the transform recipe."
    return "Inspect transform candidates, then route to crypto, archive, or stego follow-up."


def _archive_hypothesis(flags: tuple[str, ...], source_markers: dict[str, list[str]] | None = None) -> str:
    if flags:
        return "Archive preview content contains a flag-like token."
    markers = source_markers or {}
    if "restricted_unpickler" in markers or "pickle_module" in markers:
        return "Archive sources implement restricted deserialization; exploit diverging pickle consumer behaviors on the authorized local service to reach the flag."
    if "dynamic_exec" in markers:
        return "Archive sources evaluate dynamic payloads; build a bounded payload that satisfies the sandbox checks."
    if "server_flag_file" in markers:
        return "Archive sources reference a server-side flag file, so a local service replay is needed for the proof of solve."
    return "Misc archive puzzle has structured entries that should be inspected before broader puzzle triage."


def _archive_next_action(
    archive: dict[str, object],
    flags: tuple[str, ...] = (),
    source_markers: dict[str, list[str]] | None = None,
) -> str:
    if flags:
        return "Send archive-derived candidates to Verifier and preserve the archive preview evidence."
    markers = source_markers or {}
    if "restricted_unpickler" in markers:
        return "Compare pickle consumer implementations (python unpickler, C unpickler, pickletools) and craft opcodes that only one accepts."
    if "server_flag_file" in markers:
        return "Stand up the local challenge service and replay the proof-of-solve payload to capture the flag."
    if archive.get("encrypted"):
        return "Collect password hints before attempting archive extraction."
    return "Inspect interesting archive entries and extract only into a managed artifact workspace."


def _analyze_jpeg_stego_tools(
    context: SolverContext,
    image_path: Path,
    image_stego: dict[str, object] | None,
) -> tuple[dict[str, object], tuple[str, ...]]:
    if not image_stego or image_stego.get("format") != "jpeg":
        return {}, ()

    evidence: dict[str, object] = {}
    flags: list[str] = []
    info = ctf.steghide_info(str(image_path), scope=context.scope)
    evidence["steghide_info"] = _tool_result_payload(info)

    attempts: list[dict[str, object]] = []
    output_dir = image_path.parent / ".forgeflag-stego"
    output_dir.mkdir(parents=True, exist_ok=True)
    passphrases = _jpeg_hint_passphrases(context, image_path)
    for passphrase in passphrases:
        result = ctf.steghide_extract(str(image_path), passphrase, str(output_dir), scope=context.scope)
        payload = _tool_result_payload(result)
        payload["passphrase_hint"] = _mask_passphrase_hint(passphrase)
        attempts.append(payload)
        flags.extend(extract_flags(_tool_text(result)))
        for artifact in result.artifacts:
            try:
                artifact_text = Path(artifact).read_bytes()[:64_000].decode("utf-8", errors="ignore")
            except OSError:
                continue
            flags.extend(extract_flags(artifact_text))
        if result.status == "success":
            break

    if attempts:
        best = next((attempt for attempt in attempts if attempt.get("status") == "success"), attempts[-1])
        evidence["steghide_extract"] = best
        evidence["steghide_attempts"] = attempts[:8]
    if not any(attempt.get("status") == "success" for attempt in attempts) and hasattr(ctf, "stegseek_crack"):
        stegseek = ctf.stegseek_crack(str(image_path), passphrases, str(output_dir), scope=context.scope)
        evidence["stegseek_crack"] = _tool_result_payload(stegseek)
        evidence["stegseek_crack"]["wordlist_size"] = len(passphrases)
        flags.extend(extract_flags(_tool_text(stegseek)))
        for artifact in stegseek.artifacts:
            try:
                artifact_text = Path(artifact).read_bytes()[:64_000].decode("utf-8", errors="ignore")
            except OSError:
                continue
            flags.extend(extract_flags(artifact_text))
    return evidence, tuple(dict.fromkeys(flags))


def _jpeg_hint_passphrases(context: SolverContext, image_path: Path, limit: int = 24) -> tuple[str, ...]:
    challenge = context.challenge
    sources = [
        image_path.stem,
        challenge.title or "",
        challenge.description or "",
        " ".join(challenge.tags),
    ]
    values: list[str] = ["", image_path.stem]
    for source in sources:
        cleaned = " ".join(source.replace("_", " ").replace("-", " ").split())
        if cleaned:
            values.append(cleaned)
        for token in re.findall(r"[A-Za-z0-9]{2,32}", source):
            values.append(token)
            values.append(token.lower())
            if token.lower().endswith("s") and len(token) > 3:
                values.append(token[:-1])
                values.append(token[:-1].lower())
    deduped: list[str] = []
    for value in values:
        if len(value) > 64 or value in deduped:
            continue
        deduped.append(value)
        if len(deduped) >= limit:
            break
    return tuple(deduped)


def _tool_result_payload(result: object) -> dict[str, object]:
    status = str(getattr(result, "status", "unknown"))
    raw = getattr(result, "raw", {})
    stdout = str(raw.get("stdout", "")) if isinstance(raw, dict) else ""
    stderr = str(raw.get("stderr", "")) if isinstance(raw, dict) else ""
    payload: dict[str, object] = {
        "status": status,
        "evidence": list(getattr(result, "evidence", []))[:6],
        "artifacts": list(getattr(result, "artifacts", []))[:4],
    }
    if stdout:
        payload["stdout_preview"] = stdout[:500]
    if stderr:
        payload["stderr_preview"] = stderr[:500]
    return payload


def _tool_text(result: object) -> str:
    raw = getattr(result, "raw", {})
    if not isinstance(raw, dict):
        return ""
    return "\n".join(str(raw.get(key, "")) for key in ("stdout", "stderr"))


def _mask_passphrase_hint(passphrase: str) -> str:
    if not passphrase:
        return "<empty>"
    if len(passphrase) <= 2:
        return passphrase[0] + "*"
    return f"{passphrase[0]}{'*' * min(len(passphrase) - 2, 10)}{passphrase[-1]}"


def _image_hypothesis(
    flags: tuple[str, ...],
    magic_mismatch: dict[str, object] | None,
    png_ihdr: dict[str, object] | None,
    image_stego: dict[str, object] | None,
    jpeg_tools: dict[str, object] | None = None,
) -> str:
    if flags:
        return "Image metadata or appended bytes contain a flag-like token."
    if magic_mismatch:
        return "The filename extension is misleading; image puzzle triage should follow the magic-byte format."
    if png_ihdr:
        return "Misc image puzzle has PNG structure evidence that should be inspected before broader puzzle triage."
    if jpeg_tools:
        return "JPEG structure and bounded stego-tool evidence were collected; hidden data may require a stronger passphrase/tool path."
    if image_stego:
        return "Image metadata or structure contains stego-style hints worth inspecting before generic puzzle triage."
    return "Image artifact should be routed to visual and stego follow-up."


def _image_next_action(
    flags: tuple[str, ...],
    magic_mismatch: dict[str, object] | None,
    png_ihdr: dict[str, object] | None,
    image_stego: dict[str, object] | None,
    jpeg_tools: dict[str, object] | None = None,
) -> str:
    if flags:
        return "Send image-derived flag candidates to Verifier and preserve the image evidence path."
    if magic_mismatch:
        actual = magic_mismatch.get("actual_format")
        return f"Ignore the misleading extension and continue image/stego checks as {actual}."
    if png_ihdr and png_ihdr.get("repaired_path"):
        return "Open the repaired PNG, then inspect visible hints, channels, and bit planes."
    if jpeg_tools:
        extract = jpeg_tools.get("steghide_extract") if isinstance(jpeg_tools, dict) else None
        if isinstance(extract, dict) and extract.get("status") == "success":
            return "Inspect the extracted steghide artifact manually if no flag pattern was detected."
        return "Try a challenge-scoped steghide/stegseek wordlist, then move to outguess/F5/JPEG DCT stego checks if passphrases fail."
    if image_stego:
        return "Review image text chunks, comments, and trailing bytes before trying low-bit-plane tools."
    return "Inspect transform candidates, then route to crypto, archive, or stego follow-up."


def _image_text(image_stego: dict[str, object] | None) -> str:
    if not image_stego:
        return ""
    values: list[str] = []
    for item in image_stego.get("text_chunks", []):
        if isinstance(item, dict):
            values.append(str(item.get("text_preview", "")))
    for item in image_stego.get("comments", []):
        if isinstance(item, dict):
            values.append(str(item.get("text_preview", "")))
    for item in image_stego.get("idat_payloads", []):
        if isinstance(item, dict):
            values.append(str(item.get("text_preview", "")))
            values.extend(str(flag) for flag in item.get("flag_like_strings", []) if isinstance(flag, str))
    for item in image_stego.get("lsb_candidates", []):
        if isinstance(item, dict):
            values.append(str(item.get("text_preview", "")))
            values.extend(str(flag) for flag in item.get("flag_like_strings", []) if isinstance(flag, str))
    trailing = image_stego.get("trailing_data")
    if isinstance(trailing, dict):
        values.append(str(trailing.get("ascii_preview", "")))
    return "\n".join(values)
