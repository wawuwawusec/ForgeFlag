from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlparse

from forgeflag.domain import ChallengeCategory, Finding, SolverResult
from forgeflag.flags import extract_flags
from forgeflag.solvers.base import SolverContext
from forgeflag.tools import ctf
from forgeflag.tools.http_probe import HttpProbeTool
from forgeflag.web_analysis import HtmlSummary, summarize_html


_SCRIPT_ROUTE_PATTERN = re.compile(r"""["'](\/[A-Za-z0-9][A-Za-z0-9._~!$&()*+,;=:@%\/?#[\]-]*)["']""")
_STATIC_ROUTE_SUFFIXES = (".css", ".gif", ".ico", ".jpg", ".jpeg", ".js", ".map", ".png", ".svg", ".webp")
_SOURCE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".py", ".php", ".rb", ".go", ".java", ".kt", ".cs"}


class WebSolver:
    name = "WebSolver"
    supported_categories = {ChallengeCategory.WEB, ChallengeCategory.UNKNOWN}

    def solve(self, context: SolverContext) -> SolverResult:
        challenge = context.challenge
        findings: list[Finding] = []
        flag_candidates: list[str] = []
        checklist = [
            "map visible routes and forms",
            "identify auth/session boundaries",
            "test input handling only inside declared scope",
            "capture request/response evidence before flag submission",
        ]
        finding = Finding(
            challenge_id=challenge.challenge_id,
            solver=self.name,
            finding="Prepared scoped web challenge workflow",
            evidence={"target": challenge.target, "checklist": checklist},
            hypothesis="The challenge likely requires route, auth, or input-behavior analysis.",
            confidence=0.62,
            next_action="Probe the scoped HTTP target and parse visible HTML structure.",
        )
        context.notebook.add_finding(finding)
        findings.append(finding)

        source_finding, source_flags = _analyze_web_source_attachments(context)
        if source_finding:
            context.notebook.add_finding(source_finding)
            findings.append(source_finding)
            flag_candidates.extend(source_flags)

        if not challenge.target or not challenge.target.startswith(("http://", "https://")):
            return SolverResult(
                solver=self.name,
                challenge_id=challenge.challenge_id,
                status="flag_candidate" if flag_candidates else ("ok" if source_finding else "no_http_target"),
                findings=tuple(findings),
                flag_candidates=tuple(dict.fromkeys(flag_candidates)),
            )

        if not context.scope.active_probe:
            inactive = Finding(
                challenge_id=challenge.challenge_id,
                solver=self.name,
                finding="Skipped HTTP analysis because active probing is disabled",
                evidence={"target": challenge.target},
                hypothesis="Enable --active-probe with --allow-host for authorized challenge targets.",
                confidence=0.5,
                next_action="Rerun with explicit scope if this is an authorized CTF target.",
            )
            context.notebook.add_finding(inactive)
            findings.append(inactive)
            return SolverResult(
                solver=self.name,
                challenge_id=challenge.challenge_id,
                status="scope_required",
                findings=tuple(findings),
            )

        tool_result = HttpProbeTool(context.scope).run(challenge.target)
        context.notebook.add_tool_result(challenge.challenge_id, tool_result)
        sample = str(tool_result.raw.get("sample", ""))
        flags = extract_flags(sample)
        flag_candidates.extend(flags)

        html = summarize_html(sample)
        analysis = Finding(
            challenge_id=challenge.challenge_id,
            solver=self.name,
            finding="Analyzed scoped HTTP response structure",
            evidence={
                "target": challenge.target,
                "tool_status": tool_result.status,
                "tool_evidence": tool_result.evidence,
                "response_sample": sample[:500],
                "chain_hints": _chain_hints(sample),
                "html": html.as_evidence(),
                "flag_candidates": list(flags),
            },
            hypothesis=_web_hypothesis(html, flags),
            confidence=0.82 if tool_result.status == "success" else 0.35,
            next_action=_next_action(html, flags),
        )
        context.notebook.add_finding(analysis)
        findings.append(analysis)

        link_finding, link_flags = _follow_visible_links(context, challenge.target, html)
        if link_finding:
            context.notebook.add_finding(link_finding)
            findings.append(link_finding)
            flag_candidates.extend(link_flags)

        script_finding, script_flags = _follow_script_mentioned_routes(context, challenge.target, sample)
        if script_finding:
            context.notebook.add_finding(script_finding)
            findings.append(script_finding)
            flag_candidates.extend(script_flags)

        ffuf_result = ctf.ffuf_route_discovery(
            challenge.target,
            route_words=_route_words_from_html(html),
            scope=context.scope,
        )
        context.notebook.add_tool_result(challenge.challenge_id, ffuf_result)
        ffuf_finding = Finding(
            challenge_id=challenge.challenge_id,
            solver=self.name,
            finding="Ran scoped ffuf route discovery",
            evidence={
                "target": challenge.target,
                "tool_status": ffuf_result.status,
                "tool_evidence": ffuf_result.evidence,
                "tool_sample": str(ffuf_result.raw.get("stdout", ""))[:1000],
            },
            hypothesis=_ffuf_hypothesis(ffuf_result.status),
            confidence=0.62 if ffuf_result.status == "success" else 0.34,
            next_action=_ffuf_next_action(ffuf_result.status),
        )
        context.notebook.add_finding(ffuf_finding)
        findings.append(ffuf_finding)

        return SolverResult(
            solver=self.name,
            challenge_id=challenge.challenge_id,
            status="flag_candidate" if flag_candidates else "ok",
            findings=tuple(findings),
            flag_candidates=tuple(dict.fromkeys(flag_candidates)),
        )


def _web_hypothesis(html: HtmlSummary, flags: tuple[str, ...]) -> str:
    if flags:
        return "The first scoped response contains a flag-like token that should be verified."
    if html.forms:
        return "The target exposes forms; auth, parameter handling, and route behavior are likely relevant."
    if html.links:
        return "The target exposes links; route mapping is the next useful step."
    return "The target responded, but visible HTML structure is sparse."


def _next_action(html: HtmlSummary, flags: tuple[str, ...]) -> str:
    if flags:
        return "Send candidates to Verifier and record the minimal reproduction path."
    if html.forms:
        return "Add scoped form request capture and low-risk parameter analysis."
    if html.links:
        return "Add route queueing with same-host scope checks."
    return "Capture headers and expand content-type specific analyzers."


def _route_words_from_html(html: HtmlSummary) -> tuple[str, ...]:
    words = ["admin", "login", "flag", "robots.txt"]
    for link in html.links[:10]:
        href = str(link).strip("/")
        if href:
            words.append(href.split("/", 1)[0])
    for form in html.forms[:5]:
        action = str(form.action or "").strip("/")
        if action:
            words.append(action.split("/", 1)[0])
    return tuple(dict.fromkeys(words))


def _chain_hints(sample: str) -> list[str]:
    lowered = sample.lower()
    hints: list[str] = []
    if "lfi" in lowered or "file://" in lowered or "../" in lowered or "..%2f" in lowered:
        hints.append("LFI")
    if ".war" in lowered or "webapps" in lowered:
        hints.append("WAR")
    if "java" in lowered or ".class" in lowered or "tomcat" in lowered:
        hints.append("Java")
    return hints


def _analyze_web_source_attachments(context: SolverContext) -> tuple[Finding | None, tuple[str, ...]]:
    route_map: dict[str, list[str]] = {}
    all_hints: list[str] = []
    samples: dict[str, list[str]] = {}
    flag_candidates: list[str] = []

    for attachment_path in context.challenge.attachment_paths:
        try:
            resolved = ctf.ensure_existing_file(attachment_path)
        except FileNotFoundError:
            continue
        path = Path(resolved)
        if path.suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        routes = _source_routes(source)
        hints = _source_bug_class_hints(source, routes)
        flags = extract_flags(source)
        route_map[resolved] = routes
        all_hints.extend(hints)
        flag_candidates.extend(flags)
        samples[resolved] = _source_sample_lines(source, tuple(dict.fromkeys((*routes, *hints))))

    routes = tuple(dict.fromkeys(route for routes_for_file in route_map.values() for route in routes_for_file))
    hints = tuple(dict.fromkeys(all_hints))
    flags = tuple(dict.fromkeys(flag_candidates))
    if not route_map and not hints and not flags:
        return None, ()

    finding = Finding(
        challenge_id=context.challenge.challenge_id,
        solver=WebSolver.name,
        finding="Analyzed web source attachments",
        evidence={
            "attachments": list(route_map.keys()),
            "routes": list(routes),
            "routes_by_attachment": route_map,
            "bug_class_hints": list(hints),
            "source_samples": samples,
            "flag_candidates": list(flags),
        },
        hypothesis=_source_hypothesis(routes, hints, flags),
        confidence=0.78 if routes or hints else 0.55,
        next_action=_source_next_action(routes, hints, flags),
    )
    return finding, flags


def _source_routes(source: str) -> list[str]:
    patterns = (
        r"@(?:[A-Za-z_][A-Za-z0-9_]*\.)?route\s*\(\s*['\"]([^'\"]+)['\"]",
        r"@(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]",
        r"\b(?:app|router)\.(?:get|post|put|delete|patch|use|all)\s*\(\s*['\"]([^'\"]+)['\"]",
        r"\b(?:path|re_path)\s*\(\s*['\"]([^'\"]+)['\"]",
        r"\bRoute::(?:get|post|put|delete|patch|any)\s*\(\s*['\"]([^'\"]+)['\"]",
    )
    routes: list[str] = []
    for pattern in patterns:
        for match in re.finditer(pattern, source):
            route = match.group(1).strip()
            if route and route not in routes:
                routes.append(route)
    return routes


def _source_bug_class_hints(source: str, routes: list[str]) -> list[str]:
    lowered = source.lower()
    hints: list[str] = []
    if any(route.lower().startswith("/api/options") for route in routes) or (
        "/api/options" in lowered and ("commands" in lowered or "options" in lowered)
    ):
        hints.append("api option leakage")
    if (
        "jwt" in lowered
        or "jsonwebtoken" in lowered
        or "secret_key" in lowered
        or "session" in lowered
        or "cookie" in lowered
    ):
        hints.append("JWT/session")
    if re.search(r"\b(?:requests|urllib|axios|fetch|http\.get|httpx)\s*\.\s*(?:get|post|request|urlopen)\s*\(", source) and re.search(
        r"(?:request\.args|request\.form|req\.query|req\.body|\$_(?:GET|POST)|params)", source
    ):
        hints.append("SSRF")
    if re.search(r"\b(?:open|send_file|file_get_contents|include|require)\s*\(", source) and re.search(
        r"(?:request\.args|request\.form|req\.query|req\.body|\$_(?:GET|POST)|params|filename|path|file)", source
    ):
        hints.append("path traversal")
    if "../" in lowered or "..%2f" in lowered or "safe_join" in lowered:
        hints.append("path traversal")
    return list(dict.fromkeys(hints))


def _source_sample_lines(source: str, terms: tuple[str, ...], limit: int = 8) -> list[str]:
    if not terms:
        return []
    lowered_terms = tuple(term.lower() for term in terms if term)
    lines: list[str] = []
    for line in source.splitlines():
        if any(term in line.lower() for term in lowered_terms):
            lines.append(line.strip()[:220])
        if len(lines) >= limit:
            break
    return lines


def _source_hypothesis(routes: tuple[str, ...], hints: tuple[str, ...], flags: tuple[str, ...]) -> str:
    if flags:
        return "Source attachments contain a flag-like token that should be verified."
    if routes and hints:
        return "Source attachments expose routes and Web bug-class hints for targeted follow-up."
    if routes:
        return "Source attachments expose framework routes that should guide scoped probing."
    return "Source attachments expose Web bug-class hints even without a live target."


def _source_next_action(routes: tuple[str, ...], hints: tuple[str, ...], flags: tuple[str, ...]) -> str:
    if flags:
        return "Send source-derived candidates to Verifier and preserve the attachment path."
    if routes and hints:
        return "Map the listed routes to the live target, then test the hinted bug classes inside declared scope."
    if routes:
        return "Use the extracted route list to prioritize same-origin probing once a target is available."
    return "Review the hinted source sinks and add a target URL before active exploitation."


def _follow_visible_links(
    context: SolverContext,
    target: str,
    html: HtmlSummary,
    limit: int = 5,
) -> tuple[Finding | None, tuple[str, ...]]:
    targets = _scoped_link_targets(target, html, limit)
    if not targets:
        return None, ()

    probe = HttpProbeTool(context.scope)
    statuses: dict[str, str] = {}
    samples: dict[str, str] = {}
    flag_candidates: list[str] = []
    for url in targets:
        result = probe.run(url)
        context.notebook.add_tool_result(context.challenge.challenge_id, result)
        statuses[url] = result.status
        sample = str(result.raw.get("sample", ""))
        samples[url] = sample[:500]
        flag_candidates.extend(extract_flags(sample))

    flags = tuple(dict.fromkeys(flag_candidates))
    finding = Finding(
        challenge_id=context.challenge.challenge_id,
        solver=WebSolver.name,
        finding="Followed scoped visible web links",
        evidence={
            "followed_urls": targets,
            "tool_statuses": statuses,
            "samples": samples,
            "flag_candidates": list(flags),
        },
        hypothesis=_linked_hypothesis(flags),
        confidence=0.84 if flags else 0.58,
        next_action=_linked_next_action(flags),
    )
    return finding, flags


def _follow_script_mentioned_routes(
    context: SolverContext,
    target: str,
    sample: str,
    limit: int = 8,
) -> tuple[Finding | None, tuple[str, ...]]:
    targets = _script_route_targets(target, sample, limit)
    if not targets:
        return None, ()

    probe = HttpProbeTool(context.scope)
    statuses: dict[str, str] = {}
    samples: dict[str, str] = {}
    flag_candidates: list[str] = []
    for url in targets:
        result = probe.run(url)
        context.notebook.add_tool_result(context.challenge.challenge_id, result)
        statuses[url] = result.status
        route_sample = str(result.raw.get("sample", ""))
        samples[url] = route_sample[:500]
        flag_candidates.extend(extract_flags(route_sample))

    flags = tuple(dict.fromkeys(flag_candidates))
    finding = Finding(
        challenge_id=context.challenge.challenge_id,
        solver=WebSolver.name,
        finding="Followed scoped script-mentioned web routes",
        evidence={
            "followed_urls": targets,
            "tool_statuses": statuses,
            "samples": samples,
            "flag_candidates": list(flags),
        },
        hypothesis=_script_route_hypothesis(flags),
        confidence=0.84 if flags else 0.55,
        next_action=_script_route_next_action(flags),
    )
    return finding, flags


def _scoped_link_targets(target: str, html: HtmlSummary, limit: int) -> list[str]:
    parsed_target = urlparse(target)
    urls: list[str] = []
    for link in html.links:
        href = str(link).strip()
        if not href or href.startswith(("#", "mailto:", "javascript:")):
            continue
        joined = urldefrag(urljoin(target, href)).url
        parsed_joined = urlparse(joined)
        if parsed_joined.scheme not in {"http", "https"}:
            continue
        if (parsed_joined.scheme, parsed_joined.netloc) != (parsed_target.scheme, parsed_target.netloc):
            continue
        if joined != target and joined not in urls:
            urls.append(joined)
        if len(urls) >= limit:
            break
    return urls


def _script_route_targets(target: str, sample: str, limit: int) -> list[str]:
    parsed_target = urlparse(target)
    target_without_fragment = urldefrag(target).url
    urls: list[str] = []
    for match in _SCRIPT_ROUTE_PATTERN.finditer(sample):
        path = match.group(1).strip()
        if not path or path.startswith(("//", "/#", "/javascript:")):
            continue
        parsed_path = urlparse(path)
        if parsed_path.path.lower().endswith(_STATIC_ROUTE_SUFFIXES):
            continue
        joined = urldefrag(urljoin(target, path)).url
        parsed_joined = urlparse(joined)
        if parsed_joined.scheme not in {"http", "https"}:
            continue
        if (parsed_joined.scheme, parsed_joined.netloc) != (parsed_target.scheme, parsed_target.netloc):
            continue
        if joined != target_without_fragment and joined not in urls:
            urls.append(joined)
        if len(urls) >= limit:
            break
    return urls


def _linked_hypothesis(flags: tuple[str, ...]) -> str:
    if flags:
        return "A same-origin visible link returned a flag-like token."
    return "Visible same-origin links were reachable and can guide manual route follow-up."


def _linked_next_action(flags: tuple[str, ...]) -> str:
    if flags:
        return "Send linked-route candidates to Verifier and preserve the followed URL path."
    return "Inspect linked pages, then expand to forms or route discovery if needed."


def _script_route_hypothesis(flags: tuple[str, ...]) -> str:
    if flags:
        return "A same-origin route referenced by client-side script returned a flag-like token."
    return "Client-side script referenced reachable same-origin routes that may hide API state."


def _script_route_next_action(flags: tuple[str, ...]) -> str:
    if flags:
        return "Send script-route candidates to Verifier and record the API path as the reproduction step."
    return "Inspect script-referenced API responses and add parameter-aware follow-up if needed."


def _ffuf_hypothesis(status: str) -> str:
    if status == "success":
        return "Low-budget scoped route discovery produced route evidence for follow-up."
    if status == "missing":
        return "ffuf is not installed locally; route discovery was skipped after scope validation."
    return "Scoped ffuf route discovery did not complete successfully."


def _ffuf_next_action(status: str) -> str:
    if status == "success":
        return "Inspect discovered routes and enqueue same-host follow-up only inside declared scope."
    if status == "missing":
        return "Install ffuf or continue with visible links and forms from the HTTP response."
    return "Review ffuf tool evidence before expanding route discovery."
