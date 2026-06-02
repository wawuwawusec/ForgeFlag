from __future__ import annotations

from collections import Counter, defaultdict
from typing import Iterable

from forgeflag.flags import extract_flags
from forgeflag.transforms import transform_candidates


_COMMON_DNS_SUFFIX_LABELS = {
    "c2",
    "com",
    "corp",
    "dns",
    "example",
    "exfil",
    "internal",
    "lan",
    "local",
    "net",
    "org",
    "test",
}


def dns_summary_from_tshark(output: str, limit: int = 20) -> dict[str, object]:
    query_counts: Counter[str] = Counter()
    txt_answers: list[str] = []
    long_query_names: list[str] = []
    decoded_query_hints: list[str] = []
    rcode_counts: Counter[str] = Counter()

    for line in output.splitlines():
        frame, query, answer, txt, rcode = _split_fields(line, 5)
        del frame, answer
        query = query.strip()
        txt = txt.strip()
        rcode = rcode.strip()
        if query:
            query_counts[query] += 1
            if _has_long_label(query) and query not in long_query_names:
                long_query_names.append(query)
            for hint in _decoded_query_hints(query):
                if hint not in decoded_query_hints:
                    decoded_query_hints.append(hint)
        if txt and txt not in txt_answers:
            txt_answers.append(txt)
        if rcode:
            rcode_counts[rcode] += 1

    return {
        "query_names": [
            {"name": name, "count": count} for name, count in query_counts.most_common(limit)
        ],
        "txt_answers": txt_answers[:limit],
        "long_query_names": long_query_names[:limit],
        "decoded_query_hints": decoded_query_hints[:limit],
        "rcode_counts": dict(rcode_counts),
    }


def tcp_stream_shortlist(
    tcp_output: str,
    http_requests_output: str = "",
    decoded_payloads: Iterable[str] = (),
    limit: int = 10,
) -> list[dict[str, object]]:
    stream_rows: dict[str, dict[str, object]] = {}
    http_streams = _streams_from_http_requests(http_requests_output)
    flag_streams = _streams_with_flag_hints(tcp_output)
    decoded_flag_present = any(extract_flags(value) for value in decoded_payloads)

    for line in tcp_output.splitlines():
        frame, stream_id, src, sport, dst, dport, protocol, info = _split_fields(line, 8)
        if not stream_id:
            continue
        row = stream_rows.setdefault(
            stream_id,
            {
                "stream_id": stream_id,
                "frames": 0,
                "endpoints": [],
                "protocols": set(),
                "hints": set(),
                "score": 0,
                "sample": "",
            },
        )
        row["frames"] = int(row["frames"]) + 1
        endpoint = f"{src}:{sport}->{dst}:{dport}"
        if endpoint not in row["endpoints"]:
            row["endpoints"].append(endpoint)
        if protocol:
            row["protocols"].add(protocol)
        if not row["sample"] and info:
            row["sample"] = info
        score = 1
        if stream_id in http_streams or protocol.upper() == "HTTP" or "HTTP/" in info:
            row["hints"].add("http_request")
            score += 6
        if stream_id in flag_streams or extract_flags(info):
            row["hints"].add("flag_candidate")
            score += 8
        if decoded_flag_present and stream_id in http_streams:
            row["hints"].add("decoded_payload")
            score += 5
        row["score"] = int(row["score"]) + score
        del frame

    rows = []
    for row in stream_rows.values():
        rows.append(
            {
                "stream_id": row["stream_id"],
                "frames": row["frames"],
                "endpoints": row["endpoints"][:5],
                "protocols": sorted(row["protocols"]),
                "hints": sorted(row["hints"]),
                "score": row["score"],
                "sample": row["sample"],
            }
        )
    return sorted(rows, key=lambda row: (-int(row["score"]), str(row["stream_id"])))[:limit]


def _split_fields(line: str, count: int) -> list[str]:
    parts = line.split("|")
    if len(parts) < count:
        parts.extend([""] * (count - len(parts)))
    return parts[:count]


def _has_long_label(query: str, threshold: int = 24) -> bool:
    return any(len(label) >= threshold for label in query.split("."))


def _decoded_query_hints(query: str) -> list[str]:
    hints: list[str] = []
    for value in _query_payload_candidates(query):
        for candidate in transform_candidates(value, max_depth=2, max_candidates=20):
            for flag in extract_flags(candidate.value):
                if flag not in hints:
                    hints.append(flag)
    return hints


def _query_payload_candidates(query: str) -> list[str]:
    labels = [label for label in query.rstrip(".").split(".") if label]
    candidates: list[str] = []
    for label in labels:
        _add_payload_candidate(candidates, label)

    prefix_payload_labels: list[str] = []
    for label in labels:
        if label.lower() in _COMMON_DNS_SUFFIX_LABELS:
            break
        if len(label) >= 4:
            prefix_payload_labels.append(label)
    for start in range(len(prefix_payload_labels)):
        for end in range(start + 2, len(prefix_payload_labels) + 1):
            _add_payload_candidate(candidates, "".join(prefix_payload_labels[start:end]))

    joined = "".join(label for label in labels if len(label) >= 4)
    _add_payload_candidate(candidates, joined)
    return candidates


def _add_payload_candidate(candidates: list[str], value: str) -> None:
    if len(value) >= 8 and value not in candidates:
        candidates.append(value)


def _streams_from_http_requests(output: str) -> set[str]:
    streams = set()
    for line in output.splitlines():
        _, stream_id, *_ = _split_fields(line, 2)
        if stream_id:
            streams.add(stream_id)
    return streams


def _streams_with_flag_hints(output: str) -> set[str]:
    streams: defaultdict[str, list[str]] = defaultdict(list)
    for line in output.splitlines():
        parts = line.split("|")
        if len(parts) < 2:
            continue
        _, stream_id, *rest = parts
        if not stream_id:
            continue
        text = " ".join(rest)
        streams[stream_id].append(text)
    return {
        stream_id
        for stream_id, values in streams.items()
        if any(extract_flags(value) for value in values)
        or any(extract_flags(candidate.value) for value in values for candidate in transform_candidates(value))
    }
