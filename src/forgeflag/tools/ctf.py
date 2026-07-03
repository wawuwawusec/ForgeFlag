from __future__ import annotations

import os
from pathlib import Path
import socket
import tempfile
from urllib.parse import urlparse

from forgeflag.domain import ToolResult
from forgeflag.safety import ScopePolicy
from forgeflag.tools.runner import ToolRunner


def file_identify(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("file", [path])


def strings_extract(path: str, min_length: int = 4, scope: ScopePolicy | None = None) -> ToolResult:
    min_length = max(1, min(min_length, 64))
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("strings", ["-n", str(min_length), path])


def checksec_binary(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("checksec", ["--file", path])


def ropgadget_scan(path: str, depth: int = 5, scope: ScopePolicy | None = None) -> ToolResult:
    depth = max(1, min(depth, 20))
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("ROPgadget", ["--binary", path, "--depth", str(depth)])


def ropper_scan(path: str, search: str = "pop rdi; ret", scope: ScopePolicy | None = None) -> ToolResult:
    search = _tool_search_literal(search)
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("ropper", ["--file", path, "--search", search, "--nocolor"])


def rsactftool_attack(
    public_key_path: str,
    cipher_path: str | None = None,
    scope: ScopePolicy | None = None,
) -> ToolResult:
    args = ["--publickey", public_key_path]
    if cipher_path:
        args.extend(["--uncipherfile", cipher_path])
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("RsaCtfTool", args, timeout_seconds=30)


def objdump_disassemble(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("objdump", ["-d", "-M", "intel", path], timeout_seconds=30)


def objdump_section_dump(path: str, section: str = ".rodata", scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("objdump", ["-s", "-j", _section_name_literal(section), path], timeout_seconds=20)


def readelf_sections(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("readelf", ["-S", path], timeout_seconds=20)


def radare2_info(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("radare2", ["-2", "-q", "-c", "iI; izz~{}", path], timeout_seconds=20)


def hashcat_dictionary_attack(
    hash_path: str,
    wordlist_path: str,
    hash_mode: int,
    scope: ScopePolicy | None = None,
) -> ToolResult:
    hash_mode = max(0, min(int(hash_mode), 99_999))
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run(
        "hashcat",
        ["-m", str(hash_mode), "-a", "0", "--status", "--potfile-disable", hash_path, wordlist_path],
        timeout_seconds=60,
    )


def john_dictionary_attack(
    hash_path: str,
    wordlist_path: str,
    hash_format: str | None = None,
    scope: ScopePolicy | None = None,
) -> ToolResult:
    args = [f"--wordlist={wordlist_path}"]
    if hash_format:
        args.append(f"--format={_tool_search_literal(hash_format)}")
    args.append(hash_path)
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("john", args, timeout_seconds=60)


def binwalk_scan(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("binwalk", [path])


def exiftool_read(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("exiftool", [path])


def foremost_carve(path: str, output_dir: str, scope: ScopePolicy | None = None) -> ToolResult:
    destination = Path(output_dir).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("foremost", ["-q", "-i", path, "-o", str(destination)], timeout_seconds=30)


def yara_scan(
    path: str,
    rules: dict[str, str] | None = None,
    output_dir: str | None = None,
    scope: ScopePolicy | None = None,
) -> ToolResult:
    destination = Path(output_dir or _tool_temp_dir() or tempfile.mkdtemp(prefix="forgeflag-yara-")).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    rule_path = destination / "forgeflag-yara-rules.yar"
    rule_path.write_text(_yara_rules(rules or {"flag_text": "flag{", "svi_flag": "SVI"}), encoding="utf-8")
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("yara", [str(rule_path), path], timeout_seconds=20)


def steghide_info(path: str, passphrase: str = "", scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("steghide", ["info", path, "-p", passphrase], timeout_seconds=15)


def steghide_extract(
    path: str,
    passphrase: str,
    output_dir: str,
    scope: ScopePolicy | None = None,
) -> ToolResult:
    destination = Path(output_dir).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    output_path = destination / f"{Path(path).stem}-steghide-payload.bin"
    runner = ToolRunner(scope or ScopePolicy())
    result = runner.run(
        "steghide",
        ["extract", "-sf", path, "-p", passphrase, "-xf", str(output_path), "-f"],
        timeout_seconds=20,
    )
    if result.status == "success" and output_path.is_file():
        return ToolResult(
            tool=result.tool,
            target=result.target,
            status=result.status,
            evidence=result.evidence,
            artifacts=[str(output_path)],
            next_hints=result.next_hints,
            raw=result.raw,
            created_at=result.created_at,
        )
    return result


def stegseek_crack(
    path: str,
    wordlist: tuple[str, ...],
    output_dir: str,
    scope: ScopePolicy | None = None,
) -> ToolResult:
    destination = Path(output_dir).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    words = _bounded_wordlist(wordlist)
    if not words:
        return ToolResult(tool="stegseek", target=path, status="refused", evidence=["wordlist is empty"])
    wordlist_path = destination / "stegseek-wordlist.txt"
    output_path = destination / f"{Path(path).stem}-stegseek-payload.bin"
    wordlist_path.write_text("\n".join(words) + "\n", encoding="utf-8")
    runner = ToolRunner(scope or ScopePolicy())
    result = runner.run("stegseek", [path, str(wordlist_path), str(output_path)], timeout_seconds=30)
    if result.status == "success" and output_path.is_file():
        return ToolResult(
            tool=result.tool,
            target=result.target,
            status=result.status,
            evidence=result.evidence,
            artifacts=[str(output_path)],
            next_hints=result.next_hints,
            raw=result.raw,
            created_at=result.created_at,
        )
    return result


def tshark_pcap_summary(path: str, packet_limit: int = 50, scope: ScopePolicy | None = None) -> ToolResult:
    packet_limit = max(1, min(packet_limit, 500))
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("tshark", ["-r", path, "-c", str(packet_limit)])


def tshark_traffic_analysis(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("tshark", ["-r", path, "-q", "-z", "io,phs", "-z", "conv,tcp", "-z", "conv,udp"])


def tshark_dns_summary(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run(
        "tshark",
        [
            "-r",
            path,
            "-Y",
            "dns",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "dns.qry.name",
            "-e",
            "dns.a",
            "-e",
            "dns.txt",
            "-e",
            "dns.flags.rcode",
            "-E",
            "separator=|",
            "-E",
            "occurrence=f",
        ],
    )


def tshark_tcp_streams(path: str, packet_limit: int = 500, scope: ScopePolicy | None = None) -> ToolResult:
    packet_limit = max(1, min(packet_limit, 500))
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run(
        "tshark",
        [
            "-r",
            path,
            "-Y",
            "tcp",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "tcp.stream",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
            "-e",
            "_ws.col.Protocol",
            "-e",
            "_ws.col.Info",
            "-E",
            "separator=|",
            "-E",
            "occurrence=f",
            "-c",
            str(packet_limit),
        ],
    )


def tshark_follow_tcp_stream(path: str, stream_id: int, scope: ScopePolicy | None = None) -> ToolResult:
    stream_id = max(0, min(int(stream_id), 10_000))
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run(
        "tshark",
        ["-r", path, "-q", "-z", f"follow,tcp,ascii,{stream_id}"],
        timeout_seconds=20,
    )


def tshark_http_requests(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run(
        "tshark",
        [
            "-r",
            path,
            "-Y",
            "http.request",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "tcp.stream",
            "-e",
            "http.request.method",
            "-e",
            "http.host",
            "-e",
            "http.request.uri",
            "-e",
            "http.user_agent",
            "-E",
            "separator=|",
            "-E",
            "occurrence=f",
        ],
    )


def tshark_http_artifact_scan(path: str, scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run(
        "tshark",
        [
            "-r",
            path,
            "-Y",
            (
                'http.file_data contains "flag" || http.file_data contains "f1ag" || '
                'http.file_data contains "f1Ag" || http.file_data contains "flAg" || '
                'http.file_data contains "&#102;" || http.file_data contains "hnt.txt" || '
                'http.file_data contains "filename=\\"hnt" || http.request.uri contains "flag" || '
                'http.request.uri contains "hnt"'
            ),
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "tcp.stream",
            "-e",
            "http.request.method",
            "-e",
            "http.request.uri",
            "-e",
            "http.response.code",
            "-e",
            "http.file_data",
            "-E",
            "separator=|",
            "-E",
            "occurrence=f",
        ],
    )


def tshark_http_object_export(path: str, output_dir: str, scope: ScopePolicy | None = None) -> ToolResult:
    destination = Path(output_dir).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run(
        "tshark",
        ["-r", path, "--export-objects", f"http,{destination}"],
        timeout_seconds=20,
    )


def tshark_flag_scan(
    path: str,
    needle: str = "flag{",
    packet_limit: int = 50,
    scope: ScopePolicy | None = None,
) -> ToolResult:
    packet_limit = max(1, min(packet_limit, 200))
    needle = _tshark_contains_literal(needle)
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("tshark", ["-r", path, "-Y", f'frame contains "{needle}"', "-x", "-c", str(packet_limit)])


def nmap_tcp_basic(target: str, ports: str = "1-1024", scope: ScopePolicy | None = None) -> ToolResult:
    runner = ToolRunner(scope or ScopePolicy())
    return runner.run("nmap_tcp_basic", ["-p", ports, target], target=target)


def ffuf_route_discovery(
    target: str,
    route_words: tuple[str, ...] = ("admin", "login", "flag", "robots.txt"),
    rate: int = 25,
    timeout_seconds: int = 15,
    scope: ScopePolicy | None = None,
) -> ToolResult:
    scope = scope or ScopePolicy()
    target_url = _ffuf_target_url(target)
    words = _route_words(route_words)
    rate = max(1, min(rate, 100))
    timeout_seconds = max(3, min(timeout_seconds, 30))
    runner = ToolRunner(scope)
    wordlist_path = ""
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=_tool_temp_dir()) as wordlist:
            wordlist_path = wordlist.name
            wordlist.write("\n".join(words) + "\n")
        return runner.run(
            "ffuf",
            [
                "-u",
                target_url,
                "-w",
                wordlist_path,
                "-of",
                "json",
                "-noninteractive",
                "-rate",
                str(rate),
                "-t",
                "5",
            ],
            target=target,
            timeout_seconds=timeout_seconds,
        )
    finally:
        if wordlist_path:
            try:
                os.unlink(wordlist_path)
            except OSError:
                pass


def tcp_interact(
    target: str,
    payload: bytes | str = b"",
    timeout_seconds: int = 5,
    receive_bytes: int = 4096,
    scope: ScopePolicy | None = None,
) -> ToolResult:
    scope = scope or ScopePolicy()
    try:
        scope.require_active_allowed(target)
        host, port = _tcp_host_port(target)
    except ValueError as exc:
        return ToolResult(tool="tcp_interact", target=target, status="refused", evidence=[str(exc)])

    timeout_seconds = max(1, min(timeout_seconds, 15))
    receive_bytes = max(1, min(receive_bytes, 16_384))
    data = payload.encode("utf-8") if isinstance(payload, str) else payload[:1024]
    received = b""
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            if data:
                sock.sendall(data)
            try:
                received = sock.recv(receive_bytes)
            except socket.timeout:
                received = b""
    except OSError as exc:
        return ToolResult(tool="tcp_interact", target=target, status="error", evidence=[f"network error: {exc}"])

    transcript = received.decode("utf-8", errors="replace")
    return ToolResult(
        tool="tcp_interact",
        target=target,
        status="success",
        evidence=[f"bytes_sent={len(data)}", f"bytes_received={len(received)}"],
        raw={
            "host": host,
            "port": port,
            "payload_preview": data.decode("utf-8", errors="replace")[:200],
            "transcript": transcript,
        },
    )


def ensure_existing_file(path: str) -> str:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"file not found: {resolved}")
    return str(resolved)


def _tcp_host_port(target: str) -> tuple[str, int]:
    parsed = urlparse(target)
    if parsed.scheme in {"tcp", "nc"} and parsed.hostname and parsed.port:
        return parsed.hostname, int(parsed.port)
    if parsed.scheme and parsed.hostname and parsed.port:
        return parsed.hostname, int(parsed.port)
    value = target.strip().removeprefix("nc ").strip()
    parts = value.split()
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1])
    if ":" in value:
        host, port_text = value.rsplit(":", 1)
        if host and port_text.isdigit():
            return host.strip("/"), int(port_text)
    raise ValueError("target must include host and port for tcp_interact")


def _tshark_contains_literal(value: str) -> str:
    cleaned = "".join(char for char in value if char.isprintable() and char not in {'"', "\\"})
    return cleaned[:64] or "flag{"


def _tool_search_literal(value: str) -> str:
    cleaned = "".join(char for char in value if char.isprintable() and char not in {"\x00", "\n", "\r"})
    return cleaned[:80] or "pop rdi; ret"


def _section_name_literal(value: str) -> str:
    cleaned = "".join(char for char in value.strip() if char.isalnum() or char in {"_", "-", "."})
    return cleaned[:80] or ".rodata"


def _yara_rules(rules: dict[str, str]) -> str:
    strings: list[str] = []
    for index, (name, value) in enumerate(rules.items()):
        identifier = "".join(char if char.isalnum() or char == "_" else "_" for char in name.strip()) or f"needle_{index}"
        literal = "".join(char for char in value if char.isprintable() and char not in {"\x00", "\n", "\r"})
        if not literal:
            continue
        escaped = literal.replace("\\", "\\\\").replace('"', '\\"')
        strings.append(f"        ${identifier[:40]} = \"{escaped[:120]}\" ascii wide nocase")
    if not strings:
        strings.append('        $flag_text = "flag{" ascii wide nocase')
    return "rule ForgeFlag_Triage_Needles {\n    strings:\n" + "\n".join(strings) + "\n    condition:\n        any of them\n}\n"


def _bounded_wordlist(words: tuple[str, ...], limit: int = 256) -> tuple[str, ...]:
    cleaned: list[str] = []
    for word in words:
        value = "".join(char for char in word.strip() if char.isprintable() and char not in {"\x00", "\n", "\r"})
        if len(value) > 128 or value in cleaned:
            continue
        if value:
            cleaned.append(value)
        if len(cleaned) >= limit:
            break
    return tuple(cleaned)


def _ffuf_target_url(target: str) -> str:
    if "FUZZ" in target:
        return target
    parsed = urlparse(target)
    if not parsed.scheme:
        return target.rstrip("/") + "/FUZZ"
    return target.rstrip("/") + "/FUZZ"


def _route_words(words: tuple[str, ...], limit: int = 32) -> tuple[str, ...]:
    cleaned: list[str] = []
    for word in words:
        value = "".join(char for char in word.strip().lstrip("/") if char.isprintable() and char not in {"\x00", "\n", "\r"})
        if not value or value in cleaned:
            continue
        cleaned.append(value[:80])
    return tuple(cleaned[:limit]) or ("admin", "login", "flag", "robots.txt")


def _tool_temp_dir() -> str | None:
    docker_mount = os.environ.get("FORGEFLAG_TOOL_DOCKER_MOUNT")
    if not docker_mount:
        return None
    path = Path(docker_mount).expanduser().resolve() / ".forgeflag" / "tool-temp"
    path.mkdir(parents=True, exist_ok=True)
    return str(path)
