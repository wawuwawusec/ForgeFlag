# ForgeFlag MCP Tools

ForgeFlag includes an optional MCP server for CTF tool wrappers.

Install the optional dependency:

```bash
pip install -e '.[mcp]'
```

Run the server:

```bash
forgeflag-mcp
```

For scoped network tools, set the allowed hosts before starting the server:

```bash
export FORGEFLAG_ALLOWED_HOSTS=127.0.0.1,challenge.local
forgeflag-mcp
```

Current MCP tools:

- `tool_inventory`
- `analysis_hints`
- `file_identify`
- `strings_extract`
- `checksec_binary`
- `ropgadget_scan`
- `ropper_scan`
- `objdump_disassemble`
- `objdump_section_dump`
- `readelf_sections`
- `radare2_info`
- `rsactftool_attack`
- `hashcat_dictionary_attack`
- `john_dictionary_attack`
- `binwalk_scan`
- `exiftool_read`
- `foremost_carve`
- `yara_scan`
- `tshark_pcap_summary`
- `tshark_traffic_analysis`
- `tshark_dns_summary`
- `tshark_tcp_streams`
- `tshark_follow_tcp_stream`
- `tshark_http_requests`
- `tshark_http_artifact_scan`
- `tshark_http_object_export`
- `tshark_flag_scan`
- `nmap_tcp_basic`
- `ffuf_route_discovery`
- `tcp_interact`

Network-capable tools refuse to run unless the target host is listed in `FORGEFLAG_ALLOWED_HOSTS`. Active network tools such as `nmap_tcp_basic`, `ffuf_route_discovery`, and `tcp_interact` use active-probe scope inside the MCP wrapper and still enforce the allowed-host list.

`analysis_hints` is a read-only ForgeFlag knowledge entrypoint. It returns the same recurrent CTF pattern hints exposed by the Tools tab and `forgeflag hints`, optionally filtered by category.

Reverse and forensics MCP tools remain bounded typed wrappers: they operate on local registered-style artifact paths, sanitize tool-specific arguments in `forgeflag.tools.ctf`, and return structured `ToolResult` payloads instead of exposing arbitrary shell access.

## External Analysis Adapters

Binary-analysis integrations should follow the same boundary as the current IDA MCP adapter:

- disabled unless explicitly configured
- read-only by default
- operate on registered attachment paths only
- expose small typed operations instead of arbitrary shell execution
- return structured evidence that solvers can store in the notebook

Use this pattern for future Ghidra/headless adapters. Heavyweight tools should run from the Docker targets documented in `docs/tool-containers.md` rather than being installed into the local ForgeFlag venv.
