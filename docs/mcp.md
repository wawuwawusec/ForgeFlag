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
- `file_identify`
- `strings_extract`
- `checksec_binary`
- `ropgadget_scan`
- `ropper_scan`
- `rsactftool_attack`
- `hashcat_dictionary_attack`
- `john_dictionary_attack`
- `binwalk_scan`
- `exiftool_read`
- `tshark_pcap_summary`
- `tshark_traffic_analysis`
- `tshark_dns_summary`
- `tshark_tcp_streams`
- `tshark_http_requests`
- `tshark_http_artifact_scan`
- `tshark_flag_scan`
- `nmap_tcp_basic`
- `ffuf_route_discovery`

Network-capable tools refuse to run unless the target host is listed in `FORGEFLAG_ALLOWED_HOSTS`.

## External Analysis Adapters

Binary-analysis integrations should follow the same boundary as the current IDA MCP adapter:

- disabled unless explicitly configured
- read-only by default
- operate on registered attachment paths only
- expose small typed operations instead of arbitrary shell execution
- return structured evidence that solvers can store in the notebook

Use this pattern for future Ghidra/headless adapters. Heavyweight tools should run from the Docker targets documented in `docs/tool-containers.md` rather than being installed into the local ForgeFlag venv.
