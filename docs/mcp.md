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
- `binwalk_scan`
- `exiftool_read`
- `tshark_pcap_summary`
- `tshark_traffic_analysis`
- `tshark_http_requests`
- `tshark_http_artifact_scan`
- `tshark_flag_scan`
- `nmap_tcp_basic`

Network-capable tools refuse to run unless the target host is listed in `FORGEFLAG_ALLOWED_HOSTS`.
