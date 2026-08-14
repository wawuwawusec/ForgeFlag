# ForgeFlag Delivery Guide

ForgeFlag ships as a cross-platform CTF solving client for macOS, Linux, and
Windows. Four delivery channels cover different operator needs.

## 1. Standalone executable (no Python required)

The release pipeline builds a single-file `forgeflag` executable for every
platform on each `v*` tag:

| Asset | Platform |
| --- | --- |
| `forgeflag-macos-arm64` | macOS (Apple Silicon) |
| `forgeflag-linux-x86_64` | Linux x86_64 |
| `forgeflag-windows-x86_64.exe` | Windows x86_64 |

Download from <https://github.com/wawuwawusec/ForgeFlag/releases>, then:

```bash
chmod +x forgeflag-linux-x86_64
./forgeflag-linux-x86_64 --db .forgeflag/notebook.sqlite init
./forgeflag-linux-x86_64 --db .forgeflag/notebook.sqlite run-all
```

Build one locally with:

```bash
pip install -e ".[build]"
make build-exe        # output: dist/forgeflag
```

## 2. pip install

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install git+https://github.com/wawuwawusec/ForgeFlag.git
forgeflag --db .forgeflag/notebook.sqlite init
```

Runs on Python 3.11+ on all three platforms.

## 3. Docker image

The Kali-based `forgeflag-default` image carries the full toolchain
(binwalk, gdb, hashcat, john, radare2, tshark, volatility3, pwntools, ...):

```bash
make docker-build
docker run --rm -it forgeflag-ctf:latest /bin/bash
```

ToolRunner falls back to this image automatically when host tools are missing,
including on Windows via Docker Desktop.

## 4. From source

```bash
git clone https://github.com/wawuwawusec/ForgeFlag.git
cd ForgeFlag
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
make test && make smoke
```

## Platform notes

- **Windows**: core Unix tools (`file`, `strings`, `tshark`) are not present;
  `forgeflag doctor` reports the toolkit as LIMITED and ToolRunner falls back
  to the Docker image. Docker bind mounts are translated to `//c/...` form
  automatically.
- **macOS**: full native support; install optional tools with
  `brew install binwalk exiftool wireshark` for local (non-Docker) forensics.
- **Linux**: everything works natively; the Docker image adds commercial tools
  (Ghidra, Volatility 3, SageMath) via its extra targets.

## Releasing

```bash
# tag and push; CI builds binaries, sdist, wheel, and attaches them to a GitHub Release
git tag v0.2.0 && git push origin v0.2.0
```

CI (`.github/workflows/ci.yml`) runs the full test suite on all three
platforms on every push/PR to `main`.
